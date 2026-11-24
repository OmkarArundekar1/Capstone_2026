import networkx as nx
import pytest
import torch
from ml.gnn.graph_encoder import EDGE_FEATURE_DIM, EDGE_TYPE_INDEX, FEATURE_DIM, NODE_TYPE_INDEX, encode_graph
from ml.gnn.layers import SAGEConvLayer
from ml.gnn.model import CampaignGNN, batch_graphs
from ml.gnn.synthetic_graphs import generate_synthetic_campaign_graph, generate_synthetic_dataset
from ml.gnn.train_gnn import MIN_TRAINING_GRAPHS, load_gnn, train_gnn

def _tiny_graph():
    G = nx.DiGraph()
    G.add_node('a', labels=['Attacker'], vt_reputation=80.0)
    G.add_node('c', labels=['Campaign'], risk_score=50.0)
    G.add_node('t', labels=['Technique'])
    G.add_edge('a', 'c', relationship='LAUNCHED')
    G.add_edge('c', 't', relationship='HAS_EVENT')
    return G

def test_encode_graph_shapes_and_type_onehot():
    encoded = encode_graph(_tiny_graph())
    assert encoded.x.shape == (3, FEATURE_DIM)
    assert encoded.num_nodes == 3
    attacker_row = encoded.x[encoded.node_ids.index('a')]
    assert attacker_row[NODE_TYPE_INDEX['Attacker']] == 1.0
    assert attacker_row[NODE_TYPE_INDEX['Campaign']] == 0.0

def test_encode_graph_reads_numeric_properties():
    G = _tiny_graph()
    G.nodes['c']['total_tps'] = 42.0
    encoded = encode_graph(G)
    campaign_row = encoded.x[encoded.node_ids.index('c')]
    from ml.gnn.graph_encoder import NODE_TYPES, NUMERIC_PROPS
    total_tps_col = len(NODE_TYPES) + NUMERIC_PROPS.index('total_tps')
    assert campaign_row[total_tps_col] == 42.0

def test_encode_graph_excludes_risk_score_as_a_leakage_source():
    from ml.gnn.graph_encoder import NUMERIC_PROPS
    assert 'risk_score' not in NUMERIC_PROPS
    G = _tiny_graph()
    G.nodes['c']['risk_score'] = 999.0
    encoded = encode_graph(G)
    campaign_row = encoded.x[encoded.node_ids.index('c')]
    assert 999.0 not in campaign_row.tolist()

def test_encode_graph_symmetrizes_edges():
    encoded = encode_graph(_tiny_graph())
    assert encoded.edge_index.shape[1] == 4

def test_encode_graph_edge_attr_shape_and_alignment():
    encoded = encode_graph(_tiny_graph())
    assert encoded.edge_attr.shape == (encoded.edge_index.shape[1], EDGE_FEATURE_DIM)
    assert torch.allclose(encoded.edge_attr.sum(dim=1), torch.ones(encoded.edge_attr.shape[0]))

def test_encode_graph_edge_attr_reflects_real_relationship_type():
    encoded = encode_graph(_tiny_graph())
    launched_row = encoded.edge_attr[0]
    assert launched_row[EDGE_TYPE_INDEX['LAUNCHED']] == 1.0
    assert launched_row.sum().item() == 1.0

def test_encode_graph_symmetrized_reverse_edge_keeps_same_type():
    encoded = encode_graph(_tiny_graph())
    assert torch.equal(encoded.edge_attr[0], encoded.edge_attr[1])

def test_encode_graph_unrecognized_relationship_falls_back_to_unknown():
    G = nx.DiGraph()
    G.add_node('x', labels=['Campaign'])
    G.add_node('y', labels=['ThreatActor'])
    G.add_edge('x', 'y', relationship='RESEMBLES')
    encoded = encode_graph(G)
    assert encoded.edge_attr[0, EDGE_TYPE_INDEX['Unknown']] == 1.0

def test_encode_graph_missing_relationship_attr_falls_back_to_unknown():
    G = nx.DiGraph()
    G.add_node('x', labels=['Campaign'])
    G.add_node('y', labels=['Host'])
    G.add_edge('x', 'y')
    encoded = encode_graph(G)
    assert encoded.edge_attr[0, EDGE_TYPE_INDEX['Unknown']] == 1.0

def test_encode_empty_graph_returns_zero_nodes():
    encoded = encode_graph(nx.DiGraph())
    assert encoded.num_nodes == 0
    assert encoded.edge_index.shape == (2, 0)
    assert encoded.edge_attr.shape == (0, EDGE_FEATURE_DIM)

def test_unknown_label_falls_back_to_unknown_type():
    G = nx.DiGraph()
    G.add_node('x', labels=['SomeNewLabel'])
    encoded = encode_graph(G)
    assert encoded.node_types == ['Unknown']

def test_sageconv_mean_aggregation_is_correct():
    x = torch.tensor([[1.0, 0.0], [0.0, 1.0], [0.0, 0.0]])
    edge_index = torch.tensor([[0, 1], [2, 2]])
    layer = SAGEConvLayer(2, 2)
    with torch.no_grad():
        layer.self_lin.weight.copy_(torch.eye(2))
        layer.self_lin.bias.zero_()
        layer.neigh_lin.weight.copy_(torch.eye(2))
        layer.neigh_lin.bias.zero_()
    out = layer(x, edge_index)
    assert torch.allclose(out[2], torch.tensor([0.5, 0.5]), atol=1e-05)
    assert torch.allclose(out[0], torch.tensor([1.0, 0.0]), atol=1e-05)

def test_model_forward_produces_correct_shapes():
    graphs = [encode_graph(g) for g, _ in generate_synthetic_dataset(4, seed=1)]
    x, edge_index, batch = batch_graphs(graphs)
    model = CampaignGNN(hidden_dim=16, num_classes=4, num_layers=2)
    logits, embedding = model(x, edge_index, batch, num_graphs=4)
    assert logits.shape == (4, 4)
    assert embedding.shape == (4, 16)

def test_model_gradients_flow():
    graphs = [encode_graph(g) for g, _ in generate_synthetic_dataset(3, seed=2)]
    x, edge_index, batch = batch_graphs(graphs)
    model = CampaignGNN(hidden_dim=8, num_classes=2, num_layers=2)
    logits, _ = model(x, edge_index, batch, num_graphs=3)
    loss = logits.sum()
    loss.backward()
    assert model.convs[0].self_lin.weight.grad is not None
    assert not torch.all(model.convs[0].self_lin.weight.grad == 0)

def test_embed_single_matches_batched_embedding():
    graph, _ = generate_synthetic_campaign_graph(seed=5)
    encoded = encode_graph(graph)
    model = CampaignGNN(hidden_dim=8, num_classes=4, num_layers=2)
    model.eval()
    single = model.embed_single(encoded)
    x, edge_index, batch = batch_graphs([encoded])
    with torch.no_grad():
        _, batched = model(x, edge_index, batch, num_graphs=1)
    assert torch.allclose(single, batched.squeeze(0), atol=1e-06)

def test_train_gnn_rejects_too_few_graphs():
    data = generate_synthetic_dataset(MIN_TRAINING_GRAPHS - 1, seed=3)
    with pytest.raises(ValueError, match='Not enough labeled campaign graphs'):
        train_gnn(data)

def test_train_gnn_end_to_end_and_reload(tmp_path):
    data = generate_synthetic_dataset(120, seed=4)
    result = train_gnn(data, save_dir=str(tmp_path), epochs=30)
    assert result.train_graphs + result.val_graphs == 120
    assert 0.0 <= result.val_accuracy <= 1.0
    assert 0.0 <= result.val_macro_f1 <= 1.0
    assert result.final_train_loss == result.final_train_loss
    loaded = load_gnn(result.model_path)
    graph, _ = data[0]
    encoded = encode_graph(graph)
    embedding = loaded.embed_single(encoded)
    assert embedding.shape == (loaded.embedding_dim,)