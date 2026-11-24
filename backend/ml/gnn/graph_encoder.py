from __future__ import annotations
from dataclasses import dataclass, field
import networkx as nx
import torch
NODE_TYPES = ['Attacker', 'Campaign', 'AttackEvent', 'Technique', 'Host', 'Unknown']
NODE_TYPE_INDEX = {t: i for i, t in enumerate(NODE_TYPES)}
NUMERIC_PROPS = ['occurrences', 'total_tps', 'tps', 'rule_level', 'vt_reputation', 'threat_actor_reputation', 'malware_confidence', 'tool_confidence', 'misp_confidence', 'ioc_confidence']
FEATURE_DIM = len(NODE_TYPES) + len(NUMERIC_PROPS)
EDGE_TYPES = ['LAUNCHED', 'HAS_EVENT', 'MATCHES', 'TARGETS', 'Unknown']
EDGE_TYPE_INDEX = {t: i for i, t in enumerate(EDGE_TYPES)}
EDGE_FEATURE_DIM = len(EDGE_TYPES)

@dataclass
class EncodedGraph:
    x: torch.Tensor
    edge_index: torch.Tensor
    edge_attr: torch.Tensor = field(default_factory=lambda: torch.zeros((0, EDGE_FEATURE_DIM)))
    node_ids: list[str] = field(default_factory=list)
    node_types: list[str] = field(default_factory=list)

    @property
    def num_nodes(self) -> int:
        return self.x.shape[0]

def _node_type(labels) -> str:
    for label in labels or []:
        if label in NODE_TYPE_INDEX:
            return label
    return 'Unknown'

def _numeric(value) -> float:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0

def _edge_type(attrs: dict) -> str:
    relationship = attrs.get('relationship')
    return relationship if relationship in EDGE_TYPE_INDEX else 'Unknown'

def encode_graph(graph: nx.DiGraph) -> EncodedGraph:
    if graph.number_of_nodes() == 0:
        return EncodedGraph(x=torch.zeros((0, FEATURE_DIM)), edge_index=torch.zeros((2, 0), dtype=torch.long), edge_attr=torch.zeros((0, EDGE_FEATURE_DIM)))
    node_ids = list(graph.nodes())
    id_to_idx = {node_id: i for i, node_id in enumerate(node_ids)}
    node_types = []
    features = torch.zeros((len(node_ids), FEATURE_DIM), dtype=torch.float32)
    for i, node_id in enumerate(node_ids):
        attrs = graph.nodes[node_id]
        node_type = _node_type(attrs.get('labels'))
        node_types.append(node_type)
        features[i, NODE_TYPE_INDEX[node_type]] = 1.0
        for j, prop in enumerate(NUMERIC_PROPS):
            features[i, len(NODE_TYPES) + j] = _numeric(attrs.get(prop))
    src, dst, edge_types = ([], [], [])
    for u, v, attrs in graph.edges(data=True):
        edge_type = _edge_type(attrs)
        src.append(id_to_idx[u])
        dst.append(id_to_idx[v])
        edge_types.append(edge_type)
        src.append(id_to_idx[v])
        dst.append(id_to_idx[u])
        edge_types.append(edge_type)
    edge_index = torch.tensor([src, dst], dtype=torch.long) if src else torch.zeros((2, 0), dtype=torch.long)
    edge_attr = torch.zeros((len(edge_types), EDGE_FEATURE_DIM), dtype=torch.float32)
    for i, edge_type in enumerate(edge_types):
        edge_attr[i, EDGE_TYPE_INDEX[edge_type]] = 1.0
    return EncodedGraph(x=features, edge_index=edge_index, edge_attr=edge_attr, node_ids=node_ids, node_types=node_types)