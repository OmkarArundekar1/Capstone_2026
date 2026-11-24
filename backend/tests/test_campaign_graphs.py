import networkx as nx
import pytest
import ml.gnn.campaign_graphs as campaign_graphs
import ml.label_generator as label_generator
from ml.gnn.campaign_graphs import build_campaign_graph_sample, build_real_campaign_dataset, list_campaign_ids
from ml.gnn.graph_encoder import NUMERIC_PROPS

class _FakeSingleResult:

    def __init__(self, row):
        self._row = row

    def single(self):
        return self._row

class _FakeIterResult:

    def __init__(self, rows):
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)

class _FakeSession:

    def __init__(self, campaign_id_rows):
        self._campaign_id_rows = campaign_id_rows

    def run(self, query, **kwargs):
        assert 'MATCH (c:Campaign) RETURN c.campaign_id' in query
        return _FakeIterResult(self._campaign_id_rows)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

class _FakeDriver:

    def __init__(self, campaign_ids):
        self._rows = [{'id': cid} for cid in campaign_ids]

    def session(self):
        return _FakeSession(self._rows)

class _FakeGraphAnalytics:

    def __init__(self, graphs_by_campaign):
        self._graphs = graphs_by_campaign

    def load_graph(self, campaign_id, force_reload=False):
        return self._graphs.get(campaign_id, nx.DiGraph())

def _campaign_subgraph(campaign_id: str, risk_score: float) -> nx.DiGraph:
    G = nx.DiGraph()
    G.add_node(f'attacker-{campaign_id}', labels=['Attacker'], threat_actor_reputation=70.0)
    G.add_node(campaign_id, labels=['Campaign'], risk_score=risk_score)
    G.add_node(f'event-{campaign_id}', labels=['AttackEvent'], occurrences=5)
    G.add_edge(f'attacker-{campaign_id}', campaign_id)
    G.add_edge(campaign_id, f'event-{campaign_id}')
    return G

def test_list_campaign_ids_returns_ids_in_query_order(monkeypatch):
    monkeypatch.setattr('neo4j_client.driver', _FakeDriver(['camp-b', 'camp-a', 'camp-c']))
    assert list_campaign_ids() == ['camp-b', 'camp-a', 'camp-c']

def test_list_campaign_ids_empty_database(monkeypatch):
    monkeypatch.setattr('neo4j_client.driver', _FakeDriver([]))
    assert list_campaign_ids() == []

def test_build_campaign_graph_sample_returns_none_for_unknown_campaign(monkeypatch):
    monkeypatch.setattr('neo4j_client.get_campaign_context_data', lambda campaign_id: None)
    assert build_campaign_graph_sample('does-not-exist') is None

def test_build_campaign_graph_sample_returns_none_when_risk_score_missing(monkeypatch):
    monkeypatch.setattr('neo4j_client.get_campaign_context_data', lambda campaign_id: {'campaign': {'campaign_id': campaign_id}, 'techniques': [], 'attack_chain': []})
    assert build_campaign_graph_sample('camp-no-risk') is None

@pytest.mark.parametrize('risk_score,expected_severity', [(0.0, 'Low'), (600.0, 'Medium'), (975.0, 'High'), (1350.0, 'Critical')])
def test_build_campaign_graph_sample_derives_severity_from_risk_score(monkeypatch, risk_score, expected_severity):
    campaign_id = 'camp-1'
    monkeypatch.setattr('neo4j_client.get_campaign_context_data', lambda cid: {'campaign': {'campaign_id': cid, 'risk_score': risk_score}, 'techniques': [], 'attack_chain': []})
    monkeypatch.setattr('graph_feature_engine.graph_analytics', _FakeGraphAnalytics({campaign_id: _campaign_subgraph(campaign_id, risk_score)}))
    sample = build_campaign_graph_sample(campaign_id)
    assert sample is not None
    assert sample.campaign_id == campaign_id
    assert sample.severity == expected_severity
    assert sample.risk_score == risk_score
    assert sample.num_events == 1
    assert sample.graph.num_nodes == 3

def test_build_campaign_graph_sample_does_not_leak_risk_score_into_graph_features(monkeypatch):
    campaign_id = 'camp-leak-check'
    risk_score = 12345.0
    monkeypatch.setattr('neo4j_client.get_campaign_context_data', lambda cid: {'campaign': {'campaign_id': cid, 'risk_score': risk_score}, 'techniques': [], 'attack_chain': []})
    monkeypatch.setattr('graph_feature_engine.graph_analytics', _FakeGraphAnalytics({campaign_id: _campaign_subgraph(campaign_id, risk_score)}))
    sample = build_campaign_graph_sample(campaign_id)
    assert risk_score not in sample.graph.x.flatten().tolist()

def test_build_real_campaign_dataset_skips_campaigns_without_risk_score(monkeypatch):
    monkeypatch.setattr('neo4j_client.driver', _FakeDriver(['camp-good', 'camp-bad']))

    def fake_context(cid):
        if cid == 'camp-bad':
            return {'campaign': {'campaign_id': cid}, 'techniques': [], 'attack_chain': []}
        return {'campaign': {'campaign_id': cid, 'risk_score': 10.0}, 'techniques': [], 'attack_chain': []}
    monkeypatch.setattr('neo4j_client.get_campaign_context_data', fake_context)
    monkeypatch.setattr('graph_feature_engine.graph_analytics', _FakeGraphAnalytics({'camp-good': _campaign_subgraph('camp-good', 10.0)}))
    dataset = build_real_campaign_dataset()
    assert len(dataset) == 1
    assert dataset[0].campaign_id == 'camp-good'

def test_build_real_campaign_dataset_is_deterministic(monkeypatch):
    monkeypatch.setattr('neo4j_client.driver', _FakeDriver(['camp-a', 'camp-b']))
    monkeypatch.setattr('neo4j_client.get_campaign_context_data', lambda cid: {'campaign': {'campaign_id': cid, 'risk_score': 20.0}, 'techniques': [], 'attack_chain': []})
    monkeypatch.setattr('graph_feature_engine.graph_analytics', _FakeGraphAnalytics({'camp-a': _campaign_subgraph('camp-a', 20.0), 'camp-b': _campaign_subgraph('camp-b', 20.0)}))
    first = build_real_campaign_dataset()
    second = build_real_campaign_dataset()
    assert [s.campaign_id for s in first] == [s.campaign_id for s in second]
    for a, b in zip(first, second):
        assert torch_allclose(a.graph.x, b.graph.x)

def torch_allclose(a, b):
    import torch
    return bool(torch.equal(a, b))

def test_severity_mapping_matches_label_generator():
    assert campaign_graphs._LEVEL_TO_SEVERITY == label_generator._LEVEL_TO_SEVERITY
requires_live_neo4j = pytest.mark.usefixtures('live_neo4j')

@requires_live_neo4j
def test_build_real_campaign_dataset_against_live_neo4j():
    ids = list_campaign_ids()
    dataset = build_real_campaign_dataset()
    assert len(dataset) <= len(ids)
    valid_severities = {'Low', 'Medium', 'High', 'Critical'}
    for sample in dataset:
        assert sample.severity in valid_severities
        assert sample.graph.num_nodes >= 1
        assert 'risk_score' not in NUMERIC_PROPS

@requires_live_neo4j
def test_build_real_campaign_dataset_against_live_neo4j_is_reproducible():
    first = [s.campaign_id for s in build_real_campaign_dataset()]
    second = [s.campaign_id for s in build_real_campaign_dataset()]
    assert first == second