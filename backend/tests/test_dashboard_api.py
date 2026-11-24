import pytest
import dashboard_api

@pytest.fixture()
def client():
    dashboard_api.app.config['TESTING'] = True
    with dashboard_api.app.test_client() as c:
        yield c

def test_query_route_is_registered_exactly_once():
    rules = [r for r in dashboard_api.app.url_map.iter_rules() if r.rule == '/api/query']
    assert len(rules) == 1
    assert rules[0].endpoint == 'execute_query'

def test_query_console_endpoint_no_longer_exists():
    endpoints = {r.endpoint for r in dashboard_api.app.url_map.iter_rules()}
    assert 'query_console' not in endpoints

def test_rag_mitre_search_requires_query(client):
    resp = client.post('/api/rag/mitre/search', json={})
    assert resp.status_code == 400

def test_rag_mitre_search_end_to_end_real_corpus(client):
    resp = client.post('/api/rag/mitre/search', json={'query': 'attacker repeatedly guessing account passwords', 'top_k': 3})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['query']
    assert len(data['results']) > 0
    for r in data['results']:
        assert r['source'] == 'mitre'
        assert 0.0 <= r['relevance'] <= 1.0

def test_investigate_requires_json_body_tolerant(client):
    resp = client.post('/api/investigate/nonexistent-campaign')
    assert resp.status_code in (404, 500, 503)
    assert resp.is_json

def test_ml_predict_severity_without_model_returns_503(client, monkeypatch):
    real_exists = dashboard_api.os.path.exists
    monkeypatch.setattr(dashboard_api.os.path, 'exists', lambda path: False if str(path).endswith('xgb_severity.json') else real_exists(path))
    resp = client.post('/api/ml/predict/severity', json={'campaign_id': 'camp-1'})
    assert resp.status_code == 503
    assert 'error' in resp.get_json()

def test_ml_predict_severity_requires_campaign_id(client):
    resp = client.post('/api/ml/predict/severity', json={})
    assert resp.status_code == 400