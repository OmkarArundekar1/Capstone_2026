from __future__ import annotations
import os
import pandas as pd
import pytest
from investigation.actions import InvestigationAction
from investigation.loop import default_model_predictor, run_investigation
from ml.dataset_utils import FEATURE_COLUMNS
from ml.train_xgboost import XGBoostCampaignClassifier
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'ml', 'models', 'xgb_severity.json')
MODEL_PATH = os.path.normpath(MODEL_PATH)
DATASET_PATH = os.path.join(os.path.dirname(__file__), '..', 'ml', 'datasets', 'campaign_dataset.csv')
DATASET_PATH = os.path.normpath(DATASET_PATH)
pytestmark = pytest.mark.skipif(not os.path.exists(MODEL_PATH), reason='ml/models/xgb_severity.json is a local, gitignored build artifact -- run `python -m ml.train_xgboost` (from backend/) to produce it.')

@pytest.fixture(scope='module')
def production_model() -> XGBoostCampaignClassifier:
    return XGBoostCampaignClassifier.load(MODEL_PATH)

@pytest.fixture(scope='module')
def real_dataset_row():
    df = pd.read_csv(DATASET_PATH)
    row = df.iloc[0]
    return row[FEATURE_COLUMNS].apply(pd.to_numeric, errors='coerce').fillna(0.0).values

def test_production_artifact_loads_without_error(production_model):
    assert production_model._model is not None
    assert production_model._calibrated is not None

def test_production_artifact_runtime_predictor_loads_it():
    from ml.runtime_predictor import RuntimeCampaignPredictor
    predictor = RuntimeCampaignPredictor.from_model_path(MODEL_PATH)
    assert predictor._model is not None

def test_production_artifact_feature_count_matches_current_schema(production_model):
    assert production_model._model.n_features_in_ == len(FEATURE_COLUMNS)

def test_production_artifact_predicts_on_a_real_historical_feature_vector(production_model, real_dataset_row):
    assert len(real_dataset_row) == len(FEATURE_COLUMNS)
    result = production_model.predict(real_dataset_row)
    assert result['label'] in production_model._classes

def test_production_artifact_prediction_retains_full_contract(production_model, real_dataset_row):
    result = production_model.predict(real_dataset_row)
    assert isinstance(result['label'], str)
    assert 0.0 <= result['confidence'] <= 1.0
    assert isinstance(result['probabilities'], dict) and result['probabilities']
    assert abs(sum(result['probabilities'].values()) - 1.0) < 0.001
    assert result['top_k'] == sorted(result['top_k'], key=lambda item: item['probability'], reverse=True)
    assert {item['label'] for item in result['top_k']} == set(result['probabilities'].keys())
    meta = result['model_metadata']
    assert meta['target_column'] == 'severity'
    assert meta['n_features'] == len(FEATURE_COLUMNS)
    assert set(meta['classes']) == set(production_model._classes)
    assert meta['feature_schema_version']
    assert meta['trained_at']

def test_production_artifact_prediction_context_traces_back_to_campaign(monkeypatch):
    import ml.runtime_predictor as runtime_predictor_module
    import feature_extractors
    from ml.data_prep.generate_synthetic_dataset import generate_synthetic_records
    fixture_record = generate_synthetic_records(1, seed=3)[0]
    monkeypatch.setattr(feature_extractors.extractor, 'extract', lambda campaign_context, current_attack_id, attacker_ip, event_id, **labels: fixture_record)

    class _FakeCampaignContext:
        campaign_id = 'camp-prod-check'
        attacker_ip = '10.0.0.5'
        victim_ip = '10.0.0.6'
    predictor = runtime_predictor_module.RuntimeCampaignPredictor.from_model_path(MODEL_PATH)
    result = predictor.predict_for_campaign(_FakeCampaignContext(), 'T1110', 'evt-1')
    assert result['prediction_context'] == {'campaign_id': 'camp-prod-check', 'attack_id': 'T1110', 'event_id': 'evt-1'}
    assert result['label']
    assert result['model_metadata']['feature_schema_version']

def test_default_model_predictor_serves_real_probabilities_from_production_artifact(monkeypatch):
    import feature_extractors
    from ml.data_prep.generate_synthetic_dataset import generate_synthetic_records
    fixture_record = generate_synthetic_records(1, seed=5)[0]
    monkeypatch.setattr(feature_extractors.extractor, 'extract', lambda campaign_context, current_attack_id, attacker_ip, event_id, **labels: fixture_record)

    class _FakeCampaignContext:
        campaign_id = 'camp-prod-e2e'
        attacker_ip = '10.0.0.9'
        victim_ip = '10.0.0.10'
    predictor = default_model_predictor(_FakeCampaignContext(), 'T1110', 'evt-1')
    assert predictor is not None, 'the committed production artifact must be servable via the default path'
    probabilities = predictor()
    assert probabilities is not None
    assert abs(sum(probabilities.values()) - 1.0) < 0.001

def test_full_closed_loop_with_production_model_artifact(monkeypatch):
    from unittest.mock import MagicMock
    import mitre_feature_engine
    import threat_intelligence_engine
    import detection_confidence_engine
    import threat_attribution_engine
    import attribution_context as attribution_context_module
    import graph_feature_engine
    import evidence.collectors.mitre_collector as mitre_collector_module
    import evidence.collectors.cti_collector as cti_collector_module
    import evidence.collectors.detection_collector as detection_collector_module
    import evidence.collectors.attribution_collector as attribution_collector_module
    import evidence.collectors.campaign_history_collector as history_collector_module
    import evidence.collectors.graph_collector as graph_collector_module
    from rag.mitre_retriever import mitre_retriever
    import feature_extractors
    from evidence.schema import Evidence, EvidenceSource, EvidenceType
    from investigation.loop import default_action_executor

    def _fake_evidence(source):
        return [Evidence(source=source, source_id='x', timestamp='t', type=EvidenceType.TECHNIQUE_KNOWLEDGE, content={}, confidence=0.9, relevance=0.9)]
    monkeypatch.setattr(mitre_feature_engine.engine, 'extract_features', MagicMock(return_value=object()))
    monkeypatch.setattr(mitre_collector_module, 'collect_mitre_evidence', lambda f: _fake_evidence(EvidenceSource.MITRE))
    monkeypatch.setattr(mitre_retriever, 'query', MagicMock(return_value=_fake_evidence(EvidenceSource.MITRE)))
    monkeypatch.setattr(threat_intelligence_engine.engine, 'calculate', MagicMock(return_value=object()))
    monkeypatch.setattr(cti_collector_module, 'collect_cti_evidence', lambda ip, r: _fake_evidence(EvidenceSource.CTI))
    monkeypatch.setattr(detection_confidence_engine.engine, 'calculate', MagicMock(return_value=object()))
    monkeypatch.setattr(detection_collector_module, 'collect_detection_evidence', lambda e, r: _fake_evidence(EvidenceSource.SIEM))
    monkeypatch.setattr(threat_attribution_engine.engine, 'attribute', MagicMock(return_value=object()))
    monkeypatch.setattr(attribution_collector_module, 'collect_attribution_evidence', lambda r: _fake_evidence(EvidenceSource.ATTRIBUTION))
    monkeypatch.setattr(attribution_context_module.context, 'load_historical_campaigns', MagicMock(return_value=[]))
    monkeypatch.setattr(history_collector_module, 'collect_campaign_history_evidence', lambda t, c: _fake_evidence(EvidenceSource.CAMPAIGN_HISTORY))
    monkeypatch.setattr(graph_feature_engine.graph_analytics, 'extract_features', MagicMock(return_value=object()))
    monkeypatch.setattr(graph_collector_module, 'collect_graph_evidence', lambda cid, f: _fake_evidence(EvidenceSource.GRAPH))
    from ml.data_prep.generate_synthetic_dataset import generate_synthetic_records
    fixture_record = generate_synthetic_records(1, seed=9)[0]
    monkeypatch.setattr(feature_extractors.extractor, 'extract', lambda campaign_context, current_attack_id, attacker_ip, event_id, **labels: fixture_record)

    class _FakeCampaignContext:
        campaign_id = 'camp-prod-closed-loop'
        attacker_ip = '10.0.0.20'
        victim_ip = '10.0.0.21'
        techniques = {'T1110', 'T1078'}
    context = _FakeCampaignContext()
    executor = default_action_executor(context, 'T1110', 'evt-1')
    model_predictor = default_model_predictor(context, 'T1110', 'evt-1')
    assert model_predictor is not None
    record = run_investigation(executor, model_predictor=model_predictor, max_steps=8)
    assert record.steps
    actions_taken = [s.action_taken for s in record.steps]
    assert InvestigationAction.XGBOOST_PREDICTION in actions_taken
    xgboost_step = next((s for s in record.steps if s.action_taken == InvestigationAction.XGBOOST_PREDICTION))
    assert xgboost_step.state_after.model_probabilities
    assert xgboost_step.state_after.conclusion in xgboost_step.state_after.model_probabilities
    import json
    json.dumps(record.to_dict())