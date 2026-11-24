from __future__ import annotations
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import pytest
from campaign_context import CampaignContext
from campaign_correlation_engine import CampaignCorrelationEngine
from operation_decision_engine import OperationDecisionEngine
from operation_feature_engine import OperationFeatureEngine, OperationFeatures
from operation_manager import OperationManager
NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

def _campaign(campaign_id='CAMP_NEW', attacker_ip='10.0.0.5', victim_ip='10.0.0.9', techniques=None, attack_chain=None, first_seen=NOW, last_technique=None):
    return CampaignContext(campaign_id=campaign_id, attacker_ip=attacker_ip, victim_ip=victim_ip, techniques=set(techniques or []), attack_chain=list(attack_chain or []), first_seen=first_seen, last_technique=last_technique)

def _operation_row(operation_id='OP_EXISTING', primary_attacker='10.0.0.5', victim_ip='10.0.0.9', techniques=None, attack_chain=None, created_at=NOW - timedelta(days=1), last_seen=NOW):
    techniques = techniques or []
    return {'operation': {'operation_id': operation_id, 'primary_attacker': primary_attacker, 'created_at': created_at, 'last_seen': last_seen}, 'campaigns': [{'campaign_id': f'{operation_id}_C1', 'victim_ip': victim_ip}] if victim_ip else [], 'techniques': techniques, 'attack_chain': list(attack_chain or techniques)}

@pytest.fixture()
def engine(monkeypatch):
    import campaign_correlation_engine as cce_module
    import operation_manager as om_module
    state = {'active_ids': [], 'inactive_ids': [], 'operations': {}, 'reopened': []}
    monkeypatch.setattr(cce_module, 'get_active_operations', lambda: list(state['active_ids']))
    monkeypatch.setattr(cce_module, 'get_recent_inactive_operations', lambda: list(state['inactive_ids']))
    monkeypatch.setattr(cce_module, 'reopen_operation_db', lambda op_id: state['reopened'].append(op_id))
    monkeypatch.setattr(om_module, 'get_operation_context_data', lambda op_id: state['operations'].get(op_id))
    eng = CampaignCorrelationEngine()
    eng._state = state
    return eng

def test_matching_attacker_victim_and_overlapping_techniques_attaches(engine):
    engine._state['active_ids'] = ['OP_1']
    engine._state['operations']['OP_1'] = _operation_row('OP_1', primary_attacker='10.0.0.5', victim_ip='10.0.0.9', techniques=['T1110', 'T1078', 'T1059'], attack_chain=['T1110', 'T1078', 'T1059'], last_seen=NOW)
    campaign = _campaign(attacker_ip='10.0.0.5', victim_ip='10.0.0.9', techniques=['T1078', 'T1059', 'T1053'], attack_chain=['T1078', 'T1059', 'T1053'], first_seen=NOW)
    result = engine.correlate(campaign)
    assert result.matched is True
    assert result.operation_id == 'OP_1'
    assert result.score >= OperationDecisionEngine.ATTACH_THRESHOLD
    assert result.score == pytest.approx(0.767, abs=0.01)

def test_different_attacker_and_victim_does_not_attach_even_with_identical_techniques(engine):
    engine._state['active_ids'] = ['OP_1']
    shared_techniques = ['T1110', 'T1078', 'T1059']
    engine._state['operations']['OP_1'] = _operation_row('OP_1', primary_attacker='203.0.113.1', victim_ip='198.51.100.1', techniques=shared_techniques, last_seen=NOW)
    campaign = _campaign(attacker_ip='10.0.0.5', victim_ip='10.0.0.9', techniques=shared_techniques, attack_chain=shared_techniques, first_seen=NOW)
    result = engine.correlate(campaign)
    assert result.matched is False
    assert result.operation_id is None

def test_no_active_or_inactive_operations_returns_unmatched_without_error(engine):
    result = engine.correlate(_campaign())
    assert result.matched is False
    assert result.candidate_count == 0
    assert result.candidates == []

@pytest.mark.parametrize('delta,expected', [(timedelta(minutes=59), 1.0), (timedelta(hours=1), 1.0), (timedelta(hours=1, minutes=1), 0.8), (timedelta(hours=23, minutes=59), 0.8), (timedelta(hours=24), 0.8), (timedelta(hours=24, minutes=1), 0.5), (timedelta(days=6, hours=23), 0.5), (timedelta(days=7), 0.5), (timedelta(days=7, hours=1), 0.0), (timedelta(days=30), 0.0)])
def test_temporal_similarity_matches_documented_bands(delta, expected):
    fe = OperationFeatureEngine()
    campaign = _campaign(first_seen=NOW)
    om = OperationManager.__new__(OperationManager)
    from operation_context import OperationContext
    operation = OperationContext(operation_id='OP_X', last_seen=NOW - delta)
    assert fe.extract_temporal_similarity(campaign, operation) == expected

def test_temporal_boundary_flips_the_attach_decision(engine):
    engine._state['active_ids'] = ['OP_1']
    techniques = ['T1110', 'T1078']

    def _try(delta):
        engine._state['operations']['OP_1'] = _operation_row('OP_1', primary_attacker='10.0.0.5', victim_ip='10.0.0.9', techniques=techniques, last_seen=NOW - delta)
        campaign = _campaign(attacker_ip='10.0.0.5', victim_ip='10.0.0.9', techniques=techniques, attack_chain=techniques, first_seen=NOW)
        return engine.correlate(campaign)
    just_inside = _try(timedelta(hours=24))
    just_outside = _try(timedelta(hours=24, minutes=1))
    assert just_inside.score > just_outside.score
    assert just_inside.breakdown['temporal_similarity']['value'] == 0.8
    assert just_outside.breakdown['temporal_similarity']['value'] == 0.5

def test_missing_attacker_victim_technique_and_timestamp_degrades_to_zero_not_crash(engine):
    engine._state['active_ids'] = ['OP_1']
    engine._state['operations']['OP_1'] = _operation_row('OP_1', primary_attacker='10.0.0.5', victim_ip='10.0.0.9')
    campaign = _campaign(attacker_ip='', victim_ip='', techniques=[], attack_chain=[], first_seen=None)
    result = engine.correlate(campaign)
    assert result.matched is False
    assert result.score == 0.0

def test_missing_timestamps_degrade_temporal_similarity_to_zero():
    fe = OperationFeatureEngine()
    from operation_context import OperationContext
    campaign = _campaign(first_seen=None)
    operation = OperationContext(operation_id='OP_X', last_seen=NOW)
    assert fe.extract_temporal_similarity(campaign, operation) == 0.0
    campaign2 = _campaign(first_seen=NOW)
    operation2 = OperationContext(operation_id='OP_X', last_seen=None)
    assert fe.extract_temporal_similarity(campaign2, operation2) == 0.0

def test_empty_technique_sets_on_both_sides_do_not_divide_by_zero():
    fe = OperationFeatureEngine()
    from operation_context import OperationContext
    campaign = _campaign(techniques=[])
    operation = OperationContext(operation_id='OP_X', techniques=set())
    assert fe.extract_technique_similarity(campaign, operation) == 0.0

def test_vanished_operation_candidate_is_skipped_not_fatal(engine):
    engine._state['active_ids'] = ['OP_GONE', 'OP_1']
    engine._state['operations']['OP_1'] = _operation_row('OP_1', primary_attacker='10.0.0.5', victim_ip='10.0.0.9', techniques=['T1110'])
    campaign = _campaign(attacker_ip='10.0.0.5', victim_ip='10.0.0.9', techniques=['T1110'])
    result = engine.correlate(campaign)
    assert result.matched is True
    assert result.operation_id == 'OP_1'
    assert result.candidate_count == 2

def test_none_campaign_context_returns_controlled_empty_result(engine):
    result = engine.correlate(None)
    assert result.matched is False
    assert result.operation_id is None
    assert result.candidates == []

def test_correlating_the_same_campaign_twice_is_idempotent(engine):
    engine._state['active_ids'] = ['OP_1']
    engine._state['operations']['OP_1'] = _operation_row('OP_1', primary_attacker='10.0.0.5', victim_ip='10.0.0.9', techniques=['T1110', 'T1078'])
    campaign = _campaign(attacker_ip='10.0.0.5', victim_ip='10.0.0.9', techniques=['T1110'])
    first = engine.correlate(campaign)
    second = engine.correlate(campaign)
    assert first.matched == second.matched
    assert first.operation_id == second.operation_id
    assert first.score == second.score

def test_attach_campaign_to_operation_sends_correct_parameters(monkeypatch):
    import neo4j_client
    captured = {}

    class _FakeSession:

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def run(self, query, **params):
            captured['query'] = query
            captured['params'] = params

    class _FakeDriver:

        def session(self):
            return _FakeSession()
    monkeypatch.setattr(neo4j_client, 'driver', _FakeDriver())
    campaign = _campaign(campaign_id='CAMP_7', attacker_ip='10.0.0.5', victim_ip='10.0.0.9')
    campaign.last_seen = NOW
    neo4j_client.attach_campaign_to_operation('OP_1', campaign)
    assert captured['params']['operation_id'] == 'OP_1'
    assert captured['params']['campaign_id'] == 'CAMP_7'
    assert captured['params']['attacker'] == '10.0.0.5'
    assert captured['params']['victim'] == '10.0.0.9'
    assert 'MERGE' in captured['query'] and 'HAS_CAMPAIGN' in captured['query']

def test_update_operation_activity_sends_correct_parameters(monkeypatch):
    import neo4j_client
    captured = {}

    class _FakeSession:

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def run(self, query, **params):
            captured['query'] = query
            captured['params'] = params

    class _FakeDriver:

        def session(self):
            return _FakeSession()
    monkeypatch.setattr(neo4j_client, 'driver', _FakeDriver())
    campaign = _campaign(campaign_id='CAMP_7')
    campaign.last_seen = NOW
    neo4j_client.update_operation_activity('OP_1', campaign)
    assert captured['params']['operation_id'] == 'OP_1'
    assert captured['params']['last_seen'] == NOW
    assert "status='ACTIVE'" in captured['query']

def test_attacker_and_victim_mismatch_can_never_reach_attach_threshold():
    max_score_without_identity_match = 1.0 * OperationDecisionEngine.weights['temporal_similarity'] + 1.0 * OperationDecisionEngine.weights['technique_similarity'] + 1.0 * OperationDecisionEngine.weights['chain_similarity'] + 1.0 * OperationDecisionEngine.weights['prediction_similarity'] + 1.0 * OperationDecisionEngine.weights['graph_similarity']
    assert max_score_without_identity_match < OperationDecisionEngine.ATTACH_THRESHOLD
    features = OperationFeatures(attacker_similarity=0.0, victim_similarity=0.0, temporal_similarity=1.0, technique_similarity=1.0, chain_similarity=1.0, prediction_similarity=1.0, graph_similarity=1.0)
    decision = OperationDecisionEngine().evaluate(features)
    assert decision.decision == 'CREATE_NEW_OPERATION'

def test_confidence_is_a_constant_data_completeness_ratio_not_a_match_score():
    strong = OperationDecisionEngine().evaluate(OperationFeatures(attacker_similarity=1.0, victim_similarity=1.0, temporal_similarity=1.0, technique_similarity=1.0, chain_similarity=1.0))
    weak = OperationDecisionEngine().evaluate(OperationFeatures())
    assert strong.confidence == weak.confidence
    from config import IMPLEMENTED_FEATURES
    assert strong.confidence == round(len(IMPLEMENTED_FEATURES) / len(OperationFeatures.__dataclass_fields__) * 100, 1)

def test_realistic_two_campaign_same_attacker_operation_from_real_dataset_techniques():
    engine = CampaignCorrelationEngine()
    import campaign_correlation_engine as cce_module
    import operation_manager as om_module
    active_ids = ['OP_APT']
    operations = {'OP_APT': _operation_row('OP_APT', primary_attacker='185.220.101.7', victim_ip='10.20.0.15', techniques=['T1110.001', 'T1110', 'T1078'], attack_chain=['T1110.001', 'T1110', 'T1078'], last_seen=NOW - timedelta(minutes=30))}
    import pytest as _pytest
    mp = _pytest.MonkeyPatch()
    mp.setattr(cce_module, 'get_active_operations', lambda: active_ids)
    mp.setattr(cce_module, 'get_recent_inactive_operations', lambda: [])
    mp.setattr(cce_module, 'reopen_operation_db', lambda op_id: None)
    mp.setattr(om_module, 'get_operation_context_data', lambda op_id: operations.get(op_id))
    try:
        campaign = _campaign(campaign_id='CAMP_NEW_ALERT', attacker_ip='185.220.101.7', victim_ip='10.20.0.99', techniques=['T1110.001', 'T1110', 'T1078'], attack_chain=['T1110.001', 'T1110', 'T1078'])
        result = engine.correlate(campaign)
    finally:
        mp.undo()
    assert result.matched is True
    assert result.operation_id == 'OP_APT'
    assert result.breakdown['attacker_similarity']['value'] == 1.0
    assert result.breakdown['victim_similarity']['value'] == 0.0

def test_get_active_operations_query_orders_results_deterministically():
    import inspect
    import neo4j_client
    source = inspect.getsource(neo4j_client.get_active_operations)
    assert 'ORDER BY' in source

def test_correlate_breaks_exact_score_ties_by_first_candidate_in_list():
    engine = CampaignCorrelationEngine()
    import campaign_correlation_engine as cce_module
    import operation_manager as om_module
    identical_row_kwargs = dict(primary_attacker='10.0.0.5', victim_ip='10.0.0.9', techniques=['T1110'], attack_chain=['T1110'], last_seen=NOW)
    operations = {'OP_FIRST': _operation_row('OP_FIRST', **identical_row_kwargs), 'OP_SECOND': _operation_row('OP_SECOND', **identical_row_kwargs)}
    import pytest as _pytest
    mp = _pytest.MonkeyPatch()
    mp.setattr(cce_module, 'get_active_operations', lambda: ['OP_FIRST', 'OP_SECOND'])
    mp.setattr(cce_module, 'get_recent_inactive_operations', lambda: [])
    mp.setattr(om_module, 'get_operation_context_data', lambda op_id: operations.get(op_id))
    try:
        campaign = _campaign(attacker_ip='10.0.0.5', victim_ip='10.0.0.9', techniques=['T1110'], first_seen=NOW)
        result = engine.correlate(campaign)
    finally:
        mp.undo()
    assert result.operation_id == 'OP_FIRST'