from __future__ import annotations
import json
from datetime import datetime, timezone
import pytest
from attribution_models import HistoricalCampaign
from campaign_context import CampaignContext
from evidence.schema import Evidence, EvidenceSource, EvidenceType
from evidence.collectors.attribution_collector import collect_attribution_evidence
from evidence.collectors.campaign_history_collector import collect_campaign_history_evidence
from evidence.store import EvidenceStore
from threat_attribution_engine import ThreatAttributionEngine

def _historical(campaign_id, techniques, attacker='203.0.113.9', victim='198.51.100.9', status='INACTIVE'):
    return HistoricalCampaign(campaign_id=campaign_id, attacker=attacker, victim=victim, techniques=list(techniques), timestamps=['2026-01-01T00:00:00+00:00'] * len(techniques), status=status)

def _campaign(techniques, attack_chain=None, campaign_id='CAMP_CURRENT'):
    return CampaignContext(campaign_id=campaign_id, attacker_ip='10.0.0.5', victim_ip='10.0.0.9', techniques=set(techniques), attack_chain=list(attack_chain if attack_chain is not None else techniques))

@pytest.fixture()
def engine():
    return ThreatAttributionEngine()

@pytest.fixture()
def mock_history(monkeypatch):
    import attribution_context as attribution_context_module
    import threat_attribution_engine as threat_attribution_engine_module
    state = {'campaigns': []}
    monkeypatch.setattr(attribution_context_module.context, 'load_historical_campaigns', lambda: list(state['campaigns']))
    monkeypatch.setattr(threat_attribution_engine_module, '_gnn_topology_similarity_for_attribution', lambda a, b: None)
    return state

def test_strong_technique_overlap_produces_populated_attribution_candidate(engine, mock_history):
    mock_history['campaigns'] = [_historical('CAMP_OLD_1', ['T1110', 'T1078', 'T1059'])]
    campaign = _campaign(['T1110', 'T1078', 'T1059'])
    result = engine.attribute(campaign)
    assert len(result.actors) == 1
    actor = result.actors[0]
    assert actor.actor == 'CAMP_OLD_1'
    assert actor.total_score == 100.0
    assert actor.confidence == 100.0
    assert actor.coverage == 100.0
    assert actor.precision == 100.0
    assert actor.matched_techniques == ['T1059', 'T1078', 'T1110']
    assert actor.evidence
    assert any(('Coverage' in e for e in actor.evidence))
    assert any(('Matched 3 ATT&CK techniques' in e for e in actor.evidence))

def test_partial_overlap_computes_documented_weighted_formula(engine, mock_history):
    mock_history['campaigns'] = [_historical('CAMP_OLD_2', ['T1110', 'T1059', 'T1053'])]
    campaign = _campaign(['T1110', 'T1078'])
    result = engine.attribute(campaign)
    assert len(result.actors) == 1
    actor = result.actors[0]
    expected = round((0.5 * 0.5 + 1 / 3 * 0.2 + 0.5 * 0.3) * 100, 2)
    assert actor.total_score == expected
    assert actor.coverage == 50.0
    assert actor.precision == round(100 / 3, 2)

def test_no_historical_campaigns_returns_empty_actors_not_fabricated(engine, mock_history):
    mock_history['campaigns'] = []
    result = engine.attribute(_campaign(['T1110']))
    assert result.actors == []

def test_zero_technique_overlap_is_excluded_not_a_low_confidence_candidate(engine, mock_history):
    mock_history['campaigns'] = [_historical('CAMP_UNRELATED', ['T1595', 'T1592'])]
    result = engine.attribute(_campaign(['T1110', 'T1078']))
    assert result.actors == []

def test_current_campaign_with_no_techniques_yields_no_attribution(engine, mock_history):
    mock_history['campaigns'] = [_historical('CAMP_OLD_1', ['T1110'])]
    result = engine.attribute(_campaign([]))
    assert result.actors == []

def test_competing_candidates_are_ranked_by_the_real_weighted_score_not_arbitrarily(engine, mock_history):
    mock_history['campaigns'] = [_historical('CAMP_HIGH_PRECISION', ['T1110', 'T1078']), _historical('CAMP_LOW_PRECISION', ['T1110', 'T1078', 'T1595', 'T1592', 'T1590'])]
    campaign = _campaign(['T1110', 'T1078'])
    result = engine.attribute(campaign)
    by_id = {a.actor: a for a in result.actors}
    assert by_id['CAMP_HIGH_PRECISION'].precision == 100.0
    assert by_id['CAMP_LOW_PRECISION'].precision == 40.0
    assert by_id['CAMP_HIGH_PRECISION'].total_score > by_id['CAMP_LOW_PRECISION'].total_score
    assert result.actors[0].actor == 'CAMP_HIGH_PRECISION'
    assert result.actors == sorted(result.actors, key=lambda a: a.total_score, reverse=True)

def test_more_than_top_k_candidates_truncates_deterministically(engine, mock_history):
    mock_history['campaigns'] = [_historical(f'CAMP_{i}', ['T1110', 'T1078'] + ([f'T900{i}'] if i else [])) for i in range(8)]
    campaign = _campaign(['T1110', 'T1078'])
    result = engine.attribute(campaign)
    assert len(result.actors) == 5
    assert result.actors[0].actor == 'CAMP_0'
    scores = [a.total_score for a in result.actors]
    assert scores == sorted(scores, reverse=True)

def test_tied_candidates_preserve_deterministic_input_order(engine, mock_history):
    mock_history['campaigns'] = [_historical('CAMP_A', ['T1110', 'T1078']), _historical('CAMP_B', ['T1110', 'T1078'])]
    result = engine.attribute(_campaign(['T1110', 'T1078']))
    assert result.actors[0].total_score == result.actors[1].total_score
    assert [a.actor for a in result.actors] == ['CAMP_A', 'CAMP_B']

def test_attribute_actually_calls_the_real_historical_campaign_loader(engine, monkeypatch):
    import attribution_context as attribution_context_module
    import threat_attribution_engine as threat_attribution_engine_module
    monkeypatch.setattr(threat_attribution_engine_module, '_gnn_topology_similarity_for_attribution', lambda a, b: None)
    calls = []

    def fake_loader():
        calls.append(1)
        return [_historical('CAMP_OLD', ['T1110'])]
    monkeypatch.setattr(attribution_context_module.context, 'load_historical_campaigns', fake_loader)
    engine.attribute(_campaign(['T1110']))
    assert len(calls) == 1

def test_historical_campaign_query_excludes_active_campaigns():
    import inspect
    import attribution_context as attribution_context_module
    source = inspect.getsource(attribution_context_module.AttributionContext.load_historical_campaigns)
    assert 'INACTIVE' in source and 'ARCHIVED' in source
    assert 'ACTIVE' not in source.replace('INACTIVE', '').replace('PROACTIVE', '')

def test_chain_order_not_just_set_overlap_affects_score(engine, mock_history):
    mock_history['campaigns'] = [_historical('CAMP_ORDERED', ['T1110', 'T1078', 'T1059'])]
    in_order = engine.attribute(_campaign(['T1110', 'T1078', 'T1059'], attack_chain=['T1110', 'T1078', 'T1059']))
    reversed_order = engine.attribute(_campaign(['T1110', 'T1078', 'T1059'], attack_chain=['T1059', 'T1078', 'T1110']))
    assert in_order.actors[0].chain_similarity > reversed_order.actors[0].chain_similarity
    assert in_order.actors[0].coverage == reversed_order.actors[0].coverage

def test_attribute_engine_never_writes_to_neo4j():
    import inspect
    import threat_attribution_engine
    source = inspect.getsource(threat_attribution_engine)
    for forbidden in ('driver.session', 'MERGE', 'CREATE', '.run('):
        assert forbidden not in source

def test_attribution_result_propagates_into_misp_event_generation(engine, mock_history):
    from types import SimpleNamespace
    from misp_event_generator import IncidentContext, MISPEventGenerator
    mock_history['campaigns'] = [_historical('CAMP_OLD_1', ['T1110', 'T1078'])]
    campaign = _campaign(['T1110', 'T1078'])
    attribution = engine.attribute(campaign)
    assert attribution.actors
    detection = SimpleNamespace(confidence=0.5, level='MEDIUM', breakdown={'Wazuh': 1, 'Suricata': 1, 'Zeek': 1, 'Sigma': 1, 'YARA': 1})
    dynamic_risk = SimpleNamespace(risk_score=50.0, risk_level='MEDIUM', confidence=0.5)
    cti = SimpleNamespace(score=50.0, level='MEDIUM', publish=False)
    incident = IncidentContext(campaign_id='CAMP_CURRENT', operation_id='OP_1', attacker_ip='10.0.0.5', victim_ip='10.0.0.9', event_id='evt-1', technique='T1078', stage='Initial Access', prediction='T1059', prediction_confidence=0.5, detection=detection, threat=None, dynamic_risk=dynamic_risk, cti=cti, recommendations=[], investigation_payload='{}', timestamp='2026-01-01T00:00:00+00:00', attribution=attribution)
    misp_payload = MISPEventGenerator().generate(incident)
    best = attribution.actors[0]
    attributes = misp_payload['Event']['Attribute']
    tag_names = [t['name'] for t in misp_payload['Event']['Tag']]
    assert any((a['value'] == f'Threat Actor : {best.actor}' for a in attributes))
    assert f'actor:{best.actor}' in tag_names
    assert f'attribution:{int(best.total_score)}' in tag_names

def test_attribution_result_propagates_into_investigation_trace_via_evidence(engine, mock_history):
    mock_history['campaigns'] = [_historical('CAMP_OLD_1', ['T1110', 'T1078'])]
    campaign = _campaign(['T1110', 'T1078'])
    attribution = engine.attribute(campaign)
    evidence_items = collect_attribution_evidence(attribution)
    store = EvidenceStore()
    store.add_many(evidence_items)
    payload = [e.to_dict() for e in store.all()]
    json.dumps(payload)
    assert payload[0]['source'] == 'attribution'
    assert payload[0]['content']['candidate_campaign_id'] == 'CAMP_OLD_1'

def test_attribution_evidence_derives_from_campaign_history_evidence_with_real_candidates(mock_history):
    from investigation.actions import ACTION_METADATA, InvestigationAction
    from investigation.loop import _tag_derived_from
    historical = [_historical('CAMP_OLD_1', ['T1110', 'T1078']), _historical('CAMP_OLD_2', ['T1110', 'T1059'])]
    mock_history['campaigns'] = historical
    campaign = _campaign(['T1110', 'T1078', 'T1059'])
    history_evidence = collect_campaign_history_evidence(campaign.techniques, historical)
    attribution_result = ThreatAttributionEngine().attribute(campaign)
    assert len(attribution_result.actors) >= 2
    attribution_evidence = collect_attribution_evidence(attribution_result)
    store = EvidenceStore()
    store.add_many(history_evidence)
    _tag_derived_from(attribution_evidence, InvestigationAction.ATTRIBUTION_MATCH, store)
    history_ids = {e.evidence_id for e in history_evidence}
    for item in attribution_evidence:
        assert history_ids <= set(item.derived_from), 'every attribution candidate must trace back to the campaign-history evidence its computation depends on, per ActionMeta.depends_on'
    assert ACTION_METADATA[InvestigationAction.ATTRIBUTION_MATCH].depends_on == frozenset({InvestigationAction.CAMPAIGN_HISTORY})