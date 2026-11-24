from __future__ import annotations
from datetime import datetime, timezone
from types import SimpleNamespace
import pytest
import campaign_manager as campaign_manager_module
import chain_updater
import config
import realtime_socgraph as rsg
from campaign_manager import CampaignManager

class FakeGraph:

    def __init__(self):
        self.campaigns: dict[str, dict] = {}
        self.techniques: set[str] = set()
        self.edges: dict[tuple[str, str], int] = {}
        self.events: list[dict] = []
        self.score = 1.0
        self._next_id = 0

    def create_campaign_db(self, attacker_ip, victim_ip, event_time=None):
        self._next_id += 1
        cid = f'CAMP_FAKE{self._next_id:03d}'
        now = event_time or datetime.now(timezone.utc)
        self.campaigns[cid] = {'campaign_id': cid, 'attacker_ip': attacker_ip, 'victim_ip': victim_ip, 'status': 'ACTIVE', 'first_seen': now, 'last_seen': now, 'last_technique': '', 'predicted_next': '', 'prediction_confidence': 0, 'prediction_generated_at': None, 'reopened_count': 0}
        return cid

    def update_campaign_activity(self, campaign_id, technique=None, event_time=None):
        c = self.campaigns[campaign_id]
        t = event_time or datetime.now(timezone.utc)
        c['last_seen'] = max(c['last_seen'], t) if c['last_seen'] else t
        c['status'] = 'ACTIVE'
        c['last_technique'] = technique

    def get_active_campaign_db(self, attacker_ip, victim_ip):
        for c in self.campaigns.values():
            if c['attacker_ip'] == attacker_ip and c['victim_ip'] == victim_ip and (c['status'] == 'ACTIVE'):
                return dict(c)
        return None

    def get_recent_inactive_campaign_db(self, attacker_ip, victim_ip, limit=5):
        rows = [dict(c) for c in self.campaigns.values() if c['attacker_ip'] == attacker_ip and c['victim_ip'] == victim_ip and (c['status'] in ('INACTIVE', 'REOPENED'))]
        rows.sort(key=lambda c: c['last_seen'], reverse=True)
        return rows[:limit]

    def get_campaign_chain(self, campaign_id):
        return [e['mitre_id'] for e in self.events if e['campaign_id'] == campaign_id and e.get('mitre_id')]

    def close_campaign_db(self, campaign_id, closed_at=None):
        self.campaigns[campaign_id]['status'] = 'INACTIVE'
        self.campaigns[campaign_id]['closed_at'] = closed_at

    def reopen_campaign_db(self, campaign_id, event_time=None):
        c = self.campaigns[campaign_id]
        c['status'] = 'ACTIVE'
        if event_time is not None and event_time > c['last_seen']:
            c['last_seen'] = event_time
        c['reopened_count'] += 1

    def expire_stale_campaigns_db(self, timeout_seconds, reference_time=None):
        from datetime import timedelta
        expired = []
        for c in self.campaigns.values():
            if c['status'] == 'ACTIVE' and c['last_seen'] < reference_time - timedelta(seconds=timeout_seconds):
                c['status'] = 'INACTIVE'
                c['closed_at'] = c['last_seen'] + timedelta(seconds=timeout_seconds)
                expired.append(c['campaign_id'])
        return expired

    def _touch(self, campaign_id, event_time):
        c = self.campaigns[campaign_id]
        if event_time is not None and event_time > c['last_seen']:
            c['last_seen'] = event_time

    def create_attack_event(self, **kw):
        self.campaigns[kw['campaign_id']]['last_technique'] = kw['mitre_id']
        self._touch(kw['campaign_id'], kw.get('event_time'))
        self.techniques.add(kw['mitre_id'])
        self.events.append(dict(kw))
        return f"EVT-{len(self.events)}-{kw['campaign_id']}-{kw['mitre_id']}"

    def create_unattributed_attack_event(self, **kw):
        self._touch(kw['campaign_id'], kw.get('event_time'))
        self.events.append(dict(kw))
        return f"EVT-{len(self.events)}-{kw['campaign_id']}-UNKNOWN"

    def run_cypher(self, query, params):
        if 'RETURN c.last_technique AS previous' in query:
            c = self.campaigns.get(params['campaign_id'])
            return [] if c is None else [{'previous': c['last_technique']}]
        if 'SET c.last_technique' in query:
            self.campaigns[params['campaign_id']]['last_technique'] = params['current']
            return []
        if 'MERGE (a)-[r:NEXT_TECHNIQUE]->(b)' in query:
            src, dst = (params['src'], params['dst'])
            if src in self.techniques and dst in self.techniques:
                self.edges[src, dst] = self.edges.get((src, dst), 0) + 1
            return []
        if 'SET rel.confidence' in query:
            return []
        if 'RETURN' in query and 'r.count AS count' in query:
            n = self.edges.get((params['src'], params['dst']))
            if n is None:
                return []
            return [{'count': n, 'confidence': 1.0, 'created_at': None, 'last_seen': None}]
        raise AssertionError(f'Unexpected Cypher in chain_updater: {query!r}')

class _Result:

    def __init__(self, rows):
        self._rows = rows

    def single(self):
        return self._rows[0] if self._rows else None

    def __iter__(self):
        return iter(self._rows)

class _Session:

    def __init__(self, graph):
        self._graph = graph

    def run(self, query, **params):
        return _Result(self._graph.run_cypher(query, params))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

class _Driver:

    def __init__(self, graph):
        self._graph = graph

    def session(self):
        return _Session(self._graph)

@pytest.fixture
def pipeline(monkeypatch):
    return install_fake_pipeline(monkeypatch)

def install_fake_pipeline(monkeypatch):
    graph = FakeGraph()
    manager = CampaignManager()
    graph.manager = manager
    monkeypatch.setattr(rsg, 'campaign_manager', manager)
    monkeypatch.setattr(campaign_manager_module, 'campaign_manager', manager)
    monkeypatch.setattr(chain_updater, 'campaign_manager', manager, raising=False)
    for name in ('create_campaign_db', 'update_campaign_activity', 'get_active_campaign_db', 'get_recent_inactive_campaign_db', 'get_campaign_chain', 'close_campaign_db', 'reopen_campaign_db', 'expire_stale_campaigns_db'):
        monkeypatch.setattr(campaign_manager_module, name, getattr(graph, name))
    monkeypatch.setattr(chain_updater, 'driver', _Driver(graph))
    monkeypatch.setattr(rsg, 'create_attack_event', graph.create_attack_event)
    monkeypatch.setattr(rsg, 'create_unattributed_attack_event', graph.create_unattributed_attack_event)
    monkeypatch.setattr(campaign_manager_module.campaign_feature_engine, 'extract', lambda context, technique, attacker_ip, reference_time=None: SimpleNamespace())
    monkeypatch.setattr(campaign_manager_module.campaign_decision_engine, 'evaluate', lambda features: SimpleNamespace(score=graph.score, confidence=100.0, available_features=7, total_features=7, breakdown={}))
    monkeypatch.setattr(config, 'GNN_ENABLED', False)
    monkeypatch.setattr(rsg.dedup_engine, 'is_duplicate', lambda **kw: (False, f'fp-{id(kw)}'))
    monkeypatch.setattr(rsg.dedup_engine, 'register_event', lambda **kw: None)
    monkeypatch.setattr(rsg.feature_engine, 'extract_features', lambda *a, **k: SimpleNamespace())
    monkeypatch.setattr(rsg.severity_engine, 'calculate', lambda features: 'Low')
    monkeypatch.setattr(rsg.dynamic_risk_engine, 'calculate', lambda features, severity: SimpleNamespace(risk_score=0.0, risk_level='LOW', confidence=0, breakdown={}))
    monkeypatch.setattr(rsg, 'store_dynamic_risk', lambda campaign_id, dynamic_risk: None)
    monkeypatch.setattr(rsg, 'update_campaign_similarity', lambda campaign_id: None)
    monkeypatch.setattr(rsg, 'update_actor_attribution', lambda campaign_id: None)
    monkeypatch.setattr(rsg, 'predict_next', lambda campaign_id, technique: None)
    monkeypatch.setattr(rsg, 'get_recommendations', lambda predicted: [])
    monkeypatch.setattr(rsg.operation_manager, 'build_campaign_context', lambda campaign_id: SimpleNamespace(campaign_id=campaign_id, techniques=set(), attack_chain=[], predicted_next=None))
    monkeypatch.setattr(rsg.operation_engine, 'correlate', lambda context, reference_time=None: SimpleNamespace(matched=False, score=0.0, confidence=0.0, candidate_count=0, operation_id=None))
    monkeypatch.setattr(rsg.detection_engine, 'calculate', lambda event_id: SimpleNamespace(confidence=0.0))
    monkeypatch.setattr(rsg.threat_engine, 'calculate', lambda attacker_ip: SimpleNamespace(confidence=0.0))
    monkeypatch.setattr(rsg.cti_engine, 'calculate', lambda **kw: SimpleNamespace(score=0.0, level='LOW', publish=False, breakdown={}))
    monkeypatch.setattr(rsg, 'store_cti_confidence', lambda campaign_id, cti: None)
    monkeypatch.setattr(rsg, 'IncidentContext', lambda **kw: SimpleNamespace(**kw))
    monkeypatch.setattr(rsg.attribution_engine, 'attribute', lambda context: SimpleNamespace(actors=[]))
    monkeypatch.setattr(rsg, 'create_operation_db', lambda context: 'OP_FAKE')
    monkeypatch.setattr(rsg, 'attach_campaign_to_operation', lambda operation_id, context: None)
    monkeypatch.setattr(rsg, 'update_operation_activity', lambda operation_id, context: None)
    monkeypatch.setattr(rsg.sync, 'publish_campaign', lambda incident: {'success': False, 'action': 'skipped'})
    monkeypatch.setattr(rsg.requests, 'post', lambda *a, **k: SimpleNamespace(status_code=204))
    return graph

def _alert(technique: str | None, src='10.0.0.5', dst='10.0.0.9', rule_id='900001'):
    rule = {'id': rule_id, 'level': 10, 'description': 'test', 'groups': []}
    if technique is not None:
        rule['mitre'] = {'id': [technique], 'technique': [technique], 'tactic': []}
    return {'rule': rule, 'agent': {'id': '001', 'name': 'victim-host'}, 'data': {'src_ip': src, 'dest_ip': dst}, 'timestamp': '2026-11-03T12:00:00.000+0000'}

def test_consecutive_alerts_in_one_campaign_record_the_transition(pipeline):
    assert rsg.process_alert(_alert('T1595')) is True
    assert rsg.process_alert(_alert('T1110')) is True
    assert pipeline.edges == {('T1595', 'T1110'): 1}

def test_three_step_chain_records_each_consecutive_transition(pipeline):
    for t in ('T1595', 'T1110', 'T1078'):
        assert rsg.process_alert(_alert(t)) is True
    assert pipeline.edges == {('T1595', 'T1110'): 1, ('T1110', 'T1078'): 1}

def test_campaign_last_technique_still_reflects_the_latest_event(pipeline):
    rsg.process_alert(_alert('T1595'))
    rsg.process_alert(_alert('T1110'))
    campaign, = pipeline.campaigns.values()
    assert campaign['last_technique'] == 'T1110'

def test_first_event_of_a_new_campaign_records_no_transition(pipeline):
    rsg.process_alert(_alert('T1595'))
    assert pipeline.edges == {}

def test_repeated_same_technique_records_no_self_transition(pipeline):
    rsg.process_alert(_alert('T1110'))
    rsg.process_alert(_alert('T1110', rule_id='900002'))
    assert pipeline.edges == {}

def test_unknown_alert_between_two_techniques_does_not_hide_the_transition(pipeline):
    rsg.process_alert(_alert('T1595'))
    rsg.process_alert(_alert(None, rule_id='31101'))
    rsg.process_alert(_alert('T1110'))
    assert pipeline.edges == {('T1595', 'T1110'): 1}

def test_second_campaign_segment_after_split_starts_without_a_transition(pipeline, monkeypatch):
    rsg.process_alert(_alert('T1595'))
    monkeypatch.setattr(campaign_manager_module.campaign_decision_engine, 'evaluate', lambda features: SimpleNamespace(score=0.0, confidence=100.0, available_features=7, total_features=7, breakdown={}))
    rsg.process_alert(_alert('T1110'))
    assert len(pipeline.campaigns) == 2
    assert pipeline.edges == {}

def test_previous_technique_is_tracked_per_campaign_not_globally(pipeline):
    rsg.process_alert(_alert('T1595', dst='10.0.0.9'))
    rsg.process_alert(_alert('T1190', dst='10.0.0.10'))
    rsg.process_alert(_alert('T1110', dst='10.0.0.9'))
    assert pipeline.edges == {('T1595', 'T1110'): 1}
from campaign_context import CampaignContext, TransitionContext

def test_update_attack_chain_refuses_to_run_without_a_transition_context():
    with pytest.raises(ValueError):
        chain_updater.update_attack_chain('CAMP_X', 'T1110', None)

def test_update_attack_chain_rejects_a_transition_for_another_event():
    transition = TransitionContext('CAMP_OTHER', 'T1110', 'T1595', False)
    with pytest.raises(ValueError):
        chain_updater.update_attack_chain('CAMP_X', 'T1110', transition)

def test_transition_snapshot_is_taken_before_campaign_state_is_mutated(monkeypatch):
    writes = []
    monkeypatch.setattr(campaign_manager_module, 'update_campaign_activity', lambda campaign_id, technique=None, event_time=None: writes.append((campaign_id, technique)))
    manager = CampaignManager()
    context = CampaignContext(campaign_id='CAMP_X', attacker_ip='a', victim_ip='v', last_technique='T1595', observed_chain=['T1595'], last_seen=datetime.now(timezone.utc))
    transition = manager.activate_campaign_with_transition(context, 'T1110')
    assert transition == TransitionContext('CAMP_X', 'T1110', 'T1595', False)
    assert context.last_technique == 'T1110'
    assert writes == [('CAMP_X', 'T1110')]
    with pytest.raises(Exception):
        transition.previous_technique = 'T1110'

def test_segment_start_flag_is_consumed_exactly_once(monkeypatch):
    monkeypatch.setattr(campaign_manager_module, 'update_campaign_activity', lambda *a, **k: None)
    manager = CampaignManager()
    context = CampaignContext(campaign_id='CAMP_X', attacker_ip='a', victim_ip='v', last_technique='T1595', observed_chain=['T1595'], last_seen=datetime.now(timezone.utc))
    context.skip_next_chain_update = True
    first = manager.activate_campaign_with_transition(context, 'T1595')
    second = manager.activate_campaign_with_transition(context, 'T1110')
    assert first.segment_start is True and first.previous_technique is None
    assert second.segment_start is False and second.previous_technique == 'T1595'
    assert context.skip_next_chain_update is False

def test_legacy_entry_points_still_return_campaign_ids(monkeypatch):
    monkeypatch.setattr(campaign_manager_module, 'update_campaign_activity', lambda *a, **k: None)
    manager = CampaignManager()
    context = CampaignContext(campaign_id='CAMP_X', attacker_ip='a', victim_ip='v', last_seen=datetime.now(timezone.utc))
    assert manager.activate_campaign(context, 'T1110') == 'CAMP_X'