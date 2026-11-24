from __future__ import annotations
import json
import logging
from dataclasses import dataclass
import pytest
from attribution_models import HistoricalCampaign
from campaign_context import CampaignContext
from cti_publisher import CTIPublisher
from misp_cache import MISPCache
from misp_event_generator import IncidentContext, MISPEventGenerator
from misp_sync import MISPSync
from threat_attribution_engine import ThreatAttributionEngine

class _FakeResponse:

    def __init__(self, status_code, json_body=None, text='', raise_json_error=False):
        self.status_code = status_code
        self.ok = 200 <= status_code < 400
        self._json_body = json_body
        self.text = text if not raise_json_error else '<html>not json</html>'
        self._raise_json_error = raise_json_error

    def json(self):
        if self._raise_json_error:
            raise ValueError('not JSON')
        return self._json_body

@dataclass
class _Stub:
    confidence: float = 0.5
    level: str = 'MEDIUM'
    breakdown: dict = None
    risk_score: float = 50.0
    risk_level: str = 'MEDIUM'
    score: float = 50.0
    publish: bool = True

    def __post_init__(self):
        if self.breakdown is None:
            self.breakdown = {k: 1 for k in ('Wazuh', 'Suricata', 'Zeek', 'Sigma', 'YARA')}

def _incident(**overrides):
    defaults = dict(campaign_id='CAMP_TEST', operation_id='OP_TEST', attacker_ip='203.0.113.7', victim_ip='10.0.0.9', event_id='evt-1', technique='T1110', stage='Credential Access', prediction='T1078', prediction_confidence=0.6, detection=_Stub(), threat=_Stub(), dynamic_risk=_Stub(), cti=_Stub(), recommendations=['Rotate credentials'], investigation_payload='{}', timestamp='2026-01-15T12:00:00+00:00', attribution=None)
    defaults.update(overrides)
    return IncidentContext(**defaults)

@pytest.fixture()
def publisher():
    return CTIPublisher('https://misp.test.invalid', 'test-api-key-should-never-leak', verify_ssl=False)

def _mock_request(monkeypatch, pub, fn):
    monkeypatch.setattr(pub.session, 'request', fn)

def test_basic_event_generation_has_required_structure_and_serializes():
    incident = _incident()
    event = MISPEventGenerator().generate(incident)
    assert 'Event' in event
    body = event['Event']
    for key in ('info', 'distribution', 'threat_level_id', 'analysis', 'published', 'date', 'Attribute', 'Tag'):
        assert key in body
    assert body['info'] == 'CYUKTI Campaign CAMP_TEST'
    assert isinstance(body['Attribute'], list) and body['Attribute']
    assert isinstance(body['Tag'], list) and body['Tag']
    json.dumps(event)

def test_attribution_enrichment_reaches_generated_event():
    engine = ThreatAttributionEngine()
    historical = [HistoricalCampaign(campaign_id='CAMP_OLD', attacker='203.0.113.7', victim='10.0.0.1', techniques=['T1110', 'T1078'], timestamps=['2026-01-01T00:00:00+00:00'] * 2, status='ARCHIVED')]
    campaign = CampaignContext(campaign_id='CAMP_TEST', attacker_ip='203.0.113.7', victim_ip='10.0.0.9', techniques={'T1110', 'T1078'}, attack_chain=['T1110', 'T1078'])
    import attribution_context as attribution_context_module
    original = attribution_context_module.context.load_historical_campaigns
    attribution_context_module.context.load_historical_campaigns = lambda: historical
    try:
        attribution = engine.attribute(campaign)
    finally:
        attribution_context_module.context.load_historical_campaigns = original
    assert attribution.actors
    incident = _incident(attribution=attribution)
    event = MISPEventGenerator().generate(incident)
    attributes = event['Event']['Attribute']
    tag_names = [t['name'] for t in event['Event']['Tag']]
    best = attribution.actors[0]
    assert any((a['value'] == f'Threat Actor : {best.actor}' for a in attributes))
    assert f'actor:{best.actor}' in tag_names
    assert any((a['value'] == e for a in attributes for e in best.evidence))

def test_no_attribution_omits_attribution_fields_without_error():
    incident = _incident(attribution=None)
    event = MISPEventGenerator().generate(incident)
    tag_names = [t['name'] for t in event['Event']['Tag']]
    assert not any((t.startswith('actor:') for t in tag_names))

def test_campaign_and_operation_context_propagate():
    incident = _incident(campaign_id='CAMP_XYZ', operation_id='OP_XYZ')
    event = MISPEventGenerator().generate(incident)
    attributes = event['Event']['Attribute']
    tag_names = [t['name'] for t in event['Event']['Tag']]
    assert any((a['value'] == 'Campaign : CAMP_XYZ' for a in attributes))
    assert any((a['value'] == 'Operation : OP_XYZ' for a in attributes))
    assert 'campaign:CAMP_XYZ' in tag_names
    assert 'operation:OP_XYZ' in tag_names

def test_technique_and_stage_propagate_as_tags():
    incident = _incident(technique='T1110.001', stage='Credential Access')
    event = MISPEventGenerator().generate(incident)
    tag_names = [t['name'] for t in event['Event']['Tag']]
    assert 'mitre:T1110.001' in tag_names
    assert 'stage:Credential Access' in tag_names

def test_recommendation_dicts_from_get_recommendations_serialize_as_scalar_values():
    mitigation_dict = {'recommendation': 'Account Use Policies', 'priority': 'MITRE', 'mitre_mitigation': 'M1036', 'reason': 'Account Use Policies help mitigate unauthorized access...', 'predicted_technique': 'T1078', 'traceability': 'MITRE ATT&CK → M1036'}
    incident = _incident(recommendations=[mitigation_dict, 'Rotate credentials'])
    event = MISPEventGenerator().generate(incident)
    comment_values = [a['value'] for a in event['Event']['Attribute'] if a['type'] == 'comment']
    assert 'Account Use Policies' in comment_values
    assert 'Rotate credentials' in comment_values
    for attribute in event['Event']['Attribute']:
        assert isinstance(attribute['value'], (str, int, float, bool)), f"MISP attribute value must be a scalar, got {type(attribute['value'])}: {attribute['value']!r}"
    json.dumps(event)

def test_attacker_ip_is_a_typed_ip_src_ioc_attribute():
    incident = _incident(attacker_ip='198.51.100.23')
    event = MISPEventGenerator().generate(incident)
    ip_attrs = [a for a in event['Event']['Attribute'] if a['type'] == 'ip-src']
    assert len(ip_attrs) == 1
    assert ip_attrs[0]['value'] == '198.51.100.23'
    assert ip_attrs[0]['category'] == 'Network activity'

def test_create_event_success_extracts_event_id(publisher, monkeypatch):
    _mock_request(monkeypatch, publisher, lambda **kw: _FakeResponse(200, {'Event': {'id': '42'}}))
    result = publisher.create_event({'Event': {'info': 'test'}})
    assert result['success'] is True
    assert result['event_id'] == 42

def test_authentication_failure_reports_explicit_failure_not_false_success(publisher, monkeypatch):
    _mock_request(monkeypatch, publisher, lambda **kw: _FakeResponse(403, {'name': 'Authentication failed.', 'message': 'Authentication failed.', 'url': '/events/add'}))
    result = publisher.create_event({'Event': {'info': 'test'}})
    assert result['success'] is False
    assert result['status'] == 403
    assert result.get('event_id') is None

def test_health_check_false_on_auth_failure(publisher, monkeypatch):
    _mock_request(monkeypatch, publisher, lambda **kw: _FakeResponse(403, {'name': 'Authentication failed.'}))
    assert publisher.health_check() is False

def test_http_500_is_a_controlled_failure(publisher, monkeypatch):
    _mock_request(monkeypatch, publisher, lambda **kw: _FakeResponse(500, {'error': 'Internal Server Error'}))
    result = publisher.create_event({'Event': {'info': 'test'}})
    assert result['success'] is False
    assert result['status'] == 500

def test_http_400_is_a_controlled_failure(publisher, monkeypatch):
    _mock_request(monkeypatch, publisher, lambda **kw: _FakeResponse(400, {'errors': 'Invalid payload'}))
    result = publisher.create_event({'Event': {'info': 'test'}})
    assert result['success'] is False
    assert result['status'] == 400

def test_timeout_is_a_controlled_failure_not_a_raised_exception(publisher, monkeypatch):
    import requests

    def _raise(**kw):
        raise requests.exceptions.Timeout('Connection timed out')
    _mock_request(monkeypatch, publisher, _raise)
    result = publisher.create_event({'Event': {'info': 'test'}})
    assert result['success'] is False
    assert result['status'] is None
    assert 'error' in result['response']

def test_connection_failure_is_a_controlled_failure_not_a_raised_exception(publisher, monkeypatch):
    import requests

    def _raise(**kw):
        raise requests.exceptions.ConnectionError('Failed to establish a new connection')
    _mock_request(monkeypatch, publisher, _raise)
    result = publisher.create_event({'Event': {'info': 'test'}})
    assert result['success'] is False

def test_missing_configuration_does_not_crash_at_construction():
    pub = CTIPublisher('', '', verify_ssl=False)
    assert pub.url == ''
    assert pub.api_key == ''

def test_malformed_url_produces_a_controlled_failure_not_a_crash():
    pub = CTIPublisher('not a valid url', 'key', verify_ssl=False)
    result = pub.create_event({'Event': {'info': 'test'}})
    assert result['success'] is False

def test_create_event_2xx_with_malformed_body_does_not_report_success(publisher, monkeypatch):
    _mock_request(monkeypatch, publisher, lambda **kw: _FakeResponse(200, {'unexpected': 'shape'}))
    result = publisher.create_event({'Event': {'info': 'test'}})
    assert result['success'] is False
    assert result['event_id'] is None

def test_create_event_2xx_with_non_json_body_does_not_report_success(publisher, monkeypatch):
    _mock_request(monkeypatch, publisher, lambda **kw: _FakeResponse(200, raise_json_error=True))
    result = publisher.create_event({'Event': {'info': 'test'}})
    assert result['success'] is False

def test_update_event_2xx_with_malformed_body_does_not_report_success(publisher, monkeypatch):
    _mock_request(monkeypatch, publisher, lambda **kw: _FakeResponse(200, {'unexpected': 'shape'}))
    result = publisher.update_event(42, {'Event': {'info': 'test'}})
    assert result['success'] is False

def test_update_event_success_with_well_formed_body(publisher, monkeypatch):
    _mock_request(monkeypatch, publisher, lambda **kw: _FakeResponse(200, {'Event': {'id': '42'}}))
    result = publisher.update_event(42, {'Event': {'info': 'test'}})
    assert result['success'] is True

def test_misp_sync_action_label_is_unambiguous_for_a_create_with_parse_failure(monkeypatch):
    pub = CTIPublisher('https://misp.test.invalid', 'key', verify_ssl=False)
    _mock_request(monkeypatch, pub, lambda **kw: _FakeResponse(200, {'unexpected': 'shape'}))
    sync = MISPSync(pub)
    fake_cache = MISPCache(cache_file='__unused__.json')
    monkeypatch.setattr(fake_cache, '_save', lambda: None)
    monkeypatch.setattr('misp_sync.cache', fake_cache)
    monkeypatch.setattr(pub, 'search_campaign', lambda campaign_id: None)
    incident = _incident()
    result = sync.publish_campaign(incident)
    assert result['action'] == 'created'
    assert result['success'] is False

def test_api_key_never_appears_in_log_output(publisher, monkeypatch, caplog):
    secret = publisher.api_key
    assert secret == 'test-api-key-should-never-leak'
    import requests

    def _raise(**kw):
        raise requests.exceptions.ConnectionError(f"Failed to connect to {kw.get('url')}")
    _mock_request(monkeypatch, publisher, _raise)
    with caplog.at_level(logging.DEBUG):
        publisher.create_event({'Event': {'info': 'test'}})
        publisher.health_check()
    all_log_text = '\n'.join((record.getMessage() for record in caplog.records))
    assert secret not in all_log_text

def test_api_key_never_appears_in_success_or_error_response_dicts(publisher, monkeypatch):
    _mock_request(monkeypatch, publisher, lambda **kw: _FakeResponse(403, {'name': 'Authentication failed.'}))
    result = publisher.create_event({'Event': {'info': 'test'}})
    assert publisher.api_key not in json.dumps(result)

def test_generated_misp_event_never_embeds_the_api_key():
    incident = _incident()
    event = MISPEventGenerator().generate(incident)
    assert 'test-api-key-should-never-leak' not in json.dumps(event)

@pytest.fixture()
def sync_with_fake_cache(monkeypatch, tmp_path):
    pub = CTIPublisher('https://misp.test.invalid', 'key', verify_ssl=False)
    sync = MISPSync(pub)
    fake_cache = MISPCache(cache_file=str(tmp_path / 'misp_cache_test.json'))
    monkeypatch.setattr('misp_sync.cache', fake_cache)
    return (sync, pub, fake_cache)

def test_first_publish_of_a_new_campaign_creates_one_event(sync_with_fake_cache, monkeypatch):
    sync, pub, fake_cache = sync_with_fake_cache
    calls = []

    def fake_request(**kw):
        calls.append(kw['url'])
        if kw['url'].endswith('/events/restSearch'):
            return _FakeResponse(200, [])
        if kw['url'].endswith('/events/add'):
            return _FakeResponse(200, {'Event': {'id': '100'}})
        raise AssertionError(f"unexpected call: {kw['url']}")
    _mock_request(monkeypatch, pub, fake_request)
    result = sync.publish_campaign(_incident())
    assert result['success'] is True
    assert result['action'] == 'created'
    assert fake_cache.get_event_id('CAMP_TEST') == 100
    assert sum((1 for u in calls if u.endswith('/events/add'))) == 1

def test_republishing_the_same_campaign_updates_instead_of_duplicating(sync_with_fake_cache, monkeypatch):
    sync, pub, fake_cache = sync_with_fake_cache
    fake_cache.set_event_id('CAMP_TEST', 100)
    calls = []

    def fake_request(**kw):
        calls.append(kw['url'])
        if kw['url'].endswith('/events/view/100'):
            return _FakeResponse(200, {'Event': {'id': '100'}})
        if kw['url'].endswith('/events/edit/100'):
            return _FakeResponse(200, {'Event': {'id': '100'}})
        raise AssertionError(f"unexpected call: {kw['url']}")
    _mock_request(monkeypatch, pub, fake_request)
    result = sync.publish_campaign(_incident())
    assert result['success'] is True
    assert result['action'] == 'updated'
    assert not any((u.endswith('/events/add') for u in calls))

def test_stale_cache_entry_self_heals_via_search_then_recreates_if_absent(sync_with_fake_cache, monkeypatch):
    sync, pub, fake_cache = sync_with_fake_cache
    fake_cache.set_event_id('CAMP_TEST', 100)
    calls = []

    def fake_request(**kw):
        calls.append(kw['url'])
        if kw['url'].endswith('/events/view/100'):
            return _FakeResponse(404, {'errors': 'Event not found'})
        if kw['url'].endswith('/events/restSearch'):
            return _FakeResponse(200, [])
        if kw['url'].endswith('/events/add'):
            return _FakeResponse(200, {'Event': {'id': '200'}})
        raise AssertionError(f"unexpected call: {kw['url']}")
    _mock_request(monkeypatch, pub, fake_request)
    result = sync.publish_campaign(_incident())
    assert result['success'] is True
    assert result['action'] == 'created'
    assert fake_cache.get_event_id('CAMP_TEST') == 200

def test_cache_miss_but_event_already_exists_in_misp_updates_not_duplicates(sync_with_fake_cache, monkeypatch):
    sync, pub, fake_cache = sync_with_fake_cache
    calls = []

    def fake_request(**kw):
        calls.append(kw['url'])
        if kw['url'].endswith('/events/restSearch'):
            return _FakeResponse(200, [{'Event': {'id': '77'}}])
        if kw['url'].endswith('/events/edit/77'):
            return _FakeResponse(200, {'Event': {'id': '77'}})
        raise AssertionError(f"unexpected call: {kw['url']}")
    _mock_request(monkeypatch, pub, fake_request)
    result = sync.publish_campaign(_incident())
    assert result['success'] is True
    assert result['action'] == 'updated'
    assert fake_cache.get_event_id('CAMP_TEST') == 77
    assert not any((u.endswith('/events/add') for u in calls))

def test_should_publish_gates_on_cti_policy_not_just_availability(sync_with_fake_cache, monkeypatch):
    sync, pub, fake_cache = sync_with_fake_cache

    def _fail_if_called(**kw):
        raise AssertionError("no HTTP call should happen when CTI policy says don't publish")
    _mock_request(monkeypatch, pub, _fail_if_called)
    incident = _incident(cti=_Stub(publish=False))
    result = sync.publish_campaign(incident)
    assert result['success'] is False
    assert result['action'] == 'skipped'

def test_full_pipeline_investigation_evidence_confidence_to_misp_publish(monkeypatch, tmp_path):
    import attribution_context as attribution_context_module
    historical = [HistoricalCampaign(campaign_id='CAMP_OLD', attacker='203.0.113.7', victim='10.0.0.1', techniques=['T1110', 'T1078'], timestamps=['2026-01-01T00:00:00+00:00'] * 2, status='ARCHIVED')]
    monkeypatch.setattr(attribution_context_module.context, 'load_historical_campaigns', lambda: historical)
    campaign = CampaignContext(campaign_id='CAMP_FULL', attacker_ip='203.0.113.7', victim_ip='10.0.0.55', techniques={'T1110', 'T1078'}, attack_chain=['T1110', 'T1078'])
    attribution = ThreatAttributionEngine().attribute(campaign)
    assert attribution.actors
    incident = _incident(campaign_id='CAMP_FULL', attacker_ip='203.0.113.7', victim_ip='10.0.0.55', attribution=attribution)
    pub = CTIPublisher('https://misp.test.invalid', 'key', verify_ssl=False)
    sync = MISPSync(pub)
    fake_cache = MISPCache(cache_file=str(tmp_path / 'cache.json'))
    monkeypatch.setattr('misp_sync.cache', fake_cache)
    sent_payloads = []

    def fake_request(**kw):
        if kw['url'].endswith('/events/restSearch'):
            return _FakeResponse(200, [])
        if kw['url'].endswith('/events/add'):
            sent_payloads.append(kw['json'])
            return _FakeResponse(200, {'Event': {'id': '999'}})
        raise AssertionError(f"unexpected call: {kw['url']}")
    _mock_request(monkeypatch, pub, fake_request)
    result = sync.publish_campaign(incident)
    assert result['success'] is True
    assert result['event_id'] == 999
    assert len(sent_payloads) == 1
    sent_event = sent_payloads[0]['Event']
    assert sent_event['info'] == 'CYUKTI Campaign CAMP_FULL'
    tag_names = [t['name'] for t in sent_event['Tag']]
    assert 'actor:CAMP_OLD' in tag_names
    json.dumps(sent_payloads[0])