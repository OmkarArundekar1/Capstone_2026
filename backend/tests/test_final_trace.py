from __future__ import annotations
from campaign_context import CampaignContext
from campaign_selection import BestCampaignSelector
from mitre_resolver import resolve_mitre, PROVENANCE_NATIVE_WAZUH, CONFIDENCE_CONFIRMED
from soar.generator import PlaybookGenerator
from soar.response_plan import ResponsePlanGenerator
from threat_qualification import ThreatQualificationEngine, QUALIFIED_THREAT

class _CtiStub:

    def __init__(self, classification, score):
        self.threat_classification = classification
        self.score = score

class _IncidentStub:

    def __init__(self, campaign: CampaignContext, technique: str, cti: _CtiStub):
        self.campaign_id = campaign.campaign_id
        self.attacker_ip = campaign.attacker_ip
        self.technique = technique
        self.timestamp = '2026-09-25T06:41:34+00:00'
        self.cti = cti

def test_full_alert_to_misp_decision_object_chain_is_actually_connected():
    alert = {'rule': {'id': '100500', 'mitre': {'id': ['T1595']}}}
    resolution = resolve_mitre(alert)
    assert resolution.provenance == PROVENANCE_NATIVE_WAZUH
    assert resolution.confidence == CONFIDENCE_CONFIRMED
    resolved_technique = resolution.technique_ids[0]
    assert resolved_technique == 'T1595'
    campaign = CampaignContext(campaign_id='CAMP_TRACE_TEST', attacker_ip='192.168.56.106', victim_ip='192.168.56.105', risk_score=250.0, last_technique=resolved_technique, techniques={resolved_technique})
    assert resolved_technique in campaign.techniques
    cti = _CtiStub(QUALIFIED_THREAT, 49.08)
    incident = _IncidentStub(campaign, campaign.last_technique, cti)
    qualification = ThreatQualificationEngine().qualify(incident)
    assert qualification.classification == QUALIFIED_THREAT
    assert any((c.name == 'valid_mitre_provenance' and resolved_technique in c.detail for c in qualification.checks))
    assert qualification.may_publish_to_misp is True
    selector = BestCampaignSelector()
    historical_candidate = selector.build_candidate('CAMP_HISTORICAL', topology_similarity=0.92, technique_similarity=1.0, attacker_similarity=1.0, host_similarity=1.0)
    selection = selector.select([historical_candidate])
    assert selection.selected is not None
    assert selection.selected.campaign_id == 'CAMP_HISTORICAL'
    playbook = PlaybookGenerator().generate(campaign)
    assert playbook.source_campaign_id == campaign.campaign_id
    attacker_referenced = any((a.inputs.get('ip') == campaign.attacker_ip for a in playbook.actions if 'ip' in a.inputs))
    assert attacker_referenced, "no playbook action references the real campaign's attacker IP"
    plan = ResponsePlanGenerator().generate(campaign, playbook=playbook, qualification=qualification, selection=selection)
    assert plan.campaign_id == campaign.campaign_id
    assert plan.playbook is playbook
    assert plan.selected_historical_campaign == 'CAMP_HISTORICAL'
    assert resolved_technique in plan.mitre_techniques
    assert plan.misp_status == 'READY'
    assert plan.misp_reason == qualification.reason
    cti_benign = _CtiStub('NOT_THREAT', 5.0)
    incident_benign = _IncidentStub(campaign, campaign.last_technique, cti_benign)
    qualification_benign = ThreatQualificationEngine().qualify(incident_benign)
    plan_benign = ResponsePlanGenerator().generate(campaign, playbook=playbook, qualification=qualification_benign, selection=selection)
    assert qualification_benign.may_publish_to_misp is False
    assert plan_benign.misp_status == 'BLOCKED'