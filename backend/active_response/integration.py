from __future__ import annotations
from campaign_context import CampaignContext
from risk_scoring import severity_from_tps
from threat_qualification import ThreatQualificationResult
from active_response.containment_actions import ContainmentAction
from active_response.correlation import derive_correlation_id
from active_response.decision import ResponseDecision
from active_response.policy import PolicyInput, ResponsePolicyEngine
_policy_engine = ResponsePolicyEngine()
MIN_EVIDENCE_COVERAGE_FOR_RESPONSE = 0.15

def decide_for_campaign(campaign: CampaignContext, qualification: ThreatQualificationResult | None, investigation_confidence: float | None=None, evidence_coverage: float | None=None, requested_action: ContainmentAction | None=ContainmentAction.BLOCK_SOURCE_IP, auto_contain_config: bool=False, never_block_ips: frozenset[str]=frozenset(), environment: str='production', operation_id: str | None=None, investigation_id: str | None=None, incident_id: str | None=None, attack_event_id: str | None=None) -> ResponseDecision:
    correlation_id = derive_correlation_id(campaign_id=campaign.campaign_id)
    threat_class = qualification.classification if qualification is not None else None
    evidence_sufficient = evidence_coverage is not None and evidence_coverage >= MIN_EVIDENCE_COVERAGE_FOR_RESPONSE
    severity = severity_from_tps(campaign.risk_score)
    policy_input = PolicyInput(correlation_id=correlation_id, threat_class=threat_class, investigation_confidence=investigation_confidence, evidence_sufficient=evidence_sufficient, attack_progression=campaign.last_technique, attacker_ip=campaign.attacker_ip, victim_ip=campaign.victim_ip, severity=severity, requested_action=requested_action, environment=environment, auto_contain_config=auto_contain_config, never_block_ips=never_block_ips, incident_id=incident_id, attack_event_id=attack_event_id, campaign_id=campaign.campaign_id, operation_id=operation_id, investigation_id=investigation_id, risk_level=severity)
    return _policy_engine.decide(policy_input)