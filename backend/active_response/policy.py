from __future__ import annotations
from dataclasses import dataclass
from active_response.containment_actions import ContainmentAction, is_executable
from active_response.decision import PolicyOutcome, ResponseDecision, new_id
_QUALIFIED_THREAT = 'QUALIFIED_THREAT'
_SUSPICIOUS = 'SUSPICIOUS'
_NOT_THREAT = 'NOT_THREAT'
MIN_INVESTIGATION_CONFIDENCE_FOR_CONTAIN = 0.5

@dataclass
class PolicyInput:
    correlation_id: str
    threat_class: str | None
    investigation_confidence: float | None
    evidence_sufficient: bool
    attack_progression: str | None
    attacker_ip: str | None
    victim_ip: str | None
    severity: str | None
    requested_action: ContainmentAction | None
    environment: str
    auto_contain_config: bool
    never_block_ips: frozenset[str]
    incident_id: str | None = None
    attack_event_id: str | None = None
    campaign_id: str | None = None
    operation_id: str | None = None
    investigation_id: str | None = None
    risk_level: str = 'LOW'

class ResponsePolicyEngine:

    def decide(self, inp: PolicyInput) -> ResponseDecision:
        outcome, reason, selected_action, approval_required = self._evaluate(inp)
        return ResponseDecision.new(correlation_id=inp.correlation_id, incident_id=inp.incident_id, attack_event_id=inp.attack_event_id, campaign_id=inp.campaign_id, operation_id=inp.operation_id, investigation_id=inp.investigation_id, threat_class=inp.threat_class, confidence=inp.investigation_confidence, evidence_sufficient=inp.evidence_sufficient, requested_action=inp.requested_action, selected_action=selected_action, policy_result=outcome, policy_reason=reason, risk_level=inp.risk_level, approval_required=approval_required, auto_contain_allowed=inp.auto_contain_config, environment=inp.environment)

    def _evaluate(self, inp: PolicyInput) -> tuple[PolicyOutcome, str, ContainmentAction | None, bool]:
        if inp.threat_class in (None, _NOT_THREAT):
            return (PolicyOutcome.OBSERVE, f'threat_class={inp.threat_class!r} -- no qualified threat, nothing to contain.', None, False)
        if not inp.evidence_sufficient:
            return (PolicyOutcome.INVESTIGATE, 'Evidence coverage insufficient to support a containment decision yet.', None, False)
        if inp.investigation_confidence is None or inp.investigation_confidence < MIN_INVESTIGATION_CONFIDENCE_FOR_CONTAIN:
            return (PolicyOutcome.RECOMMEND, f'investigation_confidence={inp.investigation_confidence} is below the {MIN_INVESTIGATION_CONFIDENCE_FOR_CONTAIN} containment threshold -- recommending action for analyst review, not auto-containing.', inp.requested_action, True)
        if inp.threat_class == _SUSPICIOUS:
            return (PolicyOutcome.RECOMMEND, 'threat_class=SUSPICIOUS (not QUALIFIED_THREAT) -- recommend only, containment requires analyst approval regardless of confidence.', inp.requested_action, True)
        if inp.requested_action is None:
            return (PolicyOutcome.RECOMMEND, 'No containment action was requested.', None, True)
        if not is_executable(inp.requested_action):
            return (PolicyOutcome.RECOMMEND, f'{inp.requested_action.value} is not on the executable allowlist this phase -- recommending for manual/future handling, never auto-executing an unsupported action.', inp.requested_action, True)
        if inp.attacker_ip and inp.attacker_ip in inp.never_block_ips:
            return (PolicyOutcome.RECOMMEND, f'{inp.attacker_ip} is on CONTAINMENT_NEVER_BLOCK_IPS -- containment is recommended for human override only, never auto-executed against an allowlisted source.', inp.requested_action, True)
        if not inp.auto_contain_config:
            return (PolicyOutcome.RECOMMEND, 'AUTO_CONTAIN is false in this environment -- containment is recommended, pending explicit analyst approval, never auto-executed.', inp.requested_action, True)
        return (PolicyOutcome.CONTAIN, f'QUALIFIED_THREAT, evidence sufficient, confidence {inp.investigation_confidence:.2f} >= {MIN_INVESTIGATION_CONFIDENCE_FOR_CONTAIN}, {inp.requested_action.value} is executable and approved, AUTO_CONTAIN is true, source not allowlisted -- containment permitted.', inp.requested_action, False)
policy_engine = ResponsePolicyEngine()