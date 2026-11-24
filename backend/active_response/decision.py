from __future__ import annotations
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4
from active_response.containment_actions import ContainmentAction

class PolicyOutcome(str, Enum):
    OBSERVE = 'OBSERVE'
    INVESTIGATE = 'INVESTIGATE'
    RECOMMEND = 'RECOMMEND'
    CONTAIN = 'CONTAIN'

def new_id(prefix: str) -> str:
    return f'{prefix}_{uuid4().hex[:12]}'

@dataclass
class ResponseDecision:
    decision_id: str
    correlation_id: str
    incident_id: str | None
    attack_event_id: str | None
    campaign_id: str | None
    operation_id: str | None
    investigation_id: str | None
    threat_class: str | None
    confidence: float | None
    evidence_sufficient: bool
    requested_action: ContainmentAction | None
    selected_action: ContainmentAction | None
    policy_result: PolicyOutcome
    policy_reason: str
    risk_level: str
    approval_required: bool
    auto_contain_allowed: bool
    environment: str
    created_at: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d['requested_action'] = self.requested_action.value if self.requested_action else None
        d['selected_action'] = self.selected_action.value if self.selected_action else None
        d['policy_result'] = self.policy_result.value
        return d

    @staticmethod
    def new(**kwargs) -> 'ResponseDecision':
        kwargs.setdefault('decision_id', new_id('dec'))
        kwargs.setdefault('created_at', datetime.now(timezone.utc).isoformat())
        return ResponseDecision(**kwargs)