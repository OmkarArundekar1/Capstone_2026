from __future__ import annotations
from dataclasses import dataclass
from evaluators.base import EvaluationResult, MetricStatus
REQUIRED_LABEL_FIELDS = ('detection_success', 'response_decision_correct', 'containment_executed', 'attack_recurrence', 'false_containment')

@dataclass
class ActiveResponseGroundTruthSchema:
    sample_id: str
    correlation_id: str
    scenario_id: str
    detection_success: bool | None = None
    response_decision_correct: bool | None = None
    containment_executed: bool | None = None
    attack_recurrence: bool | None = None
    false_containment: bool | None = None
    evidence_reference: str = ''
    reviewer: str = 'unreviewed'

def evaluate() -> EvaluationResult:
    return EvaluationResult(task='active_response_accuracy', status=MetricStatus.BLOCKED_BY_ENVIRONMENT, n=0, reason="No real containment action has ever executed against a live host in this environment (review/phaseX_active_response_report.md, Section N: BLOCKED_BY_ENVIRONMENT). There is zero real data to build ground truth from, human-reviewed or otherwise. This evaluator's schema (ActiveResponseGroundTruthSchema) and the required label fields are ready; running it requires a real lab demonstration first, then independent human review of that real event -- neither has happened. Reported as BLOCKED_BY_ENVIRONMENT, not NOT_MEASURED, because no code gap blocks this -- only the absence of a real event to evaluate.", method='Schema/import-hook only, per Phase Z Section 11 -- never fabricates labels or reports an accuracy number.', limitations=['containment_verified is not independently re-labelable from different evidence than ContainmentVerifier itself already requires -- see module docstring.'])