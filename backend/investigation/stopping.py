from __future__ import annotations
from dataclasses import dataclass
from investigation.confidence import ConfidenceEstimate
DEFAULT_CONFIDENCE_THRESHOLD = 0.75
DEFAULT_MAX_UNCERTAINTY = 0.4
DEFAULT_MAX_STEPS = 8
MIN_USEFUL_ACTION_VALUE = 0.0

@dataclass
class StoppingDecision:
    should_stop: bool
    reason: str

def check_stopping(confidence: ConfidenceEstimate, steps_taken: int, best_remaining_action_value: float | None, confidence_threshold: float=DEFAULT_CONFIDENCE_THRESHOLD, max_uncertainty: float=DEFAULT_MAX_UNCERTAINTY, max_steps: int=DEFAULT_MAX_STEPS) -> StoppingDecision:
    uncertainty_ok = confidence.model_uncertainty is None or confidence.model_uncertainty <= max_uncertainty
    if confidence.investigation_confidence >= confidence_threshold and uncertainty_ok and (confidence.conflict_count == 0):
        return StoppingDecision(True, f"investigation_confidence {confidence.investigation_confidence:.2f} >= threshold {confidence_threshold} (model_uncertainty={(confidence.model_uncertainty if confidence.model_uncertainty is not None else 'n/a')}, no unresolved evidence conflicts)")
    if steps_taken >= max_steps:
        return StoppingDecision(True, f'reached maximum investigation depth ({max_steps} steps)')
    if best_remaining_action_value is not None and best_remaining_action_value <= MIN_USEFUL_ACTION_VALUE:
        return StoppingDecision(True, f'no remaining evidence-gathering action has positive expected value (best={best_remaining_action_value:.3f}) — further investigation cost exceeds its expected benefit')
    if best_remaining_action_value is None:
        return StoppingDecision(True, 'no evidence-gathering actions remain')
    return StoppingDecision(False, 'continuing investigation')