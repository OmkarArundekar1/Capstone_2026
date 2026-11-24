from __future__ import annotations
from dataclasses import dataclass
from evidence.store import EvidenceStore
from investigation.actions import ACTION_METADATA, InvestigationAction
W_GAIN = 1.0
W_RELIABILITY = 0.3
W_NOVELTY = 0.5
W_UNCERTAINTY_REDUCTION = 0.6
W_COST = 0.4
W_LATENCY = 0.2
W_REDUNDANCY = 0.5
REPEAT_QUERY_NOVELTY = 0.15
DEPENDENCY_REDUNDANCY_PENALTY = 0.5
CONCLUSION_ACTIONS = frozenset({InvestigationAction.XGBOOST_PREDICTION})

@dataclass
class ActionValue:
    action: InvestigationAction
    expected_gain: float
    reliability: float
    novelty: float
    uncertainty_reduction: float
    redundancy_penalty: float
    cost: float
    latency: float
    value: float

def score_action(action: InvestigationAction, store: EvidenceStore, current_uncertainty: float=1.0, taken_actions: frozenset[InvestigationAction]=frozenset()) -> ActionValue:
    meta = ACTION_METADATA[action]
    already_covered = len(store.by_source(meta.source)) > 0
    novelty = REPEAT_QUERY_NOVELTY if already_covered else 1.0
    expected_gain = meta.reliability * novelty
    uncertainty_reduction = current_uncertainty if action in CONCLUSION_ACTIONS else 0.0
    overlapping_taken = meta.depends_on & taken_actions
    redundancy_penalty = len(overlapping_taken) * DEPENDENCY_REDUNDANCY_PENALTY
    value = W_GAIN * expected_gain + W_RELIABILITY * meta.reliability + W_NOVELTY * novelty + W_UNCERTAINTY_REDUCTION * uncertainty_reduction - W_COST * meta.cost - W_LATENCY * meta.latency - W_REDUNDANCY * redundancy_penalty
    return ActionValue(action=action, expected_gain=round(expected_gain, 4), reliability=meta.reliability, novelty=round(novelty, 4), uncertainty_reduction=round(uncertainty_reduction, 4), redundancy_penalty=round(redundancy_penalty, 4), cost=meta.cost, latency=meta.latency, value=round(value, 4))

def select_next_best_evidence(store: EvidenceStore, available_actions: list[InvestigationAction], current_uncertainty: float=1.0, taken_actions: frozenset[InvestigationAction]=frozenset()) -> ActionValue | None:
    if not available_actions:
        return None
    scored = [score_action(a, store, current_uncertainty, taken_actions) for a in available_actions]
    return max(scored, key=lambda av: av.value)