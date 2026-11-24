from __future__ import annotations
import math
from dataclasses import dataclass, field
from evidence.schema import EvidenceSource
from evidence.store import EvidenceStore
CONFLICT_PENALTY = 0.85
MIN_COVERAGE_FOR_MODEL_TRUST = 0.15

def predictive_entropy(probabilities: dict[str, float]) -> float:
    ps = [p for p in probabilities.values() if p > 0]
    if len(ps) <= 1:
        return 0.0
    entropy = -sum((p * math.log(p) for p in ps))
    max_entropy = math.log(len(probabilities))
    return entropy / max_entropy if max_entropy > 0 else 0.0

def evidence_coverage(store: EvidenceStore) -> float:
    all_sources = list(EvidenceSource)
    if not all_sources:
        return 0.0
    best_relevance_per_source: dict[EvidenceSource, float] = {}
    for e in store.all():
        best_relevance_per_source[e.source] = max(best_relevance_per_source.get(e.source, 0.0), e.relevance)
    return sum(best_relevance_per_source.values()) / len(all_sources)

@dataclass
class ConfidenceEstimate:
    evidence_reliability: float
    evidence_coverage: float
    conflict_count: int
    model_probabilities: dict[str, float] | None = None
    model_confidence: float | None = None
    model_uncertainty: float | None = None
    investigation_confidence: float = 0.0
    uncertainty: float = 1.0

def estimate_confidence(store: EvidenceStore, model_probabilities: dict[str, float] | None=None) -> ConfidenceEstimate:
    reliability = store.weighted_confidence()
    coverage = evidence_coverage(store)
    conflicts = store.detect_conflicts()
    if model_probabilities:
        model_confidence = max(model_probabilities.values())
        model_uncertainty = predictive_entropy(model_probabilities)
        model_term = model_confidence * (1.0 - model_uncertainty)
        coverage_gate = min(1.0, coverage / MIN_COVERAGE_FOR_MODEL_TRUST) if MIN_COVERAGE_FOR_MODEL_TRUST > 0 else 1.0
        investigation_confidence = model_term * coverage_gate
    else:
        model_confidence = None
        model_uncertainty = None
        investigation_confidence = reliability * coverage
    if conflicts:
        investigation_confidence *= CONFLICT_PENALTY ** len(conflicts)
    investigation_confidence = round(max(0.0, min(1.0, investigation_confidence)), 4)
    return ConfidenceEstimate(evidence_reliability=round(reliability, 4), evidence_coverage=round(coverage, 4), conflict_count=len(conflicts), model_probabilities={k: round(v, 4) for k, v in model_probabilities.items()} if model_probabilities else None, model_confidence=round(model_confidence, 4) if model_confidence is not None else None, model_uncertainty=round(model_uncertainty, 4) if model_uncertainty is not None else None, investigation_confidence=investigation_confidence, uncertainty=round(1.0 - investigation_confidence, 4))