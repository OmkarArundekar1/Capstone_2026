from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable
from evidence.schema import Evidence
from evidence.store import EvidenceStore
from investigation.actions import ACTION_METADATA, InvestigationAction
from investigation.confidence import ConfidenceEstimate, estimate_confidence
from investigation.next_best_evidence import ActionValue, score_action
from investigation.stopping import StoppingDecision, check_stopping
ActionExecutor = Callable[[InvestigationAction], list[Evidence]]
ModelPredictor = Callable[[], 'dict[str, float] | None']

def _candidate_hypotheses(model_probabilities: dict[str, float] | None) -> list[tuple[str, float]]:
    if not model_probabilities:
        return []
    return sorted(((label, round(p, 4)) for label, p in model_probabilities.items() if p > 0), key=lambda item: item[1], reverse=True)

@dataclass
class InvestigationState:
    step_number: int
    conclusion: str | None
    candidate_hypotheses: list[tuple[str, float]]
    model_probabilities: dict[str, float] | None
    model_confidence: float | None
    uncertainty: float
    evidence_reliability: float
    evidence_coverage: float
    candidate_evidence: list[InvestigationAction]
    selected_evidence: InvestigationAction | None
    investigation_cost: float

@dataclass
class InvestigationStep:
    step_index: int
    action_taken: InvestigationAction
    action_value: ActionValue
    candidate_scores: list[ActionValue]
    evidence_added: int
    confidence_before: ConfidenceEstimate
    confidence_after: ConfidenceEstimate
    state_after: InvestigationState

    @property
    def why_selected(self) -> str:
        runner_up = max((av for av in self.candidate_scores if av.action != self.action_taken), key=lambda av: av.value, default=None)
        margin = f', value={self.action_value.value} vs. next-best {runner_up.action.value}={runner_up.value}' if runner_up else f', value={self.action_value.value} (only candidate remaining)'
        return f'highest-scoring of {len(self.candidate_scores)} candidate action(s){margin}'

@dataclass
class InvestigationRecord:
    steps: list[InvestigationStep] = field(default_factory=list)
    final_confidence: ConfidenceEstimate | None = None
    stopping_reason: str = ''
    evidence_store: EvidenceStore = field(default_factory=EvidenceStore)

    def to_dict(self) -> dict:
        return {'steps': [{'step_index': s.step_index, 'action_taken': s.action_taken.value, 'action_value': s.action_value.value, 'why_selected': s.why_selected, 'candidate_actions': [av.action.value for av in s.candidate_scores], 'action_scores': [{'action': av.action.value, 'value': av.value, 'expected_gain': av.expected_gain, 'reliability': av.reliability, 'novelty': av.novelty, 'uncertainty_reduction': av.uncertainty_reduction, 'redundancy_penalty': av.redundancy_penalty, 'cost': av.cost, 'latency': av.latency} for av in s.candidate_scores], 'evidence_added': s.evidence_added, 'previous_confidence': s.confidence_before.investigation_confidence, 'previous_uncertainty': s.confidence_before.uncertainty, 'model_probabilities': s.confidence_after.model_probabilities, 'model_confidence': s.confidence_after.model_confidence, 'model_uncertainty': s.confidence_after.model_uncertainty, 'evidence_reliability': s.confidence_after.evidence_reliability, 'evidence_coverage': s.confidence_after.evidence_coverage, 'investigation_confidence': s.confidence_after.investigation_confidence, 'uncertainty': s.confidence_after.uncertainty, 'candidate_hypotheses': s.state_after.candidate_hypotheses} for s in self.steps], 'final_confidence': self.final_confidence.investigation_confidence if self.final_confidence else None, 'final_model_probabilities': self.final_confidence.model_probabilities if self.final_confidence else None, 'stopping_reason': self.stopping_reason, 'total_evidence': len(self.evidence_store)}

def _cumulative_cost(taken_actions: list[InvestigationAction]) -> float:
    return round(sum((ACTION_METADATA[a].cost for a in taken_actions)), 4)

def _tag_derived_from(new_evidence: list[Evidence], action: InvestigationAction, store: EvidenceStore) -> None:
    depends_on = ACTION_METADATA[action].depends_on
    if not depends_on:
        return
    overlapping_ids = [e.evidence_id for dep_action in depends_on for e in store.by_source(ACTION_METADATA[dep_action].source)]
    if not overlapping_ids:
        return
    for e in new_evidence:
        e.derived_from = list(dict.fromkeys(e.derived_from + overlapping_ids))

def run_investigation(action_executor: ActionExecutor, model_predictor: ModelPredictor | None=None, initial_evidence: list[Evidence] | None=None, confidence_threshold: float=0.75, max_uncertainty: float=0.4, max_steps: int=8) -> InvestigationRecord:
    store = EvidenceStore()
    if initial_evidence:
        store.add_many(initial_evidence)
    record = InvestigationRecord(evidence_store=store)
    remaining_actions = list(ACTION_METADATA.keys())
    taken_actions: list[InvestigationAction] = []
    model_probabilities: dict[str, float] | None = None
    step_index = 0
    while True:
        confidence = estimate_confidence(store, model_probabilities)
        candidate_scores = [score_action(a, store, confidence.uncertainty, frozenset(taken_actions)) for a in remaining_actions]
        best_action_value = max(candidate_scores, key=lambda av: av.value) if candidate_scores else None
        stop = check_stopping(confidence, step_index, best_action_value.value if best_action_value else None, confidence_threshold=confidence_threshold, max_uncertainty=max_uncertainty, max_steps=max_steps)
        if stop.should_stop:
            record.final_confidence = confidence
            record.stopping_reason = stop.reason
            return record
        action = best_action_value.action
        if action == InvestigationAction.XGBOOST_PREDICTION:
            model_probabilities = model_predictor() if model_predictor else None
            new_evidence: list[Evidence] = []
        else:
            new_evidence = action_executor(action)
            _tag_derived_from(new_evidence, action, store)
        added = store.add_many(new_evidence)
        taken_actions.append(action)
        step_index += 1
        confidence_after = estimate_confidence(store, model_probabilities)
        remaining_actions = [a for a in remaining_actions if a != action]
        record.steps.append(InvestigationStep(step_index=step_index, action_taken=action, action_value=best_action_value, candidate_scores=candidate_scores, evidence_added=added, confidence_before=confidence, confidence_after=confidence_after, state_after=InvestigationState(step_number=step_index, conclusion=max(model_probabilities, key=model_probabilities.get) if model_probabilities else None, candidate_hypotheses=_candidate_hypotheses(confidence_after.model_probabilities), model_probabilities=confidence_after.model_probabilities, model_confidence=confidence_after.model_confidence, uncertainty=confidence_after.uncertainty, evidence_reliability=confidence_after.evidence_reliability, evidence_coverage=confidence_after.evidence_coverage, candidate_evidence=list(remaining_actions), selected_evidence=action, investigation_cost=_cumulative_cost(taken_actions))))

def default_action_executor(campaign_context, current_attack_id: str, event_id: str | None) -> ActionExecutor:

    def execute(action: InvestigationAction) -> list[Evidence]:
        if action == InvestigationAction.MITRE_KNOWLEDGE:
            import mitre_feature_engine
            from evidence.collectors.mitre_collector import collect_mitre_evidence
            return collect_mitre_evidence(mitre_feature_engine.engine.extract_features(current_attack_id))
        if action == InvestigationAction.MITRE_SEMANTIC_SEARCH:
            from rag.mitre_retriever import mitre_retriever
            query_text = ' '.join(campaign_context.techniques) or current_attack_id
            return mitre_retriever.query(query_text)
        if action == InvestigationAction.CTI_LOOKUP:
            import threat_intelligence_engine
            from evidence.collectors.cti_collector import collect_cti_evidence
            result = threat_intelligence_engine.engine.calculate(campaign_context.attacker_ip)
            return collect_cti_evidence(campaign_context.attacker_ip, result)
        if action == InvestigationAction.DETECTION_CHECK:
            if not event_id:
                return []
            import detection_confidence_engine
            from evidence.collectors.detection_collector import collect_detection_evidence
            result = detection_confidence_engine.engine.calculate(event_id)
            return collect_detection_evidence(event_id, result)
        if action == InvestigationAction.ATTRIBUTION_MATCH:
            import threat_attribution_engine
            from evidence.collectors.attribution_collector import collect_attribution_evidence
            result = threat_attribution_engine.engine.attribute(campaign_context)
            return collect_attribution_evidence(result)
        if action == InvestigationAction.CAMPAIGN_HISTORY:
            import attribution_context as attribution_context_module
            from evidence.collectors.campaign_history_collector import collect_campaign_history_evidence
            campaigns = attribution_context_module.context.load_historical_campaigns()
            return collect_campaign_history_evidence(campaign_context.techniques, campaigns)
        if action == InvestigationAction.CAMPAIGN_NARRATIVE_SEARCH:
            from rag.campaign_retriever import CampaignNarrativeRetriever
            query_text = ' '.join(campaign_context.attack_chain) or ' '.join(campaign_context.techniques) or current_attack_id
            try:
                return CampaignNarrativeRetriever().query(query_text)
            except RuntimeError:
                return []
        if action == InvestigationAction.GNN_TOPOLOGY_RETRIEVAL:
            from rag.gnn_topology_retriever import GNNTopologyRetriever
            try:
                return GNNTopologyRetriever().query(campaign_context.campaign_id)
            except Exception:
                import logging
                logging.getLogger(__name__).exception('GNN topology retrieval failed for campaign %s -- continuing without it.', campaign_context.campaign_id)
                return []
        if action == InvestigationAction.GRAPH_STRUCTURE:
            import graph_feature_engine
            from evidence.collectors.graph_collector import collect_graph_evidence
            features = graph_feature_engine.graph_analytics.extract_features(campaign_context.campaign_id, force_reload=True)
            return collect_graph_evidence(campaign_context.campaign_id, features)
        if action == InvestigationAction.XGBOOST_PREDICTION:
            return []
        return []
    return execute

def default_model_predictor(campaign_context, current_attack_id: str, event_id: str, model_path: str | None=None) -> ModelPredictor | None:
    import os
    if model_path is None:
        model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ml', 'models', 'xgb_severity.json')
        model_path = os.path.normpath(model_path)
    if not os.path.exists(model_path):
        return None

    def predict() -> dict[str, float] | None:
        try:
            from ml.runtime_predictor import RuntimeCampaignPredictor
            predictor = RuntimeCampaignPredictor.from_model_path(model_path)
            result = predictor.predict_for_campaign(campaign_context, current_attack_id, event_id or '')
            return result['probabilities']
        except Exception:
            return None
    return predict