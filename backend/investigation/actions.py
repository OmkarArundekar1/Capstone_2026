from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from evidence.schema import EvidenceSource

class InvestigationAction(str, Enum):
    MITRE_KNOWLEDGE = 'mitre_knowledge'
    MITRE_SEMANTIC_SEARCH = 'mitre_semantic_search'
    CTI_LOOKUP = 'cti_lookup'
    DETECTION_CHECK = 'detection_check'
    ATTRIBUTION_MATCH = 'attribution_match'
    CAMPAIGN_HISTORY = 'campaign_history'
    CAMPAIGN_NARRATIVE_SEARCH = 'campaign_narrative_search'
    GRAPH_STRUCTURE = 'graph_structure'
    XGBOOST_PREDICTION = 'xgboost_prediction'
    GNN_TOPOLOGY_RETRIEVAL = 'gnn_topology_retrieval'

@dataclass(frozen=True)
class ActionMeta:
    source: EvidenceSource
    reliability: float
    cost: float
    latency: float
    depends_on: frozenset[InvestigationAction] = frozenset()
ACTION_METADATA: dict[InvestigationAction, ActionMeta] = {InvestigationAction.MITRE_KNOWLEDGE: ActionMeta(EvidenceSource.MITRE, reliability=1.0, cost=0.1, latency=0.1), InvestigationAction.MITRE_SEMANTIC_SEARCH: ActionMeta(EvidenceSource.MITRE, reliability=0.7, cost=0.15, latency=0.15), InvestigationAction.CTI_LOOKUP: ActionMeta(EvidenceSource.CTI, reliability=0.75, cost=0.5, latency=0.7), InvestigationAction.DETECTION_CHECK: ActionMeta(EvidenceSource.SIEM, reliability=0.85, cost=0.2, latency=0.2), InvestigationAction.ATTRIBUTION_MATCH: ActionMeta(EvidenceSource.ATTRIBUTION, reliability=0.65, cost=0.4, latency=0.3, depends_on=frozenset({InvestigationAction.CAMPAIGN_HISTORY})), InvestigationAction.CAMPAIGN_HISTORY: ActionMeta(EvidenceSource.CAMPAIGN_HISTORY, reliability=0.9, cost=0.3, latency=0.3), InvestigationAction.CAMPAIGN_NARRATIVE_SEARCH: ActionMeta(EvidenceSource.CAMPAIGN_HISTORY, reliability=0.65, cost=0.3, latency=0.3), InvestigationAction.GRAPH_STRUCTURE: ActionMeta(EvidenceSource.GRAPH, reliability=1.0, cost=0.3, latency=0.3), InvestigationAction.XGBOOST_PREDICTION: ActionMeta(EvidenceSource.GRAPH, reliability=0.6, cost=0.25, latency=0.25), InvestigationAction.GNN_TOPOLOGY_RETRIEVAL: ActionMeta(EvidenceSource.GNN_TOPOLOGY, reliability=0.5, cost=0.35, latency=0.4, depends_on=frozenset({InvestigationAction.CAMPAIGN_HISTORY}))}