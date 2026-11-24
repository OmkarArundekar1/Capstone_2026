from __future__ import annotations
from datetime import datetime, timezone
from evidence.schema import Evidence, EvidenceSource, EvidenceType
_STRUCTURAL_RISK_NORMALIZER = 40.0

def collect_graph_evidence(campaign_id: str, graph_features) -> list[Evidence]:
    if graph_features is None:
        return []
    relevance = min(1.0, max(0.0, graph_features.structural_risk / _STRUCTURAL_RISK_NORMALIZER))
    return [Evidence(source=EvidenceSource.GRAPH, source_id=campaign_id, timestamp=datetime.now(timezone.utc).isoformat(), type=EvidenceType.GRAPH_RELATIONSHIP, content={'campaign_id': campaign_id, 'node_count': graph_features.node_count, 'edge_count': graph_features.edge_count, 'graph_density': graph_features.graph_density, 'average_degree': graph_features.average_degree, 'attack_chain_depth': graph_features.attack_chain_depth, 'community_count': graph_features.community_count, 'campaign_complexity': graph_features.campaign_complexity, 'structural_risk': graph_features.structural_risk}, confidence=1.0, relevance=relevance, provenance='graph_feature_engine (Neo4j structural analytics)', relationships=[campaign_id])]