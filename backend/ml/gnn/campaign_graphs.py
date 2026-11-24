from __future__ import annotations
from collections import Counter
from dataclasses import dataclass
from graph_encoder import EncodedGraph, encode_graph
_LEVEL_TO_SEVERITY = {'CRITICAL': 'Critical', 'HIGH': 'High', 'MEDIUM': 'Medium', 'LOW': 'Low'}

@dataclass
class CampaignGraphSample:
    campaign_id: str
    graph: EncodedGraph
    severity: str
    risk_score: float
    num_events: int

def list_campaign_ids() -> list[str]:
    from neo4j_client import driver
    with driver.session() as session:
        result = session.run('MATCH (c:Campaign) RETURN c.campaign_id AS id ORDER BY c.campaign_id')
        return [record['id'] for record in result]

def build_campaign_graph_sample(campaign_id: str) -> CampaignGraphSample | None:
    from neo4j_client import get_campaign_context_data
    from risk_scoring import normalize_risk_score, risk_level_from_score
    from graph_feature_engine import graph_analytics
    context = get_campaign_context_data(campaign_id)
    if context is None:
        return None
    risk_score = context['campaign'].get('risk_score')
    if risk_score is None:
        return None
    severity = _LEVEL_TO_SEVERITY[risk_level_from_score(normalize_risk_score(risk_score))]
    nx_graph = graph_analytics.load_graph(campaign_id)
    encoded = encode_graph(nx_graph)
    num_events = sum((1 for node_type in encoded.node_types if node_type == 'AttackEvent'))
    return CampaignGraphSample(campaign_id=campaign_id, graph=encoded, severity=severity, risk_score=float(risk_score), num_events=num_events)

def build_real_campaign_dataset() -> list[CampaignGraphSample]:
    samples = []
    for campaign_id in list_campaign_ids():
        sample = build_campaign_graph_sample(campaign_id)
        if sample is not None:
            samples.append(sample)
    return samples
if __name__ == '__main__':
    import json
    samples = build_real_campaign_dataset()
    print(json.dumps({'campaigns_in_neo4j': len(list_campaign_ids()), 'samples_built': len(samples), 'severity_distribution': dict(Counter((s.severity for s in samples))), 'events_per_campaign_distribution': dict(Counter((s.num_events for s in samples)))}, indent=2))