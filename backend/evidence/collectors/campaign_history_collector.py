from __future__ import annotations
from datetime import datetime, timezone
from attribution_similarity import AttributionSimilarity
from evidence.schema import Evidence, EvidenceSource, EvidenceType

def collect_campaign_history_evidence(observed_techniques, historical_campaigns) -> list[Evidence]:
    if not historical_campaigns:
        return []
    observed = set(observed_techniques or [])
    evidence_items = []
    for campaign in historical_campaigns:
        historical = set(campaign.techniques)
        relevance = AttributionSimilarity.coverage(observed, historical)
        evidence_items.append(Evidence(source=EvidenceSource.CAMPAIGN_HISTORY, source_id=campaign.campaign_id, timestamp=campaign.timestamps[-1] if campaign.timestamps else datetime.now(timezone.utc).isoformat(), type=EvidenceType.HISTORICAL_MATCH, content={'campaign_id': campaign.campaign_id, 'attacker': campaign.attacker, 'victim': campaign.victim, 'techniques': campaign.techniques, 'status': campaign.status}, confidence=1.0, relevance=relevance, provenance='attribution_context (historical campaign record)', relationships=[campaign.campaign_id]))
    return evidence_items