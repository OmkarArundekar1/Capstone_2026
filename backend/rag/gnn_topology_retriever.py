from __future__ import annotations
from datetime import datetime, timezone
from evidence.schema import Evidence, EvidenceSource, EvidenceType

class GNNTopologyRetriever:

    def query(self, campaign_id: str, top_k: int=5, min_similarity: float=0.0) -> list[Evidence]:
        from ml.gnn.inference import gnn_inference_service
        from ml.gnn.topology_similarity import gnn_graph_similarity
        query_embedding = gnn_inference_service.embed_campaign(campaign_id)
        if query_embedding is None:
            return []
        import attribution_context as attribution_context_module
        historical = attribution_context_module.context.load_historical_campaigns()
        scored = []
        for campaign in historical:
            if campaign.campaign_id == campaign_id:
                continue
            candidate_embedding = gnn_inference_service.embed_campaign(campaign.campaign_id)
            if candidate_embedding is None:
                continue
            similarity = gnn_graph_similarity(query_embedding, candidate_embedding)
            if similarity >= min_similarity:
                scored.append((similarity, campaign))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        model_version = gnn_inference_service.metadata.model_version if gnn_inference_service.metadata else 'unknown'
        evidence_items = []
        for similarity, campaign in scored[:top_k]:
            evidence_items.append(Evidence(source=EvidenceSource.GNN_TOPOLOGY, source_id=campaign.campaign_id, timestamp=campaign.timestamps[-1] if campaign.timestamps else datetime.now(timezone.utc).isoformat(), type=EvidenceType.HISTORICAL_MATCH, content={'campaign_id': campaign.campaign_id, 'attacker': campaign.attacker, 'victim': campaign.victim, 'techniques': campaign.techniques, 'status': campaign.status, 'topology_similarity': round(similarity, 4), 'model_version': model_version}, confidence=1.0, relevance=max(0.0, min(1.0, (similarity + 1.0) / 2.0)), provenance=f'ml.gnn.inference (GraphAutoencoder topology similarity, model_version={model_version})', relationships=[campaign.campaign_id], derived_from=[]))
        return evidence_items