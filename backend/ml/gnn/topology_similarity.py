from __future__ import annotations

def gnn_graph_similarity(embedding_a, embedding_b) -> float:
    import torch
    denom = (embedding_a.norm() * embedding_b.norm()).clamp(min=1e-09)
    return float(torch.dot(embedding_a, embedding_b) / denom)

def gnn_topology_similarity_between_campaigns(campaign_id_a: str, campaign_id_b: str) -> float | None:
    from ml.gnn.inference import gnn_inference_service
    embedding_a = gnn_inference_service.embed_campaign(campaign_id_a)
    if embedding_a is None:
        return None
    embedding_b = gnn_inference_service.embed_campaign(campaign_id_b)
    if embedding_b is None:
        return None
    return gnn_graph_similarity(embedding_a, embedding_b)