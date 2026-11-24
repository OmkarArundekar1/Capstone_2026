from __future__ import annotations
from datetime import datetime, timezone
from evidence.schema import Evidence, EvidenceSource, EvidenceType
from rag.retriever import SemanticRetriever

def _campaign_documents() -> list[dict]:
    from attribution_context import context
    documents = []
    for campaign in context.load_historical_campaigns():
        if not campaign.techniques:
            continue
        text = f"Campaign {campaign.campaign_id}: attacker {campaign.attacker} targeting {campaign.victim}. Techniques observed: {' '.join(campaign.techniques)}."
        documents.append({'doc_id': campaign.campaign_id, 'text': text, 'attacker': campaign.attacker, 'victim': campaign.victim, 'techniques': campaign.techniques, 'status': campaign.status})
    return documents

class CampaignNarrativeRetriever:

    def __init__(self) -> None:
        self._retriever: SemanticRetriever | None = None

    def _ensure_indexed(self) -> SemanticRetriever:
        if self._retriever is None:
            documents = _campaign_documents()
            if not documents:
                raise RuntimeError('No historical campaigns with resolved techniques are available yet to index — the campaign-narrative RAG source has nothing to search until at least one real campaign has resolved (see attribution_context.py).')
            retriever = SemanticRetriever()
            retriever.index(documents)
            self._retriever = retriever
        return self._retriever

    def query(self, query_text: str, top_k: int=5, min_relevance: float=0.05) -> list[Evidence]:
        retriever = self._ensure_indexed()
        results = retriever.query(query_text, top_k=top_k, min_relevance=min_relevance)
        return [Evidence(source=EvidenceSource.CAMPAIGN_HISTORY, source_id=doc.doc_id, timestamp=datetime.now(timezone.utc).isoformat(), type=EvidenceType.HISTORICAL_MATCH, content={'campaign_id': doc.doc_id, 'attacker': doc.metadata.get('attacker'), 'victim': doc.metadata.get('victim'), 'techniques': doc.metadata.get('techniques'), 'status': doc.metadata.get('status'), 'matched_text': doc.text}, confidence=1.0, relevance=doc.relevance, provenance='rag.campaign_retriever (TF-IDF over historical campaign records)', relationships=[doc.doc_id]) for doc in results]