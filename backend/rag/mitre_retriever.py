from __future__ import annotations
from datetime import datetime, timezone
from evidence.schema import Evidence, EvidenceSource, EvidenceType
from rag.retriever import SemanticRetriever

def _technique_documents() -> list[dict]:
    from mitre_import.parser import get_by_type
    documents = []
    for obj in get_by_type('attack-pattern'):
        if obj.get('revoked') or obj.get('x_mitre_deprecated'):
            continue
        attack_id = None
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                attack_id = ref.get('external_id')
                break
        if not attack_id:
            continue
        name = obj.get('name', '')
        description = obj.get('description', '')
        documents.append({'doc_id': attack_id, 'text': f'{name}. {description}', 'name': name, 'kill_chain_phases': [p.get('phase_name') for p in obj.get('kill_chain_phases', [])]})
    return documents

class MitreSemanticRetriever:

    def __init__(self) -> None:
        self._retriever: SemanticRetriever | None = None

    def _ensure_indexed(self) -> SemanticRetriever:
        if self._retriever is None:
            documents = _technique_documents()
            retriever = SemanticRetriever()
            retriever.index(documents)
            self._retriever = retriever
        return self._retriever

    def query(self, query_text: str, top_k: int=5, min_relevance: float=0.05) -> list[Evidence]:
        retriever = self._ensure_indexed()
        results = retriever.query(query_text, top_k=top_k, min_relevance=min_relevance)
        return [Evidence(source=EvidenceSource.MITRE, source_id=doc.doc_id, timestamp=datetime.now(timezone.utc).isoformat(), type=EvidenceType.TECHNIQUE_KNOWLEDGE, content={'attack_id': doc.doc_id, 'name': doc.metadata.get('name'), 'matched_text': doc.text, 'kill_chain_phases': doc.metadata.get('kill_chain_phases')}, confidence=1.0, relevance=doc.relevance, provenance='rag.mitre_retriever (TF-IDF over ATT&CK STIX corpus)', relationships=[doc.doc_id]) for doc in results]
mitre_retriever = MitreSemanticRetriever()