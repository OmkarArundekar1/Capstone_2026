from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass
class RetrievedDocument:
    doc_id: str
    text: str
    relevance: float
    metadata: dict[str, Any]

class SemanticRetriever:

    def __init__(self, max_features: int=20000) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer
        self._vectorizer = TfidfVectorizer(max_features=max_features, stop_words='english')
        self._matrix = None
        self._documents: list[dict[str, Any]] = []

    def index(self, documents: list[dict[str, Any]]) -> None:
        if not documents:
            raise ValueError('Cannot index an empty document set.')
        self._documents = documents
        texts = [d['text'] for d in documents]
        self._matrix = self._vectorizer.fit_transform(texts)

    @property
    def is_indexed(self) -> bool:
        return self._matrix is not None

    def query(self, query_text: str, top_k: int=5, min_relevance: float=0.0) -> list[RetrievedDocument]:
        from sklearn.metrics.pairwise import cosine_similarity
        if not self.is_indexed:
            raise RuntimeError('SemanticRetriever has not been indexed yet — call index() first.')
        query_vec = self._vectorizer.transform([query_text])
        similarities = cosine_similarity(query_vec, self._matrix)[0]
        ranked = similarities.argsort()[::-1][:top_k]
        results = []
        for i in ranked:
            score = float(similarities[i])
            if score < min_relevance:
                continue
            doc = self._documents[i]
            metadata = {k: v for k, v in doc.items() if k not in ('doc_id', 'text')}
            results.append(RetrievedDocument(doc_id=doc['doc_id'], text=doc['text'], relevance=score, metadata=metadata))
        return results