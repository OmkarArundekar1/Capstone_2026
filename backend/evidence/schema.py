from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class EvidenceSource(str, Enum):
    SIEM = 'siem'
    MITRE = 'mitre'
    CTI = 'cti'
    GRAPH = 'graph'
    CAMPAIGN_HISTORY = 'campaign_history'
    ATTRIBUTION = 'attribution'
    GNN_TOPOLOGY = 'gnn_topology'

class EvidenceType(str, Enum):
    DETECTION = 'detection'
    TECHNIQUE_KNOWLEDGE = 'technique_knowledge'
    THREAT_INTEL = 'threat_intel'
    GRAPH_RELATIONSHIP = 'graph_relationship'
    HISTORICAL_MATCH = 'historical_match'
    ATTRIBUTION_MATCH = 'attribution_match'

def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))

@dataclass
class Evidence:
    source: EvidenceSource
    source_id: str
    timestamp: str
    type: EvidenceType
    content: dict[str, Any]
    confidence: float
    relevance: float = 0.0
    provenance: str = ''
    relationships: list[str] = field(default_factory=list)
    derived_from: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.confidence = _clamp01(self.confidence)
        self.relevance = _clamp01(self.relevance)
        if isinstance(self.source, str):
            self.source = EvidenceSource(self.source)
        if isinstance(self.type, str):
            self.type = EvidenceType(self.type)

    @property
    def evidence_id(self) -> str:
        return f'{self.source.value}:{self.type.value}:{self.source_id}'

    def to_dict(self) -> dict[str, Any]:
        return {'evidence_id': self.evidence_id, 'source': self.source.value, 'source_id': self.source_id, 'timestamp': self.timestamp, 'type': self.type.value, 'content': self.content, 'confidence': round(self.confidence, 4), 'relevance': round(self.relevance, 4), 'provenance': self.provenance, 'relationships': list(self.relationships), 'derived_from': list(self.derived_from)}