from __future__ import annotations
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum

class ReviewStatus(str, Enum):
    AUTO_PROPOSED = 'AUTO_PROPOSED'
    HUMAN_REVIEWED = 'HUMAN_REVIEWED'
    LOCKED = 'LOCKED'
_SYSTEM_OUTPUT_MARKERS = {'__FROM_MITRE_RESOLVER__', '__FROM_CAMPAIGN_MANAGER__', '__FROM_ATTRIBUTION_ENGINE__', '__FROM_THREAT_QUALIFICATION__', '__FROM_PREDICTION_ENGINE__'}

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

@dataclass
class GroundTruthRecord:
    sample_id: str
    source: str
    timestamp: str
    scenario_id: str
    raw_event_id: str
    attacker_identity: str | None = None
    victim_identity: str | None = None
    expected_attack: str | None = None
    expected_mitre_techniques: list[str] = field(default_factory=list)
    expected_campaign_id: str | None = None
    expected_threat_status: str | None = None
    expected_attribution: str | None = None
    reviewer: str = 'unreviewed'
    review_status: ReviewStatus = ReviewStatus.AUTO_PROPOSED
    evidence_reference: str = ''
    labeling_method: str = ''
    created_at: str = field(default_factory=_now_iso)
    dataset_version: str = 'v0-unlocked'

    def validate(self) -> None:
        for f in (self.expected_attack, self.expected_campaign_id, self.expected_threat_status, self.expected_attribution, *self.expected_mitre_techniques):
            if f in _SYSTEM_OUTPUT_MARKERS:
                raise ValueError(f"GroundTruthRecord {self.sample_id}: an expected_* field is a system-output marker ({f!r}) -- ground truth must never be derived from CYUKTI's own output.")
        if self.review_status != ReviewStatus.AUTO_PROPOSED and self.reviewer in ('', 'unreviewed'):
            raise ValueError(f'GroundTruthRecord {self.sample_id}: review_status={self.review_status.value} but no reviewer is named -- cannot promote past AUTO_PROPOSED without an identified reviewer.')

    def to_dict(self) -> dict:
        d = asdict(self)
        d['review_status'] = self.review_status.value
        return d

    @staticmethod
    def from_dict(d: dict) -> 'GroundTruthRecord':
        d = dict(d)
        d['review_status'] = ReviewStatus(d['review_status'])
        return GroundTruthRecord(**d)

def record_hash(record: GroundTruthRecord) -> str:
    payload = {'sample_id': record.sample_id, 'scenario_id': record.scenario_id, 'raw_event_id': record.raw_event_id, 'attacker_identity': record.attacker_identity, 'victim_identity': record.victim_identity, 'expected_attack': record.expected_attack, 'expected_mitre_techniques': sorted(record.expected_mitre_techniques), 'expected_campaign_id': record.expected_campaign_id, 'expected_threat_status': record.expected_threat_status, 'expected_attribution': record.expected_attribution}
    blob = json.dumps(payload, sort_keys=True).encode('utf-8')
    return hashlib.sha256(blob).hexdigest()