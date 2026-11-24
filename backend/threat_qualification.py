from __future__ import annotations
from dataclasses import dataclass
NOT_THREAT = 'NOT_THREAT'
SUSPICIOUS = 'SUSPICIOUS'
QUALIFIED_THREAT = 'QUALIFIED_THREAT'

@dataclass
class QualityGateCheck:
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict:
        return {'name': self.name, 'passed': self.passed, 'detail': self.detail}

@dataclass
class ThreatQualificationResult:
    classification: str
    cti_score: float | None
    checks: list[QualityGateCheck]
    may_publish_to_misp: bool
    reason: str

    def to_dict(self) -> dict:
        return {'classification': self.classification, 'cti_score': self.cti_score, 'checks': [c.to_dict() for c in self.checks], 'may_publish_to_misp': self.may_publish_to_misp, 'reason': self.reason}

class ThreatQualificationEngine:

    def qualify(self, incident, already_published: bool=False) -> ThreatQualificationResult:
        cti = getattr(incident, 'cti', None)
        classification = getattr(cti, 'threat_classification', None)
        cti_score = getattr(cti, 'score', None)
        if classification is None:
            classification = NOT_THREAT
            classification_reason = 'No CTI confidence has been computed for this incident yet.'
        else:
            classification_reason = f'CTI confidence score {cti_score} -> {classification} (cti_confidence_engine.py).'
        attacker_ip = getattr(incident, 'attacker_ip', None)
        technique = getattr(incident, 'technique', None)
        timestamp = getattr(incident, 'timestamp', None)
        campaign_id = getattr(incident, 'campaign_id', None)
        checks = [QualityGateCheck('threat_classification_qualified', classification == QUALIFIED_THREAT, classification_reason), QualityGateCheck('has_ioc', bool(attacker_ip), f'Attacker IP: {attacker_ip}' if attacker_ip else 'No attacker IP recorded on this incident.'), QualityGateCheck('valid_mitre_provenance', technique not in (None, '', 'UNKNOWN'), f'MITRE technique: {technique}' if technique not in (None, '', 'UNKNOWN') else 'No defensible MITRE technique mapped for this incident.'), QualityGateCheck('valid_timestamp', bool(timestamp), f'Timestamp: {timestamp}' if timestamp else 'No timestamp recorded on this incident.'), QualityGateCheck('has_campaign_context', bool(campaign_id), f'Campaign: {campaign_id}' if campaign_id else 'No campaign context for this incident.'), QualityGateCheck('not_already_published', not already_published, 'Not previously published.' if not already_published else 'This campaign already has a published MISP event.')]
        may_publish = all((c.passed for c in checks))
        failed_names = [c.name for c in checks if not c.passed]
        reason = 'All publication-readiness checks passed.' if may_publish else f"Blocked on: {', '.join(failed_names)}."
        return ThreatQualificationResult(classification=classification, cti_score=cti_score, checks=checks, may_publish_to_misp=may_publish, reason=reason)
engine = ThreatQualificationEngine()