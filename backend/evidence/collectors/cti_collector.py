from __future__ import annotations
from datetime import datetime, timezone
from evidence.schema import Evidence, EvidenceSource, EvidenceType

def collect_cti_evidence(attacker_ip: str, threat_intel_result) -> list[Evidence]:
    if threat_intel_result is None:
        return []
    return [Evidence(source=EvidenceSource.CTI, source_id=attacker_ip, timestamp=datetime.now(timezone.utc).isoformat(), type=EvidenceType.THREAT_INTEL, content={'attacker_ip': attacker_ip, 'level': threat_intel_result.level, 'breakdown': threat_intel_result.breakdown}, confidence=threat_intel_result.confidence / 100.0, provenance='threat_intelligence_engine (MISP/CTI + VT reputation)')]