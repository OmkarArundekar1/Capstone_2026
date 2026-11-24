from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Optional
from neo4j_client import driver
from mitre_rule_registry import REVIEWED_RULE_MAPPINGS
try:
    from wazuh_rule_mapper import mapper as wazuh_mapper
    WAZUH_MAPPER_AVAILABLE = True
except ImportError:
    WAZUH_MAPPER_AVAILABLE = False
    wazuh_mapper = None
RESOLVER_VERSION = '1.0.0'
PROVENANCE_NATIVE_WAZUH = 'NATIVE_WAZUH'
PROVENANCE_REVIEWED_RULE_MAPPING = 'REVIEWED_RULE_MAPPING'
PROVENANCE_CURATED_WAZUH_MAPPING = 'CURATED_WAZUH_MAPPING'
PROVENANCE_DETERMINISTIC_INFERENCE = 'DETERMINISTIC_INFERENCE'
PROVENANCE_AMBIGUOUS = 'AMBIGUOUS'
PROVENANCE_UNKNOWN = 'UNKNOWN'
CONFIDENCE_CONFIRMED = 'CONFIRMED'
CONFIDENCE_REVIEWED = 'REVIEWED'
CONFIDENCE_CANDIDATE = 'CANDIDATE'
CONFIDENCE_NONE = 'NONE'

@dataclass(frozen=True)
class MitreResolution:
    technique_ids: tuple[str, ...]
    provenance: str
    confidence: str
    reason: str
    resolver_version: str = RESOLVER_VERSION

def _unknown(reason: str) -> MitreResolution:
    return MitreResolution(technique_ids=(), provenance=PROVENANCE_UNKNOWN, confidence=CONFIDENCE_NONE, reason=reason)

def _validate_technique_ids(technique_ids: tuple[str, ...]) -> tuple[bool, str]:
    with driver.session() as session:
        for technique_id in technique_ids:
            record = session.run('MATCH (t:Technique {attack_id: $id}) RETURN t.revoked AS revoked, t.deprecated AS deprecated', id=technique_id).single()
            if record is None:
                return (False, f'{technique_id} does not exist in the imported ATT&CK STIX corpus')
            if record['revoked']:
                return (False, f'{technique_id} is revoked in ATT&CK')
            if record['deprecated']:
                return (False, f'{technique_id} is deprecated in ATT&CK')
    return (True, '')

def _resolve_native(alert: dict) -> Optional[MitreResolution]:
    rule = alert.get('rule') or {}
    mitre = rule.get('mitre') or {}
    technique_ids = tuple(mitre.get('id') or [])
    if not technique_ids:
        return None
    return MitreResolution(technique_ids=technique_ids, provenance=PROVENANCE_NATIVE_WAZUH, confidence=CONFIDENCE_CONFIRMED, reason='Wazuh rule.mitre.id')

def _resolve_reviewed(alert: dict) -> Optional[MitreResolution]:
    rule = alert.get('rule') or {}
    rule_id = rule.get('id')
    if rule_id is None:
        return None
    entry = REVIEWED_RULE_MAPPINGS.get(str(rule_id))
    if entry is None or not entry.get('enabled', True):
        return None
    technique_ids = tuple(entry.get('technique_ids') or ())
    if not technique_ids:
        return None
    valid, invalid_reason = _validate_technique_ids(technique_ids)
    if not valid:
        return _unknown(f'Reviewed mapping for rule {rule_id} rejected: {invalid_reason}')
    rationale = entry.get('rationale', '')
    return MitreResolution(technique_ids=technique_ids, provenance=PROVENANCE_REVIEWED_RULE_MAPPING, confidence=CONFIDENCE_REVIEWED, reason=f'Reviewed mapping for rule {rule_id}' + (f': {rationale}' if rationale else ''))
DETERMINISTIC_INFERENCE_RULES: list[Callable[[dict], Optional[tuple[str, ...]]]] = []

def _resolve_curated_wazuh(alert: dict) -> Optional[MitreResolution]:
    if not WAZUH_MAPPER_AVAILABLE:
        return None
    technique_id = wazuh_mapper.map_alert(alert)
    if technique_id is None:
        return None
    valid, invalid_reason = _validate_technique_ids((technique_id,))
    if not valid:
        return _unknown(f'Curated Wazuh mapping rejected: {invalid_reason}')
    rule = alert.get('rule') or {}
    rule_id = rule.get('id')
    description = wazuh_mapper.get_description(int(rule_id)) if rule_id else None
    reason_text = f'Curated Wazuh rule mapping for rule {rule_id}'
    if description:
        reason_text += f': {description}'
    return MitreResolution(technique_ids=(technique_id,), provenance=PROVENANCE_CURATED_WAZUH_MAPPING, confidence=CONFIDENCE_REVIEWED, reason=reason_text)

def _resolve_inference(alert: dict) -> Optional[MitreResolution]:
    for rule_fn in DETERMINISTIC_INFERENCE_RULES:
        candidates = rule_fn(alert)
        if not candidates:
            continue
        if len(candidates) > 1:
            return MitreResolution(technique_ids=(), provenance=PROVENANCE_AMBIGUOUS, confidence=CONFIDENCE_NONE, reason=f'Deterministic inference rule {rule_fn!r} produced multiple candidates {candidates} with no defensible way to choose one')
        valid, invalid_reason = _validate_technique_ids(candidates)
        if not valid:
            return _unknown(f'Deterministic inference candidate from {rule_fn!r} rejected: {invalid_reason}')
        return MitreResolution(technique_ids=candidates, provenance=PROVENANCE_DETERMINISTIC_INFERENCE, confidence=CONFIDENCE_CANDIDATE, reason=f'Deterministic inference rule {rule_fn!r} matched')
    return None

def resolve_mitre(alert: dict) -> MitreResolution:
    native = _resolve_native(alert)
    if native is not None:
        return native
    reviewed = _resolve_reviewed(alert)
    if reviewed is not None:
        return reviewed
    curated = _resolve_curated_wazuh(alert)
    if curated is not None:
        return curated
    inferred = _resolve_inference(alert)
    if inferred is not None:
        return inferred
    return _unknown('No native, reviewed, curated, or deterministically-inferred ATT&CK mapping')

def _tactic_labels_from_kill_chain_phases(phases: list[str] | None) -> list[str]:
    labels = []
    for phase in phases or []:
        name = phase.split(':')[-1]
        labels.append(name.replace('-', ' ').title())
    return labels

def enrich_technique_metadata(resolution: MitreResolution) -> list[dict]:
    if not resolution.technique_ids:
        return []
    records = []
    for technique_id in resolution.technique_ids:
        technique_name = None
        tactics: list[str] = []
        try:
            with driver.session() as session:
                row = session.run('MATCH (t:Technique {attack_id: $id}) RETURN t.name AS name, t.kill_chain_phases AS phases', id=technique_id).single()
            if row is not None:
                technique_name = row['name']
                tactics = _tactic_labels_from_kill_chain_phases(row['phases'])
        except Exception:
            pass
        records.append({'mitre_id': technique_id, 'technique_name': technique_name, 'tactic': tactics, 'mapping_source': resolution.provenance, 'mapping_confidence': resolution.confidence, 'mapping_reason': resolution.reason})
    return records