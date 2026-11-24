from __future__ import annotations
from ground_truth.schema import GroundTruthRecord, ReviewStatus
from scenarios.registry import AttackScenario
_LABELING_METHOD_ALERT = "raw Wazuh alert rule.description text cross-referenced against the scenario's pre-declared expected_techniques (themselves derived from MITRE ATT&CK's own technique definitions applied to the rule text) -- independent of mitre_resolver.py"
_LABELING_METHOD_SESSION = "attacker/victim IP pair + attack_family taken directly from the pre-declared AttackScenario -- independent of campaign_manager.py's own clustering output"

def build_from_raw_alert(scenario: AttackScenario, alert: dict, sample_id: str) -> GroundTruthRecord:
    rule = alert.get('rule') or {}
    rule_id = str(rule.get('id', ''))
    agent = alert.get('agent') or {}
    record = GroundTruthRecord(sample_id=sample_id, source='wazuh_alert', timestamp=alert.get('timestamp', ''), scenario_id=scenario.scenario_id, raw_event_id=f"rule={rule_id}|agent={agent.get('id', '?')}", attacker_identity=scenario.attacker, victim_identity=scenario.victim, expected_attack=scenario.scenario_name, expected_mitre_techniques=list(scenario.expected_techniques), expected_threat_status=scenario.expected_threat_status, expected_attribution=scenario.expected_attribution, reviewer='unreviewed', review_status=ReviewStatus.AUTO_PROPOSED, evidence_reference=f"raw alert rule.description={rule.get('description', '')!r} rule.id={rule_id}; scenario evidence: {scenario.evidence_sources}", labeling_method=_LABELING_METHOD_ALERT, dataset_version='v0-unlocked')
    record.validate()
    return record

def build_session_boundary(scenario: AttackScenario, sample_id: str, involved_raw_event_ids: list[str]) -> GroundTruthRecord:
    independent_campaign_key = f'SESSION::{scenario.scenario_id}::{scenario.attacker}->{scenario.victim}'
    record = GroundTruthRecord(sample_id=sample_id, source='scenario_session_boundary', timestamp='', scenario_id=scenario.scenario_id, raw_event_id='|'.join(involved_raw_event_ids), attacker_identity=scenario.attacker, victim_identity=scenario.victim, expected_attack=scenario.scenario_name, expected_mitre_techniques=[], expected_campaign_id=independent_campaign_key, expected_threat_status=scenario.expected_threat_status, expected_attribution=scenario.expected_attribution, reviewer='unreviewed', review_status=ReviewStatus.AUTO_PROPOSED, evidence_reference=f'scenario evidence: {scenario.evidence_sources}', labeling_method=_LABELING_METHOD_SESSION, dataset_version='v0-unlocked')
    record.validate()
    return record