from config import TPS_MAP
from mitre_mapper import MITRE_TO_STAGE
MAPPABLE_OBSERVED_TECHNIQUES = ['T1595', 'T1595.002', 'T1110', 'T1110.001', 'T1053.003', 'T1078', 'T1021.004', 'T1055', 'T1190', 'T1210']
INTENTIONALLY_UNMAPPED_TECHNIQUES = ['T1057', 'T1059', 'T1059.007', 'T1114', 'T1562.001']

def test_every_mappable_observed_technique_has_an_explicit_mapping():
    for technique_id in MAPPABLE_OBSERVED_TECHNIQUES:
        assert technique_id in MITRE_TO_STAGE, f'{technique_id} should have an explicit stage mapping'

def test_intentionally_unmapped_techniques_fall_through_to_unknown():
    for technique_id in INTENTIONALLY_UNMAPPED_TECHNIQUES:
        assert technique_id not in MITRE_TO_STAGE
        assert MITRE_TO_STAGE.get(technique_id, 'Unknown') == 'Unknown'

def test_every_mapped_stage_is_a_valid_tps_map_key():
    for technique_id, stage in MITRE_TO_STAGE.items():
        assert stage in TPS_MAP, f"{technique_id} maps to '{stage}', which is not a TPS_MAP key — this technique would silently contribute tps=0 despite having an entry"

def test_t1053_003_no_longer_maps_to_invalid_cron_abuse_string():
    assert MITRE_TO_STAGE['T1053.003'] != 'Cron abuse'
    assert MITRE_TO_STAGE['T1053.003'] == 'Privilege Escalation'

def test_newly_added_techniques_have_expected_stages():
    assert MITRE_TO_STAGE['T1055'] == 'Privilege Escalation'
    assert MITRE_TO_STAGE['T1190'] == 'Initial Access'
    assert MITRE_TO_STAGE['T1210'] == 'Lateral Movement'
    assert MITRE_TO_STAGE['T1595.002'] == 'Reconnaissance'

def test_parent_subtechnique_stage_consistency():
    assert MITRE_TO_STAGE['T1595.002'] == MITRE_TO_STAGE['T1595']
    assert MITRE_TO_STAGE['T1110.001'] == MITRE_TO_STAGE['T1110']
    assert MITRE_TO_STAGE['T1021.004'] == MITRE_TO_STAGE['T1021']

def test_unmapped_subtechnique_pair_consistent_absence():
    assert 'T1059' not in MITRE_TO_STAGE
    assert 'T1059.007' not in MITRE_TO_STAGE

def test_unmapped_future_technique_falls_back_to_unknown():
    assert MITRE_TO_STAGE.get('T9999.999', 'Unknown') == 'Unknown'