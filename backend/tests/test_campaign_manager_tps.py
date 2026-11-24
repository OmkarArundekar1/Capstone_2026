from campaign_manager import _tps_for_technique
from config import TPS_MAP

def test_tps_for_technique_routes_through_stage_mapping():
    assert _tps_for_technique('T1595') == TPS_MAP['Reconnaissance']
    assert _tps_for_technique('T1595') != 0

def test_tps_for_technique_unmapped_technique_is_zero():
    assert _tps_for_technique('T9999.999') == 0

def test_tps_for_technique_matches_real_observed_values():
    assert _tps_for_technique('T1110.001') == 45
    assert _tps_for_technique('T1078') == 70