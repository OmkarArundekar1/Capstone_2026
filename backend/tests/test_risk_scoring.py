from risk_scoring import normalize_risk_score, risk_level_from_score, severity_from_tps

def test_normalize_clamps_at_100():
    assert normalize_risk_score(999999) == 100

def test_normalize_zero_is_zero():
    assert normalize_risk_score(0) == 0
    assert normalize_risk_score(None) == 0

def test_normalize_scales_linearly_below_ceiling():
    assert normalize_risk_score(750) == 50

def test_risk_level_thresholds():
    assert risk_level_from_score(80) == 'CRITICAL'
    assert risk_level_from_score(60) == 'HIGH'
    assert risk_level_from_score(35) == 'MEDIUM'
    assert risk_level_from_score(34.9) == 'LOW'

def test_severity_from_tps_real_outlier_is_still_critical():
    assert severity_from_tps(8330) == 'CRITICAL'

def test_severity_from_tps_mid_range_real_campaign_is_not_trivially_critical():
    assert severity_from_tps(630) == 'MEDIUM'

def test_severity_from_tps_low_real_campaign_is_low():
    assert severity_from_tps(90) == 'LOW'