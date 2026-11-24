from ml.dataset_utils import FEATURE_COLUMNS, LABEL_COLUMNS, LEAKAGE_COLUMNS

def test_risk_score_excluded_from_features():
    assert 'risk_score' not in FEATURE_COLUMNS
    assert 'risk_score' in LEAKAGE_COLUMNS

def test_no_label_columns_leak_into_features():
    assert not set(LABEL_COLUMNS) & set(FEATURE_COLUMNS)

def test_independent_graph_features_are_not_excluded():
    for col in ['campaign_complexity', 'structural_risk', 'graph_density', 'campaign_duration']:
        assert col in FEATURE_COLUMNS