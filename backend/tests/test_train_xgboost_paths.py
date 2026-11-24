import os
from ml.train_xgboost import DEFAULT_MODEL_DIR

def test_default_model_dir_matches_api_expectation():
    expected = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'ml', 'models')
    assert os.path.normpath(DEFAULT_MODEL_DIR) == os.path.normpath(expected)