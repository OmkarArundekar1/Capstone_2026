from __future__ import annotations
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import numpy as np
from sklearn.naive_bayes import GaussianNB
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedKFold
logger = logging.getLogger(__name__)

@dataclass
class NBEPrediction:
    score: float
    confidence: float
    contributions: Dict[str, float]

class NaiveBayesEnsemble:

    def __init__(self):
        self.classifiers: List[CalibratedClassifierCV] = []
        self.feature_names: List[str] = []
        self.feature_means: Dict[str, float] = {}
        self.feature_stds: Dict[str, float] = {}
        self.prior_positive: float = 0.5
        self.is_fitted: bool = False

    def fit(self, X: np.ndarray, y: np.ndarray, feature_names: Optional[List[str]]=None) -> Dict[str, float]:
        n_samples, n_features = X.shape
        if feature_names is None:
            feature_names = [f'feature_{i}' for i in range(n_features)]
        if len(feature_names) != n_features:
            raise ValueError(f'feature_names length {len(feature_names)} != n_features {n_features}')
        self.feature_names = feature_names
        self.prior_positive = float(np.mean(y))
        for i in range(n_features):
            feature_data = X[:, i].reshape(-1, 1)
            self.feature_means[feature_names[i]] = float(np.nanmean(feature_data))
            self.feature_stds[feature_names[i]] = float(np.nanstd(feature_data))
            base_nb = GaussianNB()
            calibrated_nb = CalibratedClassifierCV(base_nb, method='sigmoid', cv=StratifiedKFold(n_splits=min(5, n_samples // 10), shuffle=True, random_state=42))
            calibrated_nb.fit(feature_data, y)
            self.classifiers.append(calibrated_nb)
        self.is_fitted = True
        feature_importances = {}
        for i, name in enumerate(feature_names):
            feature_data = X[:, i].reshape(-1, 1)
            probs = self.classifiers[i].predict_proba(feature_data)[:, 1]
            correlation = np.corrcoef(probs, y)[0, 1]
            feature_importances[name] = abs(correlation)
        return feature_importances

    def predict(self, features: Dict[str, Optional[float]]) -> NBEPrediction:
        if not self.is_fitted:
            raise RuntimeError('Model not fitted')
        feature_probs = []
        contributions = {}
        for i, name in enumerate(self.feature_names):
            value = features.get(name)
            if value is None or np.isnan(value):
                value = self.feature_means[name]
            feature_array = np.array([[value]])
            prob_positive = self.classifiers[i].predict_proba(feature_array)[0, 1]
            feature_probs.append(prob_positive)
            contributions[name] = float(prob_positive)
        geometric_mean = np.exp(np.mean(np.log(np.clip(feature_probs, 1e-10, 1 - 1e-10))))
        p = np.clip(geometric_mean, 1e-10, 1 - 1e-10)
        entropy = -p * np.log2(p) - (1 - p) * np.log2(1 - p)
        confidence = 1.0 - entropy
        return NBEPrediction(score=float(geometric_mean), confidence=float(confidence), contributions=contributions)

    def save(self, path: str):
        if not self.is_fitted:
            raise RuntimeError('Cannot save unfitted model')
        import pickle
        artifact = {'feature_names': self.feature_names, 'classifiers': self.classifiers, 'feature_means': self.feature_means, 'feature_stds': self.feature_stds, 'prior_positive': self.prior_positive, 'is_fitted': self.is_fitted}
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump(artifact, f)
        logger.info(f'NBE baseline saved to {path}')

    @classmethod
    def load(cls, path: str) -> 'NaiveBayesEnsemble':
        import pickle
        with open(path, 'rb') as f:
            artifact = pickle.load(f)
        instance = cls()
        instance.feature_names = artifact['feature_names']
        instance.classifiers = artifact['classifiers']
        instance.feature_means = artifact['feature_means']
        instance.feature_stds = artifact['feature_stds']
        instance.prior_positive = artifact['prior_positive']
        instance.is_fitted = artifact['is_fitted']
        logger.info(f'NBE baseline loaded from {path}')
        return instance
_nbe_baseline: Optional[NaiveBayesEnsemble] = None

def get_nbe_baseline() -> Optional[NaiveBayesEnsemble]:
    global _nbe_baseline
    if _nbe_baseline is not None:
        return _nbe_baseline
    import config
    baseline_path = Path(config.ML_ARTIFACTS_DIR) / 'baselines' / 'nbe_baseline.pkl'
    if baseline_path.exists():
        try:
            _nbe_baseline = NaiveBayesEnsemble.load(str(baseline_path))
            return _nbe_baseline
        except Exception:
            logger.exception('Failed to load NBE baseline from %s', baseline_path)
            return None
    return None

def predict_with_nbe_baseline(features: Dict[str, Optional[float]]) -> Optional[NBEPrediction]:
    baseline = get_nbe_baseline()
    if baseline is None:
        return None
    try:
        return baseline.predict(features)
    except Exception:
        logger.exception('NBE baseline prediction failed')
        return None