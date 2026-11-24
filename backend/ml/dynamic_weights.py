from __future__ import annotations
import logging
from pathlib import Path
from typing import Dict, List, Literal, Optional
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
logger = logging.getLogger(__name__)

class DynamicWeightLearner:

    def __init__(self, method: Literal['logistic', 'random_forest', 'gradient_boosting']='logistic'):
        self.method = method
        self.model = None
        self.feature_names: List[str] = []
        self.learned_weights: Dict[str, float] = {}
        self.is_fitted: bool = False

    def fit(self, X: np.ndarray, y: np.ndarray, feature_names: Optional[List[str]]=None) -> Dict[str, float]:
        n_samples, n_features = X.shape
        if feature_names is None:
            feature_names = [f'feature_{i}' for i in range(n_features)]
        if len(feature_names) != n_features:
            raise ValueError(f'feature_names length {len(feature_names)} != n_features {n_features}')
        self.feature_names = feature_names
        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        if self.method == 'logistic':
            self.model = LogisticRegression(penalty='l2', C=1.0, solver='lbfgs', max_iter=1000)
        elif self.method == 'random_forest':
            self.model = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42, class_weight='balanced')
        elif self.method == 'gradient_boosting':
            self.model = GradientBoostingClassifier(n_estimators=100, max_depth=3, learning_rate=0.1, random_state=42)
        self.model.fit(X_train, y_train)
        if hasattr(self.model, 'coef_'):
            raw_weights = np.abs(self.model.coef_[0])
        elif hasattr(self.model, 'feature_importances_'):
            raw_weights = self.model.feature_importances_
        else:
            raw_weights = np.ones(n_features) / n_features
        normalized_weights = raw_weights / (raw_weights.sum() + 1e-10)
        self.learned_weights = {name: float(weight) for name, weight in zip(feature_names, normalized_weights)}
        self.is_fitted = True
        val_accuracy = self.model.score(X_val, y_val)
        return {'validation_accuracy': val_accuracy, 'weights': self.learned_weights}

    def get_weights(self) -> Dict[str, float]:
        if not self.is_fitted:
            raise RuntimeError('Model not fitted')
        return self.learned_weights.copy()

    def save(self, path: str):
        if not self.is_fitted:
            raise RuntimeError('Cannot save unfitted model')
        import pickle
        artifact = {'method': self.method, 'model': self.model, 'feature_names': self.feature_names, 'learned_weights': self.learned_weights, 'is_fitted': self.is_fitted}
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump(artifact, f)
        logger.info(f'Weight learner saved to {path}')

    @classmethod
    def load(cls, path: str) -> 'DynamicWeightLearner':
        import pickle
        with open(path, 'rb') as f:
            artifact = pickle.load(f)
        instance = cls(method=artifact['method'])
        instance.model = artifact['model']
        instance.feature_names = artifact['feature_names']
        instance.learned_weights = artifact['learned_weights']
        instance.is_fitted = artifact['is_fitted']
        logger.info(f'Weight learner loaded from {path}')
        return instance
_dynamic_weight_learner: Optional[DynamicWeightLearner] = None

def get_dynamic_weight_learner() -> Optional[DynamicWeightLearner]:
    global _dynamic_weight_learner
    if _dynamic_weight_learner is not None:
        return _dynamic_weight_learner
    import config
    learner_path = Path(config.ML_ARTIFACTS_DIR) / 'weight_learner.pkl'
    if learner_path.exists():
        try:
            _dynamic_weight_learner = DynamicWeightLearner.load(str(learner_path))
            return _dynamic_weight_learner
        except Exception:
            logger.exception('Failed to load weight learner from %s', learner_path)
            return None
    return None

def get_weights_for_decision_engine() -> Dict[str, float]:
    learner = get_dynamic_weight_learner()
    if learner is not None:
        try:
            return learner.get_weights()
        except Exception:
            logger.exception('Failed to get learned weights')
    import config
    return config.CAMPAIGN_WEIGHTS.copy()