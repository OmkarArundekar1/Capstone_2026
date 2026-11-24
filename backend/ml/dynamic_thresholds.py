from __future__ import annotations
import logging
from pathlib import Path
from typing import Dict, Literal, Optional, Tuple
import numpy as np
from sklearn.metrics import f1_score, precision_recall_curve, roc_curve
logger = logging.getLogger(__name__)

class DynamicThresholdLearner:

    def __init__(self, objective: Literal['f1', 'youden', 'cost_sensitive']='f1'):
        self.objective = objective
        self.continue_threshold: float = 0.3
        self.reopen_threshold: float = 0.7
        self.is_fitted: bool = False

    def fit_continue_threshold(self, scores: np.ndarray, labels: np.ndarray) -> Dict[str, float]:
        thresholds = np.linspace(0.1, 0.9, 81)
        best_threshold = 0.3
        best_metric = 0.0
        for threshold in thresholds:
            predictions = (scores >= threshold).astype(int)
            if self.objective == 'f1':
                metric = f1_score(labels, predictions, zero_division=0)
            elif self.objective == 'youden':
                tn = np.sum((predictions == 0) & (labels == 0))
                fp = np.sum((predictions == 1) & (labels == 0))
                fn = np.sum((predictions == 0) & (labels == 1))
                tp = np.sum((predictions == 1) & (labels == 1))
                sensitivity = tp / (tp + fn) if tp + fn > 0 else 0
                specificity = tn / (tn + fp) if tn + fp > 0 else 0
                metric = sensitivity + specificity - 1
            elif self.objective == 'cost_sensitive':
                fn = np.sum((predictions == 0) & (labels == 1))
                fp = np.sum((predictions == 1) & (labels == 0))
                cost_fn = 2.0
                cost_fp = 1.0
                metric = -(cost_fn * fn + cost_fp * fp)
            if metric > best_metric:
                best_metric = metric
                best_threshold = threshold
        self.continue_threshold = best_threshold
        return {'continue_threshold': best_threshold, 'metric_value': best_metric, 'objective': self.objective}

    def fit_reopen_threshold(self, scores: np.ndarray, should_reopen: np.ndarray) -> Dict[str, float]:
        thresholds = np.linspace(0.1, 0.9, 81)
        best_threshold = 0.7
        best_metric = 0.0
        for threshold in thresholds:
            predictions = (scores >= threshold).astype(int)
            if self.objective == 'f1':
                metric = f1_score(should_reopen, predictions, zero_division=0)
            elif self.objective == 'youden':
                tn = np.sum((predictions == 0) & (should_reopen == 0))
                fp = np.sum((predictions == 1) & (should_reopen == 0))
                fn = np.sum((predictions == 0) & (should_reopen == 1))
                tp = np.sum((predictions == 1) & (should_reopen == 1))
                sensitivity = tp / (tp + fn) if tp + fn > 0 else 0
                specificity = tn / (tn + fp) if tn + fp > 0 else 0
                metric = sensitivity + specificity - 1
            elif self.objective == 'cost_sensitive':
                fn = np.sum((predictions == 0) & (should_reopen == 1))
                fp = np.sum((predictions == 1) & (should_reopen == 0))
                cost_fn = 3.0
                cost_fp = 1.0
                metric = -(cost_fn * fn + cost_fp * fp)
            if metric > best_metric:
                best_metric = metric
                best_threshold = threshold
        self.reopen_threshold = best_threshold
        return {'reopen_threshold': best_threshold, 'metric_value': best_metric, 'objective': self.objective}

    def get_thresholds(self) -> Tuple[float, float]:
        return (self.continue_threshold, self.reopen_threshold)

    def save(self, path: str):
        import pickle
        artifact = {'objective': self.objective, 'continue_threshold': self.continue_threshold, 'reopen_threshold': self.reopen_threshold, 'is_fitted': self.is_fitted}
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump(artifact, f)
        logger.info(f'Threshold learner saved to {path}')

    @classmethod
    def load(cls, path: str) -> 'DynamicThresholdLearner':
        import pickle
        with open(path, 'rb') as f:
            artifact = pickle.load(f)
        instance = cls(objective=artifact['objective'])
        instance.continue_threshold = artifact['continue_threshold']
        instance.reopen_threshold = artifact['reopen_threshold']
        instance.is_fitted = artifact['is_fitted']
        logger.info(f'Threshold learner loaded from {path}')
        return instance
_dynamic_threshold_learner: Optional[DynamicThresholdLearner] = None

def get_dynamic_threshold_learner() -> Optional[DynamicThresholdLearner]:
    global _dynamic_threshold_learner
    if _dynamic_threshold_learner is not None:
        return _dynamic_threshold_learner
    import config
    learner_path = Path(config.ML_ARTIFACTS_DIR) / 'threshold_learner.pkl'
    if learner_path.exists():
        try:
            _dynamic_threshold_learner = DynamicThresholdLearner.load(str(learner_path))
            return _dynamic_threshold_learner
        except Exception:
            logger.exception('Failed to load threshold learner from %s', learner_path)
            return None
    return None

def get_thresholds_for_campaign_manager() -> Dict[str, float]:
    learner = get_dynamic_threshold_learner()
    if learner is not None:
        try:
            continue_thresh, reopen_thresh = learner.get_thresholds()
            return {'continue': continue_thresh, 'reopen': reopen_thresh}
        except Exception:
            logger.exception('Failed to get learned thresholds')
    return {'continue': 0.3, 'reopen': 0.7}