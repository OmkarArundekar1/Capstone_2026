from __future__ import annotations
import logging
from pathlib import Path
from typing import Dict, Literal, Optional
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.dummy import DummyClassifier
logger = logging.getLogger(__name__)

class ConfidenceCalibrator:

    def __init__(self, method: Literal['platt', 'isotonic', 'temperature']='platt'):
        self.method = method
        self.calibrator = None
        self.temperature = 1.0
        self.is_fitted = False

    def fit(self, scores: np.ndarray, correctness: np.ndarray) -> Dict[str, float]:
        n_samples = len(scores)
        if n_samples < 10:
            raise ValueError(f'Need at least 10 samples, got {n_samples}')
        if self.method == 'platt':
            dummy = DummyClassifier(strategy='constant', constant=1)
            dummy.fit(scores.reshape(-1, 1), correctness)
            self.calibrator = CalibratedClassifierCV(dummy, method='sigmoid', cv='prefit')
            self.calibrator.fit(scores.reshape(-1, 1), correctness)
        elif self.method == 'isotonic':
            self.calibrator = IsotonicRegression(out_of_bounds='clip')
            self.calibrator.fit(scores, correctness)
        elif self.method == 'temperature':
            X = scores.reshape(-1, 1)
            self.calibrator = LogisticRegression(penalty=None, solver='lbfgs')
            self.calibrator.fit(X, correctness)
            if hasattr(self.calibrator, 'coef_'):
                self.temperature = 1.0 / max(abs(self.calibrator.coef_[0][0]), 0.01)
        self.is_fitted = True
        metrics = self.compute_metrics(scores, correctness)
        return metrics

    def calibrate(self, score: float) -> float:
        if not self.is_fitted:
            return score
        score = np.clip(score, 0.0, 1.0)
        if self.method == 'platt':
            return float(self.calibrator.predict_proba([[score]])[0, 1])
        elif self.method == 'isotonic':
            return float(self.calibrator.predict([score])[0])
        elif self.method == 'temperature':
            logit = np.log(np.clip(score / (1 - score), 1e-10, 10000000000.0))
            scaled_logit = logit / self.temperature
            calibrated = 1.0 / (1.0 + np.exp(-scaled_logit))
            return float(calibrated)
        return score

    def compute_metrics(self, scores: np.ndarray, correctness: np.ndarray) -> Dict[str, float]:
        calibrated_scores = np.array([self.calibrate(s) for s in scores])
        bins = np.linspace(0, 1, 11)
        bin_indices = np.digitize(calibrated_scores, bins[:-1]) - 1
        bin_indices = np.clip(bin_indices, 0, len(bins) - 2)
        ece = 0.0
        mce = 0.0
        for i in range(len(bins) - 1):
            mask = bin_indices == i
            if mask.sum() == 0:
                continue
            bin_confidence = calibrated_scores[mask].mean()
            bin_accuracy = correctness[mask].mean()
            bin_weight = mask.sum() / len(scores)
            calibration_error = abs(bin_confidence - bin_accuracy)
            ece += bin_weight * calibration_error
            mce = max(mce, calibration_error)
        return {'ece': float(ece), 'mce': float(mce), 'mean_confidence': float(calibrated_scores.mean()), 'mean_accuracy': float(correctness.mean())}

    def save(self, path: str):
        if not self.is_fitted:
            raise RuntimeError('Cannot save unfitted calibrator')
        import pickle
        artifact = {'method': self.method, 'calibrator': self.calibrator, 'temperature': self.temperature, 'is_fitted': self.is_fitted}
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump(artifact, f)
        logger.info(f'Confidence calibrator saved to {path}')

    @classmethod
    def load(cls, path: str) -> 'ConfidenceCalibrator':
        import pickle
        with open(path, 'rb') as f:
            artifact = pickle.load(f)
        instance = cls(method=artifact['method'])
        instance.calibrator = artifact['calibrator']
        instance.temperature = artifact['temperature']
        instance.is_fitted = artifact['is_fitted']
        logger.info(f'Confidence calibrator loaded from {path}')
        return instance
_confidence_calibrator: Optional[ConfidenceCalibrator] = None

def get_confidence_calibrator() -> Optional[ConfidenceCalibrator]:
    global _confidence_calibrator
    if _confidence_calibrator is not None:
        return _confidence_calibrator
    import config
    calibrator_path = Path(config.ML_ARTIFACTS_DIR) / 'confidence_calibrator.pkl'
    if calibrator_path.exists():
        try:
            _confidence_calibrator = ConfidenceCalibrator.load(str(calibrator_path))
            return _confidence_calibrator
        except Exception:
            logger.exception('Failed to load confidence calibrator from %s', calibrator_path)
            return None
    return None

def calibrate_confidence(score: float, features_available: int, total_features: int) -> float:
    calibrator = get_confidence_calibrator()
    if calibrator is not None:
        try:
            return calibrator.calibrate(score)
        except Exception:
            logger.exception('Confidence calibration failed')
    return float(features_available) / total_features if total_features > 0 else 0.0