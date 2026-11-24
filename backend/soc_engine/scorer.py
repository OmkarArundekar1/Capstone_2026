from __future__ import annotations
import logging
import math
from typing import Any
import numpy as np
logger = logging.getLogger(__name__)
DEFAULT_THRESHOLDS = {'HIGH': 8.0, 'MEDIUM': 4.0, 'LOW': 2.0}
MAD_CONSISTENCY = 1.4826

class SeverityScorer:

    def __init__(self, thresholds: dict[str, float] | None=None, clip_percentile: float=99.9) -> None:
        self.thresholds = thresholds or DEFAULT_THRESHOLDS
        self.clip_percentile = clip_percentile
        self.median_log: float = 0.0
        self.mad_log: float = 1.0
        self.upper_bound: float = float('inf')
        self._fitted: bool = False

    def fit(self, errors: np.ndarray) -> 'SeverityScorer':
        errors = self._validate(errors)
        errors_log = np.log1p(errors)
        self.upper_bound = float(np.percentile(errors_log, self.clip_percentile))
        compressed = self._soft_compress(errors_log, self.upper_bound)
        self.median_log = float(np.median(compressed))
        mad_raw = float(np.median(np.abs(compressed - self.median_log)))
        self.mad_log = max(mad_raw * MAD_CONSISTENCY, 1e-06)
        self._fitted = True
        logger.info('SeverityScorer fitted — median=%.4f  MAD=%.4f  upper_bound=%.4f', self.median_log, self.mad_log, self.upper_bound)
        return self

    def score(self, errors: np.ndarray) -> list[dict[str, Any]]:
        if not self._fitted:
            raise RuntimeError('SeverityScorer must be .fit() before scoring.')
        errors = self._validate(errors)
        errors_log = np.log1p(errors)
        compressed = self._soft_compress(errors_log, self.upper_bound)
        severity_scores = (compressed - self.median_log) / self.mad_log
        results = []
        for i, s in enumerate(severity_scores):
            label = self._label(float(s))
            is_anomaly = int(label != 'NORMAL')
            confidence = float(self._confidence(s))
            results.append({'window_index': i, 'severity_score': round(float(s), 6), 'severity_label': label, 'is_anomaly': is_anomaly, 'confidence': confidence})
        return results

    def score_single(self, error: float) -> dict[str, Any]:
        return self.score(np.array([error]))[0]

    def _label(self, severity: float) -> str:
        if severity > self.thresholds['HIGH']:
            return 'HIGH'
        elif severity > self.thresholds['MEDIUM']:
            return 'MEDIUM'
        elif severity > self.thresholds['LOW']:
            return 'LOW'
        return 'NORMAL'

    @staticmethod
    def _soft_compress(x: np.ndarray, upper_bound: float) -> np.ndarray:
        excess = x - upper_bound
        compressed = np.where(x > upper_bound, upper_bound + np.log1p(np.maximum(excess, 0.0)), x)
        compressed = np.nan_to_num(compressed, nan=0.0, posinf=upper_bound * 2, neginf=0.0)
        return compressed

    @staticmethod
    def _confidence(severity: float) -> float:
        return round(1.0 / (1.0 + math.exp(-0.5 * (severity - 2.0))), 4)

    @staticmethod
    def _validate(errors: np.ndarray) -> np.ndarray:
        arr = np.asarray(errors, dtype=np.float64).ravel()
        arr = np.nan_to_num(arr, nan=0.0, posinf=1000000.0, neginf=0.0)
        arr = np.clip(arr, 0.0, None)
        return arr

    def get_params(self) -> dict[str, float]:
        return {'median_log': self.median_log, 'mad_log': self.mad_log, 'upper_bound': self.upper_bound}

    def set_params(self, params: dict[str, float]) -> None:
        self.median_log = params['median_log']
        self.mad_log = params['mad_log']
        self.upper_bound = params['upper_bound']
        self._fitted = True

def compute_scores(errors: np.ndarray, thresholds: dict[str, float] | None=None, clip_percentile: float=99.9) -> list[dict[str, Any]]:
    scorer = SeverityScorer(thresholds=thresholds, clip_percentile=clip_percentile)
    scorer.fit(errors)
    return scorer.score(errors)