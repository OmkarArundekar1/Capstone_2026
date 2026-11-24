from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import Any
import numpy as np
logger = logging.getLogger(__name__)
MAD_CONSISTENCY = 1.4826

class AdaptiveThreshold:

    def __init__(self, multiplier: float=6.0, clip_percentile: float=99.9) -> None:
        self.multiplier = multiplier
        self.clip_percentile = clip_percentile
        self.median_: float = 0.0
        self.mad_: float = 1.0
        self.threshold_: float = 0.0
        self._fitted: bool = False

    def fit(self, errors: np.ndarray) -> 'AdaptiveThreshold':
        errors = np.asarray(errors, dtype=np.float64).ravel()
        errors = np.nan_to_num(errors, nan=0.0, posinf=1000000.0)
        errors = np.clip(errors, 0.0, None)
        upper = np.percentile(errors, self.clip_percentile)
        excess = errors - upper
        compressed = np.where(errors > upper, upper + np.log1p(np.maximum(excess, 0.0)), errors)
        self.median_ = float(np.median(compressed))
        mad_raw = float(np.median(np.abs(compressed - self.median_)))
        self.mad_ = max(mad_raw * MAD_CONSISTENCY, 1e-06)
        self.threshold_ = float(self.median_ + self.multiplier * self.mad_)
        self._fitted = True
        logger.info('Threshold calibrated — median=%.4f  MAD=%.4f  threshold=%.4f', self.median_, self.mad_, self.threshold_)
        return self

    def predict(self, errors: np.ndarray) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError('AdaptiveThreshold must be .fit() before predict().')
        errors = np.asarray(errors, dtype=np.float64).ravel()
        errors = np.nan_to_num(errors, nan=0.0, posinf=1000000.0)
        return (errors > self.threshold_).astype(np.int32)

    def predict_proba(self, errors: np.ndarray) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError('AdaptiveThreshold must be .fit() before predict_proba().')
        errors = np.asarray(errors, dtype=np.float64).ravel()
        z = (errors - self.threshold_) / self.mad_
        return 1.0 / (1.0 + np.exp(-z))

    def to_dict(self) -> dict[str, Any]:
        return {'multiplier': self.multiplier, 'clip_percentile': self.clip_percentile, 'median_': self.median_, 'mad_': self.mad_, 'threshold_': self.threshold_}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> 'AdaptiveThreshold':
        obj = cls(multiplier=d['multiplier'], clip_percentile=d['clip_percentile'])
        obj.median_ = d['median_']
        obj.mad_ = d['mad_']
        obj.threshold_ = d['threshold_']
        obj._fitted = True
        return obj

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info('Threshold saved to %s', path)

    @classmethod
    def load(cls, path: str | Path) -> 'AdaptiveThreshold':
        with open(path) as f:
            d = json.load(f)
        logger.info('Threshold loaded from %s', path)
        return cls.from_dict(d)