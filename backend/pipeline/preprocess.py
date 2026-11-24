from __future__ import annotations
import logging
from pathlib import Path
from typing import Any
import joblib
import numpy as np
import pandas as pd
logger = logging.getLogger(__name__)
_DROP_ALWAYS = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label', 'src_ip', 'dst_ip', 'source IP', 'destination IP', 'uid', 'id.orig_h', 'id.resp_h', 'sensor']

class Preprocessor:

    def __init__(self) -> None:
        self._scaler: Any = None
        self._feature_names: list[str] = []

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        from sklearn.preprocessing import StandardScaler
        df = self._clean(df)
        self._feature_names = list(df.columns)
        self._scaler = StandardScaler()
        return self._scaler.fit_transform(df.values).astype(np.float32)

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        if self._scaler is None:
            raise RuntimeError('Preprocessor has no scaler. Call fit_transform() or from_scaler().')
        df = self._clean(df, expected_cols=self._feature_names)
        return self._scaler.transform(df.values).astype(np.float32)

    def transform_array(self, X: np.ndarray) -> np.ndarray:
        if self._scaler is None:
            raise RuntimeError('Preprocessor has no scaler.')
        return self._scaler.transform(X).astype(np.float32)

    def _clean(self, df: pd.DataFrame, expected_cols: list[str] | None=None) -> pd.DataFrame:
        df = df.copy()
        df.columns = df.columns.str.strip()
        drop = [c for c in _DROP_ALWAYS if c in df.columns]
        if drop:
            logger.debug('Dropping identifier columns: %s', drop)
        df = df.drop(columns=drop, errors='ignore')
        if expected_cols:
            missing = [c for c in expected_cols if c not in df.columns]
            extra = [c for c in df.columns if c not in expected_cols]
            if missing:
                logger.warning('Missing %d features at inference — filling with 0', len(missing))
                for c in missing:
                    df[c] = 0.0
            if extra:
                df = df.drop(columns=extra)
            df = df[expected_cols]
        df = df.apply(pd.to_numeric, errors='coerce')
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0.0, inplace=True)
        return df

    def save_scaler(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump((self._scaler, self._feature_names), path)
        logger.info('Scaler saved to %s', path)

    @classmethod
    def from_scaler(cls, path: str | Path) -> 'Preprocessor':
        obj = cls()
        data = joblib.load(path)
        if isinstance(data, tuple):
            obj._scaler, obj._feature_names = data
        else:
            obj._scaler = data
            obj._feature_names = []
        logger.info('Scaler loaded from %s', path)
        return obj

    @property
    def feature_names(self) -> list[str]:
        return list(self._feature_names)

    @property
    def n_features(self) -> int:
        return len(self._feature_names)