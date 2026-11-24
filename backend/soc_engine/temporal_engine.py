from __future__ import annotations
import logging
from collections import deque
from typing import Any
logger = logging.getLogger(__name__)
LABEL_RANK = {'NORMAL': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
RANK_LABEL = {v: k for k, v in LABEL_RANK.items()}

class TemporalSmoother:

    def __init__(self, smooth_window: int=5, ema_alpha: float=0.3, high_min_count: int=1, medium_min_count: int=2, low_min_count: int=3) -> None:
        self.smooth_window = smooth_window
        self.ema_alpha = ema_alpha
        self.rules = {'HIGH': high_min_count, 'MEDIUM': medium_min_count, 'LOW': low_min_count}
        self._label_buffer: deque[str] = deque(maxlen=smooth_window)
        self._score_buffer: deque[float] = deque(maxlen=smooth_window)
        self._ema_score: float = 0.0
        self._window_count: int = 0

    def update(self, severity_score: float, severity_label: str) -> dict[str, Any]:
        self._label_buffer.append(severity_label)
        self._score_buffer.append(severity_score)
        self._window_count += 1
        if self._window_count == 1:
            self._ema_score = severity_score
        else:
            self._ema_score = self.ema_alpha * severity_score + (1 - self.ema_alpha) * self._ema_score
        temporal_label = self._compute_temporal_label()
        return {'temporal_label': temporal_label, 'smoothed_score': round(self._ema_score, 6), 'buffer_size': len(self._label_buffer), 'window_counts': self._count_labels()}

    def _compute_temporal_label(self) -> str:
        counts = self._count_labels()
        if counts.get('HIGH', 0) >= self.rules['HIGH']:
            return 'HIGH'
        if counts.get('MEDIUM', 0) >= self.rules['MEDIUM']:
            return 'MEDIUM'
        if counts.get('LOW', 0) >= self.rules['LOW']:
            return 'LOW'
        return 'NORMAL'

    def _count_labels(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for label in self._label_buffer:
            counts[label] = counts.get(label, 0) + 1
        return counts

    def reset(self) -> None:
        self._label_buffer.clear()
        self._score_buffer.clear()
        self._ema_score = 0.0
        self._window_count = 0

    @property
    def current_ema(self) -> float:
        return round(self._ema_score, 6)

def apply_temporal_smoothing(window_results: list[dict[str, Any]], smooth_window: int=5, high_min_count: int=1, medium_min_count: int=2, low_min_count: int=3) -> list[dict[str, Any]]:
    smoother = TemporalSmoother(smooth_window=smooth_window, high_min_count=high_min_count, medium_min_count=medium_min_count, low_min_count=low_min_count)
    enriched = []
    for entry in window_results:
        temporal_info = smoother.update(severity_score=entry['severity_score'], severity_label=entry['severity_label'])
        enriched.append({**entry, **temporal_info})
    return enriched