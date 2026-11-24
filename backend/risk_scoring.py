from __future__ import annotations
import os
TPS_CEILING = int(os.environ.get('TPS_CEILING', '1500'))

def normalize_risk_score(raw_tps: float | int | None) -> float:
    raw = raw_tps or 0
    return min(100, round(raw / max(TPS_CEILING, 1) * 100))

def risk_level_from_score(score: float) -> str:
    if score >= 80:
        return 'CRITICAL'
    if score >= 60:
        return 'HIGH'
    if score >= 35:
        return 'MEDIUM'
    return 'LOW'

def severity_from_tps(tps: float | int | None) -> str:
    return risk_level_from_score(normalize_risk_score(tps))