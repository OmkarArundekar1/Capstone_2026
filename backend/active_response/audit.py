from __future__ import annotations
from soar.memory import memory_store
_BANNED_DETAIL_KEYS = {'password', 'api_key', 'apikey', 'secret', 'token', 'auth_token', 'credential'}

def _scrub(detail: dict) -> dict:
    return {k: v for k, v in detail.items() if k.lower() not in _BANNED_DETAIL_KEYS}

def log_response_event(event_type: str, correlation_id: str, decision_id: str | None=None, response_plan_id: str | None=None, incident_id: str | None=None, attack_event_id: str | None=None, campaign_id: str | None=None, operation_id: str | None=None, investigation_id: str | None=None, execution_id: str | None=None, detail: dict | None=None) -> None:
    full_detail = _scrub({'correlation_id': correlation_id, 'decision_id': decision_id, 'response_plan_id': response_plan_id, 'incident_id': incident_id, 'attack_event_id': attack_event_id, **(detail or {})})
    memory_store.log_audit_event(event_type=event_type, campaign_id=campaign_id, operation_id=operation_id, investigation_id=investigation_id, execution_id=execution_id, detail=full_detail)

def audit_trail_for_correlation(correlation_id: str, limit: int=200) -> list[dict]:
    all_events = memory_store.list_audit_events(limit=limit)
    return [e for e in all_events if e.get('detail', {}).get('correlation_id') == correlation_id]