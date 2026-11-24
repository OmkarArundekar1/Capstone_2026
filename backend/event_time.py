from __future__ import annotations
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock
logger = logging.getLogger(__name__)
POLICY_STRICT = 'strict'
POLICY_PROCESSING_TIME_FALLBACK = 'processing_time_fallback'
POLICIES = (POLICY_STRICT, POLICY_PROCESSING_TIME_FALLBACK)
SOURCE_ALERT = 'ALERT_TIMESTAMP'
SOURCE_PROCESSING_TIME_FALLBACK = 'PROCESSING_TIME_FALLBACK'
REASON_MISSING = 'MISSING'
REASON_MALFORMED = 'MALFORMED'
REASON_TIMEZONE_MISSING = 'TIMEZONE_MISSING'
FUTURE_SKEW_TOLERANCE = timedelta(minutes=5)
TIMESTAMP_FIELDS = ('timestamp', '@timestamp')

class EventTimeError(ValueError):

    def __init__(self, reason: str, raw):
        super().__init__(f'{reason}: {raw!r}')
        self.reason = reason
        self.raw = raw

@dataclass(frozen=True)
class EventTime:
    value: datetime
    source: str
    fallback_reason: str | None = None
    raw: str | None = None
    late: bool = False
    future_skew: bool = False

def parse_timestamp(raw) -> datetime:
    if raw is None or (isinstance(raw, str) and (not raw.strip())):
        raise EventTimeError(REASON_MISSING, raw)
    if not isinstance(raw, str):
        raise EventTimeError(REASON_MALFORMED, raw)
    text = raw.strip()
    if text.endswith('Z') or text.endswith('z'):
        text = text[:-1] + '+00:00'
    if len(text) >= 5 and text[-5] in '+-' and text[-4:].isdigit():
        text = text[:-2] + ':' + text[-2:]
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        raise EventTimeError(REASON_MALFORMED, raw) from None
    if value.tzinfo is None or value.utcoffset() is None:
        raise EventTimeError(REASON_TIMEZONE_MISSING, raw)
    return value.astimezone(timezone.utc)

def raw_timestamp(alert: dict):
    for field in TIMESTAMP_FIELDS:
        value = alert.get(field)
        if value not in (None, ''):
            return value
    return None

def resolve_event_time(alert: dict, policy: str, now: datetime | None=None) -> EventTime:
    if policy not in POLICIES:
        raise ValueError(f'unknown event-time policy {policy!r}; expected one of {POLICIES}')
    processing_now = now or datetime.now(timezone.utc)
    raw = raw_timestamp(alert)
    try:
        value = parse_timestamp(raw)
    except EventTimeError as err:
        if policy == POLICY_STRICT:
            raise
        logger.warning('Alert event time %s (%r); using processing time %s under %s policy.', err.reason, raw, processing_now.isoformat(), POLICY_PROCESSING_TIME_FALLBACK)
        return EventTime(value=processing_now, source=SOURCE_PROCESSING_TIME_FALLBACK, fallback_reason=err.reason, raw=None if raw is None else str(raw))
    return EventTime(value=value, source=SOURCE_ALERT, raw=str(raw), future_skew=value - processing_now > FUTURE_SKEW_TOLERANCE)

class EventClock:

    def __init__(self):
        self._lock = Lock()
        self._watermark: datetime | None = None

    @property
    def watermark(self) -> datetime | None:
        with self._lock:
            return self._watermark

    def observe(self, event_time: EventTime) -> EventTime:
        with self._lock:
            late = self._watermark is not None and event_time.value < self._watermark
            if self._watermark is None or event_time.value > self._watermark:
                self._watermark = event_time.value
        if late:
            logger.info('Late alert: event time %s < watermark.', event_time.value.isoformat())
            return EventTime(value=event_time.value, source=event_time.source, fallback_reason=event_time.fallback_reason, raw=event_time.raw, late=True, future_skew=event_time.future_skew)
        return event_time

    def reset(self):
        with self._lock:
            self._watermark = None
event_clock = EventClock()