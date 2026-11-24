import hashlib
import logging
import time
from dataclasses import dataclass
from threading import Event, Lock, Thread
from datetime import datetime, timezone
from typing import Optional
from config import ENABLE_DUPLICATE_BUFFER, DUPLICATE_FLUSH_INTERVAL, MAX_PENDING_DUPLICATES, MAX_BATCH_SIZE, DEDUP_WINDOW, DEDUP_CLEANUP_INTERVAL
from neo4j_client import find_recent_duplicate, batch_update_duplicates
logger = logging.getLogger(__name__)
WORKER_STOP_TIMEOUT = 2
FINAL_FLUSH_TIMEOUT = 30

class DuplicateBuffer:

    def __init__(self):
        self.buffer = {}
        self.restored = []
        self.lock = Lock()

    def add_duplicate(self, fingerprint, event_id, campaign_id, tps, payload, timestamp=None):
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()
        with self.lock:
            if fingerprint not in self.buffer and len(self.buffer) + len(self.restored) >= MAX_PENDING_DUPLICATES:
                return False
            if fingerprint not in self.buffer:
                self.buffer[fingerprint] = {'fingerprint': fingerprint, 'event_id': event_id, 'campaign_id': campaign_id, 'occurrences': 1, 'total_tps': tps, 'latest_payload': payload, 'last_seen': timestamp}
            else:
                entry = self.buffer[fingerprint]
                entry['occurrences'] += 1
                entry['total_tps'] += tps
                entry['latest_payload'] = payload
                entry['last_seen'] = timestamp
        return True

    def snapshot(self):
        with self.lock:
            data = [entry.copy() for entry in self.restored]
            data += [entry.copy() for entry in self.buffer.values()]
            self.restored.clear()
            self.buffer.clear()
        return data

    def size(self):
        with self.lock:
            return len(self.buffer) + len(self.restored)

    def flush(self):
        return self.snapshot()

    def restore(self, pending):
        with self.lock:
            last_index = {record['fingerprint']: index for index, record in enumerate(pending)}
            for index, record in enumerate(pending):
                fingerprint = record['fingerprint']
                existing = self.buffer.get(fingerprint)
                if existing is record or any((r is record for r in self.restored)):
                    continue
                if existing is None and index == last_index[fingerprint]:
                    self.buffer[fingerprint] = record
                else:
                    self.restored.append(record)

def _log_safely(log_method, *args, **kwargs):
    try:
        log_method(*args, **kwargs)
    except Exception:
        pass

def _write_pending(pending):
    written = 0
    try:
        for i in range(0, len(pending), MAX_BATCH_SIZE):
            batch = pending[i:i + MAX_BATCH_SIZE]
            batch_update_duplicates(batch)
            written += len(batch)
    except Exception as error:
        duplicate_buffer.restore(pending[written:])
        return (written, error)
    return (written, None)

@dataclass(frozen=True)
class FlushStopResult:
    worker_stopped: bool
    written: int = 0
    unflushed: int = 0
    unresolved: int = 0
    error: Optional[Exception] = None

    @property
    def complete(self):
        return self.worker_stopped and (not (self.unflushed or self.unresolved or self.error))

class DuplicateFlushWorker:

    def __init__(self):
        self.running = False
        self.thread = None
        self._stop_requested = Event()
        self._in_flight = 0

    def start(self):
        if not ENABLE_DUPLICATE_BUFFER:
            return
        if self.running:
            return
        self.running = True
        self._stop_requested = Event()
        self.thread = Thread(target=self.run, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        self._stop_requested.set()
        worker_stopped = True
        in_flight = 0
        thread = self.thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=WORKER_STOP_TIMEOUT)
            if thread.is_alive():
                worker_stopped = False
                in_flight = self._in_flight
                _log_safely(logger.error, '[Dedup Buffer] Flush worker did not stop within %ss. %d records are in an unfinished write; whether they persisted is unknown.', WORKER_STOP_TIMEOUT, in_flight)
        pending = duplicate_buffer.flush()
        if not pending:
            return FlushStopResult(worker_stopped, unresolved=in_flight)
        outcome = {}

        def write():
            outcome['result'] = _write_pending(pending)
        writer = Thread(target=write, daemon=True)
        writer.start()
        writer.join(timeout=FINAL_FLUSH_TIMEOUT)
        if 'result' not in outcome:
            _log_safely(logger.error, '[Dedup Buffer] Final flush did not finish within %ss. %d records are in an unfinished write; whether they persisted is unknown.', FINAL_FLUSH_TIMEOUT, len(pending))
            return FlushStopResult(worker_stopped, unresolved=in_flight + len(pending))
        written, error = outcome['result']
        if error is not None:
            _log_safely(logger.error, '[Dedup Buffer] Final flush failed. %d records written, %d restored to memory and lost if the process exits.', written, len(pending) - written, exc_info=error)
            return FlushStopResult(worker_stopped, written=written, unflushed=len(pending) - written, unresolved=in_flight, error=error)
        _log_safely(logger.info, '[Dedup Buffer] Final flush completed (%d records).', written)
        return FlushStopResult(worker_stopped, written=written, unresolved=in_flight)

    def run(self):
        stop_requested = self._stop_requested
        while not stop_requested.wait(DUPLICATE_FLUSH_INTERVAL):
            self._flush_once()

    def _flush_once(self):
        pending = duplicate_buffer.snapshot()
        if not pending:
            return
        self._in_flight = len(pending)
        try:
            written, error = _write_pending(pending)
        finally:
            self._in_flight = 0
        if error is not None:
            _log_safely(logger.error, '[Dedup Buffer] Flush failed. %d records written, %d restored.', written, len(pending) - written, exc_info=error)
            return
        _log_safely(logger.info, '[Dedup Buffer] Flushed %d aggregated duplicate updates.', written)

def _seconds(event_time):
    return time.time() if event_time is None else event_time.timestamp()

class DeduplicationEngine:

    def __init__(self):
        self.cache = {}
        self.lock = Lock()
        self.last_cleanup = None

    def generate_fingerprint(self, attacker_ip, victim_ip, technique_id, rule_id, agent_id):
        raw = f'{attacker_ip}|{victim_ip}|{technique_id}|{rule_id}|{agent_id}'
        return hashlib.sha256(raw.encode()).hexdigest()

    def reload_cache(self, fingerprint, event_id, campaign_id, event_time=None):
        with self.lock:
            self._store_reloaded_entry(fingerprint, event_id, campaign_id, event_time)

    def _store_reloaded_entry(self, fingerprint, event_id, campaign_id, event_time=None):
        now = _seconds(event_time)
        self.cache[fingerprint] = {'fingerprint': fingerprint, 'first_seen': now, 'last_seen': now, 'occurrences': 1, 'campaign_id': campaign_id, 'event_id': event_id}

    def is_duplicate(self, attacker_ip, victim_ip, technique_id, rule_id, agent_id, event_time=None):
        now = _seconds(event_time)
        fingerprint = self.generate_fingerprint(attacker_ip, victim_ip, technique_id, rule_id, agent_id)
        with self.lock:
            self.cleanup(now)
            if fingerprint in self.cache:
                last_seen = self.cache[fingerprint]['last_seen']
                if now - last_seen <= DEDUP_WINDOW:
                    self.cache[fingerprint]['last_seen'] = max(last_seen, now)
                    self.cache[fingerprint]['occurrences'] += 1
                    return (True, fingerprint)
            db_event = find_recent_duplicate(fingerprint, reference_time=event_time)
            if db_event is not None:
                self._store_reloaded_entry(fingerprint, db_event['event_id'], db_event['campaign_id'], event_time=event_time)
                return (True, fingerprint)
            return (False, fingerprint)

    def register_event(self, fingerprint, campaign_id=None, event_id=None, event_time=None):
        now = _seconds(event_time)
        with self.lock:
            if fingerprint not in self.cache:
                self.cache[fingerprint] = {'fingerprint': fingerprint, 'first_seen': now, 'last_seen': now, 'occurrences': 1, 'campaign_id': campaign_id, 'event_id': event_id}
            else:
                self.cache[fingerprint]['last_seen'] = max(self.cache[fingerprint]['last_seen'], now)
                self.cache[fingerprint]['occurrences'] += 1
                if campaign_id is not None:
                    self.cache[fingerprint]['campaign_id'] = campaign_id
                if event_id is not None:
                    self.cache[fingerprint]['event_id'] = event_id

    def get_metadata(self, fingerprint):
        return self.cache.get(fingerprint)

    def cleanup(self, now=None):
        if now is None:
            now = time.time()
        if self.last_cleanup is None:
            self.last_cleanup = now
            return
        if now - self.last_cleanup < DEDUP_CLEANUP_INTERVAL:
            return
        expired = []
        for fingerprint, data in self.cache.items():
            if now - data['last_seen'] > DEDUP_WINDOW:
                expired.append(fingerprint)
        for fingerprint in expired:
            del self.cache[fingerprint]
        self.last_cleanup = now

    def reset(self):
        with self.lock:
            self.cache.clear()
            self.last_cleanup = None
duplicate_buffer = DuplicateBuffer()
duplicate_flush_worker = DuplicateFlushWorker()
dedup_engine = DeduplicationEngine()