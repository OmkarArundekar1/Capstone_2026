from __future__ import annotations
import threading
import time
from collections import defaultdict, deque
from typing import Any

class EventBuffer:

    def __init__(self, max_events: int=50, ttl_seconds: int=300) -> None:
        self.max_events = max_events
        self.ttl_seconds = ttl_seconds
        self._buffer: dict[str, deque] = defaultdict(lambda: deque(maxlen=max_events))
        self._lock = threading.Lock()

    def add(self, src_ip: str, event: dict[str, Any]) -> None:
        now = time.time()
        with self._lock:
            self._buffer[src_ip].append({'ts': now, 'event': event})

    def get_events(self, src_ip: str, prune_stale: bool=True) -> list[dict[str, Any]]:
        with self._lock:
            buf = self._buffer.get(src_ip, deque())
            if prune_stale:
                now = time.time()
                live = [e for e in buf if now - e['ts'] <= self.ttl_seconds]
            else:
                live = list(buf)
            return [e['event'] for e in live]

    def get_all_ips(self) -> list[str]:
        now = time.time()
        with self._lock:
            return [ip for ip, buf in self._buffer.items() if any((now - e['ts'] <= self.ttl_seconds for e in buf))]

    def clear_ip(self, src_ip: str) -> None:
        with self._lock:
            if src_ip in self._buffer:
                del self._buffer[src_ip]

    def clear_all(self) -> None:
        with self._lock:
            self._buffer.clear()

    def summary(self) -> dict[str, int]:
        with self._lock:
            return {ip: len(buf) for ip, buf in self._buffer.items()}