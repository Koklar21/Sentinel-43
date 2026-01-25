from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import RLock
from typing import Deque, Dict, List, Optional, Tuple

from .sentinel_threat_detector import EventContext, SequenceWindow


@dataclass
class SentinelWindowConfig:
    window_seconds: float = 60.0
    max_events_per_key: int = 200
    max_payloads: int = 50

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.max_events_per_key <= 0:
            raise ValueError("max_events_per_key must be positive")
        if self.max_payloads <= 0:
            raise ValueError("max_payloads must be positive")


@dataclass(frozen=True)
class _PayloadEntry:
    payload: bytes
    timestamp: float


class SentinelWindowStore:
    """
    Maintains short rolling windows per (identity, ip).
    Also tracks recent payloads for mutation / entropy analysis.

    This store is intentionally dumb:
    - no scoring
    - no threat decisions
    - no policy
    It only preserves time-bounded evidence.
    """

    def __init__(self, cfg: Optional[SentinelWindowConfig] = None) -> None:
        self.cfg = cfg or SentinelWindowConfig()
        self._lock = RLock()

        self._events: Dict[Tuple[str, str], Deque[EventContext]] = defaultdict(deque)
        self._payloads: Dict[Tuple[str, str], Deque[_PayloadEntry]] = defaultdict(deque)

    # ------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------

    def add_event(self, event: EventContext) -> None:
        ident = event.source_identity
        ip = event.source_ip

        if not ident or not ip:
            raise ValueError("event.source_identity and event.source_ip must be non-empty")

        key = (ident, ip)

        with self._lock:
            events_q = self._events[key]
            events_q.append(event)

            # Bound by count
            while len(events_q) > self.cfg.max_events_per_key:
                events_q.popleft()

            # Track payloads with timestamps so they prune consistently with the event window
            if event.payload:
                payload_q = self._payloads[key]
                payload_q.append(_PayloadEntry(payload=event.payload, timestamp=float(event.timestamp)))

                # Bound by count
                while len(payload_q) > self.cfg.max_payloads:
                    payload_q.popleft()

            # Prune + cleanup empty keys (prevents unbounded dict growth)
            self._prune_locked(key)

    # ------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------

    def build_window(self, identity: str, ip: str) -> SequenceWindow:
        if not identity or not ip:
            raise ValueError("identity and ip must be non-empty")

        key = (identity, ip)

        with self._lock:
            self._prune_locked(key)
            events = list(self._events.get(key, ()))

        # Build outside lock to reduce contention if SequenceWindow.add_event does work
        window = SequenceWindow()
        for event in events:
            window.add_event(event)
        return window

    def recent_payloads(self, identity: str, ip: str) -> List[bytes]:
        if not identity or not ip:
            raise ValueError("identity and ip must be non-empty")

        key = (identity, ip)

        with self._lock:
            self._prune_locked(key)
            payloads = self._payloads.get(key)
            if not payloads:
                return []
            return [p.payload for p in payloads]

    # ------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------

    def _prune_locked(self, key: Tuple[str, str]) -> None:
        cutoff = time.time() - self.cfg.window_seconds

        # Prune events by time
        q = self._events.get(key)
        if q:
            while q and float(q[0].timestamp) < cutoff:
                q.popleft()
            if not q:
                self._events.pop(key, None)

        # Prune payloads by time (align with event window)
        pq = self._payloads.get(key)
        if pq:
            while pq and pq[0].timestamp < cutoff:
                pq.popleft()
            if not pq:
                self._payloads.pop(key, None)

    def cleanup_empty_keys(self) -> int:
        """
        Optional global cleanup for long-running processes.
        Useful if you later throttle pruning frequency.
        Returns number of keys removed.
        """
        removed = 0
        with self._lock:
            for key in list(self._events.keys()):
                if not self._events.get(key):
                    self._events.pop(key, None)
                    self._payloads.pop(key, None)
                    removed += 1

            for key in list(self._payloads.keys()):
                # Safety cleanup if payload dict ever contains empty orphan keys
                if key not in self._events and not self._payloads.get(key):
                    self._payloads.pop(key, None)
                    removed += 1

        return removed