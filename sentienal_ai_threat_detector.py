from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Tuple

from .sentinel_threat_detector import EventContext, SequenceWindow


@dataclass
class SentinelWindowConfig:
    window_seconds: float = 60.0
    max_events_per_key: int = 200
    max_payloads: int = 50


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
        self._events: Dict[Tuple[str, str], Deque[EventContext]] = defaultdict(deque)
        self._payloads: Dict[Tuple[str, str], Deque[bytes]] = defaultdict(deque)

    # ------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------

    def add_event(self, event: EventContext) -> None:
        key = (event.source_identity, event.source_ip)

        events_q = self._events[key]
        events_q.append(event)
        while len(events_q) > self.cfg.max_events_per_key:
            events_q.popleft()

        if event.payload:
            payload_q = self._payloads[key]
            payload_q.append(event.payload)
            while len(payload_q) > self.cfg.max_payloads:
                payload_q.popleft()

        self._prune(key)

    # ------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------

    def build_window(self, identity: str, ip: str) -> SequenceWindow:
        key = (identity, ip)
        self._prune(key)

        window = SequenceWindow()
        for event in self._events[key]:
            window.add_event(event)

        return window

    def recent_payloads(self, identity: str, ip: str) -> List[bytes]:
        key = (identity, ip)
        self._prune(key)
        return list(self._payloads[key])

    # ------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------

    def _prune(self, key: Tuple[str, str]) -> None:
        cutoff = time.time() - self.cfg.window_seconds
        q = self._events[key]

        while q and q[0].timestamp < cutoff:
            q.popleft()

        # Payloads have no timestamps by design.
        # Bounding by count is sufficient and intentional.