from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, Tuple

_logger = logging.getLogger("sentinel43.velocity")


@dataclass(frozen=True)
class VelocityConfig:
    window_seconds: int = 60
    limit: int = 10
    gc_interval_seconds: int = 300
    max_entries_per_user: int = 1000


class VelocityGuard:
    """
    DoS/memory hardened velocity guard.

    - Sliding window per user
    - Periodic GC of old timestamps
    - Hard cap per user to prevent memory exhaustion
    """

    def __init__(self, cfg: VelocityConfig) -> None:
        self.cfg = cfg
        self._lock = threading.Lock()
        self._last_gc = datetime.now(timezone.utc)
        self._events: Dict[str, Deque[datetime]] = {}

    def _gc(self, now: datetime) -> None:
        if (now - self._last_gc).total_seconds() < self.cfg.gc_interval_seconds:
            return

        cutoff = now - timedelta(seconds=self.cfg.window_seconds)
        dead = []
        for user_id, dq in self._events.items():
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                dead.append(user_id)

        for user_id in dead:
            self._events.pop(user_id, None)

        self._last_gc = now

    def allow(self, user_id: str, now: datetime | None = None) -> Tuple[bool, str]:
        """
        Returns (allowed, reason_code).
        reason_code is a short string; caller maps it to ReasonCodes if desired.
        """
        now = now or datetime.now(timezone.utc)

        with self._lock:
            self._gc(now)

            dq = self._events.setdefault(user_id, deque())
            cutoff = now - timedelta(seconds=self.cfg.window_seconds)

            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= self.cfg.max_entries_per_user:
                _logger.warning("Velocity cap exceeded user=%s entries=%s", user_id, len(dq))
                return (False, "VELOCITY_CAP_EXCEEDED")

            if len(dq) >= self.cfg.limit:
                return (False, "VELOCITY_LIMIT")

            dq.append(now)
            return (True, "CLEARED")