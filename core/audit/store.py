# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
#
# Sentinel-43 is distributed under a dual-license model:
#
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
#
# Unauthorized copying, redistribution, relicensing, reverse engineering,
# or commercial exploitation outside the terms of the applicable license
# is strictly prohibited.
#
# By accessing, modifying, distributing, or using this software, you agree
# to comply with the terms of the applicable license.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
#
# Commercial Licensing:
# Contact the copyright holder for commercial licensing terms.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Deque

_logger = logging.getLogger("sentinel43.velocity")


@dataclass(frozen=True)
class VelocityConfig:
    """
    Configuration for VelocityGuard.

    window_seconds:       sliding window duration
    limit:                max events allowed within the window
    gc_interval_seconds:  how often stale user entries are purged
    max_entries_per_user: hard memory cap per user deque
    max_user_id_length:   input validation cap on user_id strings
    max_tracked_users:    global cap on tracked user count

    Invariants enforced by __post_init__:
      - All integer fields must be >= 1.
      - max_entries_per_user must be >= limit so the memory cap is never
        reached before the rate limit, avoiding confusing VELOCITY_CAP_EXCEEDED
        responses under normal load.
    """

    window_seconds:       int = 60
    limit:                int = 10
    gc_interval_seconds:  int = 300
    max_entries_per_user: int = 1_000
    max_user_id_length:   int = 128
    max_tracked_users:    int = 10_000

    def __post_init__(self) -> None:
        # Fix (MEDIUM): validate all fields so misconfigured guards fail loudly
        # at construction time rather than silently producing wrong behaviour.
        for name, value in [
            ("window_seconds",       self.window_seconds),
            ("limit",                self.limit),
            ("gc_interval_seconds",  self.gc_interval_seconds),
            ("max_entries_per_user", self.max_entries_per_user),
            ("max_user_id_length",   self.max_user_id_length),
            ("max_tracked_users",    self.max_tracked_users),
        ]:
            if not isinstance(value, int) or value < 1:
                raise ValueError(
                    f"VelocityConfig.{name} must be a positive integer, got {value!r}."
                )

        if self.max_entries_per_user < self.limit:
            raise ValueError(
                f"VelocityConfig.max_entries_per_user ({self.max_entries_per_user}) "
                f"must be >= limit ({self.limit}). "
                "Otherwise the memory cap is hit before the rate limit."
            )


class VelocityGuard:
    """
    DoS / memory-hardened sliding-window velocity guard.

      - Per-user sliding window with configurable limit and window duration.
      - Periodic GC purges stale user entries to reclaim memory.
      - Hard per-user deque cap prevents memory exhaustion on individual users.
      - Global tracked-user cap prevents unbounded growth across all users.
    """

    def __init__(self, cfg: VelocityConfig) -> None:
        self.cfg = cfg
        self._lock = threading.Lock()
        self._last_gc = datetime.now(timezone.utc)
        self._events: dict[str, Deque[datetime]] = {}

    def _validate_now(self, now: datetime) -> datetime:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("VelocityGuard requires a timezone-aware datetime.")
        return now.astimezone(timezone.utc)

    def _normalize_user_id(self, user_id: str) -> str:
        if not isinstance(user_id, str):
            raise TypeError("user_id must be a string.")
        user_id = user_id.strip()
        if not user_id:
            raise ValueError("user_id must not be empty.")
        if len(user_id) > self.cfg.max_user_id_length:
            raise ValueError("user_id exceeds maximum allowed length.")

        # Strip control characters and non-printable chars to prevent log
        # injection and junk IDs. isprintable() already excludes \r, \n, \t —
        # the explicit exclude list in the original was redundant; removed.
        user_id = "".join(ch for ch in user_id if ch.isprintable())
        if not user_id:
            raise ValueError("user_id became empty after normalization.")
        return user_id

    def _gc(self, now: datetime) -> None:
        """Purge stale user entries. Must be called under self._lock."""
        # Recover from backward clock movement or test time-skew.
        if now < self._last_gc:
            self._last_gc = now

        if (now - self._last_gc).total_seconds() < self.cfg.gc_interval_seconds:
            return

        # Set at the start of the sweep so a slow GC doesn't trigger
        # immediate re-entry on the next allow() call.
        self._last_gc = now

        cutoff = now - timedelta(seconds=self.cfg.window_seconds)
        dead: list[str] = []

        for user_id, dq in self._events.items():
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                dead.append(user_id)

        for user_id in dead:
            self._events.pop(user_id, None)

    def allow(self, user_id: str, now: datetime | None = None) -> tuple[bool, str]:
        """
        Check whether this user_id is within the configured velocity limit.

        Returns (allowed: bool, reason_code: str).

        Reason codes:
          CLEARED                   -> request is allowed
          VELOCITY_LIMIT            -> rate limit exceeded in current window
          VELOCITY_CAP_EXCEEDED     -> per-user memory cap exceeded
          VELOCITY_GLOBAL_CAP_EXCEEDED -> global tracked-user cap exceeded
        """
        now = self._validate_now(now or datetime.now(timezone.utc))
        user_id = self._normalize_user_id(user_id)

        with self._lock:
            self._gc(now)

            dq = self._events.get(user_id)
            if dq is None:
                if len(self._events) >= self.cfg.max_tracked_users:
                    _logger.warning(
                        "Velocity tracked-user cap exceeded users=%s",
                        len(self._events),
                    )
                    return (False, "VELOCITY_GLOBAL_CAP_EXCEEDED")
                dq = deque()
                self._events[user_id] = dq

            # Evict events outside the current window.
            cutoff = now - timedelta(seconds=self.cfg.window_seconds)
            while dq and dq[0] < cutoff:
                dq.popleft()

            # Rate limit check (fast path — checked before memory cap).
            if len(dq) >= self.cfg.limit:
                return (False, "VELOCITY_LIMIT")

            # Memory cap check (guards against misconfiguration or extremely
            # long windows causing deque growth beyond expected bounds).
            if len(dq) >= self.cfg.max_entries_per_user:
                _logger.warning(
                    "Velocity per-user cap exceeded user=%s entries=%s",
                    user_id,
                    len(dq),
                )
                return (False, "VELOCITY_CAP_EXCEEDED")

            dq.append(now)
            return (True, "CLEARED")

    def reset_user(self, user_id: str) -> bool:
        """
        Clear all velocity events for a specific user.
        Returns True if the user was tracked, False if not found.
        Useful for tests and manual operator intervention.
        """
        try:
            user_id = self._normalize_user_id(user_id)
        except (TypeError, ValueError):
            return False

        with self._lock:
            if user_id in self._events:
                del self._events[user_id]
                return True
            return False

    def tracked_user_count(self) -> int:
        """Return the current number of tracked users."""
        with self._lock:
            return len(self._events)
