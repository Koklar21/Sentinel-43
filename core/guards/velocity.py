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
# 1. GNU Affero General Public License (AGPL v3.0)
# for open-source use, modification, and distribution.
#
# 2. Commercial License
# for proprietary, enterprise, government, or other commercial use
# not permitted under the AGPL v3.0.
#
# Use, modification, redistribution, and commercial use are governed by
# the terms of the applicable license. Any use outside those terms is
# prohibited.
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
    window_seconds: int = 60
    limit: int = 10
    gc_interval_seconds: int = 300
    max_entries_per_user: int = 1000
    max_user_id_length: int = 128
    max_tracked_users: int = 10000


class VelocityGuard:
    """
    DoS/memory-hardened velocity guard.

    - Sliding window per user
    - Periodic GC of old timestamps
    - Hard cap per user to prevent memory exhaustion
    - Global tracked-user cap
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

        # Strip control chars to reduce log injection / junk IDs
        user_id = "".join(ch for ch in user_id if ch.isprintable() and ch not in "\r\n\t")
        if not user_id:
            raise ValueError("user_id became empty after normalization.")
        return user_id

    def _gc(self, now: datetime) -> None:
        # Recover from backward clock movement or test skew
        if now < self._last_gc:
            self._last_gc = now

        if (now - self._last_gc).total_seconds() < self.cfg.gc_interval_seconds:
            return

        # Set at start to avoid redundant immediate reruns after a long sweep
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
        Returns (allowed, reason_code).
        """
        now = self._validate_now(now or datetime.now(timezone.utc))
        user_id = self._normalize_user_id(user_id)

        with self._lock:
            self._gc(now)

            dq = self._events.get(user_id)
            if dq is None:
                if len(self._events) >= self.cfg.max_tracked_users:
                    _logger.warning("Velocity tracked-user cap exceeded users=%s", len(self._events))
                    return (False, "VELOCITY_GLOBAL_CAP_EXCEEDED")
                dq = deque()
                self._events[user_id] = dq

            cutoff = now - timedelta(seconds=self.cfg.window_seconds)
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= self.cfg.limit:
                return (False, "VELOCITY_LIMIT")

            if len(dq) >= self.cfg.max_entries_per_user:
                _logger.warning(
                    "Velocity per-user cap exceeded user=%s entries=%s",
                    user_id,
                    len(dq),
                )
                return (False, "VELOCITY_CAP_EXCEEDED")

            dq.append(now)
            return (True, "CLEARED")
