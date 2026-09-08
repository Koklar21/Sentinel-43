# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Process-local sliding-window velocity guard for Sentinel-43.

This guard is intentionally simple:
    - one bounded timestamp deque per normalized user id
    - one global tracked-user cap
    - periodic stale-user cleanup
    - no autonomous action beyond allow/deny

It is process-local and therefore suitable only while Sentinel-43 remains
single-worker. Multi-worker deployment requires shared rate-limit state.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Final


logger = logging.getLogger("sentinel43.velocity")


_MAX_WINDOW_SECONDS: Final[float] = 86_400.0
_MAX_LIMIT: Final[int] = 1_000_000
_MAX_USER_ID_LENGTH: Final[int] = 512
_MAX_TRACKED_USERS: Final[int] = 1_000_000


class VelocityReason(str, Enum):
    CLEARED = "CLEARED"
    VELOCITY_LIMIT = "VELOCITY_LIMIT"
    VELOCITY_GLOBAL_CAP_EXCEEDED = "VELOCITY_GLOBAL_CAP_EXCEEDED"


@dataclass(frozen=True, slots=True)
class VelocityConfig:
    window_seconds: float = 60.0
    limit: int = 10
    gc_interval_seconds: float = 300.0
    max_user_id_length: int = 128
    max_tracked_users: int = 10_000

    def __post_init__(self) -> None:
        if not 0 < self.window_seconds <= _MAX_WINDOW_SECONDS:
            raise ValueError(
                f"window_seconds must be > 0 and <= {_MAX_WINDOW_SECONDS:g}"
            )

        if not 1 <= self.limit <= _MAX_LIMIT:
            raise ValueError(
                f"limit must be between 1 and {_MAX_LIMIT}"
            )

        if not 0 < self.gc_interval_seconds <= _MAX_WINDOW_SECONDS:
            raise ValueError(
                f"gc_interval_seconds must be > 0 and <= {_MAX_WINDOW_SECONDS:g}"
            )

        if not 1 <= self.max_user_id_length <= _MAX_USER_ID_LENGTH:
            raise ValueError(
                f"max_user_id_length must be between 1 and {_MAX_USER_ID_LENGTH}"
            )

        if not 1 <= self.max_tracked_users <= _MAX_TRACKED_USERS:
            raise ValueError(
                f"max_tracked_users must be between 1 and {_MAX_TRACKED_USERS}"
            )


class VelocityGuard:
    """Thread-safe, process-local sliding-window rate limiter."""

    def __init__(
        self,
        cfg: VelocityConfig | None = None,
    ) -> None:
        self.cfg = cfg or VelocityConfig()
        self._lock = threading.Lock()

        self._last_gc_monotonic = time.monotonic()

        self._events: dict[
            str,
            deque[float],
        ] = {}

    def _normalize_user_id(
        self,
        user_id: str,
    ) -> str:
        if not isinstance(
            user_id,
            str,
        ):
            raise TypeError(
                "user_id must be a string"
            )

        normalized = "".join(
            char
            for char in user_id.strip()
            if char.isprintable()
        )

        if not normalized:
            raise ValueError(
                "user_id must not be empty"
            )

        if len(normalized) > self.cfg.max_user_id_length:
            raise ValueError(
                "user_id exceeds maximum allowed length"
            )

        return normalized

    def _gc_locked(
        self,
        now_monotonic: float,
    ) -> None:
        if (
            now_monotonic
            - self._last_gc_monotonic
            < self.cfg.gc_interval_seconds
        ):
            return

        self._last_gc_monotonic = (
            now_monotonic
        )

        cutoff = (
            now_monotonic
            - self.cfg.window_seconds
        )

        dead_users: list[str] = []

        for user_id, events in self._events.items():
            while (
                events
                and events[0] <= cutoff
            ):
                events.popleft()

            if not events:
                dead_users.append(
                    user_id
                )

        for user_id in dead_users:
            self._events.pop(
                user_id,
                None,
            )

    def allow(
        self,
        user_id: str,
    ) -> tuple[bool, str]:
        """Return whether one event is allowed for ``user_id``."""
        normalized_user_id = (
            self._normalize_user_id(
                user_id
            )
        )

        now = time.monotonic()

        with self._lock:
            self._gc_locked(
                now
            )

            events = self._events.get(
                normalized_user_id
            )

            if events is None:
                if (
                    len(self._events)
                    >= self.cfg.max_tracked_users
                ):
                    logger.warning(
                        "Velocity tracked-user capacity reached: users=%s",
                        len(self._events),
                    )

                    return (
                        False,
                        VelocityReason.VELOCITY_GLOBAL_CAP_EXCEEDED.value,
                    )

                events = deque(
                    maxlen=self.cfg.limit
                )

                self._events[
                    normalized_user_id
                ] = events

            cutoff = (
                now
                - self.cfg.window_seconds
            )

            while (
                events
                and events[0] <= cutoff
            ):
                events.popleft()

            if len(events) >= self.cfg.limit:
                return (
                    False,
                    VelocityReason.VELOCITY_LIMIT.value,
                )

            events.append(
                now
            )

            return (
                True,
                VelocityReason.CLEARED.value,
            )

    def reset_user(
        self,
        user_id: str,
    ) -> bool:
        """Clear tracked velocity state for one user."""
        try:
            normalized_user_id = (
                self._normalize_user_id(
                    user_id
                )
            )
        except (
            TypeError,
            ValueError,
        ):
            return False

        with self._lock:
            return (
                self._events.pop(
                    normalized_user_id,
                    None,
                )
                is not None
            )

    def tracked_user_count(
        self,
    ) -> int:
        with self._lock:
            return len(
                self._events
            )

    def cleanup(
        self,
    ) -> None:
        """Discard all process-local velocity state."""
        with self._lock:
            self._events.clear()
            self._last_gc_monotonic = (
                time.monotonic()
            )


__all__ = [
    "VelocityConfig",
    "VelocityGuard",
    "VelocityReason",
]
