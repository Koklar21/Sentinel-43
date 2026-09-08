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

"""Bounded rolling memory for short-term Sentinel-43 detection context."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final


_MAX_ENTRIES: Final[int] = 1_000_000
_MAX_TTL_SECONDS: Final[float] = 7 * 24 * 3600.0


@dataclass(frozen=True, slots=True)
class MemoryEvent:
    timestamp_monotonic: float
    source: str
    event_type: str
    severity: int
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        source = self.source.strip()
        event_type = self.event_type.strip()

        if not source:
            raise ValueError(
                "source must not be empty"
            )

        if not event_type:
            raise ValueError(
                "event_type must not be empty"
            )

        if self.severity < 0:
            raise ValueError(
                "severity must be >= 0"
            )

        object.__setattr__(
            self,
            "source",
            source,
        )

        object.__setattr__(
            self,
            "event_type",
            event_type,
        )

        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(
                dict(self.metadata)
            ),
        )


class RollingMemory:
    """Thread-safe bounded memory for recent detection events."""

    def __init__(
        self,
        *,
        max_entries: int = 1000,
        ttl_seconds: float = 900.0,
    ) -> None:
        if not 1 <= max_entries <= _MAX_ENTRIES:
            raise ValueError(
                f"max_entries must be between 1 and {_MAX_ENTRIES}"
            )

        if not 0 < ttl_seconds <= _MAX_TTL_SECONDS:
            raise ValueError(
                f"ttl_seconds must be > 0 and <= {_MAX_TTL_SECONDS:g}"
            )

        self._memory: deque[
            MemoryEvent
        ] = deque(
            maxlen=max_entries
        )

        self._ttl_seconds = float(
            ttl_seconds
        )

        self._lock = threading.Lock()

    def add_event(
        self,
        *,
        source: str,
        event_type: str,
        severity: int,
        metadata: Mapping[str, str] | None = None,
    ) -> None:
        event = MemoryEvent(
            timestamp_monotonic=time.monotonic(),
            source=source,
            event_type=event_type,
            severity=int(severity),
            metadata=metadata or {},
        )

        with self._lock:
            self._prune_locked(
                now=time.monotonic()
            )

            self._memory.append(
                event
            )

    def get_recent_events(
        self,
        *,
        since_seconds: float | None = None,
        source: str | None = None,
        event_type: str | None = None,
        min_severity: int | None = None,
    ) -> list[MemoryEvent]:
        if (
            since_seconds is not None
            and since_seconds < 0
        ):
            raise ValueError(
                "since_seconds must be >= 0"
            )

        if (
            min_severity is not None
            and min_severity < 0
        ):
            raise ValueError(
                "min_severity must be >= 0"
            )

        normalized_source = (
            source.strip()
            if source is not None
            else None
        )

        normalized_event_type = (
            event_type.strip()
            if event_type is not None
            else None
        )

        now = time.monotonic()

        cutoff = (
            now - since_seconds
            if since_seconds is not None
            else None
        )

        with self._lock:
            self._prune_locked(
                now=now
            )

            events = tuple(
                self._memory
            )

        return [
            event
            for event in events
            if (
                cutoff is None
                or event.timestamp_monotonic
                >= cutoff
            )
            and (
                normalized_source is None
                or event.source
                == normalized_source
            )
            and (
                normalized_event_type is None
                or event.event_type
                == normalized_event_type
            )
            and (
                min_severity is None
                or event.severity
                >= min_severity
            )
        ]

    def _prune_locked(
        self,
        *,
        now: float,
    ) -> None:
        cutoff = (
            now
            - self._ttl_seconds
        )

        while (
            self._memory
            and self._memory[0].timestamp_monotonic
            < cutoff
        ):
            self._memory.popleft()

    def stats(
        self,
    ) -> dict[str, int | float]:
        with self._lock:
            return {
                "current_entries": len(
                    self._memory
                ),
                "max_entries": (
                    self._memory.maxlen
                    or 0
                ),
                "ttl_seconds": self._ttl_seconds,
            }

    def clear(
        self,
    ) -> None:
        """Discard all rolling-memory state."""
        with self._lock:
            self._memory.clear()


__all__ = [
    "MemoryEvent",
    "RollingMemory",
]
