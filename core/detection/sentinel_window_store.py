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

"""Thread-safe rolling event/payload window storage for Sentinel-43.

Responsibilities:
    - retain recent events by (identity, IP)
    - bound memory by time, count, and optional key capacity
    - retain bounded payload samples
    - expose pure lookup/statistics primitives

No scoring, policy, governance, or enforcement belongs here.
"""

from __future__ import annotations

import ipaddress
import math
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from threading import RLock
from typing import Final

from .sentinel_threat_detector import EventContext, SequenceWindow


_MAX_WINDOW_SECONDS: Final[float] = 86_400.0
_MAX_EVENTS_PER_KEY: Final[int] = 100_000
_MAX_PAYLOADS_PER_KEY: Final[int] = 10_000
_MAX_PAYLOAD_SIZE_BYTES: Final[int] = 10 * 1024 * 1024
_MAX_KEYS: Final[int] = 1_000_000


@dataclass(frozen=True, slots=True)
class SentinelWindowConfig:
    window_seconds: float = 60.0
    max_events_per_key: int = 200
    max_payloads: int = 50

    max_payload_size_bytes: int = 1 * 1024 * 1024
    clock_skew_seconds: float = 60.0
    reject_out_of_order: bool = True

    # 0 = unlimited. Prefer an explicit positive cap in long-running services.
    max_keys_hint: int = 0

    def __post_init__(self) -> None:
        if not 0 < self.window_seconds <= _MAX_WINDOW_SECONDS:
            raise ValueError(
                f"window_seconds must be > 0 and <= {_MAX_WINDOW_SECONDS:g}"
            )

        if not 1 <= self.max_events_per_key <= _MAX_EVENTS_PER_KEY:
            raise ValueError(
                f"max_events_per_key must be between 1 and {_MAX_EVENTS_PER_KEY}"
            )

        if not 0 <= self.max_payloads <= _MAX_PAYLOADS_PER_KEY:
            raise ValueError(
                f"max_payloads must be between 0 and {_MAX_PAYLOADS_PER_KEY}"
            )

        if not 1 <= self.max_payload_size_bytes <= _MAX_PAYLOAD_SIZE_BYTES:
            raise ValueError(
                "max_payload_size_bytes must be between 1 and 10 MiB"
            )

        if self.clock_skew_seconds < 0:
            raise ValueError(
                "clock_skew_seconds must be >= 0"
            )

        if not 0 <= self.max_keys_hint <= _MAX_KEYS:
            raise ValueError(
                f"max_keys_hint must be between 0 and {_MAX_KEYS}"
            )


class SentinelWindowStore:
    """Bounded rolling event/payload store keyed by normalized identity/IP."""

    def __init__(
        self,
        cfg: SentinelWindowConfig | None = None,
    ) -> None:
        self.cfg = cfg or SentinelWindowConfig()
        self._lock = RLock()

        self._events: OrderedDict[
            tuple[str, str],
            deque[EventContext],
        ] = OrderedDict()

        self._payloads: dict[
            tuple[str, str],
            deque[tuple[float, bytes]],
        ] = {}

        self._total_events_count = 0
        self._total_payloads_count = 0

        self._stats: dict[str, int] = {
            "events_added": 0,
            "events_dropped_expired": 0,
            "events_dropped_out_of_order": 0,
            "events_dropped_overflow": 0,
            "payloads_dropped_overflow": 0,
            "payloads_dropped_expired": 0,
            "keys_removed_empty": 0,
            "keys_evicted_lru": 0,
            "payloads_rejected_too_large": 0,
            "events_rejected_bad_timestamp": 0,
        }

    def add_event(
        self,
        event: EventContext,
    ) -> None:
        """Store one event if it is valid and still inside the rolling window."""
        now = time.time()

        identity = _normalize_identity(
            event.source_identity
        )

        source_ip = _normalize_ip(
            event.source_ip
        )

        timestamp = float(
            event.timestamp
        )

        if not math.isfinite(
            timestamp
        ):
            with self._lock:
                self._stats[
                    "events_rejected_bad_timestamp"
                ] += 1

            raise ValueError(
                "event timestamp must be finite"
            )

        if (
            timestamp
            > now
            + self.cfg.clock_skew_seconds
        ):
            with self._lock:
                self._stats[
                    "events_rejected_bad_timestamp"
                ] += 1

            raise ValueError(
                "event timestamp is too far in the future"
            )

        if (
            timestamp
            < now
            - self.cfg.window_seconds
        ):
            with self._lock:
                self._stats[
                    "events_dropped_expired"
                ] += 1

            return

        key = (
            identity,
            source_ip,
        )

        with self._lock:
            is_new_key = (
                key
                not in self._events
            )

            if (
                self.cfg.max_keys_hint
                and is_new_key
                and len(self._events)
                >= self.cfg.max_keys_hint
            ):
                evicted_key, event_queue = (
                    self._events.popitem(
                        last=False
                    )
                )

                self._total_events_count -= len(
                    event_queue
                )

                payload_queue = self._payloads.pop(
                    evicted_key,
                    None,
                )

                if payload_queue is not None:
                    self._total_payloads_count -= len(
                        payload_queue
                    )

                self._stats[
                    "keys_evicted_lru"
                ] += 1

            events_queue = self._events.get(
                key
            )

            if events_queue is None:
                events_queue = deque()
                self._events[
                    key
                ] = events_queue
            else:
                self._events.move_to_end(
                    key
                )

            if (
                self.cfg.reject_out_of_order
                and events_queue
                and timestamp
                < events_queue[-1].timestamp
            ):
                self._stats[
                    "events_dropped_out_of_order"
                ] += 1
                return

            events_queue.append(
                event
            )

            self._stats[
                "events_added"
            ] += 1
            self._total_events_count += 1

            while (
                len(events_queue)
                > self.cfg.max_events_per_key
            ):
                events_queue.popleft()
                self._total_events_count -= 1
                self._stats[
                    "events_dropped_overflow"
                ] += 1

            payload = event.payload

            if payload is not None:
                if not isinstance(
                    payload,
                    (bytes, bytearray),
                ):
                    raise ValueError(
                        "event payload must be bytes, bytearray, or None"
                    )

                if (
                    len(payload)
                    > self.cfg.max_payload_size_bytes
                ):
                    self._stats[
                        "payloads_rejected_too_large"
                    ] += 1

                elif self.cfg.max_payloads > 0:
                    payload_queue = self._payloads.get(
                        key
                    )

                    if payload_queue is None:
                        payload_queue = deque()
                        self._payloads[
                            key
                        ] = payload_queue

                    payload_queue.append(
                        (
                            timestamp,
                            bytes(
                                payload
                            ),
                        )
                    )

                    self._total_payloads_count += 1

                    while (
                        len(payload_queue)
                        > self.cfg.max_payloads
                    ):
                        payload_queue.popleft()
                        self._total_payloads_count -= 1
                        self._stats[
                            "payloads_dropped_overflow"
                        ] += 1

            self._prune_locked(
                key,
                now=now,
            )

    def build_window(
        self,
        identity: str,
        ip: str,
    ) -> SequenceWindow:
        """Return a detached SequenceWindow snapshot for one key."""
        key = (
            _normalize_identity(
                identity
            ),
            _normalize_ip(
                ip
            ),
        )

        with self._lock:
            self._prune_locked(
                key,
                now=time.time(),
            )

            event_queue = self._events.get(
                key
            )

            if event_queue is not None:
                self._events.move_to_end(
                    key
                )

            window = SequenceWindow(
                max_events=self.cfg.max_events_per_key
            )

            if event_queue:
                window.extend(
                    event_queue
                )

            return window

    def recent_payloads(
        self,
        identity: str,
        ip: str,
    ) -> list[bytes]:
        """Return recent retained payload samples for one key."""
        key = (
            _normalize_identity(
                identity
            ),
            _normalize_ip(
                ip
            ),
        )

        with self._lock:
            self._prune_locked(
                key,
                now=time.time(),
            )

            if key in self._events:
                self._events.move_to_end(
                    key
                )

            payload_queue = self._payloads.get(
                key
            )

            if not payload_queue:
                return []

            return [
                payload
                for _timestamp, payload
                in payload_queue
            ]

    def events_in_interval(
        self,
        identity: str,
        ip: str,
        interval_seconds: float,
    ) -> int:
        """Count recent events for one key without making a detection decision."""
        if interval_seconds <= 0:
            raise ValueError(
                "interval_seconds must be > 0"
            )

        key = (
            _normalize_identity(
                identity
            ),
            _normalize_ip(
                ip
            ),
        )

        now = time.time()
        cutoff = (
            now
            - interval_seconds
        )

        with self._lock:
            self._prune_locked(
                key,
                now=now,
            )

            event_queue = self._events.get(
                key
            )

            if not event_queue:
                return 0

            self._events.move_to_end(
                key
            )

            if self.cfg.reject_out_of_order:
                count = 0

                for event in reversed(
                    event_queue
                ):
                    if event.timestamp < cutoff:
                        break

                    count += 1

                return count

            return sum(
                1
                for event in event_queue
                if event.timestamp >= cutoff
            )

    def active_keys(
        self,
    ) -> list[tuple[str, str]]:
        """Return a snapshot of currently tracked keys."""
        with self._lock:
            return list(
                self._events.keys()
            )

    def get_stats(
        self,
    ) -> dict[str, int]:
        """Return O(1) operational counters and current bounded-state sizes."""
        with self._lock:
            return {
                **self._stats,
                "total_keys": len(
                    self._events
                ),
                "total_events": self._total_events_count,
                "total_payload_keys": len(
                    self._payloads
                ),
                "total_payloads": self._total_payloads_count,
            }

    def periodic_cleanup(
        self,
    ) -> None:
        """Prune expired state for keys that have gone idle."""
        now = time.time()

        with self._lock:
            for key in list(
                self._events.keys()
            ):
                self._prune_locked(
                    key,
                    now=now,
                )

            # A payload-only key should be impossible after normal pruning, but
            # scan defensively so corrupted or legacy state cannot linger.
            for key in list(
                self._payloads.keys()
            ):
                if key not in self._events:
                    self._prune_locked(
                        key,
                        now=now,
                    )

    def cleanup(
        self,
    ) -> None:
        """Discard all in-memory rolling-window state."""
        with self._lock:
            self._events.clear()
            self._payloads.clear()
            self._total_events_count = 0
            self._total_payloads_count = 0

    def _prune_locked(
        self,
        key: tuple[str, str],
        *,
        now: float,
    ) -> None:
        cutoff = (
            now
            - self.cfg.window_seconds
        )

        event_queue = self._events.get(
            key
        )

        if event_queue is not None:
            if self.cfg.reject_out_of_order:
                while (
                    event_queue
                    and event_queue[0].timestamp
                    < cutoff
                ):
                    event_queue.popleft()
                    self._total_events_count -= 1
                    self._stats[
                        "events_dropped_expired"
                    ] += 1

            elif event_queue:
                before = len(
                    event_queue
                )

                filtered = deque(
                    event
                    for event in event_queue
                    if event.timestamp >= cutoff
                )

                removed = (
                    before
                    - len(filtered)
                )

                if removed:
                    self._events[
                        key
                    ] = filtered

                    event_queue = filtered

                    self._total_events_count -= (
                        removed
                    )

                    self._stats[
                        "events_dropped_expired"
                    ] += removed

            if not event_queue:
                self._events.pop(
                    key,
                    None,
                )

                self._stats[
                    "keys_removed_empty"
                ] += 1

        payload_queue = self._payloads.get(
            key
        )

        if payload_queue is not None:
            if self.cfg.reject_out_of_order:
                while (
                    payload_queue
                    and payload_queue[0][0]
                    < cutoff
                ):
                    payload_queue.popleft()
                    self._total_payloads_count -= 1
                    self._stats[
                        "payloads_dropped_expired"
                    ] += 1

            elif payload_queue:
                before = len(
                    payload_queue
                )

                filtered_payloads = deque(
                    item
                    for item in payload_queue
                    if item[0] >= cutoff
                )

                removed = (
                    before
                    - len(filtered_payloads)
                )

                if removed:
                    self._payloads[
                        key
                    ] = filtered_payloads

                    payload_queue = filtered_payloads

                    self._total_payloads_count -= (
                        removed
                    )

                    self._stats[
                        "payloads_dropped_expired"
                    ] += removed

            if not payload_queue:
                self._payloads.pop(
                    key,
                    None,
                )


def _normalize_identity(
    identity: str,
) -> str:
    value = str(
        identity
        or ""
    ).strip()

    if not value:
        raise ValueError(
            "identity must be a non-empty string"
        )

    return value


def _normalize_ip(
    ip: str,
) -> str:
    value = str(
        ip
        or ""
    ).strip()

    try:
        return str(
            ipaddress.ip_address(
                value
            )
        )
    except ValueError as exc:
        raise ValueError(
            f"ip is not a valid IP address: {value!r}"
        ) from exc


__all__ = [
    "SentinelWindowConfig",
    "SentinelWindowStore",
]
