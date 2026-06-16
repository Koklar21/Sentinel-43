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

import math
import time
from collections import deque
from dataclasses import dataclass
from threading import RLock
from typing import Deque, Dict, List, Optional, Tuple

from sentinel_43_ai.detection.sentinel_threat_detector import EventContext, SequenceWindow



@dataclass(frozen=True)
class SentinelWindowConfig:
    window_seconds: float = 60.0
    max_events_per_key: int = 200
    max_payloads: int = 50

    # Hardening knobs
    max_payload_size_bytes: int = 1 * 1024 * 1024  # 1MB
    clock_skew_seconds: float = 60.0              # allow small future skew
    reject_out_of_order: bool = True              # safest + fastest
    max_keys_hint: int = 0                        # 0 = no hard cap (optional)

    def __post_init__(self) -> None:
        if not (self.window_seconds > 0):
            raise ValueError("window_seconds must be > 0")
        if not (self.max_events_per_key > 0):
            raise ValueError("max_events_per_key must be > 0")
        if not (self.max_payloads >= 0):
            raise ValueError("max_payloads must be >= 0")
        if not (self.max_payload_size_bytes > 0):
            raise ValueError("max_payload_size_bytes must be > 0")
        if not (self.clock_skew_seconds >= 0):
            raise ValueError("clock_skew_seconds must be >= 0")
        if not (self.max_keys_hint >= 0):
            raise ValueError("max_keys_hint must be >= 0")

        # sanity ceilings (prevents absurd configs)
        if self.window_seconds > 86400:
            raise ValueError("window_seconds too large (max 86400)")
        if self.max_events_per_key > 100_000:
            raise ValueError("max_events_per_key too large (max 100000)")
        if self.max_payloads > 10_000:
            raise ValueError("max_payloads too large (max 10000)")
        if self.max_payload_size_bytes > 10 * 1024 * 1024:
            raise ValueError("max_payload_size_bytes too large (max 10MB)")


class SentinelWindowStore:
    """
    Thread-safe rolling window store for events per (identity, ip).

    Single responsibility:
    - store recent events + payloads
    - prune by time/count
    No scoring, no policy, no decisions.
    """

    def __init__(self, cfg: Optional[SentinelWindowConfig] = None) -> None:
        self.cfg = cfg or SentinelWindowConfig()
        self._lock = RLock()

        self._events: Dict[Tuple[str, str], Deque[EventContext]] = {}
        self._payloads: Dict[Tuple[str, str], Deque[bytes]] = {}

        self._stats = {
            "events_added": 0,
            "events_dropped_expired": 0,
            "events_dropped_out_of_order": 0,
            "events_dropped_overflow": 0,
            "payloads_dropped_overflow": 0,
            "keys_removed_empty": 0,
            "payloads_rejected_too_large": 0,
            "events_rejected_bad_timestamp": 0,
        }

    # ------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------

    def add_event(self, event: EventContext) -> None:
        now = time.time()

        # Validate identity/IP (cheap guardrails)
        identity = getattr(event, "source_identity", None)
        ip = getattr(event, "source_ip", None)
        if not identity or not ip:
            raise ValueError("EventContext requires source_identity and source_ip")

        # Validate timestamp
        ts = getattr(event, "timestamp", None)
        if not isinstance(ts, (int, float)) or not math.isfinite(ts):
            self._stats["events_rejected_bad_timestamp"] += 1
            raise ValueError("Event timestamp must be a finite number")

        # If it's way in the future, reject (prevents never-prune abuse)
        if ts > now + self.cfg.clock_skew_seconds:
            self._stats["events_rejected_bad_timestamp"] += 1
            raise ValueError("Event timestamp is too far in the future")

        # If already expired, drop silently (don’t store trash)
        if ts < now - self.cfg.window_seconds:
            self._stats["events_dropped_expired"] += 1
            return

        key = (identity, ip)

        with self._lock:
            # Optional safety valve (soft cap). If you want hard behavior, enforce here.
            if self.cfg.max_keys_hint and key not in self._events and len(self._events) >= self.cfg.max_keys_hint:
                # Refuse to create new keys when above hint cap. Keeps box alive under abuse.
                self._stats["events_dropped_overflow"] += 1
                return

            events_q = self._events.get(key)
            if events_q is None:
                events_q = deque()
                self._events[key] = events_q

            # Out-of-order handling
            if self.cfg.reject_out_of_order and events_q and ts < events_q[-1].timestamp:
                self._stats["events_dropped_out_of_order"] += 1
                return

            # Store event
            events_q.append(event)
            self._stats["events_added"] += 1

            # Enforce per-key event bound
            while len(events_q) > self.cfg.max_events_per_key:
                events_q.popleft()
                self._stats["events_dropped_overflow"] += 1

            # Store payloads (bounded by count + size)
            payload = getattr(event, "payload", None)
            if payload:
                if not isinstance(payload, (bytes, bytearray)):
                    # If payload isn't bytes, ignore it rather than exploding
                    # (You can be stricter if you prefer)
                    payload = None
                else:
                    if len(payload) > self.cfg.max_payload_size_bytes:
                        self._stats["payloads_rejected_too_large"] += 1
                        # Reject storing payload; still keep the event
                        payload = None

                if payload is not None and self.cfg.max_payloads > 0:
                    payload_q = self._payloads.get(key)
                    if payload_q is None:
                        payload_q = deque()
                        self._payloads[key] = payload_q

                    payload_q.append(bytes(payload))
                    while len(payload_q) > self.cfg.max_payloads:
                        payload_q.popleft()
                        self._stats["payloads_dropped_overflow"] += 1

            # Prune after insert
            self._prune_locked(key, now=now)

    # ------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------

    def build_window(self, identity: str, ip: str) -> SequenceWindow:
        key = (identity, ip)
        with self._lock:
            self._prune_locked(key, now=time.time())
            q = self._events.get(key)
            window = SequenceWindow()
            if q:
                for ev in q:
                    window.add_event(ev)
            return window

    def recent_payloads(self, identity: str, ip: str) -> List[bytes]:
        key = (identity, ip)
        with self._lock:
            self._prune_locked(key, now=time.time())
            q = self._payloads.get(key)
            return list(q) if q else []

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            # Add quick inventory counts
            return {
                **self._stats,
                "total_keys": len(self._events),
                "total_events": sum(len(q) for q in self._events.values()),
                "total_payload_keys": len(self._payloads),
                "total_payloads": sum(len(q) for q in self._payloads.values()),
            }

    def cleanup(self) -> None:
        with self._lock:
            self._events.clear()
            self._payloads.clear()

    def __enter__(self) -> "SentinelWindowStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.cleanup()
        return False

    # ------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------

    def _prune_locked(self, key: Tuple[str, str], *, now: float) -> None:
        q = self._events.get(key)
        if not q:
            # Don’t accidentally create keys just by pruning
            return

        cutoff = now - self.cfg.window_seconds

        # Fast path: monotonic queue
        while q and q[0].timestamp < cutoff:
            q.popleft()

        # If we allow out-of-order, we must occasionally clean mid-queue junk.
        if not self.cfg.reject_out_of_order and q:
            # O(n) filter, but only when needed
            if any(ev.timestamp < cutoff for ev in q):
                filtered = deque(ev for ev in q if ev.timestamp >= cutoff)
                self._events[key] = filtered
                q = filtered

        # Remove empty keys to stop dict growth
        if not q:
            del self._events[key]
            self._payloads.pop(key, None)
            self._stats["keys_removed_empty"] += 1
