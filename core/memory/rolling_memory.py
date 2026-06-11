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

import time
import threading
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional


@dataclass(frozen=True)
class MemoryEvent:
    timestamp: float
    source: str
    event_type: str
    severity: int
    metadata: Dict[str, str]


class RollingMemory:
    """
    Bounded, time-windowed rolling memory for detection systems.

    Purpose:
      - Preserve short-term behavioral context
      - Enable pattern-based escalation
      - Prevent single-event false positives
    """

    def __init__(
        self,
        *,
        max_entries: int = 1000,
        ttl_seconds: int = 900,  # 15 minutes
    ):
        self._memory: Deque[MemoryEvent] = deque(maxlen=max_entries)
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    # ----------------------------
    # Core Operations
    # ----------------------------

    def add_event(
        self,
        *,
        source: str,
        event_type: str,
        severity: int,
        metadata: Optional[Dict[str, str]] = None,
    ) -> None:
        event = MemoryEvent(
            timestamp=time.time(),
            source=source,
            event_type=event_type,
            severity=severity,
            metadata=metadata or {},
        )

        with self._lock:
            self._memory.append(event)
            self._prune_locked()

    def get_recent_events(
        self,
        *,
        since_seconds: Optional[int] = None,
        source: Optional[str] = None,
        event_type: Optional[str] = None,
        min_severity: Optional[int] = None,
    ) -> List[MemoryEvent]:
        now = time.time()
        cutoff = now - since_seconds if since_seconds else None

        with self._lock:
            self._prune_locked()
            events = list(self._memory)

        filtered: List[MemoryEvent] = []

        for e in events:
            if cutoff and e.timestamp < cutoff:
                continue
            if source and e.source != source:
                continue
            if event_type and e.event_type != event_type:
                continue
            if min_severity and e.severity < min_severity:
                continue
            filtered.append(e)

        return filtered

    # ----------------------------
    # Internal Maintenance
    # ----------------------------

    def _prune_locked(self) -> None:
        """Remove expired entries based on TTL."""
        cutoff = time.time() - self._ttl
        while self._memory and self._memory[0].timestamp < cutoff:
            self._memory.popleft()

    # ----------------------------
    # Introspection (Safe)
    # ----------------------------

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "current_entries": len(self._memory),
                "max_entries": self._memory.maxlen or 0,
                "ttl_seconds": self._ttl,
            }
