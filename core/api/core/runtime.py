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

"""Sentinel-43 runtime identity and uptime state."""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import settings


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class RuntimeState:
    """Track Sentinel-43 process identity and process-local uptime."""

    node_name: str = settings.node_name

    _pid: int = field(
        default_factory=os.getpid,
        init=False,
        repr=False,
    )

    _instance_id: str = field(
        default_factory=lambda: uuid.uuid4().hex,
        init=False,
        repr=False,
    )

    _start_monotonic: float = field(
        default_factory=time.monotonic,
        init=False,
        repr=False,
    )

    _started_at: datetime = field(
        default_factory=_utc_now,
        init=False,
        repr=False,
    )

    def _refresh_after_fork(self) -> None:
        """Reset process-local identity if this object crossed a fork boundary."""
        current_pid = os.getpid()

        if current_pid == self._pid:
            return

        self._pid = current_pid
        self._instance_id = uuid.uuid4().hex
        self._start_monotonic = time.monotonic()
        self._started_at = _utc_now()

    @property
    def process_id(self) -> str:
        """Return a unique identity for the current OS process."""
        self._refresh_after_fork()
        return f"{self.node_name}:{self._pid}:{self._instance_id}"

    @property
    def pid(self) -> int:
        self._refresh_after_fork()
        return self._pid

    @property
    def started_at(self) -> datetime:
        self._refresh_after_fork()
        return self._started_at

    def uptime_seconds(self) -> float:
        """Return process uptime using the monotonic clock."""
        self._refresh_after_fork()
        return max(0.0, time.monotonic() - self._start_monotonic)

    def uptime_human(self) -> str:
        """Return uptime as HH:MM:SS, allowing hours greater than 24."""
        total_seconds = int(self.uptime_seconds())

        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        return f"{hours:02}:{minutes:02}:{seconds:02}"

    def safe_dict(self) -> dict[str, object]:
        """Return runtime identity suitable for health/status diagnostics."""
        return {
            "node_name": self.node_name,
            "process_id": self.process_id,
            "pid": self.pid,
            "started_at": self.started_at.isoformat(),
            "uptime_seconds": round(self.uptime_seconds(), 3),
        }


runtime_state = RuntimeState()


__all__ = [
    "RuntimeState",
    "runtime_state",
]
