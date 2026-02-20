# =============================================================================
# Sentinel-43 Runtime State Module
# =============================================================================

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Final

from .config import settings


PROCESS_ID: Final[str] = str(uuid.uuid4())


@dataclass(slots=True)
class RuntimeState:
    """
    Tracks current runtime identity and uptime.
    """

    node_name: str = settings.NODE_NAME
    process_id: str = PROCESS_ID
    start_time: float = field(default_factory=time.time)

    def uptime_seconds(self) -> float:
        return time.time() - self.start_time

    def uptime_human(self) -> str:
        seconds = int(self.uptime_seconds())

        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        seconds = seconds % 60

        return f"{hours:02}:{minutes:02}:{seconds:02}"


runtime_state = RuntimeState()


__all__ = [
    "runtime_state",
    "RuntimeState",
]