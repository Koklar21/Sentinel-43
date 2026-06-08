"""
Sentinel-43 Dashboard Component
Activity Feed
"""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

ActivitySeverity = Literal["info", "warning", "error"]

VALID_SEVERITIES: set[str] = {"info", "warning", "error"}


@dataclass(frozen=True, slots=True)
class ActivityEvent:
    timestamp: str
    event_type: str
    message: str
    severity: ActivitySeverity = "info"
    metadata: dict[str, Any] = field(default_factory=dict)


class ActivityFeed:
    """
    Dashboard activity feed.

    Displays:
    - Remote Gateway events
    - Watchtower notifications
    - Audit events
    - Node state changes
    """

    def __init__(self, max_events: int = 100) -> None:
        if max_events <= 0:
            raise ValueError("max_events must be greater than zero")

        self.max_events = max_events
        self._events: deque[ActivityEvent] = deque(maxlen=max_events)

    def add_event(
        self,
        *,
        event_type: str,
        message: str,
        severity: ActivitySeverity = "info",
        metadata: dict[str, Any] | None = None,
    ) -> ActivityEvent:
        if severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid activity severity '{severity}'. "
                f"Expected one of: {', '.join(sorted(VALID_SEVERITIES))}"
            )

        event = ActivityEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            message=message,
            severity=severity,
            metadata=dict(metadata or {}),
        )

        self._events.appendleft(event)

        return event

    def get_events(self) -> list[ActivityEvent]:
        return list(self._events)

    def clear(self) -> None:
        self._events.clear()

    def count(self) -> int:
        return len(self._events)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_count": len(self._events),
            "events": [asdict(event) for event in self._events],
        }


def create_activity_feed(max_events: int = 100) -> ActivityFeed:
    return ActivityFeed(max_events=max_events)
