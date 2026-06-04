"""
Sentinel-43 Dashboard Component
Activity Feed
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class ActivityEvent:
    timestamp: str
    event_type: str
    message: str
    severity: str = "info"
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
        self.max_events = max_events
        self._events: list[ActivityEvent] = []

    def add_event(
        self,
        *,
        event_type: str,
        message: str,
        severity: str = "info",
        metadata: dict[str, Any] | None = None,
    ) -> ActivityEvent:
        event = ActivityEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            message=message,
            severity=severity,
            metadata=metadata or {},
        )

        self._events.insert(0, event)

        if len(self._events) > self.max_events:
            self._events = self._events[: self.max_events]

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
            "events": [
                {
                    "timestamp": event.timestamp,
                    "event_type": event.event_type,
                    "message": event.message,
                    "severity": event.severity,
                    "metadata": event.metadata,
                }
                for event in self._events
            ],
        }


activity_feed = ActivityFeed()
