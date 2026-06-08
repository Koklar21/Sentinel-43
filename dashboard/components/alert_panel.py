"""
Sentinel-43 Dashboard Component
Alert Panel
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Deque


VALID_SEVERITIES = frozenset({"critical", "high", "warning", "info"})


@dataclass(frozen=True, slots=True)
class Alert:
    alert_id: str
    title: str
    message: str
    severity: str
    timestamp: datetime
    acknowledged: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def acknowledge(self) -> Alert:
        if self.acknowledged:
            return self

        return replace(self, acknowledged=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "message": self.message,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "acknowledged": self.acknowledged,
            "metadata": dict(self.metadata),
        }


class AlertPanel:
    """
    Centralized dashboard alert manager.

    Handles:
    - Watchtower alerts
    - Remote Gateway alerts
    - Dependency failures
    - System warnings
    - Security notifications
    """

    def __init__(self, max_alerts: int = 500) -> None:
        if max_alerts <= 0:
            raise ValueError("max_alerts must be greater than 0")

        self.max_alerts = max_alerts
        self._alerts: Deque[Alert] = deque(maxlen=max_alerts)
        self._alert_ids: set[str] = set()

    def add_alert(
        self,
        *,
        alert_id: str,
        title: str,
        message: str,
        severity: str = "warning",
        metadata: dict[str, Any] | None = None,
    ) -> Alert:
        severity = severity.lower().strip()

        if severity not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity!r}")

        if alert_id in self._alert_ids:
            raise ValueError(f"Duplicate alert_id: {alert_id!r}")

        if len(self._alerts) == self.max_alerts:
            oldest = self._alerts[-1]
            self._alert_ids.discard(oldest.alert_id)

        alert = Alert(
            alert_id=alert_id,
            title=title,
            message=message,
            severity=severity,
            timestamp=datetime.now(timezone.utc),
            metadata=dict(metadata) if metadata else {},
        )

        self._alerts.appendleft(alert)
        self._alert_ids.add(alert_id)

        return alert

    def acknowledge_alert(self, alert_id: str) -> bool:
        for index, alert in enumerate(self._alerts):
            if alert.alert_id == alert_id:
                if alert.acknowledged:
                    return True

                self._alerts[index] = alert.acknowledge()
                return True

        return False

    def get_alerts(self) -> list[Alert]:
        return [
            replace(alert, metadata=dict(alert.metadata))
            for alert in self._alerts
        ]

    def get_unacknowledged(self) -> list[Alert]:
        return [
            replace(alert, metadata=dict(alert.metadata))
            for alert in self._alerts
            if not alert.acknowledged
        ]

    def clear(self, *, reason: str | None = None) -> None:
        if reason is not None and not reason.strip():
            raise ValueError("clear reason cannot be blank")

        self._alerts.clear()
        self._alert_ids.clear()

    def count(self) -> int:
        return len(self._alerts)

    def unacknowledged_count(self) -> int:
        return sum(1 for alert in self._alerts if not alert.acknowledged)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_alerts": len(self._alerts),
            "unacknowledged": self.unacknowledged_count(),
            "alerts": [
                alert.to_dict()
                for alert in self._alerts
            ],
        }
