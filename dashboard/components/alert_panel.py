"""
Sentinel-43 Dashboard Component
Alert Panel
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class Alert:
    alert_id: str
    title: str
    message: str
    severity: str
    timestamp: str
    acknowledged: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


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
        self.max_alerts = max_alerts
        self._alerts: list[Alert] = []

    def add_alert(
        self,
        *,
        alert_id: str,
        title: str,
        message: str,
        severity: str = "warning",
        metadata: dict[str, Any] | None = None,
    ) -> Alert:
        alert = Alert(
            alert_id=alert_id,
            title=title,
            message=message,
            severity=severity,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {},
        )

        self._alerts.insert(0, alert)

        if len(self._alerts) > self.max_alerts:
            self._alerts = self._alerts[: self.max_alerts]

        return alert

    def acknowledge_alert(self, alert_id: str) -> bool:
        for alert in self._alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                return True
        return False

    def get_alerts(self) -> list[Alert]:
        return list(self._alerts)

    def get_unacknowledged(self) -> list[Alert]:
        return [
            alert
            for alert in self._alerts
            if not alert.acknowledged
        ]

    def clear(self) -> None:
        self._alerts.clear()

    def count(self) -> int:
        return len(self._alerts)

    def unacknowledged_count(self) -> int:
        return len(self.get_unacknowledged())

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_alerts": len(self._alerts),
            "unacknowledged": self.unacknowledged_count(),
            "alerts": [
                {
                    "alert_id": alert.alert_id,
                    "title": alert.title,
                    "message": alert.message,
                    "severity": alert.severity,
                    "timestamp": alert.timestamp,
                    "acknowledged": alert.acknowledged,
                    "metadata": alert.metadata,
                }
                for alert in self._alerts
            ],
        }


alert_panel = AlertPanel()
