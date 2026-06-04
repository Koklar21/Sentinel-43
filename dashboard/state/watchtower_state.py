"""
Sentinel-43 Dashboard State
Watchtower State
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class WatchtowerState:
    health: dict[str, Any] = field(default_factory=dict)
    status: dict[str, Any] = field(default_factory=dict)

    nodes: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)

    loading: bool = False
    error: str | None = None

    def set_health(self, value: dict[str, Any]) -> None:
        self.health = value

    def set_status(self, value: dict[str, Any]) -> None:
        self.status = value

    def set_nodes(self, value: list[dict[str, Any]]) -> None:
        self.nodes = value

    def set_alerts(self, value: list[dict[str, Any]]) -> None:
        self.alerts = value

    def set_loading(self, value: bool) -> None:
        self.loading = value

    def set_error(self, error: str | None) -> None:
        self.error = error

    def clear(self) -> None:
        self.health.clear()
        self.status.clear()

        self.nodes.clear()
        self.alerts.clear()

        self.loading = False
        self.error = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "health": self.health,
            "status": self.status,
            "nodes": self.nodes,
            "alerts": self.alerts,
            "loading": self.loading,
            "error": self.error,
            "node_count": len(self.nodes),
            "alert_count": len(self.alerts),
        }


watchtower_state = WatchtowerState()
