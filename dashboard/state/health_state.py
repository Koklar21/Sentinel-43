"""
Sentinel-43 Dashboard State
Health State
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class HealthState:
    api_health: dict[str, Any] = field(default_factory=dict)
    ready_status: dict[str, Any] = field(default_factory=dict)
    system_status: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)

    loading: bool = False
    error: str | None = None

    def set_api_health(self, value: dict[str, Any]) -> None:
        self.api_health = value

    def set_ready_status(self, value: dict[str, Any]) -> None:
        self.ready_status = value

    def set_system_status(self, value: dict[str, Any]) -> None:
        self.system_status = value

    def set_metrics(self, value: dict[str, Any]) -> None:
        self.metrics = value

    def set_loading(self, value: bool) -> None:
        self.loading = value

    def set_error(self, error: str | None) -> None:
        self.error = error

    def clear(self) -> None:
        self.api_health.clear()
        self.ready_status.clear()
        self.system_status.clear()
        self.metrics.clear()

        self.loading = False
        self.error = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "api_health": self.api_health,
            "ready_status": self.ready_status,
            "system_status": self.system_status,
            "metrics": self.metrics,
            "loading": self.loading,
            "error": self.error,
        }


health_state = HealthState()
