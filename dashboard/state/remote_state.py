"""
Sentinel-43 Dashboard State
Remote State
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class RemoteState:
    gateway_health: dict[str, Any] = field(default_factory=dict)
    targets: list[dict[str, Any]] = field(default_factory=list)

    selected_target: str | None = None
    selected_event: str | None = None

    last_operation: dict[str, Any] = field(default_factory=dict)

    loading: bool = False
    error: str | None = None

    def set_gateway_health(self, value: dict[str, Any]) -> None:
        self.gateway_health = value

    def set_targets(self, value: list[dict[str, Any]]) -> None:
        self.targets = value

    def set_selected_target(self, target_id: str | None) -> None:
        self.selected_target = target_id

    def set_selected_event(self, event_name: str | None) -> None:
        self.selected_event = event_name

    def set_last_operation(self, operation: dict[str, Any]) -> None:
        self.last_operation = operation

    def set_loading(self, value: bool) -> None:
        self.loading = value

    def set_error(self, error: str | None) -> None:
        self.error = error

    def clear(self) -> None:
        self.gateway_health.clear()
        self.targets.clear()

        self.selected_target = None
        self.selected_event = None

        self.last_operation.clear()

        self.loading = False
        self.error = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "gateway_health": self.gateway_health,
            "targets": self.targets,
            "selected_target": self.selected_target,
            "selected_event": self.selected_event,
            "last_operation": self.last_operation,
            "loading": self.loading,
            "error": self.error,
            "target_count": len(self.targets),
        }


remote_state = RemoteState()
