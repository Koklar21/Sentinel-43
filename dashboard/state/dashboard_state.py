"""
dashboard/state/dashboard_state.py

Dashboard-wide state management for Sentinel-43.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(slots=True)
class DashboardState:
    """
    Stores global dashboard state.
    """

    system_status: str = "UNKNOWN"
    api_status: str = "UNKNOWN"
    watchtower_status: str = "UNKNOWN"
    remote_gateway_status: str = "UNKNOWN"

    active_alerts: int = 0
    active_nodes: int = 0

    health_data: dict[str, Any] = field(default_factory=dict)

    last_updated: datetime | None = None
    error: str | None = None

    def update(
        self,
        *,
        system_status: str | None = None,
        api_status: str | None = None,
        watchtower_status: str | None = None,
        remote_gateway_status: str | None = None,
        active_alerts: int | None = None,
        active_nodes: int | None = None,
        health_data: dict[str, Any] | None = None,
    ) -> None:
        """
        Update dashboard state.
        """

        if system_status is not None:
            self.system_status = system_status

        if api_status is not None:
            self.api_status = api_status

        if watchtower_status is not None:
            self.watchtower_status = watchtower_status

        if remote_gateway_status is not None:
            self.remote_gateway_status = remote_gateway_status

        if active_alerts is not None:
            self.active_alerts = active_alerts

        if active_nodes is not None:
            self.active_nodes = active_nodes

        if health_data is not None:
            self.health_data = health_data

        self.last_updated = datetime.now(UTC)
        self.error = None

    def set_error(
        self,
        message: str,
    ) -> None:
        """
        Record dashboard error state.
        """

        self.error = message
        self.last_updated = datetime.now(UTC)

    def clear(self) -> None:
        """
        Reset dashboard state.
        """

        self.system_status = "UNKNOWN"
        self.api_status = "UNKNOWN"
        self.watchtower_status = "UNKNOWN"
        self.remote_gateway_status = "UNKNOWN"

        self.active_alerts = 0
        self.active_nodes = 0

        self.health_data.clear()

        self.last_updated = None
        self.error = None

    @property
    def is_healthy(self) -> bool:
        """
        Quick dashboard health check.
        """

        statuses = {
            self.api_status.upper(),
            self.watchtower_status.upper(),
            self.remote_gateway_status.upper(),
        }

        unhealthy = {
            "FAILED",
            "OFFLINE",
            "ERROR",
            "CRITICAL",
        }

        return not bool(statuses & unhealthy)


dashboard_state = DashboardState()
