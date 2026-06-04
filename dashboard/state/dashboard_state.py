"""
Sentinel-43 Dashboard State
Dashboard State
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class DashboardState:
    initialized: bool = False
    loading: bool = False
    error: str | None = None

    api_online: bool = False
    watchtower_online: bool = False
    remote_gateway_online: bool = False

    active_page: str = "dashboard"

    metadata: dict[str, Any] = field(default_factory=dict)

    def set_initialized(self, value: bool) -> None:
        self.initialized = value

    def set_loading(self, value: bool) -> None:
        self.loading = value

    def set_error(self, error: str | None) -> None:
        self.error = error

    def set_active_page(self, page: str) -> None:
        self.active_page = page

    def update_status(
        self,
        *,
        api_online: bool | None = None,
        watchtower_online: bool | None = None,
        remote_gateway_online: bool | None = None,
    ) -> None:
        if api_online is not None:
            self.api_online = api_online

        if watchtower_online is not None:
            self.watchtower_online = watchtower_online

        if remote_gateway_online is not None:
            self.remote_gateway_online = remote_gateway_online

    def clear(self) -> None:
        self.initialized = False
        self.loading = False
        self.error = None

        self.api_online = False
        self.watchtower_online = False
        self.remote_gateway_online = False

        self.active_page = "dashboard"
        self.metadata.clear()

    def to_dict(self) -> dict[str, Any]:
        return {
            "initialized": self.initialized,
            "loading": self.loading,
            "error": self.error,
            "api_online": self.api_online,
            "watchtower_online": self.watchtower_online,
            "remote_gateway_online": self.remote_gateway_online,
            "active_page": self.active_page,
            "metadata": self.metadata,
        }


dashboard_state = DashboardState()
