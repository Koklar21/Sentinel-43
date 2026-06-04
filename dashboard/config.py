"""
Sentinel-43 Dashboard Configuration
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip()


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)

    if value is None or not value.strip():
        return default

    try:
        return int(value)
    except ValueError:
        return default


@dataclass(frozen=True, slots=True)
class DashboardConfig:
    app_name: str
    app_version: str

    api_base_url: str

    websocket_url: str

    refresh_interval_seconds: int

    debug: bool


def load_dashboard_config() -> DashboardConfig:
    return DashboardConfig(
        app_name=_env(
            "SENTINEL_DASHBOARD_NAME",
            "Sentinel-43 Dashboard",
        ),
        app_version=_env(
            "SENTINEL_DASHBOARD_VERSION",
            "0.1.0",
        ),
        api_base_url=_env(
            "SENTINEL_DASHBOARD_API_URL",
            "http://localhost:8000",
        ),
        websocket_url=_env(
            "SENTINEL_DASHBOARD_WS_URL",
            "ws://localhost:8000/ws",
        ),
        refresh_interval_seconds=_env_int(
            "SENTINEL_DASHBOARD_REFRESH_INTERVAL",
            15,
        ),
        debug=_env(
            "SENTINEL_DASHBOARD_DEBUG",
            "false",
        ).lower()
        in {"1", "true", "yes", "on"},
    )


CONFIG = load_dashboard_config()
