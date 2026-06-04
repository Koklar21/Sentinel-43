"""
dashboard/config.py

Configuration management for Sentinel-43 Dashboard.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str) -> str:
    """
    Read environment variable with fallback.
    """
    return os.getenv(name, default)


def _env_int(name: str, default: int) -> int:
    """
    Read integer environment variable with fallback.
    """
    value = os.getenv(name)

    if value is None:
        return default

    try:
        return int(value)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    """
    Read boolean environment variable.
    """
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


@dataclass(frozen=True, slots=True)
class DashboardConfig:
    """
    Dashboard configuration.
    """

    app_name: str
    debug: bool

    host: str
    port: int

    api_base_url: str
    websocket_url: str

    refresh_interval_seconds: int

    title: str


CONFIG = DashboardConfig(
    app_name=_env(
        "SENTINEL_DASHBOARD_NAME",
        "Sentinel-43 Dashboard",
    ),
    debug=_env_bool(
        "DASH_DEBUG",
        False,
    ),
    host=_env(
        "DASH_HOST",
        "0.0.0.0",
    ),
    port=_env_int(
        "DASH_PORT",
        8050,
    ),
    api_base_url=_env(
        "SENTINEL_API_URL",
        "http://localhost:8000",
    ),
    websocket_url=_env(
        "SENTINEL_WS_URL",
        "ws://localhost:8000/ws",
    ),
    refresh_interval_seconds=_env_int(
        "SENTINEL_REFRESH_INTERVAL",
        15,
    ),
    title=_env(
        "SENTINEL_DASHBOARD_TITLE",
        "Sentinel-43 Dashboard",
    ),
)
