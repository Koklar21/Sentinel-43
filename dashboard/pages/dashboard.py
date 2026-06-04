"""
Sentinel-43 Dashboard Page
Dashboard
"""

from __future__ import annotations

from typing import Any

from dashboard.services.health_client import get_health_snapshot
from dashboard.services.watchtower_client import get_watchtower_snapshot
from dashboard.services.remote_gateway_client import (
    get_remote_gateway_snapshot,
)


PAGE_ID = "dashboard"
PAGE_TITLE = "Sentinel-43 Dashboard"


def load_dashboard_page() -> dict[str, Any]:
    """
    Load primary dashboard data.
    """

    health = get_health_snapshot()
    watchtower = get_watchtower_snapshot()
    remote_gateway = get_remote_gateway_snapshot()

    return {
        "page_id": PAGE_ID,
        "page_title": PAGE_TITLE,
        "health": health,
        "watchtower": watchtower,
        "remote_gateway": remote_gateway,
    }


def get_dashboard_summary() -> dict[str, Any]:
    data = load_dashboard_page()

    return {
        "page": PAGE_TITLE,
        "api_online": data["health"].get("ok", False),
        "watchtower_online": data["watchtower"].get("ok", False),
        "remote_gateway_online": data["remote_gateway"].get("ok", False),
    }
