"""
dashboard/services/watchtower_client.py

Watchtower-specific service wrapper for Sentinel-43 Dashboard.
"""

from __future__ import annotations

from typing import Any

from dashboard.services.api_client import api_client


DEFAULT_TOWERS: list[dict[str, Any]] = [
    {"name": "API_HEALTH", "status": "UNKNOWN"},
    {"name": "EXPECTATION_GUARD", "status": "UNKNOWN"},
    {"name": "CONFIG_DRIFT", "status": "UNKNOWN"},
    {"name": "LOGGING_AUDIT", "status": "UNKNOWN"},
    {"name": "ERROR_RATE", "status": "UNKNOWN"},
    {"name": "DEPENDENCY_HEALTH", "status": "UNKNOWN"},
    {"name": "RESOURCE_PRESSURE", "status": "UNKNOWN"},
    {"name": "SECURITY_BASELINE", "status": "UNKNOWN"},
]


def fetch_watchtower_status() -> dict[str, Any]:
    """
    Fetch Watchtower status from the Sentinel-43 API.
    """
    return api_client.get_watchtower_status()


def normalize_watchtower_status(response: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize Watchtower API response into dashboard-ready status data.
    """

    if not response or response.get("success") is False:
        return {
            "overall_status": "UNKNOWN",
            "tower_count": len(DEFAULT_TOWERS),
            "degraded_towers": 0,
            "active_alerts": 0,
            "towers": DEFAULT_TOWERS,
        }

    towers = response.get("towers")

    if not isinstance(towers, list):
        towers = response.get("items")

    if not isinstance(towers, list):
        towers = DEFAULT_TOWERS

    degraded_count = sum(
        1
        for tower in towers
        if str(tower.get("status", "")).upper() in {"DEGRADED", "FAILED", "OFFLINE"}
    )

    return {
        "overall_status": response.get("overall_status")
        or response.get("status")
        or "UNKNOWN",
        "tower_count": response.get("tower_count") or len(towers),
        "degraded_towers": response.get("degraded_towers") or degraded_count,
        "active_alerts": response.get("active_alerts") or response.get("alerts") or 0,
        "towers": towers,
    }


def get_watchtower_dashboard_status() -> dict[str, Any]:
    """
    Fetch and normalize Watchtower status for dashboard display.
    """

    response = fetch_watchtower_status()
    return normalize_watchtower_status(response)
