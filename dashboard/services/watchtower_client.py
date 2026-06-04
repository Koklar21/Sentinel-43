"""
Sentinel-43 Dashboard Service
Watchtower Client

Provides dashboard access to Watchtower endpoints.
"""

from __future__ import annotations

from typing import Any

from dashboard.services.api_client import api_get


def get_watchtower_health() -> dict[str, Any]:
    return api_get("/watchtower/health")


def get_watchtower_status() -> dict[str, Any]:
    return api_get("/watchtower/status")


def get_watchtower_nodes() -> dict[str, Any]:
    return api_get("/watchtower/nodes")


def get_watchtower_alerts() -> dict[str, Any]:
    return api_get("/watchtower/alerts")


def get_watchtower_metrics() -> dict[str, Any]:
    return api_get("/watchtower/metrics")


def get_watchtower_snapshot() -> dict[str, Any]:
    health = get_watchtower_health()
    status = get_watchtower_status()
    nodes = get_watchtower_nodes()
    alerts = get_watchtower_alerts()

    return {
        "ok": (
            health.get("ok", False)
            and status.get("ok", False)
        ),
        "health": health,
        "status": status,
        "nodes": nodes,
        "alerts": alerts,
    }
