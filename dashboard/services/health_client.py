"""
Sentinel-43 Dashboard Service
Health Client

Calls API health, readiness, status, metrics, and route endpoints.
"""

from __future__ import annotations

from typing import Any

from dashboard.services.api_client import api_get


def get_api_health() -> dict[str, Any]:
    return api_get("/health")


def get_api_ready() -> dict[str, Any]:
    return api_get("/ready")


def get_api_status() -> dict[str, Any]:
    return api_get("/status")


def get_api_metrics() -> dict[str, Any]:
    return api_get("/metrics")


def get_system_routes() -> dict[str, Any]:
    return api_get("/system/routes")


def get_routes_status() -> dict[str, Any]:
    return api_get("/system/routes/status")


def get_health_snapshot() -> dict[str, Any]:
    """
    Combined health snapshot for dashboard panels.
    """
    health = get_api_health()
    ready = get_api_ready()
    status = get_api_status()
    metrics = get_api_metrics()
    routes = get_system_routes()

    return {
        "ok": all(
            item.get("ok", False)
            for item in [health, ready, status, metrics, routes]
        ),
        "health": health,
        "ready": ready,
        "status": status,
        "metrics": metrics,
        "routes": routes,
    }
