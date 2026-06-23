"""
Sentinel-43 Dashboard Tests
Health Client
"""

from __future__ import annotations

from dashboard.services.health_client import (
    get_api_health,
    get_api_metrics,
    get_api_ready,
    get_api_status,
    get_health_snapshot,
    get_system_routes,
)


def test_get_api_health_returns_dict() -> None:
    result = get_api_health()
    assert isinstance(result, dict)


def test_get_api_ready_returns_dict() -> None:
    result = get_api_ready()
    assert isinstance(result, dict)


def test_get_api_status_returns_dict() -> None:
    result = get_api_status()
    assert isinstance(result, dict)


def test_get_api_metrics_returns_dict() -> None:
    result = get_api_metrics()
    assert isinstance(result, dict)


def test_get_system_routes_returns_dict() -> None:
    result = get_system_routes()
    assert isinstance(result, dict)


def test_get_health_snapshot_returns_dict() -> None:
    result = get_health_snapshot()
    assert isinstance(result, dict)
    # Snapshot wraps output in ApiResponse.to_dict() — health, ready, status,
    # metrics, and routes live inside result["data"], not at the top level.
    data = result.get("data", {})
    assert "health" in data
    assert "ready" in data
    assert "status" in data
    assert "metrics" in data
    assert "routes" in data
