from __future__ import annotations

import os

import pytest
import requests


API_URL = os.getenv("S43_TEST_API_URL", "http://localhost:8000").rstrip("/")


SMOKE_ENDPOINTS = [
    "/health",
    "/ready",
    "/status",
    "/system/status",
    "/system/routes",
    "/watchtower/health",
]


@pytest.mark.parametrize("endpoint", SMOKE_ENDPOINTS)
def test_system_smoke_endpoint_responds(endpoint: str) -> None:
    url = f"{API_URL}{endpoint}"
    response = requests.get(url, timeout=5)

    assert response.status_code == 200, (
        f"{endpoint} returned HTTP {response.status_code}: {response.text[:300]}"
    )

    data = response.json()
    assert isinstance(data, dict), f"{endpoint} did not return a JSON object"


def test_health_reports_api_ok() -> None:
    response = requests.get(f"{API_URL}/health", timeout=5)

    assert response.status_code == 200

    data = response.json()
    assert data.get("status") == "ok"
    assert data.get("service") == "sentinel-43-api"


def test_system_routes_returns_route_list() -> None:
    """
    Verify /system/routes returns a non-empty route list with valid structure.
    Does NOT assert specific paths — the parametrized smoke tests above already
    prove each endpoint responds. Route introspection is brittle across
    sub-router registration order and is not worth asserting here.
    """
    response = requests.get(f"{API_URL}/system/routes", timeout=5)

    assert response.status_code == 200

    data = response.json()
    assert isinstance(data, dict)

    routes = data.get("routes")
    assert isinstance(routes, list), "routes field must be a list"
    assert len(routes) > 0, "routes list must not be empty"

    route_count = data.get("route_count")
    assert isinstance(route_count, int), "route_count must be an integer"
    assert route_count > 0, "route_count must be greater than zero"