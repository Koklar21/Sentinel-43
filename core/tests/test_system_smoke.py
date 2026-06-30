# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
#
# Sentinel-43 is distributed under a dual-license model:
#
# 1. GNU Affero General Public License (AGPL v3.0)
# for open-source use, modification, and distribution.
#
# 2. Commercial License
# for proprietary, enterprise, government, or other commercial use
# not permitted under the AGPL v3.0.
#
# Use, modification, redistribution, and commercial use are governed by
# the terms of the applicable license. Any use outside those terms is
# prohibited.
#
# By accessing, modifying, distributing, or using this software, you agree
# to comply with the terms of the applicable license.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
#
# Commercial Licensing:
# Contact the copyright holder for commercial licensing terms.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

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


def test_watchtower_bridge_reports_reachable() -> None:
    """
    /watchtower/health always returns HTTP 200 even when the Watchtower core
    is completely unreachable — watchtower_health_check() catches the
    connection failure and embeds {"reachable": False, ...} inside a normal
    200 response rather than raising. test_system_smoke_endpoint_responds
    above would pass with Watchtower fully down; this test is the one that
    actually catches that.

    Kept separate from the parametrized smoke test deliberately: "the bridge
    endpoint responds" and "Watchtower itself is healthy" are different
    claims, and collapsing them into one assertion hides which one failed.
    """
    response = requests.get(f"{API_URL}/watchtower/health", timeout=5)
    assert response.status_code == 200
    data = response.json()
    assert data.get("reachable") is True, (
        f"Watchtower bridge responded but reports unreachable: {data}"
    )


# =============================================================================
# Live auth round-trip
#
# Everything above proves the container is UP. It does not prove the
# container's actual deployed env vars are correct — S43_OPERATOR_PASSWORD_HASH,
# S43_JWT_SECRET, etc. test_auth_login.py only proves the Python test
# environment is internally consistent; it never touches the real .env file
# baked into the running Docker container. A typo'd hash there would pass
# every existing test and still lock every operator out in production.
#
# This test is the one thing in the whole suite that can catch that class of
# bug — but it needs real credentials for whatever environment API_URL points
# at, which must never be hardcoded here. Skips cleanly if they're not set,
# so it doesn't break CI for anyone who hasn't configured a live target.
# =============================================================================

_LIVE_USERNAME = os.getenv("S43_LIVE_TEST_USERNAME")
_LIVE_PASSWORD = os.getenv("S43_LIVE_TEST_PASSWORD")

_skip_reason = (
    "S43_LIVE_TEST_USERNAME / S43_LIVE_TEST_PASSWORD not set — "
    "skipping live auth round-trip against the real deployed container. "
    "Set both to verify actual .env credentials, not just the test suite's "
    "own seeded environment."
)


@pytest.mark.skipif(
    not (_LIVE_USERNAME and _LIVE_PASSWORD),
    reason=_skip_reason,
)
def test_live_login_and_protected_route_round_trip() -> None:
    """
    Logs in against the actual running container using real operator
    credentials, then uses the returned token against a protected route.
    This is the live-container equivalent of test_auth_login.py's
    test_protected_route_accepts_valid_token — same assertion, but proving
    the real deployment's config, not the test harness's seeded one.
    """
    login_response = requests.post(
        f"{API_URL}/auth/login",
        json={"username": _LIVE_USERNAME, "password": _LIVE_PASSWORD},
        timeout=5,
    )
    assert login_response.status_code == 200, (
        f"Live login failed against {API_URL} — check S43_OPERATOR_USERNAME / "
        f"S43_OPERATOR_PASSWORD_HASH in the deployed .env: "
        f"{login_response.status_code} {login_response.text[:300]}"
    )

    token = login_response.json().get("token")
    assert token, "Live login returned 200 but no token field"

    verify_response = requests.get(
        f"{API_URL}/auth/verify",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert verify_response.status_code == 200, (
        f"Token from live login was rejected by /auth/verify — check "
        f"S43_JWT_SECRET consistency in the deployed .env: "
        f"{verify_response.status_code} {verify_response.text[:300]}"
    )
    assert verify_response.json().get("valid") is True


@pytest.mark.skipif(
    not (_LIVE_USERNAME and _LIVE_PASSWORD),
    reason=_skip_reason,
)
def test_live_protected_route_rejects_missing_token() -> None:
    """
    Companion to the round-trip test above — confirms the real deployment
    actually enforces auth on a protected route, not just that login works.
    Targets /governance/pending rather than /watchtower/status: the latter
    is not currently gated with _get_operator() in main.py and would pass
    this test for the wrong reason (no auth check at all) rather than the
    right one (valid auth check, correctly rejecting no token).
    """
    response = requests.get(f"{API_URL}/governance/pending", timeout=5)
    assert response.status_code == 401, (
        f"Expected 401 with no token, got {response.status_code} — "
        f"if this is 200, the live deployment is not enforcing auth on "
        f"this route: {response.text[:300]}"
    )
