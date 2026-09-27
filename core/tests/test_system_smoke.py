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
import uuid

import pytest
import requests

API_URL = os.getenv("S43_TEST_API_URL", "http://localhost:8000").rstrip("/")

# /auth/login is a state-changing route and enforces Origin/Referer
# validation outside a local environment (core/api/routers/auth.py's
# _check_state_change_origin) so a browser's ambient, cookie-carrying
# cross-origin request can't silently log in as someone else. A plain
# `requests` client sends neither header by default, which the check
# correctly treats as unproven origin, not as "no browser, so exempt" --
# there is no separate bearer-only login path, since logging in is
# precisely the step before a bearer token exists. This self-identifies the
# harness by the address it is actually calling from; the deployment must
# list it in S43_ALLOWED_ORIGINS (scripts/ci_live_tests.py does).
_LOGIN_HEADERS = {"Origin": API_URL}


def _live_target_reachable() -> bool:
    try:
        requests.get(f"{API_URL}/health", timeout=2)
        return True
    except requests.RequestException:
        return False


pytestmark = pytest.mark.skipif(
    not _live_target_reachable(),
    reason=(
        f"no live Sentinel-43 API at {API_URL}; set S43_TEST_API_URL to a "
        "running instance to run the system smoke tests"
    ),
)

SMOKE_ENDPOINTS = [
    "/health",
    "/ready",
    "/status",
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
# container's actual deployed env vars are correct — S43_JWT_SECRET etc.
# test_auth_login.py only proves the Python test environment is internally
# consistent; it never touches the real .env file baked into the running
# container. This is the one thing in the whole suite that can catch that
# class of bug end-to-end against the real deployment.
#
# The env-operator break-glass login has no server-side session and is
# refused outside local (D1/D2) — it is not a route to a credential here.
# The only supported non-local path is a DB-backed human account created
# through the real API and authenticated through the real session/login
# flow, so that is what this file exercises, exactly like
# test_bootstrap.py's fresh_deployment/initialized_deployment fixtures do
# for the bootstrap endpoint itself:
#
#   - Against the disposable CI/acceptance database (S43_LIVE_TEST_DB_DSN
#     set to a loopback, s43_ci-/s43_accept-prefixed DSN): the
#     `_live_session` fixture below resets the users table and claims
#     bootstrap itself, establishing its own account fresh at the point of
#     use — independent of whatever test_bootstrap.py's fixtures did
#     earlier in the same run, and never dependent on file/test order.
#   - Against a real target (S43_LIVE_TEST_USERNAME/PASSWORD naming an
#     already-provisioned human account, no disposable DSN): the fixture
#     logs in with those credentials as-is and never truncates anything.
#   - With neither configured, the credentialed tests skip cleanly, as
#     before.
# =============================================================================

_DISPOSABLE_DB_PREFIXES = ("s43_ci", "s43_accept")


def _disposable_db_dsn() -> str | None:
    from urllib.parse import urlsplit

    dsn = os.getenv("S43_LIVE_TEST_DB_DSN", "")
    if not dsn:
        return None
    parts = urlsplit(dsn)
    api_host = urlsplit(API_URL).hostname
    if (
        parts.hostname not in ("127.0.0.1", "localhost")
        or api_host not in ("127.0.0.1", "localhost")
        or not (parts.path.lstrip("/")).startswith(_DISPOSABLE_DB_PREFIXES)
    ):
        return None
    return dsn


def _reset_users_on_disposable_db(dsn: str) -> None:
    from sqlalchemy import create_engine, text

    engine = create_engine(dsn.replace("+asyncpg", "+psycopg"))
    try:
        with engine.begin() as conn:
            conn.execute(text("TRUNCATE users CASCADE"))
    finally:
        engine.dispose()


def _login(username: str, password: str) -> str:
    response = requests.post(
        f"{API_URL}/auth/login",
        json={"username": username, "password": password},
        headers=_LOGIN_HEADERS,
        timeout=5,
    )
    assert response.status_code == 200, (
        f"Live login failed against {API_URL}: "
        f"{response.status_code} {response.text[:300]}"
    )
    token = response.json().get("token")
    assert token, "Live login returned 200 but no token field"
    return token


_LIVE_USERNAME = os.getenv("S43_LIVE_TEST_USERNAME")
_LIVE_PASSWORD = os.getenv("S43_LIVE_TEST_PASSWORD")

_skip_reason = (
    "Neither a disposable S43_LIVE_TEST_DB_DSN nor S43_LIVE_TEST_USERNAME / "
    "S43_LIVE_TEST_PASSWORD are set — skipping the live auth round-trip. "
    "Set the disposable DSN (CI/acceptance) or real target credentials to "
    "run it."
)


@pytest.fixture
def _live_session() -> str:
    """A live, session-bound Bearer token — never the break-glass path.

    Establishes its own account state at the point of use so it never
    depends on what test_bootstrap.py's fixtures left behind, or on test
    order within this file.
    """
    dsn = _disposable_db_dsn()
    if dsn is not None:
        _reset_users_on_disposable_db(dsn)
        username = f"smoke-{uuid.uuid4().hex[:8]}"
        password = "a-perfectly-long-enough-password-123"
        create_response = requests.post(
            f"{API_URL}/bootstrap/admin",
            json={"username": username, "password": password},
            timeout=5,
        )
        assert create_response.status_code == 201, (
            f"could not establish a live session account: "
            f"{create_response.status_code} {create_response.text[:300]}"
        )
        return _login(username, password)

    if _LIVE_USERNAME and _LIVE_PASSWORD:
        return _login(_LIVE_USERNAME, _LIVE_PASSWORD)

    pytest.skip(_skip_reason)


def test_live_login_and_protected_route_round_trip(_live_session: str) -> None:
    """
    Logs in against the actual running container (via the `_live_session`
    fixture) and uses the returned token against a protected route. This is
    the live-container equivalent of test_auth_login.py's
    test_protected_route_accepts_valid_token — same assertion, but proving
    the real deployment's config, not the test harness's seeded one.
    """
    verify_response = requests.get(
        f"{API_URL}/auth/verify",
        headers={"Authorization": f"Bearer {_live_session}"},
        timeout=5,
    )
    assert verify_response.status_code == 200, (
        f"Token from live login was rejected by /auth/verify — check "
        f"S43_JWT_SECRET consistency in the deployed .env: "
        f"{verify_response.status_code} {verify_response.text[:300]}"
    )
    assert verify_response.json().get("valid") is True


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


def test_live_system_status_and_routes_require_auth(_live_session: str) -> None:
    """
    /system/status and /system/routes are gated with _require_operator() in
    main.py — confirm both reject an unauthenticated request and accept a
    live, session-bound Bearer token (via the `_live_session` fixture, never
    the retired X-S43-Password legacy fallback), and that /system/routes
    returns a well-formed route list once authenticated.
    """
    for endpoint in ("/system/status", "/system/routes"):
        response = requests.get(f"{API_URL}{endpoint}", timeout=5)
        assert response.status_code == 401, (
            f"Expected 401 with no token for {endpoint}, got "
            f"{response.status_code}: {response.text[:300]}"
        )

    headers = {"Authorization": f"Bearer {_live_session}"}

    status_response = requests.get(f"{API_URL}/system/status", headers=headers, timeout=5)
    assert status_response.status_code == 200, (
        f"/system/status rejected a valid operator token: "
        f"{status_response.status_code} {status_response.text[:300]}"
    )

    routes_response = requests.get(f"{API_URL}/system/routes", headers=headers, timeout=5)
    assert routes_response.status_code == 200, (
        f"/system/routes rejected a valid operator token: "
        f"{routes_response.status_code} {routes_response.text[:300]}"
    )
    data = routes_response.json()
    assert isinstance(data, dict)
    routes = data.get("routes")
    assert isinstance(routes, list), "routes field must be a list"
    assert len(routes) > 0, "routes list must not be empty"
    route_count = data.get("route_count")
    assert isinstance(route_count, int), "route_count must be an integer"
    assert route_count > 0, "route_count must be greater than zero"
