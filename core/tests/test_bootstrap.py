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
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
# =============================================================================
#
# core/tests/test_bootstrap.py
#
# Live tests for GET /bootstrap/status and POST /bootstrap/admin
# (core/api/routers/bootstrap.py).
#
# These hit a running container over HTTP rather than importing core.api.main
# directly, matching test_system_smoke.py's pattern rather than
# test_auth_login.py's / test_jwt_auth.py's in-process TestClient pattern.
# Reason: bootstrap.py talks to Postgres via core.auth.users, and
# DATABASE_URL in docker-compose.yml points at the "s43-db" hostname, which
# only resolves inside the Docker network — a bare `pytest` on the host has
# no route to it. Hitting the already-running container over HTTP sidesteps
# that entirely, the same way test_system_smoke.py does for other live
# checks.
#
# /bootstrap/admin can only ever succeed once per deployment (it refuses with
# 409 the instant an active admin exists), so the two state-dependent tests
# below establish their own state through the ``fresh_deployment`` and
# ``initialized_deployment`` fixtures, which reset the users table of a
# DISPOSABLE loopback database (S43_LIVE_TEST_DB_DSN). Neither test depends on
# source order and neither skips.
#
# See also test_bootstrap_isolated.py, which covers the same create-admin ->
# login -> protected-route flow against an in-memory fake user store.
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
_BOOTSTRAP_CLAIM_TOKEN = os.getenv("S43_BOOTSTRAP_CLAIM_TOKEN", "")
_BOOTSTRAP_HEADERS = (
    {"X-S43-Bootstrap-Token": _BOOTSTRAP_CLAIM_TOKEN}
    if _BOOTSTRAP_CLAIM_TOKEN
    else {}
)


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
        "running instance (see docker-compose.yml) to run the bootstrap "
        "integration tests"
    ),
)


# --------------------------------------------------------------------------
# Explicit deployment-state fixtures (A: fresh, B: already initialized).
#
# Both states used to be inferred from whatever the live deployment happened to
# contain, so one of the two tests below skipped on every run (a fresh
# deployment skipped the rejection test; an initialized one skipped the
# create-admin test) and their outcome depended on source order. Each test now
# ESTABLISHES the state it needs. That requires resetting the users table of
# the deployment under test, which is destructive, so it is only permitted
# against a loopback disposable database named by S43_LIVE_TEST_DB_DSN
# (scripts/ci_live_tests.py and scripts/acceptance_campaign.py set it). A missing
# or non-disposable DSN FAILS the test -- it never skips and never touches a
# real deployment.
# --------------------------------------------------------------------------
_DISPOSABLE_DB_PREFIXES = ("s43_ci", "s43_accept")


def _reset_users_on_disposable_db() -> None:
    from urllib.parse import urlsplit

    from sqlalchemy import create_engine, text

    dsn = os.getenv("S43_LIVE_TEST_DB_DSN", "")
    if not dsn:
        pytest.fail(
            "S43_LIVE_TEST_DB_DSN is not set: these tests must establish their own "
            "deployment state and need the disposable database's DSN to do so.",
            pytrace=False,
        )
    parts = urlsplit(dsn)
    api_host = urlsplit(API_URL).hostname
    if (
        parts.hostname not in ("127.0.0.1", "localhost")
        or api_host not in ("127.0.0.1", "localhost")
        or not (parts.path.lstrip("/")).startswith(_DISPOSABLE_DB_PREFIXES)
    ):
        pytest.fail(
            "refusing to reset users: the database and API must both be loopback and the "
            f"database name must start with one of {_DISPOSABLE_DB_PREFIXES}",
            pytrace=False,
        )
    engine = create_engine(dsn.replace("+asyncpg", "+psycopg"))
    try:
        with engine.begin() as conn:
            conn.execute(text("TRUNCATE users CASCADE"))
    finally:
        engine.dispose()


@pytest.fixture
def fresh_deployment() -> None:
    """State A: no admin exists."""
    _reset_users_on_disposable_db()
    assert _get_status()["initialized"] is False


@pytest.fixture
def initialized_deployment() -> None:
    """State B: exactly one admin exists, created through the real endpoint."""
    _reset_users_on_disposable_db()
    response = requests.post(
        f"{API_URL}/bootstrap/admin",
        json={"username": f"seed-{uuid.uuid4().hex[:8]}", "password": "a-perfectly-long-enough-password-123"},
        headers=_BOOTSTRAP_HEADERS,
        timeout=5,
    )
    assert response.status_code == 201, (
        f"could not establish the initialized state: {response.status_code} {response.text[:300]}"
    )
    assert _get_status()["initialized"] is True


def _get_status() -> dict:
    response = requests.get(f"{API_URL}/bootstrap/status", timeout=5)
    assert response.status_code == 200, (
        f"/bootstrap/status returned HTTP {response.status_code}: {response.text[:300]}"
    )
    data = response.json()
    assert isinstance(data, dict)
    assert isinstance(data.get("initialized"), bool)
    return data


def test_bootstrap_status_responds() -> None:
    _get_status()


def test_bootstrap_admin_rejects_short_password() -> None:
    """
    Pydantic's min_length=12 on BootstrapAdminRequest.password must reject
    before any DB call is made, regardless of whether the deployment is
    already initialized.
    """
    response = requests.post(
        f"{API_URL}/bootstrap/admin",
        json={"username": f"pwtest-{uuid.uuid4().hex[:8]}", "password": "short"},
        timeout=5,
    )
    assert response.status_code == 422, (
        f"Expected 422 for a too-short password, got {response.status_code}: "
        f"{response.text[:300]}"
    )


def test_bootstrap_admin_rejects_missing_username() -> None:
    response = requests.post(
        f"{API_URL}/bootstrap/admin",
        json={"password": "a-perfectly-long-enough-password"},
        timeout=5,
    )
    assert response.status_code == 422


def test_bootstrap_admin_rejects_when_already_initialized(initialized_deployment) -> None:
    response = requests.post(
        f"{API_URL}/bootstrap/admin",
        json={
            "username": f"should-not-be-created-{uuid.uuid4().hex[:8]}",
            "password": "a-perfectly-long-enough-password",
        },
        headers=_BOOTSTRAP_HEADERS,
        timeout=5,
    )
    assert response.status_code == 409, (
        f"Expected 409 once an admin exists, got {response.status_code}: "
        f"{response.text[:300]}"
    )


def test_first_run_bootstrap_flow_creates_admin(fresh_deployment) -> None:
    """
    Full first-run flow: status reports uninitialized, POST /bootstrap/admin
    succeeds, status flips to initialized, a second POST is refused, and the
    new admin can log in and use the resulting token against a protected
    route.

    The ``fresh_deployment`` fixture establishes the uninitialized state on the
    disposable database first, so this runs regardless of test order.
    """
    username = f"bootstrap-test-{uuid.uuid4().hex[:8]}"
    password = "a-perfectly-long-enough-password-123"

    create_response = requests.post(
        f"{API_URL}/bootstrap/admin",
        json={"username": username, "password": password},
        headers=_BOOTSTRAP_HEADERS,
        timeout=5,
    )
    assert create_response.status_code == 201, (
        f"POST /bootstrap/admin failed: {create_response.status_code} "
        f"{create_response.text[:300]}"
    )
    body = create_response.json()
    assert body["username"] == username
    assert body["role"] == "admin"

    assert _get_status()["initialized"] is True

    second_response = requests.post(
        f"{API_URL}/bootstrap/admin",
        json={"username": f"second-{uuid.uuid4().hex[:8]}", "password": password},
        headers=_BOOTSTRAP_HEADERS,
        timeout=5,
    )
    assert second_response.status_code == 409

    login_response = requests.post(
        f"{API_URL}/auth/login",
        json={"username": username, "password": password},
        headers=_LOGIN_HEADERS,
        timeout=5,
    )
    assert login_response.status_code == 200, (
        f"Login with the newly bootstrapped admin failed: "
        f"{login_response.status_code} {login_response.text[:300]}"
    )
    login_data = login_response.json()
    token = login_data["token"]
    assert login_data["subject"] == username

    verify_response = requests.get(
        f"{API_URL}/auth/verify",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert verify_response.status_code == 200
    assert verify_response.json()["role"] == "admin"

    protected_response = requests.get(
        f"{API_URL}/watchtower/status",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert protected_response.status_code == 200, (
        f"Token from the newly bootstrapped admin was rejected by a "
        f"protected route: {protected_response.status_code} "
        f"{protected_response.text[:300]}"
    )
