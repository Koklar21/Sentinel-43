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
# Because /bootstrap/admin can only ever succeed once per deployment (it
# refuses with 409 the instant an active admin exists), the "actually
# create an admin" test only runs when the live target reports
# initialized=false. On a deployment that already completed setup, that one
# test is skipped, but status/validation coverage still runs — this mirrors
# how test_system_smoke.py's live-auth tests skip without live credentials
# rather than failing the whole run.
#
# See also test_bootstrap_isolated.py: once a deployment is initialized,
# the "creates the first admin" test below skips permanently on that
# deployment (there's nothing left to bootstrap). test_bootstrap_isolated.py
# covers the same create-admin -> login -> protected-route flow against an
# in-memory fake user store instead of the live DB, so that path keeps
# getting exercised on every test run regardless of this deployment's state.
# =============================================================================

from __future__ import annotations

import os
import uuid

import pytest
import requests

API_URL = os.getenv("S43_TEST_API_URL", "http://localhost:8000").rstrip("/")


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


def test_bootstrap_admin_rejects_when_already_initialized() -> None:
    if not _get_status()["initialized"]:
        pytest.skip(
            "Deployment is not initialized yet — the "
            "test_first_run_bootstrap_flow_creates_admin test below covers "
            "this deployment instead."
        )

    response = requests.post(
        f"{API_URL}/bootstrap/admin",
        json={
            "username": f"should-not-be-created-{uuid.uuid4().hex[:8]}",
            "password": "a-perfectly-long-enough-password",
        },
        timeout=5,
    )
    assert response.status_code == 409, (
        f"Expected 409 once an admin exists, got {response.status_code}: "
        f"{response.text[:300]}"
    )


def test_first_run_bootstrap_flow_creates_admin() -> None:
    """
    Full first-run flow: status reports uninitialized, POST /bootstrap/admin
    succeeds, status flips to initialized, a second POST is refused, and the
    new admin can log in and use the resulting token against a protected
    route.

    Only runs against a fresh (uninitialized) deployment — it is the only
    test in this file that mutates state, and it can only ever do so once
    per deployment by design.
    """
    if _get_status()["initialized"]:
        pytest.skip("Deployment already has an active admin — nothing left to bootstrap.")

    username = f"bootstrap-test-{uuid.uuid4().hex[:8]}"
    password = "a-perfectly-long-enough-password-123"

    create_response = requests.post(
        f"{API_URL}/bootstrap/admin",
        json={"username": username, "password": password},
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
        timeout=5,
    )
    assert second_response.status_code == 409

    login_response = requests.post(
        f"{API_URL}/auth/login",
        json={"username": username, "password": password},
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
        headers={"Authorization": f"Bearer {token}", "X-S43-Password": password},
        timeout=5,
    )
    assert protected_response.status_code == 200, (
        f"Token from the newly bootstrapped admin was rejected by a "
        f"protected route: {protected_response.status_code} "
        f"{protected_response.text[:300]}"
    )
