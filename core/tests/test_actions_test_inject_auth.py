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
# core/tests/test_actions_test_inject_auth.py
#
# POST /actions/test-inject was gated only by SENTINEL_ENV (must be
# dev/local/test) and S43_ENABLE_TEST_INJECTION — both of which must fail
# closed in production per bootstrap_expectations() — but had no operator
# auth check at all. Within a dev/test deployment with the flag on, any
# unauthenticated caller could inject a synthetic action (see finding #2 in
# docs/security/endpoint_access_matrix.md). The route now also requires
# _require_operator() once the env/flag gate passes. This file proves both
# halves: the route stays 403 when disabled regardless of auth, and once
# enabled it behaves like every other OPERATOR route (401 missing token, 403
# bad role, 200 with a valid operator).
#
# SENTINEL_ENV and S43_ENABLE_TEST_INJECTION are read into module-level
# constants in core.api.main at import time (see main.py's SENTINEL_ENV /
# TEST_INJECTION_ENABLED), not re-read per request — unlike S43_JWT_SECRET
# etc., which verify_jwt_token() reads fresh from the environment on every
# call. Setting the env vars here would only take effect if this file were
# the first to import core.api.main in the pytest process, which isn't
# guaranteed under a full-suite run. So this file monkeypatches the
# already-imported module's constants directly instead of relying on
# environment variables, the same way test_bootstrap_isolated.py patches
# bootstrap_module's imported functions rather than the environment.
# =============================================================================

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Generator

import jwt
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_ENV", "test")
os.environ.setdefault("S43_JWT_SECRET", "test-secret-for-test-inject-auth-tests")
os.environ.setdefault("S43_JWT_ALGORITHM", "HS256")

import core.api.main as main_module  # noqa: E402
import core.api.routers.auth as auth_module  # noqa: E402
from core.api.main import app  # noqa: E402

INJECT_URL = "/actions/test-inject"

JWT_SECRET = "test-secret-for-test-inject-auth-tests"
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "sentinel-43-test"
JWT_AUDIENCE = "sentinel-43-dashboard-test"
TEST_PASSWORD = "test-inject-boundary-password"


async def _fake_reverify_password(username: str, password: str) -> bool:
    return bool(username) and password == TEST_PASSWORD


@pytest.fixture(autouse=True)
def inject_env(monkeypatch) -> None:
    monkeypatch.setenv("S43_JWT_SECRET", JWT_SECRET)
    monkeypatch.setenv("S43_JWT_ALGORITHM", JWT_ALGORITHM)
    monkeypatch.setenv("S43_JWT_ISSUER", JWT_ISSUER)
    monkeypatch.setenv("S43_JWT_AUDIENCE", JWT_AUDIENCE)
    monkeypatch.setattr(auth_module, "reverify_password", _fake_reverify_password)


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client


def _build_token(*, role: str | None = "operator", subject: str = "inject-test-operator") -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()) - 5,
        "exp": int(now.timestamp()) + 3600,
    }
    if role is not None:
        payload["role"] = role
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _bearer(token: str, password: str | None = None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    if password is not None:
        headers["X-S43-Password"] = password
    return headers


def test_disabled_in_production_regardless_of_auth(client: TestClient, monkeypatch):
    """Even a valid operator token must not bypass the env/flag gate."""
    monkeypatch.setattr(main_module, "SENTINEL_ENV", "production")
    monkeypatch.setattr(main_module, "TEST_INJECTION_ENABLED", True)

    response = client.post(
        INJECT_URL,
        headers=_bearer(_build_token(), TEST_PASSWORD),
    )

    assert response.status_code == 403


def test_disabled_when_flag_off_even_in_dev(client: TestClient, monkeypatch):
    monkeypatch.setattr(main_module, "SENTINEL_ENV", "test")
    monkeypatch.setattr(main_module, "TEST_INJECTION_ENABLED", False)

    response = client.post(
        INJECT_URL,
        headers=_bearer(_build_token(), TEST_PASSWORD),
    )

    assert response.status_code == 403


def test_enabled_rejects_missing_auth(client: TestClient, monkeypatch):
    monkeypatch.setattr(main_module, "SENTINEL_ENV", "test")
    monkeypatch.setattr(main_module, "TEST_INJECTION_ENABLED", True)

    response = client.post(INJECT_URL)

    assert response.status_code == 401


def test_enabled_rejects_valid_token_without_password(client: TestClient, monkeypatch):
    monkeypatch.setattr(main_module, "SENTINEL_ENV", "test")
    monkeypatch.setattr(main_module, "TEST_INJECTION_ENABLED", True)

    response = client.post(INJECT_URL, headers=_bearer(_build_token()))

    assert response.status_code == 401


def test_enabled_rejects_unapproved_role(client: TestClient, monkeypatch):
    monkeypatch.setattr(main_module, "SENTINEL_ENV", "test")
    monkeypatch.setattr(main_module, "TEST_INJECTION_ENABLED", True)

    response = client.post(
        INJECT_URL,
        headers=_bearer(_build_token(role="guest"), TEST_PASSWORD),
    )

    assert response.status_code == 403


def test_enabled_accepts_valid_operator(client: TestClient, monkeypatch):
    monkeypatch.setattr(main_module, "SENTINEL_ENV", "test")
    monkeypatch.setattr(main_module, "TEST_INJECTION_ENABLED", True)

    response = client.post(
        INJECT_URL,
        headers=_bearer(_build_token(), TEST_PASSWORD),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True
    assert "action" in body


__all__: list[str] = []
