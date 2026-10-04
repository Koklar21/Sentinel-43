# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is distributed under a dual-license model:
#   1. GNU Affero General Public License (AGPL v3.0)
#   2. Commercial License
# =============================================================================
#
# core/tests/test_login_throttle.py
#
# Pass 3 — per-username brute-force throttle on POST /auth/login.
# Uses the env-var operator credential path (no DB).
# =============================================================================

from __future__ import annotations

import os
from typing import Generator

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from core.auth.users import hash_password

USERNAME = "throttle-operator"
PASSWORD = "correct-throttle-password-123"
PW_HASH = hash_password(PASSWORD)

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_JWT_SECRET", "test-secret-for-login-throttle-0123456789")
os.environ.setdefault("S43_JWT_ALGORITHM", "HS256")

import core.api.routers.auth as auth_module  # noqa: E402
from core.api.main import app  # noqa: E402

LOGIN_URL = "/auth/login"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("SENTINEL_ENV", "test")
    monkeypatch.setenv("S43_JWT_SECRET", "test-secret-for-login-throttle-0123456789")
    monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("S43_OPERATOR_USERNAME", USERNAME)
    monkeypatch.setenv("S43_OPERATOR_PASSWORD_HASH", PW_HASH)
    monkeypatch.setenv("S43_LOGIN_MAX_FAILURES", "5")
    monkeypatch.setenv("S43_LOGIN_FAIL_WINDOW_SECONDS", "300")
    monkeypatch.setenv("S43_LOGIN_LOCKOUT_SECONDS", "300")
    # fresh throttle state each test
    with auth_module._LOGIN_LOCK:
        auth_module._LOGIN_FAILURES.clear()
    yield
    with auth_module._LOGIN_LOCK:
        auth_module._LOGIN_FAILURES.clear()


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as c:
        yield c


def _login(client, username=USERNAME, password="wrong"):
    return client.post(LOGIN_URL, json={"username": username, "password": password})


def test_wrong_password_eventually_locks_out(client):
    for i in range(5):
        assert _login(client).status_code == 401, i
    r = _login(client)
    assert r.status_code == 429
    # Retry-After counts down from the 300s lockout; allow for the ~1s the
    # preceding requests took.
    assert 295 <= int(r.headers["Retry-After"]) <= 300


def test_lockout_is_per_username(client):
    for _ in range(5):
        _login(client, username="victim-a")
    assert _login(client, username="victim-a").status_code == 429
    # a different username is unaffected
    assert _login(client, username="victim-b").status_code == 401


def test_account_wide_lockout_survives_source_ip_rotation():
    """Rotating source IPs must not reset the username-wide failure budget."""
    for index in range(5):
        auth_module._login_record_failure(
            USERNAME,
            f"198.51.100.{index + 1}",
        )

    with pytest.raises(HTTPException) as exc_info:
        auth_module._login_check_throttled(
            USERNAME,
            "203.0.113.250",
        )

    exc = exc_info.value
    assert getattr(exc, "status_code", None) == 429


def test_successful_login_clears_the_counter(client):
    for _ in range(4):
        assert _login(client).status_code == 401
    # 4 failures, not locked yet -> a correct login succeeds and resets
    ok = _login(client, password=PASSWORD)
    assert ok.status_code == 200
    # counter cleared: 4 more failures still don't lock
    for _ in range(4):
        assert _login(client).status_code == 401
    # correct login still works
    assert _login(client, password=PASSWORD).status_code == 200


def test_throttle_key_is_case_and_whitespace_insensitive(client):
    for _ in range(5):
        _login(client, username="  Mixed-Case-User ")
    assert _login(client, username="mixed-case-user").status_code == 429


def test_lockout_blocks_before_credential_check(client, monkeypatch):
    """Once locked, the 429 must come out without spending an Argon2/SHA
    verify — i.e. _validate_credentials is not reached."""
    calls = {"n": 0}
    real = auth_module._validate_credentials

    async def counting(*a, **k):
        calls["n"] += 1
        return await real(*a, **k)

    monkeypatch.setattr(auth_module, "_validate_credentials", counting)
    for _ in range(5):
        _login(client)
    assert calls["n"] == 5
    assert _login(client).status_code == 429
    assert calls["n"] == 5   # not incremented


__all__: list[str] = []
