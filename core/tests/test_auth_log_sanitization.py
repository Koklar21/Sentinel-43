# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_auth_log_sanitization.py
#
# PR #257 blocker 2: the DB-error paths in _validate_credentials(),
# reverify_password(), and _env_operator_allowed() used to log the raw
# exception object (which for a real DB driver can carry the DSN, host, or
# other connection detail) and, in two of the three, the submitted username.
# These tests force each path's DB-error branch with a fake sessionmaker
# whose failure message and target username are distinctive sentinel
# values, then assert neither sentinel -- nor the literal word "Bearer",
# nor anything resembling a password -- ever reaches the log records.
#
# Deliberately independent of Postgres: the sessionmaker itself is faked,
# so these run in the isolated suite (no S43_TEST_PG_DSN needed). The
# adversarial "genuinely unreachable Postgres" versions of the same
# scenario live in test_break_glass_pg.py, against a real dropped
# connection, for the class of DSN-shaped exception text a driver can
# actually produce.
# =============================================================================

from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Response

from core.api.routers import auth as auth_router
from core.api.routers.auth import LoginRequest

SENTINEL_USERNAME = "sentinel-attacker-username-zzYYxx99"
SENTINEL_PASSWORD = "sentinel-attacker-password-should-not-log-qq11"
SENTINEL_DSN_FRAGMENT = "sekret-dsn-fragment-should-never-log-77qq"


class _RaisingSession:
    async def __aenter__(self):
        raise RuntimeError(
            f"connection failed: postgresql://s43:{SENTINEL_DSN_FRAGMENT}@dbhost:5432/s43"
        )

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _raising_sessionmaker():
    return _RaisingSession()


def _get_raising_sessionmaker():
    return _raising_sessionmaker


def _run(coro):
    return asyncio.run(coro)


def _assert_no_sensitive_leak(caplog):
    full_log_text = "\n".join(rec.message for rec in caplog.records)
    assert SENTINEL_USERNAME not in full_log_text
    assert SENTINEL_PASSWORD not in full_log_text
    assert SENTINEL_DSN_FRAGMENT not in full_log_text
    assert "Bearer" not in full_log_text
    return full_log_text


def test_validate_credentials_db_error_logs_no_username_or_exception_text(monkeypatch, caplog):
    monkeypatch.setattr("core.auth.users.get_sessionmaker", _get_raising_sessionmaker)
    monkeypatch.delenv("S43_BREAK_GLASS_ARMED", raising=False)

    with caplog.at_level(logging.ERROR):
        with pytest.raises(HTTPException) as exc_info:
            _run(auth_router._validate_credentials(SENTINEL_USERNAME, SENTINEL_PASSWORD))

    assert exc_info.value.status_code == 503
    full_log_text = _assert_no_sensitive_leak(caplog)
    # The operation identifier IS expected -- sanitizing must not mean going
    # silent. Losing the identifier while chasing zero leakage is the
    # opposite failure mode this pass also guards against.
    assert "auth.validate_credentials" in full_log_text
    assert "RuntimeError" in full_log_text


def test_reverify_password_db_error_logs_no_username_or_exception_text(monkeypatch, caplog):
    monkeypatch.setattr("core.auth.users.get_sessionmaker", _get_raising_sessionmaker)
    monkeypatch.delenv("S43_BREAK_GLASS_ARMED", raising=False)

    with caplog.at_level(logging.ERROR):
        with pytest.raises(HTTPException) as exc_info:
            _run(auth_router.reverify_password(SENTINEL_USERNAME, SENTINEL_PASSWORD))

    assert exc_info.value.status_code == 503
    full_log_text = _assert_no_sensitive_leak(caplog)
    assert "auth.reverify_password" in full_log_text
    assert "RuntimeError" in full_log_text


def test_env_operator_allowed_db_error_logs_no_exception_text(monkeypatch, caplog):
    monkeypatch.setattr("core.auth.users.get_sessionmaker", _get_raising_sessionmaker)
    monkeypatch.delenv("S43_BREAK_GLASS_ARMED", raising=False)

    with caplog.at_level(logging.ERROR):
        allowed = _run(auth_router._env_operator_allowed())

    assert allowed is False
    full_log_text = _assert_no_sensitive_leak(caplog)
    assert "auth.env_operator_allowed" in full_log_text
    # This path logs a fixed marker ("db_check_failed; denying break-glass")
    # and deliberately no exception detail at all -- the important property is
    # that nothing sensitive leaks, asserted above.


class _FakeRequest:
    headers: dict = {}
    client = None


def test_login_session_creation_failure_logs_no_username_or_exception_text(monkeypatch, caplog):
    """
    The credential was fine (a valid DB account authenticated) -- the
    session layer failed afterward. That must still 503, and the log line
    must still not carry the account's username or the raw exception text
    (which, for a DB write failure, can carry the same DSN-shaped detail as
    the earlier lookup failures above).
    """
    monkeypatch.setattr(
        auth_router,
        "_validate_credentials",
        AsyncMock(return_value=(SENTINEL_USERNAME, "operator", "11111111-1111-1111-1111-111111111111")),
    )
    monkeypatch.setattr(
        auth_router,
        "_create_login_session",
        AsyncMock(side_effect=RuntimeError(f"sessions table write failed: {SENTINEL_DSN_FRAGMENT}")),
    )

    body = LoginRequest(username=SENTINEL_USERNAME, password=SENTINEL_PASSWORD)

    with caplog.at_level(logging.ERROR):
        with pytest.raises(HTTPException) as exc_info:
            _run(auth_router.login(body, _FakeRequest(), Response()))

    assert exc_info.value.status_code == 503
    full_log_text = _assert_no_sensitive_leak(caplog)
    assert "auth.login" in full_log_text and "session_create_failed" in full_log_text
    assert "RuntimeError" in full_log_text  # exception class, not its message
