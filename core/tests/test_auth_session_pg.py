# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_auth_session_pg.py
#
# Beta-execution Phase 3 -- browser session end to end against a REAL
# disposable PostgreSQL: login sets the refresh cookie + CSRF cookie + a
# sid-bound access token; /auth/refresh rotates; /auth/logout revokes;
# replay of a rotated value revokes the whole session; CSRF + Origin are
# enforced; a session-bound token reaches protected routes WITHOUT
# X-S43-Password; disablement / role change / password reset kill live
# sessions immediately; an expired session is rejected.
#
#   S43_TEST_PG_DSN=postgresql+asyncpg://s43t:x@127.0.0.1:55440/s43t \
#     pytest core/tests/test_auth_session_pg.py
#
# All DB mutation goes through a SYNC psycopg engine so this file never
# spins an event loop that could collide with the TestClient portal's.
# =============================================================================

from __future__ import annotations

import os
import pathlib
import uuid

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

_DSN = os.getenv("S43_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(
    not _DSN, reason="set S43_TEST_PG_DSN to a disposable PostgreSQL to run"
)

_SYNC_DSN = (_DSN or "").replace("+asyncpg", "+psycopg")
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

_ORIGIN = "http://localhost:8000"
JWT_SECRET = "test-secret-auth-session-pg-0000000000"  # >= 32 bytes


def _cfg() -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    return cfg


def _argon2(pw: str) -> str:
    from argon2 import PasswordHasher

    return PasswordHasher().hash(pw)


@pytest.fixture()
def db(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", _DSN)  # alembic env.py reads this
    eng = create_engine(_SYNC_DSN, future=True)
    with eng.begin() as c:
        c.exec_driver_sql("DROP TABLE IF EXISTS sessions, users, alembic_version CASCADE")
    command.upgrade(_cfg(), "head")
    yield eng
    with eng.begin() as c:
        c.exec_driver_sql("DROP TABLE IF EXISTS sessions, users, alembic_version CASCADE")
    eng.dispose()


@pytest.fixture()
def client(db, monkeypatch):
    monkeypatch.setenv("SENTINEL_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", _DSN)
    monkeypatch.setenv("S43_JWT_SECRET", JWT_SECRET)
    monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("S43_JWT_ISSUER", "sentinel-43")
    monkeypatch.setenv("S43_JWT_AUDIENCE", "sentinel-43-dashboard")
    monkeypatch.setenv("S43_ALLOWED_ORIGINS", _ORIGIN)
    monkeypatch.setenv("S43_WATCHTOWER_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("S43_WATCHTOWER_TIMEOUT", "0.5")
    monkeypatch.setenv("S43_SESSION_ACCESS_TTL_SECONDS", "900")
    monkeypatch.setenv("S43_ENABLE_DEV_STORE", "true")   # so /v1/actions returns 200, not a store 503
    monkeypatch.setenv("S43_ENABLE_DEV_ENGINE", "true")
    monkeypatch.delenv("S43_REJECT_LEGACY_AUTH", raising=False)

    import core.auth.users as users_mod

    users_mod._engine = None
    users_mod._sessionmaker = None

    from fastapi.testclient import TestClient
    import core.api.main as main_module

    with TestClient(main_module.app) as c:
        yield c

    users_mod._engine = None
    users_mod._sessionmaker = None


def _mk_user(db, username="op1", password="op1-password-1234", role="operator", is_active=True):
    uid = uuid.uuid4()
    with db.begin() as c:
        c.execute(
            text(
                "INSERT INTO users (user_id, username, password_hash, role, is_active, created_at) "
                "VALUES (:i, :u, :h, :r, :a, now())"
            ),
            {"i": uid, "u": username, "h": _argon2(password), "r": role, "a": is_active},
        )
    return str(uid)


def _exec(db, sql, **params):
    with db.begin() as c:
        c.execute(text(sql), params)


def _login(client, username="op1", password="op1-password-1234"):
    return client.post(
        "/auth/login", json={"username": username, "password": password},
        headers={"Origin": _ORIGIN},
    )


def _csrf(client) -> str:
    return client.cookies.get("s43_csrf")


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------

def test_login_sets_refresh_and_csrf_cookies_and_a_sid_bound_token(client, db):
    _mk_user(db)
    r = _login(client)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["session_bound"] is True
    assert body["expires_in"] == 900

    sc = r.headers.get("set-cookie", "")
    assert "s43_refresh=" in sc and "httponly" in sc.lower()
    assert "samesite=strict" in sc.lower()
    assert "path=/auth" in sc.lower()
    assert client.cookies.get("s43_refresh")
    assert client.cookies.get("s43_csrf")

    import jwt as pyjwt

    claims = pyjwt.decode(
        body["access_token"], JWT_SECRET, algorithms=["HS256"],
        audience="sentinel-43-dashboard", issuer="sentinel-43",
    )
    assert "sid" in claims and "jti" in claims


def test_login_rejects_disallowed_origin(client, db):
    _mk_user(db)
    r = client.post(
        "/auth/login", json={"username": "op1", "password": "op1-password-1234"},
        headers={"Origin": "https://evil.example"},
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# refresh
# ---------------------------------------------------------------------------

def test_refresh_rotates_the_cookie_and_issues_a_new_token(client, db):
    _mk_user(db)
    _login(client)
    first = client.cookies.get("s43_refresh")
    r = client.post("/auth/refresh", headers={"Origin": _ORIGIN, "X-S43-CSRF": _csrf(client)})
    assert r.status_code == 200, r.text
    assert client.cookies.get("s43_refresh") != first
    assert r.json()["session_bound"] is True


def test_refresh_without_csrf_header_is_403(client, db):
    _mk_user(db)
    _login(client)
    r = client.post("/auth/refresh", headers={"Origin": _ORIGIN})
    assert r.status_code == 403


def test_refresh_after_logout_is_401(client, db):
    _mk_user(db)
    _login(client)
    csrf = _csrf(client)
    assert client.post("/auth/logout", headers={"Origin": _ORIGIN, "X-S43-CSRF": csrf}).status_code == 200
    r = client.post("/auth/refresh", headers={"Origin": _ORIGIN, "X-S43-CSRF": csrf})
    assert r.status_code == 401


def test_replay_of_a_rotated_refresh_value_revokes_the_session(client, db):
    _mk_user(db)
    _login(client)
    stale = client.cookies.get("s43_refresh")
    assert client.post("/auth/refresh", headers={"Origin": _ORIGIN, "X-S43-CSRF": _csrf(client)}).status_code == 200
    current = client.cookies.get("s43_refresh")

    # present the stale (superseded) value -> theft -> 401, session revoked
    client.cookies.set("s43_refresh", stale)
    assert client.post("/auth/refresh", headers={"Origin": _ORIGIN, "X-S43-CSRF": _csrf(client)}).status_code == 401

    # the current value is now dead too (whole session was revoked)
    client.cookies.set("s43_refresh", current)
    assert client.post("/auth/refresh", headers={"Origin": _ORIGIN, "X-S43-CSRF": _csrf(client)}).status_code == 401

    with db.connect() as c:
        n = c.execute(text("SELECT count(*) FROM sessions WHERE revoked_at IS NOT NULL")).scalar()
    assert n == 1


def test_refresh_reflects_a_role_change_at_rotation_time(client, db):
    uid = _mk_user(db, role="operator")
    _login(client)
    _exec(db, "UPDATE users SET role='admin' WHERE user_id=:i", i=uid)
    r = client.post("/auth/refresh", headers={"Origin": _ORIGIN, "X-S43-CSRF": _csrf(client)})
    assert r.status_code == 200
    assert r.json()["role"] == "admin"


# ---------------------------------------------------------------------------
# protected routes -- session-bound token skips X-S43-Password
# ---------------------------------------------------------------------------

def _v1(client, token, password=None):
    h = {"Authorization": f"Bearer {token}"}
    if password:
        h["X-S43-Password"] = password
    return client.get("/v1/actions", headers=h)


def test_session_bound_token_reaches_v1_without_password_header(client, db):
    _mk_user(db)
    token = _login(client).json()["access_token"]
    assert _v1(client, token).status_code == 200  # NOT 401


def test_disabled_user_session_is_rejected_immediately(client, db):
    uid = _mk_user(db)
    token = _login(client).json()["access_token"]
    _exec(db, "UPDATE users SET is_active=false WHERE user_id=:i", i=uid)
    assert _v1(client, token).status_code == 401


def test_expired_session_is_rejected(client, db):
    _mk_user(db)
    token = _login(client).json()["access_token"]
    _exec(db, "UPDATE sessions SET expires_at = now() - interval '1 hour'")
    assert _v1(client, token).status_code == 401
    assert client.post(
        "/auth/refresh", headers={"Origin": _ORIGIN, "X-S43-CSRF": _csrf(client)}
    ).status_code == 401


def test_admin_password_reset_revokes_target_sessions(client, db):
    _mk_user(db, username="admin1", password="admin1-password-1234", role="admin")
    op_uid = _mk_user(db, username="op2", password="op2-password-1234", role="operator")

    op_token = _login(client, "op2", "op2-password-1234").json()["access_token"]
    assert _v1(client, op_token).status_code == 200

    # same client (its cookie jar becomes the admin's — we only need op_token
    # captured above to still be checkable afterwards)
    admin_token = _login(client, "admin1", "admin1-password-1234").json()["access_token"]
    reset = client.post(
        f"/users/{op_uid}/password",
        json={"new_password": "op2-brand-new-1234"},
        headers={"Authorization": f"Bearer {admin_token}", "X-S43-CSRF": client.cookies.get("s43_csrf")},
    )
    assert reset.status_code == 200, reset.text

    # operator's old session is revoked now
    assert _v1(client, op_token).status_code == 401


def test_legacy_bearer_plus_password_still_works_dual_contract(client, db):
    _mk_user(db, username="op3", password="op3-password-1234")
    import jwt as pyjwt
    from datetime import datetime, timezone

    now = int(datetime.now(timezone.utc).timestamp())
    legacy = pyjwt.encode(
        {"sub": "op3", "role": "operator", "iss": "sentinel-43",
         "aud": "sentinel-43-dashboard", "iat": now, "nbf": now - 5, "exp": now + 3600},
        JWT_SECRET, algorithm="HS256",
    )
    assert _v1(client, legacy, password="op3-password-1234").status_code == 200
    assert _v1(client, legacy).status_code == 401  # no password -> 401
