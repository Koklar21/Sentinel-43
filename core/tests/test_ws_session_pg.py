# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_ws_session_pg.py
#
# Beta-execution Phase 3 (Phase B) -- the dashboard WebSocket accepts a
# session-bound access token with a {token}-only frame (no password), keeps
# accepting the legacy {token,password} frame, drops the connection when the
# session is revoked mid-stream, and passes a meaningful close `reason` so
# websocket.js can classify auth failures (finding #6). Against real PG.
#
#   S43_TEST_PG_DSN=postgresql+asyncpg://s43t:x@127.0.0.1:55440/s43t \
#     pytest core/tests/test_ws_session_pg.py
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
JWT_SECRET = "test-secret-ws-session-pg-00000000000"


def _cfg() -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    return cfg


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("SENTINEL_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", _DSN)
    monkeypatch.setenv("S43_JWT_SECRET", JWT_SECRET)
    monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("S43_JWT_ISSUER", "sentinel-43")
    monkeypatch.setenv("S43_JWT_AUDIENCE", "sentinel-43-dashboard")
    monkeypatch.setenv("S43_ALLOWED_ORIGINS", _ORIGIN)
    monkeypatch.setenv("S43_WS_REQUIRE_AUTH", "true")
    monkeypatch.setenv("S43_WS_SESSION_RECHECK_SECONDS", "1")
    monkeypatch.setenv("S43_WATCHTOWER_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("S43_WATCHTOWER_TIMEOUT", "0.5")
    monkeypatch.delenv("S43_REJECT_LEGACY_AUTH", raising=False)

    eng = create_engine(_SYNC_DSN, future=True)
    with eng.begin() as c:
        c.exec_driver_sql("DROP TABLE IF EXISTS sessions, users, alembic_version CASCADE")
    command.upgrade(_cfg(), "head")

    import core.auth.users as users_mod

    users_mod._engine = None
    users_mod._sessionmaker = None

    from fastapi.testclient import TestClient
    import core.api.main as main_module

    with TestClient(main_module.app) as c:
        c._db = eng  # type: ignore[attr-defined]
        yield c

    users_mod._engine = None
    users_mod._sessionmaker = None
    with eng.begin() as c:
        c.exec_driver_sql("DROP TABLE IF EXISTS sessions, users, alembic_version CASCADE")
    eng.dispose()


def _mk_user(eng, username="wsop", password="wsop-password-1234"):
    from argon2 import PasswordHasher

    uid = uuid.uuid4()
    with eng.begin() as c:
        c.execute(
            text(
                "INSERT INTO users (user_id, username, password_hash, role, is_active, created_at) "
                "VALUES (:i, :u, :h, 'operator', true, now())"
            ),
            {"i": uid, "u": username, "h": PasswordHasher().hash(password)},
        )
    return str(uid)


def _login(client, username="wsop", password="wsop-password-1234"):
    return client.post(
        "/auth/login", json={"username": username, "password": password},
        headers={"Origin": _ORIGIN},
    ).json()


def _legacy_token():
    import jwt as pyjwt
    from datetime import datetime, timezone

    now = int(datetime.now(timezone.utc).timestamp())
    return pyjwt.encode(
        {"sub": "wsop", "role": "operator", "iss": "sentinel-43",
         "aud": "sentinel-43-dashboard", "iat": now, "nbf": now - 5, "exp": now + 3600},
        JWT_SECRET, algorithm="HS256",
    )


def test_session_bound_token_connects_with_token_only_frame(client):
    _mk_user(client._db)
    token = _login(client)["access_token"]
    with client.websocket_connect("/ws", headers={"origin": _ORIGIN}) as ws:
        assert ws.receive_json()["type"] == "auth_required"
        ws.send_json({"type": "auth", "payload": {"token": token}})  # NO password
        assert ws.receive_json()["type"] == "connected"


def test_legacy_frame_still_requires_password(client):
    _mk_user(client._db)
    legacy = _legacy_token()
    with client.websocket_connect("/ws", headers={"origin": _ORIGIN}) as ws:
        ws.receive_json()  # auth_required
        ws.send_json({"type": "auth", "payload": {"token": legacy}})  # no password
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert "password" in msg["payload"]["error"].lower()


def test_legacy_frame_with_password_connects(client):
    _mk_user(client._db)
    legacy = _legacy_token()
    with client.websocket_connect("/ws", headers={"origin": _ORIGIN}) as ws:
        ws.receive_json()
        ws.send_json({"type": "auth", "payload": {"token": legacy, "password": "wsop-password-1234"}})
        assert ws.receive_json()["type"] == "connected"


def test_reject_legacy_auth_on_blocks_the_legacy_frame_not_the_session(client, monkeypatch):
    _mk_user(client._db)
    legacy = _legacy_token()
    token = _login(client)["access_token"]

    monkeypatch.setenv("S43_REJECT_LEGACY_AUTH", "true")

    # legacy {token,password} frame -> rejected outright
    with client.websocket_connect("/ws", headers={"origin": _ORIGIN}) as ws:
        ws.receive_json()  # auth_required
        ws.send_json({"type": "auth", "payload": {"token": legacy, "password": "wsop-password-1234"}})
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert "no longer accepted" in msg["payload"]["error"].lower() \
            or "log in again" in msg["payload"]["error"].lower()

    # session-bound {token}-only frame -> still connects
    with client.websocket_connect("/ws", headers={"origin": _ORIGIN}) as ws:
        ws.receive_json()
        ws.send_json({"type": "auth", "payload": {"token": token}})
        assert ws.receive_json()["type"] == "connected"


def test_session_revoked_mid_stream_drops_the_connection(client):
    _mk_user(client._db)
    token = _login(client)["access_token"]
    with client.websocket_connect("/ws", headers={"origin": _ORIGIN}) as ws:
        ws.receive_json()  # auth_required
        ws.send_json({"type": "auth", "payload": {"token": token}})
        assert ws.receive_json()["type"] == "connected"

        # revoke every session out of band
        with client._db.begin() as c:
            c.execute(text("UPDATE sessions SET revoked_at = now(), revoked_reason='test'"))

        # nudge the handler so it re-checks (also the 1s recheck timer would)
        ws.send_json({"type": "ping", "payload": {}})
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert "session" in msg["payload"]["error"]
