# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_break_glass_pg.py
#
# Beta-execution Phase 3 -- RELEASE_FINDINGS #11. The env-var operator is a
# scoped break-glass credential (AUTH_MIGRATION_PASS4 §3 Option C):
#
#   * no active admin in the DB      -> env operator works (first-run window)
#   * an active admin exists          -> env operator is INERT
#   * S43_BREAK_GLASS_ARMED=true      -> env operator works regardless
#   * DB unreachable                  -> env operator works (that's the point)
#
#   S43_TEST_PG_DSN=postgresql+asyncpg://s43t:x@127.0.0.1:55440/s43t \
#     pytest core/tests/test_break_glass_pg.py
# =============================================================================

from __future__ import annotations

import hashlib
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

_ENV_USER = "breakglass"
_ENV_PW = "break-glass-password-1234"
_ENV_HASH = hashlib.sha256(_ENV_PW.encode()).hexdigest()
JWT_SECRET = "test-secret-break-glass-000000000000"


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
    monkeypatch.setenv("S43_ALLOWED_ORIGINS", "http://localhost:8000")
    monkeypatch.setenv("S43_OPERATOR_USERNAME", _ENV_USER)
    monkeypatch.setenv("S43_OPERATOR_PASSWORD_HASH", _ENV_HASH)
    monkeypatch.setenv("S43_WATCHTOWER_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("S43_WATCHTOWER_TIMEOUT", "0.5")
    monkeypatch.delenv("S43_BREAK_GLASS_ARMED", raising=False)

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


def _add_admin(eng, username="admin1"):
    from argon2 import PasswordHasher

    with eng.begin() as c:
        c.execute(
            text(
                "INSERT INTO users (user_id, username, password_hash, role, is_active, created_at) "
                "VALUES (:i, :u, :h, 'admin', true, now())"
            ),
            {"i": uuid.uuid4(), "u": username, "h": PasswordHasher().hash("admin-pw-1234")},
        )


def _login_env(client):
    return client.post(
        "/auth/login", json={"username": _ENV_USER, "password": _ENV_PW},
        headers={"Origin": "http://localhost:8000"},
    )


def test_env_operator_works_before_first_admin(client):
    # fresh DB, zero admins -> break-glass applies
    r = _login_env(client)
    assert r.status_code == 200, r.text
    assert r.json()["session_bound"] is False  # env operator gets a legacy token, no session


def test_env_operator_is_inert_once_an_admin_exists(client):
    _add_admin(client._db)
    r = _login_env(client)
    assert r.status_code == 401


def test_armed_flag_re_enables_the_env_operator(client, monkeypatch):
    _add_admin(client._db)
    monkeypatch.setenv("S43_BREAK_GLASS_ARMED", "true")
    r = _login_env(client)
    assert r.status_code == 200


def test_wrong_env_password_is_401_even_when_allowed(client):
    r = client.post(
        "/auth/login", json={"username": _ENV_USER, "password": "wrong"},
        headers={"Origin": "http://localhost:8000"},
    )
    assert r.status_code == 401
