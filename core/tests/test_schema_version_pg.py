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
# core/tests/test_schema_version_pg.py
#
# Beta-execution Phase 1 -- the runtime schema-version compatibility check
# (core/auth/schema_version.py) and its wiring into GET /ready, against a REAL
# disposable PostgreSQL. Proves the API refuses to serve normal traffic when
# the database is not at the Alembic revision this code expects.
#
#   docker run -d --rm --name s43pg --tmpfs /var/lib/postgresql/data \
#     -e POSTGRES_PASSWORD=x -e POSTGRES_DB=s43t -e POSTGRES_USER=s43t \
#     -p 127.0.0.1:55441:5432 postgres:16.3
#   S43_TEST_PG_DSN=postgresql+asyncpg://s43t:x@127.0.0.1:55441/s43t \
#     pytest core/tests/test_schema_version_pg.py
# =============================================================================

from __future__ import annotations

import asyncio
import importlib
import os
import pathlib

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

_DSN = os.getenv("S43_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(
    not _DSN, reason="set S43_TEST_PG_DSN to a disposable PostgreSQL to run"
)

# core/api/main.py reads SENTINEL_ENV (and S43_JWT_SECRET, S43_TRUSTED_HOSTS,
# S43_TLS_TERMINATED_AT_TRUSTED_EDGE, ...) into frozen module-level constants
# (IS_LOCAL_ENV, JWT_SECRET, _TRUSTED_HOSTS, ...) exactly ONCE, at the first
# `import core.api.main` anywhere in the process -- never re-read per test,
# regardless of a later monkeypatch.setenv.
#
# This file's `_clean` fixture below is autouse and monkeypatches
# SENTINEL_ENV to "production"/"development" for its own coverage of
# core.auth.schema_version's `_check_enabled()`, which DOES read the
# environment live -- that part is fine. The problem is three tests here
# build a bare `TestClient(main_module.app)` with NO lifespan, purely to
# exercise /ready or /health, via a deferred `import core.api.main` inside
# the test function -- so if that import happens to be the FIRST one in the
# whole pytest run (it is, per this file's position in
# .github/workflows/k8s.yml's PG-suite command), it freezes IS_LOCAL_ENV as
# whatever _clean's autouse fixture happened to monkeypatch for THAT test
# ("production"), not this file's own intent. Every OTHER PG test file in
# the same run that DOES exercise the full lifespan (test_auth_session_pg.py,
# test_ws_session_pg.py) then inherits that frozen "production" state and
# fails core.api.main's non-local startup validation
# (S43_TRUSTED_HOSTS / S43_TLS_TERMINATED_AT_TRUSTED_EDGE) -- their own
# monkeypatch.setenv("SENTINEL_ENV", "test") is already too late to matter.
#
# Importing it here, eagerly, at collection time -- before any fixture in
# this file has had a chance to run -- pins that freeze to a known-safe
# local environment instead, deterministically, regardless of import order
# in later files.
os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault(
    "S43_JWT_SECRET", "test-secret-for-schema-version-pg-collection"
)
os.environ.setdefault("S43_JWT_ALGORITHM", "HS256")
import core.api.main as _pin_core_api_main_import  # noqa: F401,E402

_SYNC_DSN = (_DSN or "").replace("+asyncpg", "+psycopg")
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_DROP_ALL = "DROP TABLE IF EXISTS sessions, users, alembic_version CASCADE"


def _cfg() -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    return cfg


from core.auth.schema_version import expected_head as _expected_head  # noqa: E402

_HEAD = _expected_head()  # the single shipped head revision


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", _DSN)
    monkeypatch.setenv("SENTINEL_ENV", "production")
    monkeypatch.delenv("S43_SCHEMA_VERSION_CHECK", raising=False)
    eng = create_engine(_SYNC_DSN)
    with eng.begin() as c:
        c.exec_driver_sql(_DROP_ALL)
    # core.auth.users caches a module-level engine keyed to DATABASE_URL at
    # first use; reload it (and schema_version, which imports from it) so each
    # test starts from a clean cache bound to this DSN.
    import core.auth.users as users_mod

    users_mod._engine = None
    users_mod._sessionmaker = None
    import core.auth.schema_version as sv_mod

    importlib.reload(sv_mod)
    yield eng
    with eng.begin() as c:
        c.exec_driver_sql(_DROP_ALL)
    eng.dispose()
    users_mod._engine = None
    users_mod._sessionmaker = None


def _report():
    import core.auth.schema_version as sv

    return asyncio.run(sv.schema_report())


# ---------------------------------------------------------------------------
# state classification against a real database
# ---------------------------------------------------------------------------

def test_fresh_database_is_blocked_in_production(_clean):
    r = _report()
    assert r.state.value == "fresh"
    assert r.serving_blocked is True
    assert r.current is None
    assert r.expected == _HEAD


def test_at_head_is_ok_and_not_blocked(_clean):
    command.upgrade(_cfg(), "head")
    r = _report()
    assert r.state.value == "ok"
    assert r.serving_blocked is False
    assert r.current == _HEAD


def test_behind_is_blocked(_clean):
    command.upgrade(_cfg(), "head")
    with _clean.begin() as c:
        c.execute(text("UPDATE alembic_version SET version_num = '0001_baseline'"))
    r = _report()
    assert r.state.value == "behind"
    assert r.serving_blocked is True
    assert "alembic upgrade head" in r.detail


def test_unknown_ahead_revision_is_blocked(_clean):
    command.upgrade(_cfg(), "head")
    with _clean.begin() as c:
        c.execute(text("UPDATE alembic_version SET version_num = '9999_from_the_future'"))
    r = _report()
    assert r.state.value == "ahead"
    assert r.serving_blocked is True


def test_pre_alembic_unstamped_database_is_blocked(_clean):
    # `users` present (old create_all path) but never adopted into Alembic.
    command.upgrade(_cfg(), "0001_baseline")
    with _clean.begin() as c:
        c.execute(text("DROP TABLE alembic_version"))
    r = _report()
    assert r.state.value == "unstamped"
    assert r.serving_blocked is True
    assert "alembic stamp 0001_baseline" in r.detail


def test_local_environment_is_never_blocked(_clean, monkeypatch):
    monkeypatch.setenv("SENTINEL_ENV", "development")
    r = _report()
    assert r.state.value == "fresh"
    assert r.serving_blocked is False


def test_explicit_disable_overrides_in_production(_clean, monkeypatch):
    monkeypatch.setenv("S43_SCHEMA_VERSION_CHECK", "false")
    r = _report()
    assert r.state.value == "fresh"
    assert r.serving_blocked is False


def test_no_database_url_is_not_applicable(_clean, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    r = _report()
    assert r.state.value == "n/a"
    assert r.serving_blocked is False


# ---------------------------------------------------------------------------
# GET /ready wiring
# ---------------------------------------------------------------------------

def test_ready_endpoint_503_when_schema_behind(_clean, monkeypatch):
    monkeypatch.setenv("S43_JWT_SECRET", "test-secret-schema-version-ready")
    monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
    command.upgrade(_cfg(), "head")
    with _clean.begin() as c:
        c.execute(text("UPDATE alembic_version SET version_num = '0001_baseline'"))

    from fastapi.testclient import TestClient
    import core.api.main as main_module

    # No lifespan: we are only exercising the route, not startup.
    client = TestClient(main_module.app)
    resp = client.get("/ready")
    assert resp.status_code == 503, resp.text
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["reason"] == "schema_version"
    assert body["schema_state"] == "behind"


def test_ready_endpoint_200_when_schema_at_head(_clean, monkeypatch):
    monkeypatch.setenv("S43_JWT_SECRET", "test-secret-schema-version-ready")
    monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
    command.upgrade(_cfg(), "head")

    from fastapi.testclient import TestClient
    import core.api.main as main_module

    client = TestClient(main_module.app)
    resp = client.get("/ready")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"status": "ready", "service": "sentinel-43-api"}


def test_health_endpoint_never_touches_the_database(_clean, monkeypatch):
    # Liveness must stay green even with a totally broken schema.
    monkeypatch.setenv("S43_JWT_SECRET", "test-secret-schema-version-health")
    monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://nobody:nobody@127.0.0.1:1/nope")

    from fastapi.testclient import TestClient
    import core.api.main as main_module

    client = TestClient(main_module.app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
