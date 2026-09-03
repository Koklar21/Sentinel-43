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
# core/tests/test_migrations_pg.py
#
# Pass 5A-Migration — Alembic baseline + sessions migration, against a REAL
# disposable PostgreSQL. Covers the mission §33 MIGRATION matrix plus §21/§22
# (session layer + concurrency re-validated on the Alembic-created schema).
#
# Skipped unless S43_TEST_PG_DSN points at a DISPOSABLE PostgreSQL, e.g.:
#
#   docker run -d --rm --name s43pg --tmpfs /var/lib/postgresql/data \
#     -e POSTGRES_PASSWORD=x -e POSTGRES_DB=s43t -e POSTGRES_USER=s43t \
#     -p 127.0.0.1:55432:5432 postgres:16.3
#   S43_TEST_PG_DSN=postgresql+asyncpg://s43t:x@127.0.0.1:55432/s43t \
#     pytest core/tests/test_migrations_pg.py
#
# Each test starts from a fully dropped schema (autouse fixture). Every
# `alembic` command reads DATABASE_URL from the environment (env.py ->
# core.auth.users._database_url), which the fixture points at the test DSN.
#
# PostgreSQL 16.3, default READ COMMITTED. Recorded in PASS5AM_VALIDATION.md.
# =============================================================================

from __future__ import annotations

import asyncio
import contextlib
import functools
import os
import pathlib
import sys
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from core.auth import sessions as S
from core.auth.users import User

_DSN = os.getenv("S43_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(
    not _DSN, reason="set S43_TEST_PG_DSN to a disposable PostgreSQL to run"
)

_SYNC_DSN = (_DSN or "").replace("+asyncpg", "+psycopg")
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_DROP_ALL = "DROP TABLE IF EXISTS sessions, users, alembic_version CASCADE"


def _cfg() -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    return cfg


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", _DSN)
    eng = create_engine(_SYNC_DSN)
    with eng.begin() as c:
        c.exec_driver_sql(_DROP_ALL)
    yield eng
    with eng.begin() as c:
        c.exec_driver_sql(_DROP_ALL)
    eng.dispose()


def _insp(eng):
    with eng.connect() as c:
        return {
            "tables": set(inspect(c).get_table_names()),
        }


def _version(eng) -> str | None:
    with eng.connect() as c:
        if not inspect(c).has_table("alembic_version"):
            return None
        return c.exec_driver_sql("SELECT version_num FROM alembic_version").scalar()


def _t(coro_fn):
    @functools.wraps(coro_fn)
    def w(*a, **k):
        return asyncio.run(coro_fn(*a, **k))
    return w


# ---------------------------------------------------------------------------
# graph
# ---------------------------------------------------------------------------

# The single head + the full linear chain, computed from the shipped
# revision files so this file survives new migrations being added.
_SD = ScriptDirectory.from_config(_cfg())
_HEADS = _SD.get_heads()
_HEAD = _HEADS[0] if len(_HEADS) == 1 else None
_CHAIN = [r.revision for r in _SD.walk_revisions()]  # head -> base order


def test_single_head():
    assert _HEADS == [_HEAD], _HEADS
    assert _HEAD is not None


def test_linear_history():
    sd = ScriptDirectory.from_config(_cfg())
    revs = [r.revision for r in sd.walk_revisions()]
    # strictly linear: every revision's down_revision is the next one listed
    assert revs[-1] == "0001_baseline"
    assert sd.get_revision("0001_baseline").down_revision is None
    for child, parent in zip(revs, revs[1:]):
        assert sd.get_revision(child).down_revision == parent, (child, parent)
    assert sd.get_revision("0002_sessions").down_revision == "0001_baseline"


# ---------------------------------------------------------------------------
# fresh database
# ---------------------------------------------------------------------------

def test_fresh_db_upgrade_0001(_clean):
    command.upgrade(_cfg(), "0001_baseline")
    t = _insp(_clean)["tables"]
    assert "users" in t
    assert "sessions" not in t
    assert _version(_clean) == "0001_baseline"
    # users schema matches the model semantically
    with _clean.connect() as c:
        cols = {x["name"]: x for x in inspect(c).get_columns("users")}
        assert set(cols) == {
            "user_id", "username", "email", "password_hash",
            "role", "is_active", "created_at", "last_login_at",
        }
        assert inspect(c).get_pk_constraint("users")["constrained_columns"] == ["user_id"]
        uq = {
            *(u["column_names"][0] for u in inspect(c).get_unique_constraints("users")),
            *(i["column_names"][0] for i in inspect(c).get_indexes("users") if i["unique"]),
        }
        assert {"username", "email"} <= uq


def test_fresh_db_upgrade_head(_clean):
    command.upgrade(_cfg(), "head")
    t = _insp(_clean)["tables"]
    assert {"users", "sessions"} <= t
    assert _version(_clean) == _HEAD


def test_fresh_db_sessions_schema_matches_model(_clean):
    command.upgrade(_cfg(), "head")
    with _clean.connect() as c:
        insp = inspect(c)
        cols = {x["name"] for x in insp.get_columns("sessions")}
        model_cols = {c.name for c in S.SessionRecord.__table__.columns}
        assert cols == model_cols, (cols ^ model_cols)
        # no `role` column (role comes from users at refresh time — §13)
        assert "role" not in cols
        idx = {i["name"] for i in insp.get_indexes("sessions")}
        assert idx == {
            "ix_sessions_user_id",
            "ix_sessions_prev_refresh_hash",
            "ix_sessions_expires_at",
            "uq_sessions_active_refresh_hash",
        }, idx


# ---------------------------------------------------------------------------
# existing pre-Alembic database  (§8, §19)
# ---------------------------------------------------------------------------

_PRE_ALEMBIC_USERS = """
CREATE TABLE users (
  user_id uuid NOT NULL,
  username varchar(128) NOT NULL,
  email varchar(255),
  password_hash varchar(255) NOT NULL,
  role varchar(32) NOT NULL,
  is_active boolean NOT NULL,
  created_at timestamptz NOT NULL,
  last_login_at timestamptz,
  CONSTRAINT users_pkey PRIMARY KEY (user_id),
  CONSTRAINT users_email_key UNIQUE (email)
);
CREATE UNIQUE INDEX ix_users_username ON users (username);
"""

_REPRESENTATIVE_ROWS = [
    ("operator", None, "operator", True, None),
    ("admin", "admin@example.invalid", "admin", True, "2026-08-01T00:00:00+00:00"),
    ("active-op", None, "operator", True, "2026-08-02T03:04:05+00:00"),
    ("disabled-op", None, "operator", False, None),
]


def _seed_pre_alembic(eng):
    with eng.begin() as c:
        for stmt in _PRE_ALEMBIC_USERS.strip().split(";"):
            if stmt.strip():
                c.exec_driver_sql(stmt)
        for name, email, role, active, last_login in _REPRESENTATIVE_ROWS:
            c.exec_driver_sql(
                "INSERT INTO users(user_id,username,email,password_hash,role,is_active,created_at,last_login_at)"
                " VALUES (gen_random_uuid(), %(u)s, %(e)s, 'argon2-hash-placeholder', %(r)s, %(a)s, now(), %(ll)s)",
                {"u": name, "e": email, "r": role, "a": active, "ll": last_login},
            )


def test_existing_compatible_stamp_then_upgrade(_clean):
    _seed_pre_alembic(_clean)
    command.stamp(_cfg(), "0001_baseline")
    assert _version(_clean) == "0001_baseline"
    command.upgrade(_cfg(), "head")
    assert _version(_clean) == _HEAD
    t = _insp(_clean)["tables"]
    assert "sessions" in t
    with _clean.connect() as c:
        assert c.exec_driver_sql("SELECT count(*) FROM users").scalar() == 4
        assert c.exec_driver_sql("SELECT count(*) FROM sessions").scalar() == 0


def test_user_data_preserved_through_baseline_adoption(_clean):
    _seed_pre_alembic(_clean)
    with _clean.connect() as c:
        before = c.exec_driver_sql(
            "SELECT username,email,password_hash,role,is_active,created_at,last_login_at"
            " FROM users ORDER BY username"
        ).all()
    command.stamp(_cfg(), "0001_baseline")
    command.upgrade(_cfg(), "head")
    with _clean.connect() as c:
        after = c.exec_driver_sql(
            "SELECT username,email,password_hash,role,is_active,created_at,last_login_at"
            " FROM users ORDER BY username"
        ).all()
    assert before == after, "baseline adoption must not alter any user record"


# ---------------------------------------------------------------------------
# incompatible pre-Alembic database  (§20)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("broken_ddl", [
    # missing role
    "CREATE TABLE users (user_id uuid PRIMARY KEY, username varchar(128) NOT NULL,"
    " email varchar(255) UNIQUE, password_hash varchar(255) NOT NULL,"
    " is_active boolean NOT NULL, created_at timestamptz NOT NULL, last_login_at timestamptz);"
    " CREATE UNIQUE INDEX ix_users_username ON users(username);",
    # username not unique
    "CREATE TABLE users (user_id uuid PRIMARY KEY, username varchar(128) NOT NULL,"
    " email varchar(255) UNIQUE, password_hash varchar(255) NOT NULL, role varchar(32) NOT NULL,"
    " is_active boolean NOT NULL, created_at timestamptz NOT NULL, last_login_at timestamptz);",
    # wrong nullability on role
    "CREATE TABLE users (user_id uuid PRIMARY KEY, username varchar(128) NOT NULL,"
    " email varchar(255) UNIQUE, password_hash varchar(255) NOT NULL, role varchar(32),"
    " is_active boolean NOT NULL, created_at timestamptz NOT NULL, last_login_at timestamptz);"
    " CREATE UNIQUE INDEX ix_users_username ON users(username);",
    # incompatible credential column type
    "CREATE TABLE users (user_id uuid PRIMARY KEY, username varchar(128) NOT NULL,"
    " email varchar(255) UNIQUE, password_hash integer NOT NULL, role varchar(32) NOT NULL,"
    " is_active boolean NOT NULL, created_at timestamptz NOT NULL, last_login_at timestamptz);"
    " CREATE UNIQUE INDEX ix_users_username ON users(username);",
])
def test_incompatible_pre_alembic_refused(_clean, broken_ddl):
    with _clean.begin() as c:
        for stmt in broken_ddl.split(";"):
            if stmt.strip():
                c.exec_driver_sql(stmt)
    from migrations.baseline import BaselineIncompatibleError
    with pytest.raises(BaselineIncompatibleError):
        command.stamp(_cfg(), "0001_baseline")
    with pytest.raises(BaselineIncompatibleError):
        command.upgrade(_cfg(), "head")
    # nothing adopted / changed
    assert _version(_clean) is None
    assert "sessions" not in _insp(_clean)["tables"]


# ---------------------------------------------------------------------------
# 0003 — users.role CHECK constraint (P3-7)
# ---------------------------------------------------------------------------

def test_0003_adds_role_check_and_it_is_enforced(_clean):
    command.upgrade(_cfg(), "head")
    with _clean.connect() as c:
        cks = {
            r[0] for r in c.exec_driver_sql(
                "SELECT conname FROM pg_constraint "
                "WHERE conrelid='users'::regclass AND contype='c'"
            )
        }
    assert "ck_users_role" in cks
    import uuid as _u

    with pytest.raises(IntegrityError):
        with _clean.begin() as c:
            c.exec_driver_sql(
                "INSERT INTO users (user_id, username, password_hash, role, is_active, created_at) "
                f"VALUES ('{_u.uuid4()}', 'baduser', 'x', 'superuser', true, now())"
            )


def test_0003_refuses_when_an_existing_row_violates_it(_clean):
    # a DB at 0002 that already holds a bad role value (raw SQL / legacy bug)
    command.upgrade(_cfg(), "0002_sessions")
    import uuid as _u

    with _clean.begin() as c:
        c.exec_driver_sql(
            "INSERT INTO users (user_id, username, password_hash, role, is_active, created_at) "
            f"VALUES ('{_u.uuid4()}', 'legacy', 'x', 'root', true, now())"
        )
    with pytest.raises(RuntimeError, match="role outside"):
        command.upgrade(_cfg(), "head")
    # constraint was NOT added; DB left at 0002
    assert _version(_clean) == "0002_sessions"


def test_0003_downgrade_removes_the_check(_clean):
    command.upgrade(_cfg(), "head")
    command.downgrade(_cfg(), "0002_sessions")
    with _clean.connect() as c:
        n = c.exec_driver_sql(
            "SELECT count(*) FROM pg_constraint "
            "WHERE conrelid='users'::regclass AND contype='c'"
        ).scalar()
    assert n == 0
    assert _version(_clean) == "0002_sessions"


# ---------------------------------------------------------------------------
# downgrade  (§12, §18)
# ---------------------------------------------------------------------------

def test_downgrade_0002_to_0001(_clean):
    command.upgrade(_cfg(), "head")
    command.downgrade(_cfg(), "0001_baseline")
    t = _insp(_clean)["tables"]
    assert "sessions" not in t
    assert "users" in t
    assert _version(_clean) == "0001_baseline"


def test_downgrade_upgrade_repeatable(_clean):
    cfg = _cfg()
    command.upgrade(cfg, "0001_baseline")
    for _ in range(2):
        command.upgrade(cfg, "head")
        assert "sessions" in _insp(_clean)["tables"]
        command.downgrade(cfg, "0001_baseline")
        assert "sessions" not in _insp(_clean)["tables"]
    command.upgrade(cfg, "head")
    assert _version(_clean) == _HEAD


def test_baseline_downgrade_to_base_refused_and_rolls_back(_clean):
    command.upgrade(_cfg(), "head")
    with pytest.raises(RuntimeError):
        command.downgrade(_cfg(), "base")
    # transactional DDL: the whole downgrade rolled back — users AND sessions
    # still present, version unchanged
    t = _insp(_clean)["tables"]
    assert {"users", "sessions"} <= t
    assert _version(_clean) == _HEAD


# ---------------------------------------------------------------------------
# sessions constraints / indexes / FK  (§14, §15, §16, §33)
# ---------------------------------------------------------------------------

def _mk_user(eng, username="op", role="operator", active=True) -> uuid.UUID:
    uid = uuid.uuid4()
    with eng.begin() as c:
        c.exec_driver_sql(
            "INSERT INTO users(user_id,username,email,password_hash,role,is_active,created_at)"
            " VALUES (%(id)s,%(u)s,NULL,'h',%(r)s,%(a)s, now())",
            {"id": uid, "u": username, "r": role, "a": active},
        )
    return uid


def _insert_session(eng, *, user_id, refresh_hash, revoked=False, sid=None):
    sid = sid or uuid.uuid4()
    with eng.begin() as c:
        c.exec_driver_sql(
            "INSERT INTO sessions(sid,user_id,refresh_hash,refresh_generation,"
            "issued_at,last_seen_at,expires_at,revoked_at) VALUES "
            "(%(sid)s,%(uid)s,%(rh)s,0, now(), now(), now() + interval '7 days', %(rev)s)",
            {"sid": sid, "uid": user_id, "rh": refresh_hash,
             "rev": datetime.now(timezone.utc) if revoked else None},
        )
    return sid


def test_sessions_partial_unique_rejects_second_active(_clean):
    command.upgrade(_cfg(), "head")
    uid = _mk_user(_clean)
    _insert_session(_clean, user_id=uid, refresh_hash="H" * 64)
    with pytest.raises(IntegrityError):
        _insert_session(_clean, user_id=uid, refresh_hash="H" * 64)


def test_sessions_partial_unique_permits_revoked_historical_plus_active(_clean):
    """Shape B, not A (mission §14/§33): a REVOKED historical row and an
    ACTIVE successor may hold the same refresh_hash. An unconditional UNIQUE
    (shape A) would reject this and break legitimate rotation/replay history."""
    command.upgrade(_cfg(), "head")
    uid = _mk_user(_clean)
    shared = "R" * 64
    _insert_session(_clean, user_id=uid, refresh_hash=shared, revoked=True)   # historical
    # succeeds under shape B (partial index excludes the revoked row):
    _insert_session(_clean, user_id=uid, refresh_hash=shared, revoked=False)  # current
    with _clean.connect() as c:
        n = c.exec_driver_sql(
            "SELECT count(*) FROM sessions WHERE refresh_hash = %(h)s", {"h": shared}
        ).scalar()
    assert n == 2


def test_sessions_fk_on_delete_restrict(_clean):
    command.upgrade(_cfg(), "head")
    uid = _mk_user(_clean, "fk-user")
    _insert_session(_clean, user_id=uid, refresh_hash="F" * 64)
    with pytest.raises(IntegrityError):
        with _clean.begin() as c:
            c.exec_driver_sql("DELETE FROM users WHERE user_id = %(id)s", {"id": uid})
    # orphan session -> also rejected
    with pytest.raises(IntegrityError):
        _insert_session(_clean, user_id=uuid.uuid4(), refresh_hash="G" * 64)


def test_sessions_fk_is_restrict_not_cascade(_clean):
    command.upgrade(_cfg(), "head")
    with _clean.connect() as c:
        fk = inspect(c).get_foreign_keys("sessions")[0]
    assert fk["referred_table"] == "users"
    assert fk["options"].get("ondelete", "").upper() == "RESTRICT"


# ---------------------------------------------------------------------------
# naming convention determinism  (§5, §33)
# ---------------------------------------------------------------------------

def _constraint_names(eng) -> dict:
    with eng.connect() as c:
        insp = inspect(c)
        out = {}
        for t in ("users", "sessions"):
            if not insp.has_table(t):
                continue
            out[t] = {
                "pk": insp.get_pk_constraint(t).get("name"),
                "uq": sorted(u["name"] for u in insp.get_unique_constraints(t)),
                "ix": sorted(i["name"] for i in insp.get_indexes(t)),
                "fk": sorted(f["name"] for f in insp.get_foreign_keys(t)),
            }
        return out


def test_naming_convention_deterministic_across_roundtrip(_clean):
    cfg = _cfg()
    command.upgrade(cfg, "head")
    first = _constraint_names(_clean)
    command.downgrade(cfg, "0001_baseline")
    command.upgrade(cfg, "head")
    second = _constraint_names(_clean)
    assert first == second
    # and the names actually follow the convention
    assert first["users"]["pk"] == "pk_users"
    assert first["sessions"]["pk"] == "pk_sessions"
    assert first["sessions"]["fk"] == ["fk_sessions_user_id_users"]
    assert "uq_sessions_active_refresh_hash" in first["sessions"]["ix"]


# ---------------------------------------------------------------------------
# env.py hygiene  (§23)
# ---------------------------------------------------------------------------

def test_env_does_not_import_the_application(_clean):
    # Snapshot + restore so this test never pollutes sys.modules for the rest
    # of the suite (test_ws_auth.py et al. reload core.api.main and rely on it
    # being present).
    saved = {
        k: v for k, v in sys.modules.items()
        if k == "core.api" or k.startswith("core.api.")
    }
    for k in saved:
        del sys.modules[k]
    try:
        command.upgrade(_cfg(), "head")
        leaked = sorted(
            k for k in sys.modules
            if k == "core.api.main" or k.startswith("core.api.main.")
        )
        assert not leaked, (
            f"migrations/env.py must not import the FastAPI application (§23); "
            f"leaked: {leaked}"
        )
    finally:
        # restore the exact module objects other test modules hold references
        # to (they reload core.api.main and expect identity to hold)
        for k, v in saved.items():
            sys.modules[k] = v


# ---------------------------------------------------------------------------
# session layer + concurrency on the ALEMBIC-created schema  (§21, §22)
# ---------------------------------------------------------------------------

@pytest.fixture
def _alembic_sm(_clean):
    """Sessionmaker bound to a schema built by `alembic upgrade head`.

    Yields the sessionmaker; the async engine is created and disposed inside
    the test body's own event loop (asyncio.run) via _with_engine().
    """
    command.upgrade(_cfg(), "head")
    return _DSN


@contextlib.asynccontextmanager
async def _sm_from(dsn):
    eng = create_async_engine(dsn, pool_size=20, max_overflow=20)
    try:
        yield async_sessionmaker(eng, expire_on_commit=False)
    finally:
        await eng.dispose()


async def _mk_user_async(sm, username="op", *, role="operator", active=True):
    async with sm() as s:
        u = User(user_id=uuid.uuid4(), username=username, email=None,
                 password_hash="h", role=role, is_active=active,
                 created_at=datetime.now(timezone.utc))
        s.add(u)
        await s.commit()
        return u.user_id


@_t
async def test_session_primitives_layer_on_alembic_schema(_alembic_sm):
    async with _sm_from(_alembic_sm) as sm:
        uid = await _mk_user_async(sm)
        s1 = S.generate_refresh_secret()
        async with sm() as s:
            row = await S.create_session(s, user_id=uid, refresh_secret=s1)
            sid = row.sid
            await s.commit()
        s2 = S.generate_refresh_secret()
        async with sm() as s:
            r, outcome = await S.rotate_refresh(s, presented_secret=s1, new_refresh_secret=s2)
            assert outcome is S.RefreshOutcome.ROTATED and r.refresh_generation == 1
            await s.commit()
        async with sm() as s:  # replay superseded -> reuse -> revoke
            with pytest.raises(S.RefreshReuseError):
                await S.rotate_refresh(s, presented_secret=s1,
                                       new_refresh_secret=S.generate_refresh_secret())
            await s.commit()
        async with sm() as s:
            got = await S.get_session_by_sid(s, sid)
            assert got.revoked_at is not None and got.revoked_reason == "refresh_reuse"
        async with sm() as s:
            assert await S.logout_by_refresh(s, presented_secret=s2) is False
            await s.commit()


@pytest.mark.parametrize("racers", [2, 5])
@_t
async def test_concurrent_refresh_one_successor_on_alembic_schema(_alembic_sm, racers):
    async with _sm_from(_alembic_sm) as sm:
        uid = await _mk_user_async(sm, "racer")
        s1 = S.generate_refresh_secret()
        async with sm() as s:
            row = await S.create_session(s, user_id=uid, refresh_secret=s1)
            sid = row.sid
            await s.commit()

        gate = asyncio.Event()

        async def refr(i):
            async with sm() as s:
                await gate.wait()
                try:
                    r, _ = await S.rotate_refresh(s, presented_secret=s1,
                                                  new_refresh_secret=S.generate_refresh_secret())
                    await s.commit()
                    return "rotated"
                except S.RefreshReuseError:
                    await s.commit()
                    return "reuse"
                except S.SessionError:
                    await s.rollback()
                    return "denied"

        tasks = [asyncio.create_task(refr(i)) for i in range(racers)]
        await asyncio.sleep(0.15)
        gate.set()
        res = await asyncio.gather(*tasks)
        assert res.count("rotated") == 1, res
        async with sm() as s:
            got = await S.get_session_by_sid(s, sid)
            assert got.refresh_generation == 1
            assert got.revoked_at is not None  # reuse tripped


@_t
async def test_refresh_vs_logout_and_disablement_on_alembic_schema(_alembic_sm):
    async with _sm_from(_alembic_sm) as sm:
        uid = await _mk_user_async(sm, "rl")
        secret = S.generate_refresh_secret()
        async with sm() as s:
            await S.create_session(s, user_id=uid, refresh_secret=secret)
            await s.commit()

        gate = asyncio.Event()

        async def do_refresh():
            async with sm() as s:
                await gate.wait()
                try:
                    await S.rotate_refresh(s, presented_secret=secret,
                                           new_refresh_secret=S.generate_refresh_secret())
                    await s.commit()
                except S.SessionError:
                    await s.rollback()

        async def do_logout():
            async with sm() as s:
                await gate.wait()
                await S.logout_by_refresh(s, presented_secret=secret)
                await s.commit()

        tasks = [asyncio.create_task(do_refresh()), asyncio.create_task(do_logout())]
        await asyncio.sleep(0.12)
        gate.set()
        await asyncio.gather(*tasks)

        async with sm() as s:  # disablement + session-wide revoke
            u = await s.get(User, uid)
            u.is_active = False
            await s.flush()
            await S.revoke_all_user_sessions(s, uid, reason="disabled")
            await s.commit()
        async with sm() as s:
            with pytest.raises(S.SessionError):
                await S.rotate_refresh(s, presented_secret=secret,
                                       new_refresh_secret=S.generate_refresh_secret())


@_t
async def test_expiry_vs_refresh_on_alembic_schema(_alembic_sm):
    async with _sm_from(_alembic_sm) as sm:
        uid = await _mk_user_async(sm, "exp")
        secret = S.generate_refresh_secret()
        async with sm() as s:
            await S.create_session(
                s, user_id=uid, refresh_secret=secret, ttl_seconds=300,
                now=datetime.now(timezone.utc) - timedelta(seconds=3600),
            )
            await s.commit()
        async with sm() as s:
            with pytest.raises(S.SessionExpiredError):
                await S.rotate_refresh(s, presented_secret=secret,
                                       new_refresh_secret=S.generate_refresh_secret())


__all__: list[str] = []
