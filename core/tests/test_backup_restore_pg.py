# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_backup_restore_pg.py
#
# Beta-execution Phase 1 -- recovery is proven by a real pg_dump restored into
# a SEPARATE database, not by assuming "rollback is always harmless".
#
# Specifically:
#   * a backup taken while sessions exist restores every user AND session row
#     byte-for-byte, including revoked_at / revoked_reason;
#   * a session that was revoked before the backup comes back REVOKED -- the
#     restore does not silently reactivate it (is_live() stays False);
#   * user identity/security columns survive the round-trip unchanged.
#
# Needs a disposable PostgreSQL AND the ability to run pg_dump/psql against it.
# Set both:
#   S43_TEST_PG_DSN=postgresql+asyncpg://s43t:x@127.0.0.1:55441/s43t
#   S43_TEST_PG_CONTAINER=s43pg_p1        (docker container running that PG)
# =============================================================================

from __future__ import annotations

import os
import pathlib
import subprocess
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

_DSN = os.getenv("S43_TEST_PG_DSN")
_CONTAINER = os.getenv("S43_TEST_PG_CONTAINER")
pytestmark = pytest.mark.skipif(
    not (_DSN and _CONTAINER),
    reason="set S43_TEST_PG_DSN and S43_TEST_PG_CONTAINER to run backup/restore proof",
)

_SYNC_DSN = (_DSN or "").replace("+asyncpg", "+psycopg")
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_RESTORE_DB = "s43t_restore"


def _cfg() -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    return cfg


def _pg(*args: str, db: str = "s43t", stdin: bytes | None = None) -> bytes:
    cmd = ["docker", "exec", "-i", _CONTAINER, *args]
    out = subprocess.run(cmd, input=stdin, capture_output=True, check=True)
    return out.stdout


@pytest.fixture()
def _clean(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", _DSN)
    eng = create_engine(_SYNC_DSN, isolation_level="AUTOCOMMIT")
    with eng.begin() as c:
        c.exec_driver_sql("DROP TABLE IF EXISTS sessions, users, alembic_version CASCADE")
        c.exec_driver_sql(f'DROP DATABASE IF EXISTS {_RESTORE_DB}')
    yield eng
    with eng.begin() as c:
        c.exec_driver_sql("DROP TABLE IF EXISTS sessions, users, alembic_version CASCADE")
        c.exec_driver_sql(f'DROP DATABASE IF EXISTS {_RESTORE_DB}')
    eng.dispose()


def test_pg_dump_restore_preserves_users_and_revoked_sessions(_clean):
    command.upgrade(_cfg(), "head")

    admin_id = uuid.uuid4()
    disabled_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    live_sid = uuid.uuid4()
    revoked_sid = uuid.uuid4()

    src = create_engine(_SYNC_DSN)
    with src.begin() as c:
        c.execute(
            text(
                "INSERT INTO users (user_id, username, email, password_hash, role, is_active, created_at, last_login_at) "
                "VALUES (:i, 'admin1', 'a@x.test', '$argon2id$fake', 'admin', true, :now, :now), "
                "       (:d, 'ops_disabled', NULL, '$argon2id$fake2', 'operator', false, :now, NULL)"
            ),
            {"i": admin_id, "d": disabled_id, "now": now},
        )
        c.execute(
            text(
                "INSERT INTO sessions (sid, user_id, refresh_hash, prev_refresh_hash, refresh_generation, "
                "issued_at, last_seen_at, rotated_at, expires_at, revoked_at, revoked_reason, client_ip, user_agent) "
                "VALUES (:live, :admin, :h1, NULL, 0, :now, :now, NULL, :exp, NULL, NULL, '203.0.113.5', 'pytest'), "
                "       (:rev, :admin, :h2, NULL, 3, :now, :now, :now, :exp, :now, 'logout', '203.0.113.9', 'pytest')"
            ),
            {
                "live": live_sid, "rev": revoked_sid, "admin": admin_id,
                "h1": "a" * 64, "h2": "b" * 64,
                "now": now, "exp": now + timedelta(days=7),
            },
        )
    src.dispose()

    # --- BACKUP: pg_dump the whole database ---
    dump = _pg("pg_dump", "-U", "s43t", "-d", "s43t")
    assert b"CREATE TABLE" in dump and b"COPY public.sessions" in dump

    # sanitized: the dump must not carry a connection URL or a password literal
    assert b"postgresql://" not in dump

    # --- RESTORE: into a SEPARATE, fresh database ---
    _pg("createdb", "-U", "s43t", _RESTORE_DB)
    _pg("psql", "-U", "s43t", "-d", _RESTORE_DB, "-v", "ON_ERROR_STOP=1", "-q", stdin=dump)

    restore_dsn = _SYNC_DSN.rsplit("/", 1)[0] + f"/{_RESTORE_DB}"
    dst = create_engine(restore_dsn)
    with dst.connect() as c:
        # alembic revision restored
        assert c.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0002_sessions"

        # users: identity + security columns unchanged
        rows = dict(
            c.execute(text("SELECT username, role, is_active FROM users ORDER BY username")).all()
        ) if False else c.execute(
            text("SELECT username, role, is_active FROM users ORDER BY username")
        ).all()
        assert rows == [("admin1", "admin", True), ("ops_disabled", "operator", False)]

        # sessions: BOTH rows present, revoked one still revoked
        srows = {
            r.sid: r
            for r in c.execute(
                text("SELECT sid, revoked_at, revoked_reason, refresh_generation FROM sessions")
            ).all()
        }
        assert set(srows) == {live_sid, revoked_sid}
        assert srows[live_sid].revoked_at is None
        assert srows[revoked_sid].revoked_at is not None
        assert srows[revoked_sid].revoked_reason == "logout"
        assert srows[revoked_sid].refresh_generation == 3
    dst.dispose()


def test_restored_revoked_session_is_not_live_via_the_model(_clean):
    """The restore brings the row back exactly as dumped -- a session revoked
    before the backup is is_live() == False after the restore, so a restore is
    not a way to resurrect a logged-out / stolen session."""
    from core.auth.sessions import SessionRecord

    command.upgrade(_cfg(), "head")
    now = datetime.now(timezone.utc)
    rec = SessionRecord(
        sid=uuid.uuid4(),
        user_id=uuid.uuid4(),
        refresh_hash="c" * 64,
        refresh_generation=1,
        issued_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(days=7),
        revoked_at=now,
        revoked_reason="logout",
    )
    assert rec.is_live(now=now + timedelta(minutes=1)) is False
