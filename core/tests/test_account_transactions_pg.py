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
# core/tests/test_account_transactions_pg.py
#
# Pass 3 — account transaction ownership + first-admin / last-admin
# concurrency, against a REAL PostgreSQL (advisory-lock semantics don't exist
# on SQLite, so an in-memory fake cannot prove them).
#
# Skipped unless S43_TEST_PG_DSN points at a DISPOSABLE PostgreSQL, e.g.:
#
#   docker run -d --rm --name s43pg --tmpfs /var/lib/postgresql/data \
#     -e POSTGRES_PASSWORD=x -e POSTGRES_DB=s43t -e POSTGRES_USER=s43t \
#     -p 127.0.0.1:55432:5432 postgres:16
#   S43_TEST_PG_DSN=postgresql+asyncpg://s43t:x@127.0.0.1:55432/s43t \
#     pytest core/tests/test_account_transactions_pg.py
#
# Each test drops+recreates the schema on its own event loop, so it must
# never point at real data. No pytest-asyncio dependency: every test is a
# single asyncio.run() that owns its engine for the loop's lifetime (an async
# engine's connection pool is bound to the loop it was created on).
# =============================================================================

from __future__ import annotations

import asyncio
import contextlib
import functools
import os

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from core.auth.users import (
    ADMIN_INVARIANT_LOCK_KEY,
    Base,
    FirstAdminExistsError,
    UsernameTakenError,
    _pg_advisory_xact_lock,
    count_active_admins,
    create_first_admin,
    create_user,
    get_user_by_id,
    get_user_by_username,
    set_user_active,
    set_user_role,
)

_DSN = os.getenv("S43_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(
    not _DSN, reason="set S43_TEST_PG_DSN to a disposable PostgreSQL to run"
)


@contextlib.asynccontextmanager
async def _db():
    """Fresh schema + sessionmaker, on the current event loop. Engine disposed
    on exit."""
    engine = create_async_engine(_DSN, pool_size=25, max_overflow=25)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()


def _t(coro_fn):
    """Decorator: run an async test body via asyncio.run(), keeping the
    original signature so pytest parametrize/fixtures still introspect it."""
    @functools.wraps(coro_fn)
    def wrapper(*a, **k):
        return asyncio.run(coro_fn(*a, **k))
    return wrapper


# ---------------------------------------------------------------------------
# transaction ownership
# ---------------------------------------------------------------------------

@_t
async def test_create_user_does_not_commit():
    async with _db() as sm:
        async with sm() as s:
            await create_user(s, username="rolls-back", password="p" * 16)
            # no commit -> discarded on context exit
        async with sm() as s2:
            assert await get_user_by_username(s2, "rolls-back") is None


@_t
async def test_create_user_commit_persists():
    async with _db() as sm:
        async with sm() as s:
            await create_user(s, username="kept", password="p" * 16)
            await s.commit()
        async with sm() as s2:
            assert await get_user_by_username(s2, "kept") is not None


@_t
async def test_role_and_active_change_is_one_atomic_transaction():
    """PATCH /users: role AND is_active in one transaction; a failure after
    the first mutation leaves NEITHER persisted."""
    async with _db() as sm:
        async with sm() as s:
            u = await create_user(s, username="patchme", password="p" * 16, role="operator")
            await s.commit()
            uid = u.user_id

        with pytest.raises(RuntimeError):
            async with sm() as s:
                target = await get_user_by_id(s, uid)
                await set_user_role(s, target, role="admin")
                await set_user_active(s, target, is_active=False)
                raise RuntimeError("boom before commit")

        async with sm() as s:
            got = await get_user_by_username(s, "patchme")
            assert (got.role, got.is_active) == ("operator", True)


@_t
async def test_duplicate_username_raises_integrityerror_at_flush():
    async with _db() as sm:
        async with sm() as s:
            await create_user(s, username="dup", password="p" * 16)
            await s.commit()
        async with sm() as s:
            with pytest.raises(IntegrityError):
                await create_user(s, username="dup", password="p" * 16)


@_t
async def test_advisory_lock_released_on_rollback():
    async with _db() as sm:
        async with sm() as s:
            await _pg_advisory_xact_lock(s, ADMIN_INVARIANT_LOCK_KEY)
            held = (await s.execute(
                text("SELECT count(*) FROM pg_locks WHERE locktype='advisory'")
            )).scalar()
            await s.rollback()
        async with sm() as s2:
            after = (await s2.execute(
                text("SELECT count(*) FROM pg_locks WHERE locktype='advisory'")
            )).scalar()
        assert held >= 1 and after == 0


# ---------------------------------------------------------------------------
# first-admin concurrency (finding #12) — independent connections
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("contenders", [2, 8, 20])
@_t
async def test_first_admin_created_exactly_once_under_concurrency(contenders):
    async with _db() as sm:
        gate = asyncio.Event()

        async def contender(i):
            async with sm() as s:
                await gate.wait()
                try:
                    await create_first_admin(s, username=f"admin{i}", password="p" * 16)
                    await s.commit()
                    return "created"
                except (FirstAdminExistsError, UsernameTakenError):
                    return "rejected"

        tasks = [asyncio.create_task(contender(i)) for i in range(contenders)]
        await asyncio.sleep(0.15)
        gate.set()
        results = await asyncio.gather(*tasks)
        async with sm() as s:
            n = await count_active_admins(s)

    assert results.count("created") == 1, results
    assert n == 1


# ---------------------------------------------------------------------------
# last-admin invariant under concurrent demotion
# ---------------------------------------------------------------------------

@_t
async def test_last_two_admins_cannot_both_be_demoted_concurrently():
    async with _db() as sm:
        async with sm() as s:
            a = await create_user(s, username="A", password="p" * 16, role="admin")
            b = await create_user(s, username="B", password="p" * 16, role="admin")
            await s.commit()
            aid, bid = a.user_id, b.user_id

        gate = asyncio.Event()

        async def demote(uid):
            async with sm() as s:
                await gate.wait()
                await _pg_advisory_xact_lock(s, ADMIN_INVARIANT_LOCK_KEY)
                target = await get_user_by_id(s, uid)
                is_active_admin = target.is_active and target.role == "admin"
                if is_active_admin and await count_active_admins(s) <= 1:
                    return "blocked"
                await set_user_role(s, target, role="operator")
                await s.commit()
                return "demoted"

        tasks = [asyncio.create_task(demote(aid)), asyncio.create_task(demote(bid))]
        await asyncio.sleep(0.15)
        gate.set()
        res = await asyncio.gather(*tasks)
        async with sm() as s:
            n = await count_active_admins(s)

    assert sorted(res) == ["blocked", "demoted"], res
    assert n == 1


__all__: list[str] = []
