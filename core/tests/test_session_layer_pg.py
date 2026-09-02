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
# core/tests/test_session_layer_pg.py
#
# Pass 5A — server-side session layer (core/auth/sessions.py) against a REAL
# PostgreSQL. Row-level locking (SELECT ... FOR UPDATE) semantics and the
# "never more than one valid successor refresh generation" invariant under
# concurrency cannot be proven on SQLite, so this suite is PostgreSQL-only.
#
# Skipped unless S43_TEST_PG_DSN points at a DISPOSABLE PostgreSQL, e.g.:
#
#   docker run -d --rm --name s43pg --tmpfs /var/lib/postgresql/data \
#     -e POSTGRES_PASSWORD=x -e POSTGRES_DB=s43t -e POSTGRES_USER=s43t \
#     -p 127.0.0.1:55432:5432 postgres:16.3
#   S43_TEST_PG_DSN=postgresql+asyncpg://s43t:x@127.0.0.1:55432/s43t \
#     pytest core/tests/test_session_layer_pg.py
#
# PG version / isolation assumptions (also recorded in SESSION_MODEL_PASS5A.md):
#   * Tested against postgres:16.3 (matches docker-compose.yml).
#   * Default transaction isolation READ COMMITTED. The rotation/reuse
#     correctness argument relies only on: (a) SELECT ... FOR UPDATE blocking
#     a second writer until the first commits, and (b) READ COMMITTED
#     re-evaluating the lock predicate against the newest committed row
#     version (PostgreSQL EvalPlanQual). It does NOT require SERIALIZABLE.
#   * The sessions schema is created here via SessionBase.metadata.create_all;
#     it is NOT repository migration state (mission Pass 5A §14/§15).
#
# No pytest-asyncio: each test is a single asyncio.run() that owns its engine
# for the loop's lifetime (an async engine's pool is bound to its loop).
# =============================================================================

from __future__ import annotations

import asyncio
import contextlib
import functools
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from core.auth.users import Base as UsersBase, create_user, set_user_active
from core.auth import sessions as S

_DSN = os.getenv("S43_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(
    not _DSN, reason="set S43_TEST_PG_DSN to a disposable PostgreSQL to run"
)


@contextlib.asynccontextmanager
async def _db():
    """Fresh users+sessions schema + sessionmaker on the current loop."""
    engine = create_async_engine(_DSN, pool_size=25, max_overflow=25)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(S.SessionBase.metadata.drop_all)
            await conn.run_sync(UsersBase.metadata.drop_all)
            await conn.run_sync(UsersBase.metadata.create_all)
            await conn.run_sync(S.SessionBase.metadata.create_all)
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        async with engine.begin() as conn:
            await conn.run_sync(S.SessionBase.metadata.drop_all)
            await conn.run_sync(UsersBase.metadata.drop_all)
        await engine.dispose()


def _t(coro_fn):
    @functools.wraps(coro_fn)
    def wrapper(*a, **k):
        return asyncio.run(coro_fn(*a, **k))
    return wrapper


async def _mk_user(sm, username="op", *, active=True):
    async with sm() as s:
        u = await create_user(s, username=username, password="p" * 16, role="operator")
        if not active:
            await set_user_active(s, u, is_active=False)
        await s.commit()
        return u.user_id


# ---------------------------------------------------------------------------
# create / persistence / transaction ownership
# ---------------------------------------------------------------------------

@_t
async def test_create_session_does_not_commit():
    async with _db() as sm:
        uid = await _mk_user(sm)
        secret = S.generate_refresh_secret()
        async with sm() as s:
            await S.create_session(s, user_id=uid, refresh_secret=secret)
            # no commit -> discarded on context exit
        async with sm() as s:
            with pytest.raises(S.RefreshInvalidError):
                await S.rotate_refresh(
                    s, presented_secret=secret,
                    new_refresh_secret=S.generate_refresh_secret(),
                )


@_t
async def test_create_then_commit_persists_and_stores_only_the_hash():
    async with _db() as sm:
        uid = await _mk_user(sm)
        secret = S.generate_refresh_secret()
        async with sm() as s:
            row = await S.create_session(
                s, user_id=uid, refresh_secret=secret,
                client_ip="203.0.113.9", user_agent="pytest",
            )
            sid = row.sid
            await s.commit()
        async with sm() as s:
            got = await S.get_session_by_sid(s, sid)
            assert got is not None
            assert got.refresh_hash == S.hash_refresh_secret(secret)
            assert secret not in got.refresh_hash
            assert got.refresh_generation == 0
            assert got.prev_refresh_hash is None
            assert got.revoked_at is None
            assert got.client_ip == "203.0.113.9"
            # view model never leaks a hash
            view = S.SessionView.of(got)
            assert not hasattr(view, "refresh_hash")
            assert view.sid == str(sid)


# ---------------------------------------------------------------------------
# rotation
# ---------------------------------------------------------------------------

@_t
async def test_rotate_increments_generation_and_supersedes_old_secret():
    async with _db() as sm:
        uid = await _mk_user(sm)
        s1 = S.generate_refresh_secret()
        async with sm() as s:
            row = await S.create_session(s, user_id=uid, refresh_secret=s1)
            sid = row.sid
            await s.commit()

        s2 = S.generate_refresh_secret()
        async with sm() as s:
            row, outcome = await S.rotate_refresh(
                s, presented_secret=s1, new_refresh_secret=s2,
            )
            assert outcome is S.RefreshOutcome.ROTATED
            assert row.refresh_generation == 1
            assert row.refresh_hash == S.hash_refresh_secret(s2)
            assert row.prev_refresh_hash == S.hash_refresh_secret(s1)
            assert row.rotated_at is not None
            await s.commit()

        # the new secret works once; a third rotation supersedes it
        s3 = S.generate_refresh_secret()
        async with sm() as s:
            row, _ = await S.rotate_refresh(
                s, presented_secret=s2, new_refresh_secret=s3,
            )
            assert row.refresh_generation == 2
            await s.commit()


@_t
async def test_rotate_with_unknown_secret_is_invalid():
    async with _db() as sm:
        uid = await _mk_user(sm)
        async with sm() as s:
            await S.create_session(
                s, user_id=uid, refresh_secret=S.generate_refresh_secret()
            )
            await s.commit()
        async with sm() as s:
            with pytest.raises(S.RefreshInvalidError):
                await S.rotate_refresh(
                    s, presented_secret=S.generate_refresh_secret(),
                    new_refresh_secret=S.generate_refresh_secret(),
                )


# ---------------------------------------------------------------------------
# reuse detection (single-step)
# ---------------------------------------------------------------------------

@_t
async def test_reusing_superseded_secret_revokes_the_session():
    async with _db() as sm:
        uid = await _mk_user(sm)
        s1 = S.generate_refresh_secret()
        async with sm() as s:
            row = await S.create_session(s, user_id=uid, refresh_secret=s1)
            sid = row.sid
            await s.commit()

        s2 = S.generate_refresh_secret()
        async with sm() as s:
            await S.rotate_refresh(s, presented_secret=s1, new_refresh_secret=s2)
            await s.commit()

        # attacker replays the old (generation-0) secret
        async with sm() as s:
            with pytest.raises(S.RefreshReuseError) as ei:
                await S.rotate_refresh(
                    s, presented_secret=s1,
                    new_refresh_secret=S.generate_refresh_secret(),
                )
            assert ei.value.sid == sid
            await s.commit()   # persist the theft-response revocation (contract)

        # session is now dead: even the *legitimate* current secret is refused
        async with sm() as s:
            with pytest.raises(S.SessionRevokedError):
                await S.rotate_refresh(
                    s, presented_secret=s2,
                    new_refresh_secret=S.generate_refresh_secret(),
                )


# ---------------------------------------------------------------------------
# revocation / logout
# ---------------------------------------------------------------------------

@_t
async def test_revoke_session_is_idempotent():
    async with _db() as sm:
        uid = await _mk_user(sm)
        async with sm() as s:
            row = await S.create_session(
                s, user_id=uid, refresh_secret=S.generate_refresh_secret()
            )
            sid = row.sid
            await s.commit()
        async with sm() as s:
            assert await S.revoke_session(s, sid, reason="logout") is True
            await s.commit()
        async with sm() as s:
            assert await S.revoke_session(s, sid, reason="logout") is False
            assert await S.revoke_session(s, uuid.uuid4(), reason="x") is False
            await s.commit()


@_t
async def test_logout_by_refresh_idempotent_and_accepts_prev_generation():
    async with _db() as sm:
        uid = await _mk_user(sm)
        s1 = S.generate_refresh_secret()
        async with sm() as s:
            await S.create_session(s, user_id=uid, refresh_secret=s1)
            await s.commit()
        s2 = S.generate_refresh_secret()
        async with sm() as s:
            await S.rotate_refresh(s, presented_secret=s1, new_refresh_secret=s2)
            await s.commit()
        # logging out with the *superseded* value still ends the session
        async with sm() as s:
            assert await S.logout_by_refresh(s, presented_secret=s1) is True
            await s.commit()
        # repeated logout -> clean False, no raise
        async with sm() as s:
            assert await S.logout_by_refresh(s, presented_secret=s2) is False
            assert await S.logout_by_refresh(s, presented_secret="garbage") is False
            await s.commit()


@_t
async def test_revoke_all_user_sessions():
    async with _db() as sm:
        uid = await _mk_user(sm)
        other = await _mk_user(sm, "other")
        async with sm() as s:
            for _ in range(3):
                await S.create_session(
                    s, user_id=uid, refresh_secret=S.generate_refresh_secret()
                )
            await S.create_session(
                s, user_id=other, refresh_secret=S.generate_refresh_secret()
            )
            await s.commit()
        async with sm() as s:
            n = await S.revoke_all_user_sessions(s, uid, reason="password_change")
            assert n == 3
            await s.commit()
        async with sm() as s:
            # idempotent second sweep
            assert await S.revoke_all_user_sessions(s, uid, reason="x") == 0
            # other user's session untouched
            assert await S.revoke_all_user_sessions(s, other, reason="x") == 1
            await s.commit()


# ---------------------------------------------------------------------------
# expiry / account disablement
# ---------------------------------------------------------------------------

@_t
async def test_expired_session_cannot_refresh():
    async with _db() as sm:
        uid = await _mk_user(sm)
        secret = S.generate_refresh_secret()
        async with sm() as s:
            await S.create_session(
                s, user_id=uid, refresh_secret=secret, ttl_seconds=300,
                now=datetime.now(timezone.utc) - timedelta(seconds=3600),
            )
            await s.commit()
        async with sm() as s:
            with pytest.raises(S.SessionExpiredError):
                await S.rotate_refresh(
                    s, presented_secret=secret,
                    new_refresh_secret=S.generate_refresh_secret(),
                )


@_t
async def test_disabled_owner_cannot_refresh_and_session_is_revoked():
    async with _db() as sm:
        uid = await _mk_user(sm, "willdisable")
        secret = S.generate_refresh_secret()
        async with sm() as s:
            row = await S.create_session(s, user_id=uid, refresh_secret=secret)
            sid = row.sid
            await s.commit()
        # disable the account
        async with sm() as s:
            from core.auth.users import get_user_by_id
            u = await get_user_by_id(s, uid)
            await set_user_active(s, u, is_active=False)
            await s.commit()
        async with sm() as s:
            with pytest.raises(S.SessionOwnerInactiveError):
                await S.rotate_refresh(
                    s, presented_secret=secret,
                    new_refresh_secret=S.generate_refresh_secret(),
                )
            await s.commit()   # persist revocation (contract)
        async with sm() as s:
            got = await S.get_session_by_sid(s, sid)
            assert got.revoked_at is not None
            assert got.revoked_reason == "owner_inactive"


# ---------------------------------------------------------------------------
# unique constraint
# ---------------------------------------------------------------------------

@_t
async def test_refresh_hash_is_unique():
    async with _db() as sm:
        uid = await _mk_user(sm)
        secret = S.generate_refresh_secret()
        async with sm() as s:
            await S.create_session(s, user_id=uid, refresh_secret=secret)
            await s.commit()
        async with sm() as s:
            with pytest.raises(IntegrityError):
                # same secret -> same hash -> unique violation at flush
                await S.create_session(s, user_id=uid, refresh_secret=secret)


# ---------------------------------------------------------------------------
# CONCURRENCY (mission Pass 5A §16) — independent connections, real locking
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("racers", [2, 5])
@_t
async def test_two_concurrent_refreshes_yield_exactly_one_successor(racers):
    async with _db() as sm:
        uid = await _mk_user(sm)
        s1 = S.generate_refresh_secret()
        async with sm() as s:
            row = await S.create_session(s, user_id=uid, refresh_secret=s1)
            sid = row.sid
            await s.commit()

        gate = asyncio.Event()

        async def refresher(i):
            async with sm() as s:
                await gate.wait()
                try:
                    row, _ = await S.rotate_refresh(
                        s, presented_secret=s1,
                        new_refresh_secret=S.generate_refresh_secret(),
                    )
                    await s.commit()
                    return ("rotated", row.refresh_generation)
                except S.RefreshReuseError:
                    await s.commit()
                    return ("reuse", None)
                except (S.RefreshInvalidError, S.SessionRevokedError):
                    await s.rollback()
                    return ("rejected", None)

        tasks = [asyncio.create_task(refresher(i)) for i in range(racers)]
        await asyncio.sleep(0.15)
        gate.set()
        results = await asyncio.gather(*tasks)

        kinds = [r[0] for r in results]
        assert kinds.count("rotated") == 1, results
        assert "reuse" in kinds, results

        async with sm() as s:
            row = await S.get_session_by_sid(s, sid)
            # exactly one successor generation ever existed, and the
            # concurrent replay tripped theft-response revocation
            assert row.refresh_generation == 1
            assert row.revoked_at is not None
            assert row.revoked_reason == "refresh_reuse"


@_t
async def test_refresh_racing_logout_never_issues_after_logout():
    async with _db() as sm:
        uid = await _mk_user(sm)
        secret = S.generate_refresh_secret()
        async with sm() as s:
            row = await S.create_session(s, user_id=uid, refresh_secret=secret)
            sid = row.sid
            await s.commit()

        gate = asyncio.Event()
        outcomes: dict[str, str] = {}

        async def do_refresh():
            async with sm() as s:
                await gate.wait()
                try:
                    await S.rotate_refresh(
                        s, presented_secret=secret,
                        new_refresh_secret=S.generate_refresh_secret(),
                    )
                    await s.commit()
                    outcomes["refresh"] = "rotated"
                except S.SessionError:
                    await s.rollback()
                    outcomes["refresh"] = "denied"

        async def do_logout():
            async with sm() as s:
                await gate.wait()
                await S.logout_by_refresh(s, presented_secret=secret)
                await s.commit()
                outcomes["logout"] = "done"

        t = [asyncio.create_task(do_refresh()), asyncio.create_task(do_logout())]
        await asyncio.sleep(0.15)
        gate.set()
        await asyncio.gather(*t)

        async with sm() as s:
            row = await S.get_session_by_sid(s, sid)
            assert row.revoked_at is not None
            # whichever ran first, the session ends dead and no live successor
            # credential exists
            with pytest.raises(S.SessionError):
                await S.rotate_refresh(
                    s, presented_secret=secret,
                    new_refresh_secret=S.generate_refresh_secret(),
                )


@_t
async def test_refresh_racing_disablement():
    async with _db() as sm:
        uid = await _mk_user(sm, "racer")
        secret = S.generate_refresh_secret()
        async with sm() as s:
            await S.create_session(s, user_id=uid, refresh_secret=secret)
            await s.commit()

        gate = asyncio.Event()
        result: dict[str, str] = {}

        async def do_refresh():
            async with sm() as s:
                await gate.wait()
                try:
                    _, _ = await S.rotate_refresh(
                        s, presented_secret=secret,
                        new_refresh_secret=S.generate_refresh_secret(),
                    )
                    await s.commit()
                    result["r"] = "rotated"
                except S.SessionError:
                    await s.commit()
                    result["r"] = "denied"

        async def do_disable():
            async with sm() as s:
                from core.auth.users import get_user_by_id
                await gate.wait()
                u = await get_user_by_id(s, uid)
                await set_user_active(s, u, is_active=False)
                await s.commit()
                # session-wide revoke is what Pass 5B wires to disablement
                await S.revoke_all_user_sessions(s, uid, reason="disabled")
                await s.commit()

        t = [asyncio.create_task(do_refresh()), asyncio.create_task(do_disable())]
        await asyncio.sleep(0.15)
        gate.set()
        await asyncio.gather(*t)

        # After the dust settles the account is disabled and no session may
        # refresh, regardless of who won the race.
        async with sm() as s:
            with pytest.raises(S.SessionError):
                await S.rotate_refresh(
                    s, presented_secret=secret,
                    new_refresh_secret=S.generate_refresh_secret(),
                )


@_t
async def test_expiration_racing_refresh_is_atomic():
    """A refresh that arrives around the expiry boundary must resolve to
    exactly one of {rotated (gen 1), SessionExpiredError (gen 0)} — never a
    torn state where the row was mutated but the call also failed."""
    async with _db() as sm:
        uid = await _mk_user(sm)

        async def run_once(ttl_offset_seconds: float) -> tuple[str, int]:
            secret = S.generate_refresh_secret()
            async with sm() as s:
                row = await S.create_session(
                    s, user_id=uid, refresh_secret=secret,
                    ttl_seconds=300,
                    now=datetime.now(timezone.utc)
                    - timedelta(seconds=300)
                    + timedelta(seconds=ttl_offset_seconds),
                )
                sid = row.sid
                await s.commit()
            async with sm() as s:
                try:
                    r, _ = await S.rotate_refresh(
                        s, presented_secret=secret,
                        new_refresh_secret=S.generate_refresh_secret(),
                    )
                    await s.commit()
                    kind = "rotated"
                except S.SessionExpiredError:
                    await s.rollback()
                    kind = "expired"
            async with sm() as s:
                got = await S.get_session_by_sid(s, sid)
            return kind, got.refresh_generation

        # clearly still valid -> rotated, gen 1
        assert await run_once(60.0) == ("rotated", 1)
        # clearly expired -> expired, gen 0 (no partial mutation persisted)
        assert await run_once(-60.0) == ("expired", 0)


@_t
async def test_repeated_logout_is_clean():
    async with _db() as sm:
        uid = await _mk_user(sm)
        secret = S.generate_refresh_secret()
        async with sm() as s:
            await S.create_session(s, user_id=uid, refresh_secret=secret)
            await s.commit()
        for i in range(5):
            async with sm() as s:
                got = await S.logout_by_refresh(s, presented_secret=secret)
                await s.commit()
                assert got is (i == 0)


__all__: list[str] = []
