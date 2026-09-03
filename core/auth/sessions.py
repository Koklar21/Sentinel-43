# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
#
# Sentinel-43 is distributed under a dual-license model:
#
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
# =============================================================================

"""
File: core/auth/sessions.py

Authentication **foundation** for the browser-session redesign
(AUTH_ARCHITECTURE_PASS4.md "Model B"). Pass 5A scope:

  * the server-side session domain model (SQLAlchemy + a plain read model)
  * refresh-credential cryptographic primitives (generate / hash / verify)
  * refresh rotation, single-step reuse detection, revocation, logout — all
    as isolated service-level functions with deliberate transaction ownership
  * double-submit CSRF token primitives
  * new-style access-token claim helpers (``jti`` / ``sid``)

**This module is not wired into any live request path in Pass 5A.** Nothing
here is imported by ``core/api/main.py`` startup, ``core/api/routers/auth.py``
route bodies, ``core/auth/deps.py``, or the WebSocket handler. Legacy auth
(Bearer JWT + ``X-S43-Password``) is unchanged. See ``SESSION_MODEL_PASS5A.md``
and ``PASS5A_VALIDATION.md``.

Deliberate design choices (mission Pass 5A §7, §14, §15):

  * ``SessionRecord`` uses its **own** declarative ``Base`` (``SessionBase``),
    NOT ``core.auth.users.Base``. ``users.init_models()`` calls
    ``users.Base.metadata.create_all`` — because the sessions table lives on a
    separate metadata, that call still creates only ``users``. The sessions
    table therefore does **not** enter production bootstrap behaviour in this
    pass. ``ensure_session_schema()`` below exists for disposable-PostgreSQL
    testing only and is never called at app startup.
  * The engine / sessionmaker are reused from ``core.auth.users`` (same
    Postgres, same asyncpg pool) via ``get_sessionmaker()``.
  * Service functions never ``commit()``. They validate, mutate ORM state,
    and ``flush()`` — the calling request/service owns the transaction, the
    same contract Pass 3 established for ``core/auth/users.py``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from sqlalchemy import (
    DateTime,
    Index,
    Integer,
    MetaData,
    String,
    Uuid,
    select,
    text,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# The engine comes from the account module — one database, one asyncpg pool.
# NAMING_CONVENTION is shared so Alembic manages both metadata objects with
# identical, reproducible constraint/index names (Pass 5AM mission §5).
from .users import NAMING_CONVENTION, User, get_engine

__all__ = [
    "SessionBase",
    "SessionRecord",
    "SessionView",
    "RefreshOutcome",
    # exceptions
    "SessionError",
    "RefreshInvalidError",
    "RefreshReuseError",
    "SessionExpiredError",
    "SessionRevokedError",
    "SessionOwnerInactiveError",
    # refresh-credential primitives
    "generate_refresh_secret",
    "hash_refresh_secret",
    "verify_refresh_hash",
    "REFRESH_SECRET_ENTROPY_BITS",
    # CSRF primitives
    "generate_csrf_token",
    "csrf_tokens_match",
    # access-token claim helpers
    "new_jti",
    "new_sid",
    "claims_are_session_bound",
    "SESSION_ID_RE",
    # config
    "refresh_ttl_seconds",
    # service-level session logic
    "create_session",
    "get_session_by_sid",
    "resolve_live_session",
    "rotate_refresh",
    "revoke_session",
    "revoke_all_user_sessions",
    "logout_by_refresh",
    "purge_expired_sessions",
    # test-only schema helper (never called at app startup)
    "ensure_session_schema",
    "drop_session_schema",
]


# =============================================================================
# Exceptions — framework-agnostic. Routers/services map these to HTTP codes.
# =============================================================================

class SessionError(Exception):
    """Base for expected, caller-handled session-operation failures."""


class RefreshInvalidError(SessionError):
    """Presented refresh credential matches no live session (→ 401)."""


class RefreshReuseError(SessionError):
    """
    Presented refresh credential matches a session's *superseded* generation.
    Treated as credential theft: the whole session is revoked and the caller
    must map this to 401 + clear-cookie. ``.sid`` names the revoked session.
    """

    def __init__(self, sid: uuid.UUID) -> None:
        super().__init__(f"refresh credential reuse detected for session {sid}")
        self.sid = sid


class SessionExpiredError(SessionError):
    """The matched session is past its absolute ``expires_at`` cap (→ 401)."""

    def __init__(self, sid: uuid.UUID) -> None:
        super().__init__(f"session {sid} has expired")
        self.sid = sid


class SessionRevokedError(SessionError):
    """The matched session was already revoked (logout / theft / admin) (→ 401)."""

    def __init__(self, sid: uuid.UUID) -> None:
        super().__init__(f"session {sid} is revoked")
        self.sid = sid


class SessionOwnerInactiveError(SessionError):
    """The session's owning account is disabled (→ 401 + session revoked)."""

    def __init__(self, sid: uuid.UUID) -> None:
        super().__init__(f"account for session {sid} is inactive")
        self.sid = sid


# =============================================================================
# Refresh-credential primitives
#
# Entropy justification (mission Pass 5A §7 — "document the entropy
# assumptions"):
#
#   generate_refresh_secret() returns secrets.token_urlsafe(32): 32 bytes
#   (256 bits) drawn from os.urandom via the `secrets` module — a full-entropy,
#   uniformly random value, NOT a user-chosen or low-entropy secret.
#
#   The stored verifier is a single SHA-256 of that value. This is the correct
#   construction for a high-entropy bearer credential:
#     - There is no dictionary / guessing attack to slow down, so a
#       memory-hard KDF (Argon2/bcrypt/scrypt) or PBKDF iteration count buys
#       nothing here — those defend *low-entropy human passwords*.
#     - Per-row salting buys nothing: salts defeat precomputed rainbow tables
#       against low-entropy inputs; a 256-bit random pre-image has no
#       precomputable table.
#     - A stolen database dump yields only SHA-256 digests; recovering the
#       256-bit pre-images is infeasible.
#   Lookups compare digests with secrets.compare_digest (constant time).
#
#   Optional future hardening (NOT implemented in Pass 5A — would add env
#   surface): keyed hashing, hmac.new(server_pepper, secret, sha256), so a DB
#   dump alone cannot be replayed against a different deployment. The code
#   path below already funnels through _digest() so this is a one-line change
#   when a deployment pass decides to add S43_SESSION_HASH_PEPPER.
# =============================================================================

REFRESH_SECRET_ENTROPY_BITS = 256
_REFRESH_SECRET_NBYTES = REFRESH_SECRET_ENTROPY_BITS // 8

# Absolute session lifetime cap (sliding rotation never extends past this).
_DEFAULT_REFRESH_TTL_SECONDS = 7 * 24 * 3600  # 7 days
_REFRESH_TTL_LO = 300            # 5 min floor (keeps tests honest)
_REFRESH_TTL_HI = 30 * 24 * 3600  # 30 day ceiling


def refresh_ttl_seconds() -> int:
    """
    Absolute refresh-session lifetime, read at call time from
    ``S43_SESSION_REFRESH_TTL_SECONDS`` (default 7 days, clamped
    5 min .. 30 days). Read at call time so nothing breaks on import.
    """
    raw = os.getenv("S43_SESSION_REFRESH_TTL_SECONDS")
    if raw is None:
        return _DEFAULT_REFRESH_TTL_SECONDS
    try:
        return max(_REFRESH_TTL_LO, min(_REFRESH_TTL_HI, int(raw.strip())))
    except ValueError:
        return _DEFAULT_REFRESH_TTL_SECONDS


def generate_refresh_secret() -> str:
    """A fresh opaque 256-bit URL-safe refresh credential. Not a JWT."""
    return secrets.token_urlsafe(_REFRESH_SECRET_NBYTES)


def _digest(secret: str) -> str:
    """
    The stored-verifier construction. Isolated in one function so a keyed
    variant can be swapped in later without touching call sites.
    """
    pepper = os.getenv("S43_SESSION_HASH_PEPPER", "").strip()
    raw = secret.encode("utf-8")
    if pepper:
        return hmac.new(pepper.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return hashlib.sha256(raw).hexdigest()


def hash_refresh_secret(secret: str) -> str:
    """Return the stored verifier for a refresh secret (lowercase hex)."""
    if not isinstance(secret, str) or not secret:
        raise ValueError("refresh secret must be a non-empty string")
    return _digest(secret)


def verify_refresh_hash(secret: str, stored_hash: str) -> bool:
    """Constant-time check that ``secret`` hashes to ``stored_hash``.

    Fails closed (returns False) on any malformed input — never raises."""
    try:
        if not secret or not stored_hash:
            return False
        return hmac.compare_digest(_digest(secret), stored_hash)
    except (TypeError, AttributeError):
        return False


# =============================================================================
# CSRF primitives — double-submit cookie/header pair for /auth/refresh and
# /auth/logout (AUTH_ARCHITECTURE_PASS4.md §6). Primitives only in Pass 5A:
# nothing sets or checks a CSRF cookie in a live path yet.
# =============================================================================

_CSRF_TOKEN_NBYTES = 32  # 256-bit


def generate_csrf_token() -> str:
    """A fresh 256-bit URL-safe CSRF token (for the double-submit pair)."""
    return secrets.token_urlsafe(_CSRF_TOKEN_NBYTES)


def csrf_tokens_match(cookie_value: Optional[str], header_value: Optional[str]) -> bool:
    """
    Constant-time equality for the double-submit pair. Both sides must be
    present and non-empty; a missing half is a failed check, not a pass.
    Fails closed on any malformed input.
    """
    try:
        if not cookie_value or not header_value:
            return False
        return hmac.compare_digest(str(cookie_value), str(header_value))
    except (TypeError, AttributeError):
        return False


# =============================================================================
# Access-token claim helpers
#
# New-style (session-bound) access tokens carry `sid` (the server-side session
# id) and `jti` (a unique token id). Legacy tokens carry neither. Presence of
# a well-formed `sid` claim is the *explicit* discriminator — set by the
# issuer, never inferred from timing/shape. See core/api/routers/auth.py
# `_issue_token(..., sid=...)` and `token_is_session_bound()`.
# =============================================================================

SESSION_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def new_jti() -> str:
    """A unique, opaque token identifier for the `jti` claim (128-bit)."""
    return secrets.token_urlsafe(16)


def new_sid() -> str:
    """A new session id string (canonical UUID form) for the `sid` claim."""
    return str(uuid.uuid4())


def claims_are_session_bound(claims: object) -> bool:
    """
    True iff ``claims`` carries a well-formed ``sid`` (i.e. it is a new-style
    session-bound access token). False for legacy tokens. Never raises.
    """
    try:
        sid = claims.get("sid")  # type: ignore[union-attr]
    except (AttributeError, TypeError):
        return False
    return isinstance(sid, str) and bool(SESSION_ID_RE.match(sid))


# =============================================================================
# Domain model
# =============================================================================

class SessionBase(DeclarativeBase):
    """
    Dedicated declarative base for the sessions table. Kept separate from
    ``core.auth.users.Base`` on purpose: ``users.init_models()`` must keep
    creating only the ``users`` table (mission Pass 5A §14 — no change to
    production DB bootstrap; Alembic 0002_sessions owns this table now).

    Uses the same ``NAMING_CONVENTION`` as ``users.Base`` so Alembic
    generates reproducible constraint/index names for both (Pass 5AM §5).
    """

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class SessionRecord(SessionBase):
    """
    One server-side browser session (AUTH_ARCHITECTURE_PASS4.md §3.2).

    The opaque refresh credential is never stored — only ``refresh_hash``
    (current generation) and ``prev_refresh_hash`` (the single immediately
    superseded generation, retained for one-step reuse detection).
    """

    __tablename__ = "sessions"

    # --- refresh-hash uniqueness: shape B (Pass 5AM §14) ---------------------
    # A PARTIAL unique index over the ACTIVE (non-revoked) rows only — NOT an
    # unconditional UNIQUE across all rows. It enforces the Pass 5A invariant
    # ("one parent refresh generation -> at most one valid successor") while
    # still permitting a superseded/revoked historical row to retain a hash
    # that a later active row could also hold. An unconditional UNIQUE
    # (shape A) would forbid that and break legitimate rotation/replay
    # history. See MIGRATION_ARCHITECTURE_PASS5AM.md §refresh-hash-constraint.
    # 0002_sessions creates this exact index; the model and migration agree.
    __table_args__ = (
        Index(
            "uq_sessions_active_refresh_hash",
            "refresh_hash",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )

    sid: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Logical FK to users.user_id. Kept as a plain indexed column in the ORM
    # (SessionRecord lives on a separate MetaData from User so the two remain
    # bounded contexts — users.init_models() must never create `sessions`,
    # Pass 5A §14 / Pass 5AM §7). The REAL foreign key
    # `fk_sessions_user_id_users ... ON DELETE RESTRICT` is created by
    # 0002_sessions (Pass 5AM §15: no user-deletion pathway exists in the
    # codebase, so RESTRICT is the least-destructive default). Alembic's
    # autogenerate metadata reconstructs this FK — see
    # MIGRATION_ARCHITECTURE_PASS5AM.md.
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), nullable=False, index=True
    )
    refresh_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_refresh_hash: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, index=True
    )
    refresh_generation: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    rotated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # indexed: purge_expired_sessions() filters on expires_at (Pass 5AM §16)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_reason: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    client_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    def is_live(self, *, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return self.revoked_at is None and _aware(self.expires_at) > now


@dataclass(frozen=True)
class SessionView:
    """
    Immutable read model for surfacing a session to an operator (their own
    "active sessions" list) without exposing ORM state or any hash.
    """

    sid: str
    user_id: str
    issued_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    revoked: bool
    revoked_reason: Optional[str]
    client_ip: Optional[str]
    user_agent: Optional[str]
    refresh_generation: int

    @classmethod
    def of(cls, row: "SessionRecord") -> "SessionView":
        return cls(
            sid=str(row.sid),
            user_id=str(row.user_id),
            issued_at=_aware(row.issued_at),
            last_seen_at=_aware(row.last_seen_at),
            expires_at=_aware(row.expires_at),
            revoked=row.revoked_at is not None,
            revoked_reason=row.revoked_reason,
            client_ip=row.client_ip,
            user_agent=row.user_agent,
            refresh_generation=row.refresh_generation,
        )


class RefreshOutcome(str, Enum):
    ROTATED = "rotated"


def _aware(dt: datetime) -> datetime:
    """Treat a naive timestamp from the DB as UTC (asyncpg returns aware;
    SQLite / some drivers return naive)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _truncate(value: Optional[str], limit: int) -> Optional[str]:
    if value is None:
        return None
    value = str(value)
    return value[:limit] if len(value) > limit else value


# =============================================================================
# Service-level session logic
#
# Transaction ownership: NONE of these commit. They flush so DB-side defaults
# and constraint violations surface inside the caller's transaction, exactly
# like core/auth/users.py. The caller (a future /auth/* route in Pass 5B)
# commits on success and rolls back on failure.
#
# Concurrency: rotate_refresh() / revoke_session() / logout_by_refresh() take a
# row-level lock (SELECT ... FOR UPDATE) on the session row so two concurrent
# refreshes — or a refresh racing a logout / disablement — serialize on the
# database rather than racing to produce two successor generations. Verified
# against real PostgreSQL 16.3 in core/tests/test_session_layer_pg.py.
# =============================================================================

async def create_session(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    refresh_secret: str,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
    now: Optional[datetime] = None,
) -> SessionRecord:
    """
    Create a new server-side session for ``user_id`` bound to ``refresh_secret``
    (only its hash is stored). Flushes; does NOT commit.
    """
    now = now or datetime.now(timezone.utc)
    ttl = ttl_seconds if ttl_seconds is not None else refresh_ttl_seconds()

    row = SessionRecord(
        sid=uuid.uuid4(),
        user_id=user_id,
        refresh_hash=hash_refresh_secret(refresh_secret),
        prev_refresh_hash=None,
        refresh_generation=0,
        issued_at=now,
        last_seen_at=now,
        rotated_at=None,
        expires_at=now + timedelta(seconds=ttl),
        revoked_at=None,
        revoked_reason=None,
        client_ip=_truncate(client_ip, 45),
        user_agent=_truncate(user_agent, 256),
    )
    session.add(row)
    await session.flush()
    return row


async def get_session_by_sid(
    session: AsyncSession, sid: uuid.UUID, *, for_update: bool = False
) -> Optional[SessionRecord]:
    stmt = select(SessionRecord).where(SessionRecord.sid == sid)
    if for_update:
        stmt = stmt.with_for_update()
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def resolve_live_session(
    session: AsyncSession, sid: uuid.UUID, *, now: Optional[datetime] = None
) -> tuple[SessionRecord, User]:
    """
    Return ``(session_row, owner)`` iff the session ``sid`` is live (not
    revoked, not expired) AND its owning account is active. Read-only — no
    lock, no write (the request hot path; beta-execution Phase B). Raises the
    matching :class:`SessionError` subclass otherwise:

      no such sid            -> RefreshInvalidError
      revoked                -> SessionRevokedError
      past expires_at        -> SessionExpiredError
      owner missing/disabled -> SessionOwnerInactiveError
    """
    now = now or datetime.now(timezone.utc)
    row = await get_session_by_sid(session, sid)
    if row is None:
        raise RefreshInvalidError("no session matches the presented sid")
    if row.revoked_at is not None:
        raise SessionRevokedError(row.sid)
    if _aware(row.expires_at) <= now:
        raise SessionExpiredError(row.sid)
    result = await session.execute(select(User).where(User.user_id == row.user_id))
    owner = result.scalar_one_or_none()
    if owner is None or not owner.is_active:
        raise SessionOwnerInactiveError(row.sid)
    return row, owner


async def _lock_session_for_refresh(
    session: AsyncSession, presented_hash: str
) -> Optional[SessionRecord]:
    """
    Row-lock the session whose current OR immediately-superseded refresh hash
    equals ``presented_hash``. The ``OR prev_refresh_hash`` arm is what lets a
    caller that lost a rotation race still find the row (via its previous
    generation) and correctly classify the presentation as reuse.
    """
    stmt = (
        select(SessionRecord)
        .where(
            (SessionRecord.refresh_hash == presented_hash)
            | (SessionRecord.prev_refresh_hash == presented_hash)
        )
        .with_for_update()
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def rotate_refresh(
    session: AsyncSession,
    *,
    presented_secret: str,
    new_refresh_secret: str,
    now: Optional[datetime] = None,
) -> tuple[SessionRecord, RefreshOutcome]:
    """
    Consume ``presented_secret`` and rotate the session to
    ``new_refresh_secret``. The single source of truth for refresh semantics.

    Ordering of checks (all fail closed):
      1. locate + row-lock the session (current or prev generation)
      2. no match                       -> RefreshInvalidError
      3. matched the *prev* generation  -> revoke session, RefreshReuseError
      4. session already revoked         -> SessionRevokedError
      5. session past expires_at         -> SessionExpiredError
      6. owning account is inactive      -> revoke session, SessionOwnerInactiveError
      7. otherwise: rotate (prev<-current, current<-new, generation++,
         last_seen/rotated bumped), flush, return (row, ROTATED)

    Never commits — the caller owns the transaction. **Contract on the
    revoke-and-raise branches (3 and 6):** the session row has been mutated to
    ``revoked_at = now`` and flushed; the caller MUST ``commit()`` before
    surfacing the 401 so the theft/disablement response actually persists
    (rolling back would silently discard the revocation). Branches 2/4/5 make
    no writes, so the caller can roll back freely.

    Because step 1 takes ``FOR UPDATE``, two concurrent callers with the same
    ``presented_secret`` serialize: the first rotates + commits, the second
    then re-reads the committed row, matches on ``prev_refresh_hash`` and hits
    step 3 (theft response). At most one successor generation is ever
    produced.
    """
    now = now or datetime.now(timezone.utc)
    presented_hash = hash_refresh_secret(presented_secret)

    row = await _lock_session_for_refresh(session, presented_hash)
    if row is None:
        raise RefreshInvalidError("no session matches the presented refresh credential")

    # Reuse: the presented value is a superseded generation, not the current one.
    if not hmac.compare_digest(row.refresh_hash, presented_hash):
        # (must therefore have matched prev_refresh_hash)
        await _revoke(row, reason="refresh_reuse", now=now)
        await session.flush()
        raise RefreshReuseError(row.sid)

    if row.revoked_at is not None:
        raise SessionRevokedError(row.sid)

    if _aware(row.expires_at) <= now:
        raise SessionExpiredError(row.sid)

    if not await _owner_is_active(session, row.user_id):
        await _revoke(row, reason="owner_inactive", now=now)
        await session.flush()
        raise SessionOwnerInactiveError(row.sid)

    row.prev_refresh_hash = row.refresh_hash
    row.refresh_hash = hash_refresh_secret(new_refresh_secret)
    row.refresh_generation += 1
    row.last_seen_at = now
    row.rotated_at = now
    await session.flush()
    return row, RefreshOutcome.ROTATED


async def revoke_session(
    session: AsyncSession,
    sid: uuid.UUID,
    *,
    reason: str,
    now: Optional[datetime] = None,
) -> bool:
    """
    Revoke one session by id. Idempotent: revoking an already-revoked (or
    absent) session is a no-op success. Returns True iff this call transitioned
    a live session to revoked. Row-locked; flushes; does NOT commit.
    """
    now = now or datetime.now(timezone.utc)
    row = await get_session_by_sid(session, sid, for_update=True)
    if row is None or row.revoked_at is not None:
        return False
    await _revoke(row, reason=reason, now=now)
    await session.flush()
    return True


async def revoke_all_user_sessions(
    session: AsyncSession,
    user_id: uuid.UUID,
    *,
    reason: str,
    now: Optional[datetime] = None,
) -> int:
    """
    Revoke every live session for a user (password change / disablement /
    role change / admin action). Returns the number newly revoked. Flushes;
    does NOT commit.
    """
    now = now or datetime.now(timezone.utc)
    stmt = (
        select(SessionRecord)
        .where(SessionRecord.user_id == user_id, SessionRecord.revoked_at.is_(None))
        .with_for_update()
    )
    rows = list((await session.execute(stmt)).scalars().all())
    for row in rows:
        await _revoke(row, reason=reason, now=now)
    if rows:
        await session.flush()
    return len(rows)


async def logout_by_refresh(
    session: AsyncSession,
    *,
    presented_secret: str,
    now: Optional[datetime] = None,
) -> bool:
    """
    Log out the session identified by ``presented_secret`` (current or
    superseded generation). Idempotent — an unknown or already-revoked
    credential returns False without raising, so a double logout, or a logout
    after the cookie already expired, is a clean success at the route layer.
    Returns True iff this call revoked a live session. Row-locked; flushes;
    does NOT commit.
    """
    now = now or datetime.now(timezone.utc)
    try:
        presented_hash = hash_refresh_secret(presented_secret)
    except ValueError:
        return False
    row = await _lock_session_for_refresh(session, presented_hash)
    if row is None or row.revoked_at is not None:
        return False
    await _revoke(row, reason="logout", now=now)
    await session.flush()
    return True


async def purge_expired_sessions(
    session: AsyncSession,
    *,
    older_than: Optional[datetime] = None,
    now: Optional[datetime] = None,
) -> int:
    """
    Hard-delete sessions whose ``expires_at`` is in the past (housekeeping;
    revoked-but-unexpired rows are kept for audit until they also expire).
    Returns the delete count. Flushes; does NOT commit. Not wired to any
    scheduler in Pass 5A.
    """
    now = now or datetime.now(timezone.utc)
    cutoff = older_than or now
    stmt = select(SessionRecord).where(SessionRecord.expires_at <= cutoff)
    rows = list((await session.execute(stmt)).scalars().all())
    for row in rows:
        await session.delete(row)
    if rows:
        await session.flush()
    return len(rows)


# --- internal helpers --------------------------------------------------------

async def _revoke(row: SessionRecord, *, reason: str, now: datetime) -> None:
    if row.revoked_at is None:
        row.revoked_at = now
        row.revoked_reason = _truncate(reason, 64)


async def _owner_is_active(session: AsyncSession, user_id: uuid.UUID) -> bool:
    result = await session.execute(
        select(User.is_active).where(User.user_id == user_id)
    )
    is_active = result.scalar_one_or_none()
    return bool(is_active)


# =============================================================================
# Test-only schema helpers
#
# NOT called at app startup. Pass 5A validates the proposed schema against a
# disposable PostgreSQL only (mission §15). The production migration path is a
# separate authorization (SESSION_MIGRATION_DECISION_PASS5A.md + mission §14
# MANDATORY STOP).
# =============================================================================

async def ensure_session_schema() -> None:
    """Create the sessions table on the configured engine. Test setup only."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(SessionBase.metadata.create_all)


async def drop_session_schema() -> None:
    """Drop the sessions table. Test teardown only."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(SessionBase.metadata.drop_all)
