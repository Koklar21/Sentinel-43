# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sentinel-43 server-side browser session model and service functions.

Responsibilities:
    - refresh credential generation and verification
    - CSRF token primitives
    - session-bound token claim helpers
    - server-side session persistence model
    - refresh rotation and one-generation reuse detection
    - session revocation/logout/cleanup

Transaction ownership belongs to the caller. Service functions flush but do not
commit unless explicitly documented otherwise.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Final

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

from .users import NAMING_CONVENTION, User, get_engine


logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

REFRESH_SECRET_ENTROPY_BITS: Final[int] = 256
_REFRESH_SECRET_NBYTES: Final[int] = REFRESH_SECRET_ENTROPY_BITS // 8
_CSRF_TOKEN_NBYTES: Final[int] = 32

_DEFAULT_REFRESH_TTL_SECONDS: Final[int] = 7 * 24 * 3600
_REFRESH_TTL_MIN_SECONDS: Final[int] = 300
_REFRESH_TTL_MAX_SECONDS: Final[int] = 30 * 24 * 3600

_LOCAL_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"development", "dev", "local", "test"}
)

SESSION_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_JTI_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9_-]{1,128}$"
)

_REFRESH_HASH_RE: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-f]{64}$"
)


# =============================================================================
# Exceptions
# =============================================================================

class SessionError(Exception):
    """Base for expected session-operation failures."""


class RefreshInvalidError(SessionError):
    """Presented refresh credential or session identifier is invalid."""


class RefreshReuseError(SessionError):
    """A superseded refresh credential was presented."""

    def __init__(self, sid: uuid.UUID) -> None:
        super().__init__(
            f"refresh credential reuse detected for session {sid}"
        )
        self.sid = sid


class SessionExpiredError(SessionError):
    """Session has passed its absolute expiration time."""

    def __init__(self, sid: uuid.UUID) -> None:
        super().__init__(
            f"session {sid} has expired"
        )
        self.sid = sid


class SessionRevokedError(SessionError):
    """Session has already been revoked."""

    def __init__(self, sid: uuid.UUID) -> None:
        super().__init__(
            f"session {sid} is revoked"
        )
        self.sid = sid


class SessionOwnerInactiveError(SessionError):
    """Owning account is missing or inactive."""

    def __init__(self, sid: uuid.UUID) -> None:
        super().__init__(
            f"account for session {sid} is inactive"
        )
        self.sid = sid


class SessionConfigurationError(SessionError):
    """Session security configuration is malformed."""


# =============================================================================
# Environment helpers
# =============================================================================

def _environment() -> str:
    raw = (
        os.getenv("SENTINEL_ENV")
        or os.getenv("S43_ENV")
        or "production"
    ).strip().lower()

    aliases = {
        "dev": "development",
        "local": "development",
        "prod": "production",
        "stage": "staging",
    }

    return aliases.get(
        raw,
        raw,
    )


def _is_local() -> bool:
    return _environment() in _LOCAL_ENVIRONMENTS


def _strict_int_env(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = os.getenv(name)

    if raw is None or not raw.strip():
        return default

    try:
        value = int(
            raw.strip()
        )
    except ValueError as exc:
        if not _is_local():
            raise SessionConfigurationError(
                f"{name} must be an integer"
            ) from exc

        logger.warning(
            "Invalid %s=%r; using default %s",
            name,
            raw,
            default,
        )
        return default

    if not minimum <= value <= maximum:
        if not _is_local():
            raise SessionConfigurationError(
                f"{name} must be between {minimum} and {maximum}"
            )

        logger.warning(
            "%s=%s outside %s..%s; using default %s",
            name,
            value,
            minimum,
            maximum,
            default,
        )
        return default

    return value


def refresh_ttl_seconds() -> int:
    return _strict_int_env(
        "S43_SESSION_REFRESH_TTL_SECONDS",
        _DEFAULT_REFRESH_TTL_SECONDS,
        minimum=_REFRESH_TTL_MIN_SECONDS,
        maximum=_REFRESH_TTL_MAX_SECONDS,
    )


def _session_hash_pepper() -> bytes | None:
    raw = os.getenv(
        "S43_SESSION_HASH_PEPPER",
        "",
    ).strip()

    if not raw:
        return None

    value: bytes

    if (
        len(raw) % 2 == 0
        and all(
            char in "0123456789abcdefABCDEF"
            for char in raw
        )
    ):
        try:
            value = bytes.fromhex(
                raw
            )
        except ValueError as exc:
            raise SessionConfigurationError(
                "S43_SESSION_HASH_PEPPER contains invalid hex"
            ) from exc
    else:
        value = raw.encode(
            "utf-8"
        )

    if len(value) < 32:
        raise SessionConfigurationError(
            "S43_SESSION_HASH_PEPPER must contain at least 32 bytes"
        )

    return value


# =============================================================================
# Refresh credential primitives
# =============================================================================

def generate_refresh_secret() -> str:
    return secrets.token_urlsafe(
        _REFRESH_SECRET_NBYTES
    )


def _digest(
    secret: str,
) -> str:
    if not isinstance(
        secret,
        str,
    ) or not secret:
        raise ValueError(
            "refresh secret must be a non-empty string"
        )

    raw = secret.encode(
        "utf-8"
    )

    pepper = _session_hash_pepper()

    if pepper is None:
        return hashlib.sha256(
            raw
        ).hexdigest()

    return hmac.new(
        pepper,
        raw,
        hashlib.sha256,
    ).hexdigest()


def hash_refresh_secret(
    secret: str,
) -> str:
    return _digest(
        secret
    )


def verify_refresh_hash(
    secret: str,
    stored_hash: str,
) -> bool:
    try:
        if (
            not secret
            or not isinstance(
                stored_hash,
                str,
            )
            or not _REFRESH_HASH_RE.fullmatch(
                stored_hash
            )
        ):
            return False

        calculated = _digest(
            secret
        )

        return hmac.compare_digest(
            calculated,
            stored_hash,
        )

    except (
        TypeError,
        AttributeError,
        ValueError,
        SessionConfigurationError,
    ):
        return False


# =============================================================================
# CSRF primitives
# =============================================================================

def generate_csrf_token() -> str:
    return secrets.token_urlsafe(
        _CSRF_TOKEN_NBYTES
    )


def csrf_tokens_match(
    cookie_value: str | None,
    header_value: str | None,
) -> bool:
    if (
        not isinstance(
            cookie_value,
            str,
        )
        or not isinstance(
            header_value,
            str,
        )
        or not cookie_value
        or not header_value
    ):
        return False

    return hmac.compare_digest(
        cookie_value,
        header_value,
    )


# =============================================================================
# Access-token helpers
# =============================================================================

def new_jti() -> str:
    return secrets.token_urlsafe(
        16
    )


def new_sid() -> str:
    return str(
        uuid.uuid4()
    )


def claims_are_session_bound(
    claims: object,
) -> bool:
    try:
        sid = claims.get(
            "sid"
        )  # type: ignore[union-attr]
        jti = claims.get(
            "jti"
        )  # type: ignore[union-attr]
    except (
        AttributeError,
        TypeError,
    ):
        return False

    return (
        isinstance(
            sid,
            str,
        )
        and bool(
            SESSION_ID_RE.fullmatch(
                sid
            )
        )
        and isinstance(
            jti,
            str,
        )
        and bool(
            _JTI_RE.fullmatch(
                jti
            )
        )
    )


# =============================================================================
# ORM model
# =============================================================================

class SessionBase(DeclarativeBase):
    metadata = MetaData(
        naming_convention=NAMING_CONVENTION
    )


class SessionRecord(SessionBase):
    __tablename__ = "sessions"

    __table_args__ = (
        Index(
            "uq_sessions_active_refresh_hash",
            "refresh_hash",
            unique=True,
            postgresql_where=text(
                "revoked_at IS NULL"
            ),
        ),
    )

    sid: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    )

    refresh_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    prev_refresh_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    refresh_generation: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(
            timezone.utc
        ),
    )

    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(
            timezone.utc
        ),
    )

    rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    revoked_reason: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    client_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )

    user_agent: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
    )

    def is_live(
        self,
        *,
        now: datetime | None = None,
    ) -> bool:
        current = now or datetime.now(
            timezone.utc
        )

        return (
            self.revoked_at is None
            and _aware(
                self.expires_at
            )
            > current
        )


@dataclass(frozen=True, slots=True)
class SessionView:
    sid: str
    user_id: str
    issued_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    revoked: bool
    revoked_reason: str | None
    client_ip: str | None
    user_agent: str | None
    refresh_generation: int

    @classmethod
    def of(
        cls,
        row: SessionRecord,
    ) -> "SessionView":
        return cls(
            sid=str(
                row.sid
            ),
            user_id=str(
                row.user_id
            ),
            issued_at=_aware(
                row.issued_at
            ),
            last_seen_at=_aware(
                row.last_seen_at
            ),
            expires_at=_aware(
                row.expires_at
            ),
            revoked=(
                row.revoked_at
                is not None
            ),
            revoked_reason=row.revoked_reason,
            client_ip=row.client_ip,
            user_agent=row.user_agent,
            refresh_generation=row.refresh_generation,
        )


class RefreshOutcome(str, Enum):
    ROTATED = "rotated"


# =============================================================================
# Internal helpers
# =============================================================================

def _aware(
    value: datetime,
) -> datetime:
    if value.tzinfo is None:
        return value.replace(
            tzinfo=timezone.utc
        )

    return value.astimezone(
        timezone.utc
    )


def _truncate(
    value: str | None,
    limit: int,
) -> str | None:
    if value is None:
        return None

    text_value = str(
        value
    )

    return text_value[
        :limit
    ]


async def _owner_is_active(
    session: AsyncSession,
    user_id: uuid.UUID,
) -> bool:
    result = await session.execute(
        select(
            User.is_active
        ).where(
            User.user_id
            == user_id
        )
    )

    return bool(
        result.scalar_one_or_none()
    )


async def _revoke(
    row: SessionRecord,
    *,
    reason: str,
    now: datetime,
) -> None:
    if row.revoked_at is not None:
        return

    row.revoked_at = now
    row.revoked_reason = _truncate(
        reason,
        64,
    )


async def _lock_session_for_refresh(
    session: AsyncSession,
    presented_hash: str,
) -> SessionRecord | None:
    stmt = (
        select(
            SessionRecord
        )
        .where(
            (
                SessionRecord.refresh_hash
                == presented_hash
            )
            |
            (
                SessionRecord.prev_refresh_hash
                == presented_hash
            )
        )
        .with_for_update()
    )

    result = await session.execute(
        stmt
    )

    rows = list(
        result.scalars().all()
    )

    if not rows:
        return None

    if len(rows) > 1:
        raise SessionError(
            "Refresh hash matched multiple session records"
        )

    return rows[0]


# =============================================================================
# Service functions
# =============================================================================

async def create_session(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    refresh_secret: str,
    client_ip: str | None = None,
    user_agent: str | None = None,
    ttl_seconds: int | None = None,
    now: datetime | None = None,
) -> SessionRecord:
    current = now or datetime.now(
        timezone.utc
    )

    if current.tzinfo is None:
        raise ValueError(
            "now must be timezone-aware"
        )

    ttl = (
        ttl_seconds
        if ttl_seconds is not None
        else refresh_ttl_seconds()
    )

    if not (
        _REFRESH_TTL_MIN_SECONDS
        <= ttl
        <= _REFRESH_TTL_MAX_SECONDS
    ):
        raise ValueError(
            f"ttl_seconds must be between "
            f"{_REFRESH_TTL_MIN_SECONDS} and "
            f"{_REFRESH_TTL_MAX_SECONDS}"
        )

    row = SessionRecord(
        sid=uuid.uuid4(),
        user_id=user_id,
        refresh_hash=hash_refresh_secret(
            refresh_secret
        ),
        prev_refresh_hash=None,
        refresh_generation=0,
        issued_at=current,
        last_seen_at=current,
        rotated_at=None,
        expires_at=(
            current
            + timedelta(
                seconds=ttl
            )
        ),
        revoked_at=None,
        revoked_reason=None,
        client_ip=_truncate(
            client_ip,
            45,
        ),
        user_agent=_truncate(
            user_agent,
            256,
        ),
    )

    session.add(
        row
    )
    await session.flush()

    return row


async def get_session_by_sid(
    session: AsyncSession,
    sid: uuid.UUID,
    *,
    for_update: bool = False,
) -> SessionRecord | None:
    stmt = select(
        SessionRecord
    ).where(
        SessionRecord.sid
        == sid
    )

    if for_update:
        stmt = stmt.with_for_update()

    result = await session.execute(
        stmt
    )

    return result.scalar_one_or_none()


async def resolve_live_session(
    session: AsyncSession,
    sid: uuid.UUID,
    *,
    now: datetime | None = None,
) -> tuple[SessionRecord, User]:
    current = now or datetime.now(
        timezone.utc
    )

    row = await get_session_by_sid(
        session,
        sid,
    )

    if row is None:
        raise RefreshInvalidError(
            f"no session matches sid {sid}"
        )

    if row.revoked_at is not None:
        raise SessionRevokedError(
            row.sid
        )

    if _aware(
        row.expires_at
    ) <= current:
        raise SessionExpiredError(
            row.sid
        )

    result = await session.execute(
        select(
            User
        ).where(
            User.user_id
            == row.user_id
        )
    )

    owner = result.scalar_one_or_none()

    if (
        owner is None
        or not owner.is_active
    ):
        raise SessionOwnerInactiveError(
            row.sid
        )

    return (
        row,
        owner,
    )


async def rotate_refresh(
    session: AsyncSession,
    *,
    presented_secret: str,
    new_refresh_secret: str,
    now: datetime | None = None,
) -> tuple[SessionRecord, RefreshOutcome]:
    current = now or datetime.now(
        timezone.utc
    )

    presented_hash = hash_refresh_secret(
        presented_secret
    )

    row = await _lock_session_for_refresh(
        session,
        presented_hash,
    )

    if row is None:
        raise RefreshInvalidError(
            "No session matches the presented refresh credential"
        )

    if not hmac.compare_digest(
        row.refresh_hash,
        presented_hash,
    ):
        await _revoke(
            row,
            reason="refresh_reuse",
            now=current,
        )
        await session.flush()
        raise RefreshReuseError(
            row.sid
        )

    if row.revoked_at is not None:
        raise SessionRevokedError(
            row.sid
        )

    if _aware(
        row.expires_at
    ) <= current:
        raise SessionExpiredError(
            row.sid
        )

    if not await _owner_is_active(
        session,
        row.user_id,
    ):
        await _revoke(
            row,
            reason="owner_inactive",
            now=current,
        )
        await session.flush()
        raise SessionOwnerInactiveError(
            row.sid
        )

    new_hash = hash_refresh_secret(
        new_refresh_secret
    )

    if hmac.compare_digest(
        new_hash,
        row.refresh_hash,
    ):
        raise ValueError(
            "new refresh secret must differ from current secret"
        )

    row.prev_refresh_hash = (
        row.refresh_hash
    )
    row.refresh_hash = new_hash
    row.refresh_generation += 1
    row.last_seen_at = current
    row.rotated_at = current

    await session.flush()

    return (
        row,
        RefreshOutcome.ROTATED,
    )


async def revoke_session(
    session: AsyncSession,
    sid: uuid.UUID,
    *,
    reason: str,
    now: datetime | None = None,
) -> bool:
    current = now or datetime.now(
        timezone.utc
    )

    row = await get_session_by_sid(
        session,
        sid,
        for_update=True,
    )

    if (
        row is None
        or row.revoked_at
        is not None
    ):
        return False

    await _revoke(
        row,
        reason=reason,
        now=current,
    )
    await session.flush()

    return True


async def revoke_all_user_sessions(
    session: AsyncSession,
    user_id: uuid.UUID,
    *,
    reason: str,
    now: datetime | None = None,
) -> int:
    current = now or datetime.now(
        timezone.utc
    )

    stmt = (
        select(
            SessionRecord
        )
        .where(
            SessionRecord.user_id
            == user_id,
            SessionRecord.revoked_at.is_(
                None
            ),
        )
        .with_for_update()
    )

    rows = list(
        (
            await session.execute(
                stmt
            )
        ).scalars().all()
    )

    for row in rows:
        await _revoke(
            row,
            reason=reason,
            now=current,
        )

    if rows:
        await session.flush()

    return len(
        rows
    )


async def logout_by_refresh(
    session: AsyncSession,
    *,
    presented_secret: str,
    now: datetime | None = None,
) -> bool:
    current = now or datetime.now(
        timezone.utc
    )

    try:
        presented_hash = hash_refresh_secret(
            presented_secret
        )
    except (
        ValueError,
        SessionConfigurationError,
    ):
        return False

    row = await _lock_session_for_refresh(
        session,
        presented_hash,
    )

    if (
        row is None
        or row.revoked_at
        is not None
    ):
        return False

    await _revoke(
        row,
        reason="logout",
        now=current,
    )
    await session.flush()

    return True


async def purge_expired_sessions(
    session: AsyncSession,
    *,
    older_than: datetime | None = None,
    now: datetime | None = None,
) -> int:
    current = now or datetime.now(
        timezone.utc
    )
    cutoff = older_than or current

    stmt = select(
        SessionRecord
    ).where(
        SessionRecord.expires_at
        <= cutoff
    )

    rows = list(
        (
            await session.execute(
                stmt
            )
        ).scalars().all()
    )

    for row in rows:
        await session.delete(
            row
        )

    if rows:
        await session.flush()

    return len(
        rows
    )


# =============================================================================
# Explicit local/test schema helpers
# =============================================================================

def _require_local_schema_helper() -> None:
    if not _is_local():
        raise RuntimeError(
            "Session create_all/drop_all helpers are local/test only"
        )


async def ensure_session_schema() -> None:
    _require_local_schema_helper()

    engine = get_engine()

    async with engine.begin() as connection:
        await connection.run_sync(
            SessionBase.metadata.create_all
        )


async def drop_session_schema() -> None:
    _require_local_schema_helper()

    engine = get_engine()

    async with engine.begin() as connection:
        await connection.run_sync(
            SessionBase.metadata.drop_all
        )


__all__ = [
    "REFRESH_SECRET_ENTROPY_BITS",
    "RefreshInvalidError",
    "RefreshOutcome",
    "RefreshReuseError",
    "SESSION_ID_RE",
    "SessionBase",
    "SessionConfigurationError",
    "SessionError",
    "SessionExpiredError",
    "SessionOwnerInactiveError",
    "SessionRecord",
    "SessionRevokedError",
    "SessionView",
    "claims_are_session_bound",
    "create_session",
    "csrf_tokens_match",
    "drop_session_schema",
    "ensure_session_schema",
    "generate_csrf_token",
    "generate_refresh_secret",
    "get_session_by_sid",
    "hash_refresh_secret",
    "logout_by_refresh",
    "new_jti",
    "new_sid",
    "purge_expired_sessions",
    "refresh_ttl_seconds",
    "resolve_live_session",
    "revoke_all_user_sessions",
    "revoke_session",
    "rotate_refresh",
    "verify_refresh_hash",
]
