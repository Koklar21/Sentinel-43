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

"""Sentinel-43 authentication router.

Responsibilities:
    - credential login
    - JWT issuance / verification
    - session-bound access-token support
    - refresh rotation
    - logout / session revocation
    - scoped break-glass authentication (local/dev/test only)
    - legacy-auth observability during migration

This module does not own user persistence or session persistence primitives.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Final

import jwt as pyjwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ...security.jwt_constants import APPROVED_JWT_ALGORITHMS
from ...security_context import client_ip_of
from ..deps import get_runtime_authority

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


# =============================================================================
# Constants
# =============================================================================

MAX_USERNAME_LEN: Final[int] = 128
MAX_PASSWORD_LEN: Final[int] = 1024
MAX_TOKEN_LEN: Final[int] = 4096

PASSWORD_HEADER_NAME: Final[str] = "X-S43-Password"

REFRESH_COOKIE_NAME: Final[str] = "s43_refresh"
CSRF_COOKIE_NAME: Final[str] = "s43_csrf"
CSRF_HEADER_NAME: Final[str] = "X-S43-CSRF"
_REFRESH_COOKIE_PATH: Final[str] = "/auth"

_ALLOWED_JWT_ALGORITHMS: Final[frozenset[str]] = APPROVED_JWT_ALGORITHMS
_APPROVED_ROLES: Final[frozenset[str]] = frozenset(
    {"operator", "admin"}
)

JWT_SHAPE_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"
)
_SESSION_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_JTI_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9_-]{1,128}$"
)

_TRUE_VALUES: Final[frozenset[str]] = frozenset(
    {"1", "true", "yes", "on", "enabled"}
)
_FALSE_VALUES: Final[frozenset[str]] = frozenset(
    {"0", "false", "no", "off", "disabled"}
)
_LOCAL_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"development", "dev", "local", "test"}
)


# =============================================================================
# Generic config helpers
# =============================================================================

def _e(
    name: str,
    default: str = "",
) -> str:
    return os.getenv(
        name,
        default,
    ).strip()


def _environment() -> str:
    raw = (
        _e("SENTINEL_ENV")
        or _e("S43_ENV")
        or "production"
    ).lower()

    aliases = {
        "dev": "development",
        "local": "development",
        "prod": "production",
        "stage": "staging",
    }
    return aliases.get(raw, raw)


def _is_local() -> bool:
    return _environment() in _LOCAL_ENVIRONMENTS


def _env_bool(
    name: str,
    default: bool,
    *,
    strict: bool,
) -> bool:
    raw = os.getenv(name)

    if raw is None or not raw.strip():
        return default

    normalized = raw.strip().lower()

    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False

    if strict:
        raise RuntimeError(
            f"{name} must be boolean; got {raw!r}"
        )

    logger.warning(
        "Auth: invalid boolean for %s=%r; using default %s",
        name,
        raw,
        default,
    )
    return default


def _env_int(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
    strict: bool,
) -> int:
    raw = os.getenv(name)

    if raw is None or not raw.strip():
        value = default
    else:
        try:
            value = int(raw.strip())
        except ValueError as exc:
            if strict:
                raise RuntimeError(
                    f"{name} must be integer; got {raw!r}"
                ) from exc

            logger.warning(
                "Auth: invalid integer for %s=%r; using default %s",
                name,
                raw,
                default,
            )
            return default

    if not minimum <= value <= maximum:
        if strict:
            raise RuntimeError(
                f"{name} must be between {minimum} and {maximum}; got {value}"
            )

        logger.warning(
            "Auth: %s=%s outside %s..%s; using default %s",
            name,
            value,
            minimum,
            maximum,
            default,
        )
        return default

    return value


def _jwt_algorithm() -> str:
    algorithm = _e(
        "S43_JWT_ALGORITHM",
        "HS256",
    ).upper()

    if algorithm not in _ALLOWED_JWT_ALGORITHMS:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT algorithm is not configured correctly.",
        )

    return algorithm


def _jwt_secret() -> str:
    secret = _e("S43_JWT_SECRET")

    if len(secret) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT signing key is not configured correctly.",
        )

    return secret


def _jwt_issuer() -> str:
    return _e(
        "S43_JWT_ISSUER",
        "sentinel-43",
    )


def _jwt_audience() -> str:
    return _e(
        "S43_JWT_AUDIENCE",
        "sentinel-43-dashboard",
    )


def _legacy_access_ttl() -> int:
    return _env_int(
        "S43_JWT_TTL_SECONDS",
        28_800,
        minimum=60,
        maximum=86_400,
        strict=not _is_local(),
    )


def _session_access_ttl() -> int:
    return _env_int(
        "S43_SESSION_ACCESS_TTL_SECONDS",
        900,
        minimum=60,
        maximum=3600,
        strict=not _is_local(),
    )


def _new_jti() -> str:
    return secrets.token_urlsafe(16)


# =============================================================================
# Login throttle
# =============================================================================

_LOGIN_FAILURES: dict[str, deque[float]] = {}
_LOGIN_LOCK = threading.Lock()


def _login_throttle_config() -> tuple[int, int, int]:
    strict = not _is_local()

    return (
        _env_int(
            "S43_LOGIN_MAX_FAILURES",
            10,
            minimum=1,
            maximum=100,
            strict=strict,
        ),
        _env_int(
            "S43_LOGIN_FAIL_WINDOW_SECONDS",
            300,
            minimum=1,
            maximum=3600,
            strict=strict,
        ),
        _env_int(
            "S43_LOGIN_LOCKOUT_SECONDS",
            300,
            minimum=1,
            maximum=86_400,
            strict=strict,
        ),
    )


def _throttle_key(
    username: str,
) -> str:
    return username.strip().lower()[
        :MAX_USERNAME_LEN
    ]


def _login_check_throttled(
    username: str,
) -> None:
    max_failures, window, lockout = (
        _login_throttle_config()
    )

    key = _throttle_key(
        username
    )
    now = time.monotonic()
    cutoff = now - max(
        window,
        lockout,
    )

    with _LOGIN_LOCK:
        bucket = _LOGIN_FAILURES.get(
            key
        )

        if not bucket:
            return

        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if not bucket:
            _LOGIN_FAILURES.pop(
                key,
                None,
            )
            return

        recent_failures = sum(
            1
            for timestamp in bucket
            if timestamp >= now - window
        )

        if (
            recent_failures >= max_failures
            and now - bucket[-1] < lockout
        ):
            remaining = max(
                1,
                int(
                    lockout
                    - (
                        now
                        - bucket[-1]
                    )
                ),
            )

            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    "Too many failed login attempts. "
                    "Try again later."
                ),
                headers={
                    "Retry-After": str(
                        remaining
                    )
                },
            )


def _login_record_failure(
    username: str,
) -> None:
    _max_failures, window, lockout = (
        _login_throttle_config()
    )

    key = _throttle_key(
        username
    )
    now = time.monotonic()
    cutoff = now - max(
        window,
        lockout,
    )

    with _LOGIN_LOCK:
        bucket = _LOGIN_FAILURES.setdefault(
            key,
            deque(maxlen=256),
        )

        bucket.append(
            now
        )

        if len(_LOGIN_FAILURES) > 4096:
            stale_keys = [
                candidate
                for candidate, values in _LOGIN_FAILURES.items()
                if not values
                or values[-1] <= cutoff
            ]

            for candidate in stale_keys:
                _LOGIN_FAILURES.pop(
                    candidate,
                    None,
                )

        while len(_LOGIN_FAILURES) > 4096:
            oldest = min(
                _LOGIN_FAILURES,
                key=lambda candidate: (
                    _LOGIN_FAILURES[
                        candidate
                    ][-1]
                    if _LOGIN_FAILURES[
                        candidate
                    ]
                    else float("-inf")
                ),
            )

            _LOGIN_FAILURES.pop(
                oldest,
                None,
            )


def _login_clear(
    username: str,
) -> None:
    with _LOGIN_LOCK:
        _LOGIN_FAILURES.pop(
            _throttle_key(
                username
            ),
            None,
        )


# =============================================================================
# Models
# =============================================================================

class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class LoginRequest(StrictModel):
    username: str = Field(
        ...,
        min_length=1,
        max_length=MAX_USERNAME_LEN,
    )
    password: str = Field(
        ...,
        min_length=1,
        max_length=MAX_PASSWORD_LEN,
    )


class LoginResponse(StrictModel):
    token: str
    token_type: str = "bearer"
    subject: str
    expires_at: str

    access_token: str | None = None
    expires_in: int | None = None
    role: str | None = None
    session_bound: bool = False


class RefreshResponse(StrictModel):
    token: str
    access_token: str
    token_type: str = "bearer"
    subject: str
    role: str
    expires_in: int
    expires_at: str
    session_bound: bool = True


class VerifyResponse(StrictModel):
    valid: bool = True
    subject: str
    role: str
    expires_at: str
    session_bound: bool


# =============================================================================
# Credential helpers
# =============================================================================

def _sha256_digest(
    value: str,
) -> bytes:
    return hashlib.sha256(
        value.encode("utf-8")
    ).digest()


def _valid_argon2_hash(
    value: str,
) -> bool:
    from ...auth.users import (
        is_valid_argon2id_hash,
    )

    return is_valid_argon2id_hash(
        value
    )


async def _env_operator_allowed() -> bool:
    # The env-var operator is a local/dev/test break-glass only. Outside it
    # the login is refused whatever else is configured -- armed or not, with
    # or without an active admin, with or without a database -- because the
    # token it would issue has no server-side session and every protected
    # route there refuses it (legacy_auth_is_rejected).
    if not _is_local():
        return False

    if _env_bool(
        "S43_BREAK_GLASS_ARMED",
        False,
        strict=False,
    ):
        return True

    from ...auth.users import (
        count_active_admins,
        get_sessionmaker,
    )

    try:
        sessionmaker = (
            get_sessionmaker()
        )

    except RuntimeError:
        # DB accounts are not configured at all.
        return True

    try:
        async with sessionmaker() as session:
            return (
                await count_active_admins(
                    session
                )
                == 0
            )

    except Exception:
        logger.error(
            "op=auth.env_operator_allowed "
            "db_check_failed; denying break-glass",
            exc_info=True,
        )
        return False


async def _validate_env_credentials(
    username: str,
    password: str,
) -> str:
    from ...auth.users import (
        verify_password_async,
    )

    expected_username = _e(
        "S43_OPERATOR_USERNAME",
        "operator",
    )
    expected_hash = _e(
        "S43_OPERATOR_PASSWORD_HASH"
    )

    if (
        not expected_hash
        or not _valid_argon2_hash(
            expected_hash
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Break-glass credentials are not configured correctly."
            ),
        )

    normalized = username.strip()

    username_ok = secrets.compare_digest(
        _sha256_digest(
            normalized.lower()
        ),
        _sha256_digest(
            expected_username.lower()
        ),
    )

    password_ok = (
        await verify_password_async(
            password,
            expected_hash,
        )
    )

    if not (
        username_ok
        and password_ok
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    return expected_username


async def reverify_password(
    username: str,
    password: str,
) -> bool:
    normalized = username.strip()

    if not normalized or not password:
        return False

    from ...auth.users import (
        authenticate_user,
        get_sessionmaker,
    )

    try:
        sessionmaker = (
            get_sessionmaker()
        )

    except RuntimeError:
        sessionmaker = None

    if sessionmaker is not None:
        try:
            async with sessionmaker() as session:
                user = await authenticate_user(
                    session,
                    normalized,
                    password,
                )

                if user is not None:
                    return True

        except HTTPException:
            raise

        except Exception as exc:
            logger.error(
                "op=auth.reverify_password db_error "
                "exception_class=%s",
                type(exc).__name__,
            )

            if not await _env_operator_allowed():
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=(
                        "Authentication service is temporarily unavailable."
                    ),
                )

    if not await _env_operator_allowed():
        return False

    try:
        await _validate_env_credentials(
            normalized,
            password,
        )
        return True

    except HTTPException as exc:
        if (
            exc.status_code
            == status.HTTP_503_SERVICE_UNAVAILABLE
        ):
            raise

        return False


async def _validate_credentials(
    username: str,
    password: str,
) -> tuple[str, str, str | None]:
    normalized = username.strip()

    from ...auth.users import (
        authenticate_user,
        get_sessionmaker,
        record_login,
    )

    try:
        sessionmaker = (
            get_sessionmaker()
        )

    except RuntimeError:
        sessionmaker = None

    if sessionmaker is not None:
        try:
            async with sessionmaker() as session:
                user = await authenticate_user(
                    session,
                    normalized,
                    password,
                )

                if user is not None:
                    await record_login(
                        session,
                        user,
                    )
                    await session.commit()

                    return (
                        user.username,
                        user.role,
                        str(
                            user.user_id
                        ),
                    )

        except HTTPException:
            raise

        except Exception as exc:
            logger.error(
                "op=auth.validate_credentials db_error "
                "exception_class=%s",
                type(exc).__name__,
            )

            if not await _env_operator_allowed():
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=(
                        "Authentication service is temporarily unavailable."
                    ),
                )

    if not await _env_operator_allowed():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    subject = await _validate_env_credentials(
        normalized,
        password,
    )

    return (
        subject,
        "operator",
        None,
    )


# =============================================================================
# JWT
# =============================================================================

def _issue_token(
    subject: str,
    role: str = "operator",
    user_id: str | None = None,
    *,
    sid: str | None = None,
    jti: str | None = None,
) -> tuple[str, datetime]:
    if role not in _APPROVED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token generation failed.",
        )

    secret = _jwt_secret()

    now = int(
        time.time()
    )

    ttl = (
        _session_access_ttl()
        if sid is not None
        else _legacy_access_ttl()
    )

    exp = now + ttl

    payload: dict[str, Any] = {
        "sub": subject,
        "username": subject,
        "iss": _jwt_issuer(),
        "aud": _jwt_audience(),
        "iat": now,
        "nbf": now,
        "exp": exp,
        "role": role,
    }

    if user_id is not None:
        try:
            payload["user_id"] = str(
                uuid.UUID(
                    user_id
                )
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token generation failed.",
            ) from exc

    if sid is not None:
        if not _SESSION_ID_RE.fullmatch(
            sid
        ):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token generation failed.",
            )

        payload["sid"] = sid

        resolved_jti = (
            jti
            if jti
            and _JTI_RE.fullmatch(
                jti
            )
            else _new_jti()
        )

        payload["jti"] = (
            resolved_jti
        )

    token = pyjwt.encode(
        payload,
        secret,
        algorithm=_jwt_algorithm(),
    )

    if isinstance(
        token,
        bytes,
    ):
        token = token.decode(
            "utf-8"
        )

    if (
        not isinstance(
            token,
            str,
        )
        or not token
        or len(
            token
        )
        > MAX_TOKEN_LEN
    ):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token generation failed.",
        )

    return (
        token,
        datetime.fromtimestamp(
            exp,
            tz=timezone.utc,
        ),
    )


def verify_jwt_token(
    token: str,
) -> dict[str, Any]:
    secret = _jwt_secret()

    if (
        not isinstance(
            token,
            str,
        )
        or not token
        or len(
            token
        )
        > MAX_TOKEN_LEN
        or not JWT_SHAPE_RE.fullmatch(
            token
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    try:
        claims = pyjwt.decode(
            token,
            secret,
            algorithms=[
                _jwt_algorithm()
            ],
            issuer=_jwt_issuer(),
            audience=_jwt_audience(),
            options={
                "require": [
                    "sub",
                    "exp",
                    "iss",
                    "aud",
                    "iat",
                    "nbf",
                    "role",
                ]
            },
        )

    except pyjwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        ) from exc

    except pyjwt.InvalidIssuerError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token issuer.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        ) from exc

    except pyjwt.InvalidAudienceError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token audience.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        ) from exc

    except pyjwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        ) from exc

    subject = str(
        claims.get(
            "sub"
        )
        or ""
    ).strip()

    role = str(
        claims.get(
            "role"
        )
        or ""
    ).strip()

    if not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
        )

    if role not in _APPROVED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operator role required.",
        )

    sid = claims.get(
        "sid"
    )
    jti = claims.get(
        "jti"
    )

    if sid is not None:
        if (
            not isinstance(
                sid,
                str,
            )
            or not _SESSION_ID_RE.fullmatch(
                sid
            )
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token.",
                headers={
                    "WWW-Authenticate": "Bearer"
                },
            )

        if (
            not isinstance(
                jti,
                str,
            )
            or not _JTI_RE.fullmatch(
                jti
            )
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token.",
                headers={
                    "WWW-Authenticate": "Bearer"
                },
            )

    elif jti is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    return claims


def token_is_session_bound(
    claims: dict[str, Any],
) -> bool:
    sid = claims.get(
        "sid"
    )

    return (
        isinstance(
            sid,
            str,
        )
        and bool(
            _SESSION_ID_RE.fullmatch(
                sid
            )
        )
    )


# =============================================================================
# Session / cookie helpers
# =============================================================================

_LEGACY_AUTH_LOCK = threading.Lock()
_LEGACY_AUTH_COUNTS: dict[str, int] = {}


def legacy_auth_request_total() -> dict[str, int]:
    with _LEGACY_AUTH_LOCK:
        return dict(
            _LEGACY_AUTH_COUNTS
        )


def note_legacy_auth(
    route: str,
) -> None:
    key = route[
        :64
    ] or "unknown"

    with _LEGACY_AUTH_LOCK:
        _LEGACY_AUTH_COUNTS[
            key
        ] = (
            _LEGACY_AUTH_COUNTS.get(
                key,
                0,
            )
            + 1
        )

        _LEGACY_AUTH_COUNTS[
            "_all"
        ] = (
            _LEGACY_AUTH_COUNTS.get(
                "_all",
                0,
            )
            + 1
        )


def legacy_auth_is_rejected() -> bool:
    """Whether per-request password ("legacy") authentication is refused.

    Outside local/dev/test it is ALWAYS refused. Startup
    (validate_legacy_auth_config) will not run there unless
    S43_REJECT_LEGACY_AUTH is explicitly true, and no value read here can
    turn legacy authentication back on -- a value that is missing, false or
    malformed after startup still refuses it. Local/dev/test keeps its
    compatibility default of accepting it.

    Never raises: this runs per request, including mid-WebSocket-handshake,
    where an exception is a crash rather than a clean rejection.
    """
    if not _is_local():
        return True

    return _env_bool(
        "S43_REJECT_LEGACY_AUTH",
        False,
        strict=False,
    )


def validate_legacy_auth_config() -> None:
    """Startup gate for non-local environments.

    Outside local/dev/test S43_REJECT_LEGACY_AUTH must be explicitly true.
    Unset, blank, malformed and false all refuse startup: there is no
    non-local override that accepts per-request password authentication.
    """
    if _is_local():
        return

    raw = os.getenv("S43_REJECT_LEGACY_AUTH")

    if raw is None or not raw.strip():
        raise RuntimeError(
            "S43_REJECT_LEGACY_AUTH must be set to true outside "
            f"development/local/test (environment {_environment()!r}); it is "
            "unset. Per-request password authentication cannot be enabled here."
        )

    try:
        rejected = _env_bool(
            "S43_REJECT_LEGACY_AUTH",
            True,
            strict=True,
        )
    except RuntimeError as exc:
        raise RuntimeError(
            f"S43_REJECT_LEGACY_AUTH={raw.strip()!r} is not a boolean; it must "
            f"be true outside development/local/test (environment "
            f"{_environment()!r})."
        ) from exc

    if not rejected:
        raise RuntimeError(
            f"S43_REJECT_LEGACY_AUTH={raw.strip()!r} is not permitted outside "
            f"development/local/test (environment {_environment()!r}): "
            "per-request password authentication cannot be enabled there. "
            "Set it to true."
        )


def _cookie_secure() -> bool:
    if _is_local():
        return _env_bool(
            "S43_FORCE_SECURE_COOKIES",
            False,
            strict=False,
        )

    return True


def _allowed_origins() -> frozenset[str]:
    raw = _e(
        "S43_ALLOWED_ORIGINS",
        (
            "http://127.0.0.1:5500,"
            "http://localhost:5500,"
            "http://127.0.0.1:8000,"
            "http://localhost:8000"
        ),
    )

    origins = frozenset(
        origin.strip()
        for origin in raw.split(",")
        if origin.strip()
    )

    if not _is_local():
        if not origins:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Allowed origins are not configured.",
            )

        if "*" in origins:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Wildcard origin is not permitted.",
            )

    return origins


def _check_state_change_origin(
    request: Request,
) -> None:
    from urllib.parse import (
        urlsplit,
    )

    allowed = _allowed_origins()

    origin = request.headers.get(
        "origin",
        "",
    ).strip()

    if origin:
        if origin not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Origin not allowed.",
            )
        return

    referer = request.headers.get(
        "referer",
        "",
    ).strip()

    if referer:
        parsed = urlsplit(
            referer
        )

        if not (
            parsed.scheme
            and parsed.netloc
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Referer not allowed.",
            )

        base = (
            f"{parsed.scheme}://"
            f"{parsed.netloc}"
        )

        if base not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Referer not allowed.",
            )

        return

    # Browser cookie-authenticated state changes should provide Origin/Referer.
    # Non-browser clients can use the Authorization API instead.
    if not _is_local():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Origin validation required.",
        )


def _set_session_cookies(
    response: Response,
    refresh_secret: str,
    csrf_token: str,
) -> None:
    from ...auth.sessions import (
        refresh_ttl_seconds,
    )

    ttl = refresh_ttl_seconds()
    secure = _cookie_secure()

    response.set_cookie(
        REFRESH_COOKIE_NAME,
        refresh_secret,
        max_age=ttl,
        path=_REFRESH_COOKIE_PATH,
        httponly=True,
        secure=secure,
        samesite="strict",
    )

    response.set_cookie(
        CSRF_COOKIE_NAME,
        csrf_token,
        max_age=ttl,
        path="/",
        httponly=False,
        secure=secure,
        samesite="strict",
    )


def _clear_session_cookies(
    response: Response,
) -> None:
    secure = _cookie_secure()

    response.set_cookie(
        REFRESH_COOKIE_NAME,
        "",
        max_age=0,
        path=_REFRESH_COOKIE_PATH,
        httponly=True,
        secure=secure,
        samesite="strict",
    )

    response.set_cookie(
        CSRF_COOKIE_NAME,
        "",
        max_age=0,
        path="/",
        httponly=False,
        secure=secure,
        samesite="strict",
    )


async def _create_login_session(
    *,
    user_id: str,
    subject: str,
    request: Request,
    authority: Any,
) -> tuple[str, str, str]:
    from ...auth.sessions import (
        generate_csrf_token,
        generate_refresh_secret,
    )
    from ...auth.users import get_sessionmaker

    refresh_secret = generate_refresh_secret()
    csrf_token = generate_csrf_token()

    # Canonical resolver: the firewall owns the trusted-proxy decision.
    client_ip = client_ip_of(request)
    user_agent = request.headers.get("user-agent")

    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        row = await authority.identity.create_login_session(
            session,
            actor=subject,
            user_id=uuid.UUID(user_id),
            refresh_secret=refresh_secret,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    return str(row.sid), refresh_secret, csrf_token


async def resolve_session_subject(
    claims: dict[str, Any],
) -> tuple[str, str] | None:
    if not token_is_session_bound(
        claims
    ):
        return None

    from ...auth.sessions import (
        SessionError,
        resolve_live_session,
    )
    from ...auth.users import (
        get_sessionmaker,
    )

    try:
        sid = uuid.UUID(
            str(
                claims.get(
                    "sid"
                )
            )
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        ) from exc

    try:
        sessionmaker = (
            get_sessionmaker()
        )

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Session service is unavailable.",
        ) from exc

    try:
        async with sessionmaker() as session:
            row, owner = await resolve_live_session(
                session,
                sid,
            )

    except SessionError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Session is no longer valid. "
                "Log in again."
            ),
            headers={
                "WWW-Authenticate": "Bearer"
            },
        ) from exc

    token_subject = str(
        claims.get(
            "sub"
        )
        or ""
    ).strip()

    token_role = str(
        claims.get(
            "role"
        )
        or ""
    ).strip()

    if token_subject != owner.username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session subject mismatch.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    if token_role != owner.role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session role changed. Log in again.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    return (
        owner.username,
        owner.role,
    )


# =============================================================================
# Routes
# =============================================================================

@router.post(
    "/login",
    response_model=LoginResponse,
)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    authority: Any = Depends(get_runtime_authority),
) -> LoginResponse:
    _check_state_change_origin(
        request
    )

    _login_check_throttled(
        body.username
    )

    try:
        subject, role, user_id = (
            await _validate_credentials(
                body.username,
                body.password,
            )
        )

    except HTTPException as exc:
        if (
            exc.status_code
            == status.HTTP_401_UNAUTHORIZED
        ):
            _login_record_failure(
                body.username
            )

        raise

    _login_clear(
        body.username
    )

    if user_id is not None:
        try:
            (
                sid,
                refresh_secret,
                csrf_token,
            ) = await _create_login_session(
                user_id=user_id,
                subject=subject,
                request=request,
                authority=authority,
            )

        except Exception as exc:
            logger.error(
                "op=auth.login "
                "session_create_failed "
                "exception_class=%s",
                type(exc).__name__,
            )

            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "Login succeeded but the session could not be created."
                ),
            ) from exc

        token, exp_dt = _issue_token(
            subject=subject,
            role=role,
            user_id=user_id,
            sid=sid,
        )

        _set_session_cookies(
            response,
            refresh_secret,
            csrf_token,
        )

        return LoginResponse(
            token=token,
            access_token=token,
            subject=subject,
            role=role,
            expires_in=_session_access_ttl(),
            expires_at=exp_dt.isoformat(),
            session_bound=True,
        )

    # Break-glass/env operator path, reachable only in local/dev/test
    # (_env_operator_allowed). This intentionally remains legacy-style
    # because it has no DB-backed server session.
    token, exp_dt = _issue_token(
        subject=subject,
        role=role,
        user_id=None,
    )

    return LoginResponse(
        token=token,
        subject=subject,
        role=role,
        expires_in=_legacy_access_ttl(),
        expires_at=exp_dt.isoformat(),
        session_bound=False,
    )


@router.post(
    "/refresh",
    response_model=RefreshResponse,
)
async def refresh(
    request: Request,
    response: Response,
    authority: Any = Depends(get_runtime_authority),
) -> RefreshResponse:
    _check_state_change_origin(
        request
    )

    cookie = request.cookies.get(
        REFRESH_COOKIE_NAME,
        "",
    )

    if not cookie:
        _clear_session_cookies(
            response
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No session.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    from ...auth.sessions import (
        RefreshInvalidError,
        RefreshReuseError,
        SessionExpiredError,
        SessionOwnerInactiveError,
        SessionRevokedError,
        csrf_tokens_match,
        generate_refresh_secret,
    )
    from ...auth.users import get_sessionmaker

    csrf_cookie = request.cookies.get(
        CSRF_COOKIE_NAME
    )
    csrf_header = request.headers.get(
        CSRF_HEADER_NAME
    )

    if not csrf_tokens_match(
        csrf_cookie,
        csrf_header,
    ):
        _clear_session_cookies(
            response
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF check failed.",
        )

    new_secret = (
        generate_refresh_secret()
    )
    new_csrf = csrf_cookie

    if not new_csrf:
        _clear_session_cookies(
            response
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF check failed.",
        )

    sessionmaker = (
        get_sessionmaker()
    )

    async with sessionmaker() as session:
        try:
            row, _outcome, owner = await authority.identity.rotate_session_refresh(
                session,
                presented_secret=cookie,
                new_refresh_secret=new_secret,
            )

        except RefreshReuseError as exc:
            _clear_session_cookies(response)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session ended. Log in again.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

        except SessionOwnerInactiveError as exc:
            _clear_session_cookies(response)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is disabled.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

        except (
            RefreshInvalidError,
            SessionRevokedError,
            SessionExpiredError,
        ) as exc:
            _clear_session_cookies(response)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session is no longer valid. Log in again.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

        subject = owner.username
        role = owner.role
        user_id = str(owner.user_id)

    token, exp_dt = _issue_token(
        subject=subject,
        role=role,
        user_id=user_id,
        sid=str(
            row.sid
        ),
    )

    _set_session_cookies(
        response,
        new_secret,
        new_csrf,
    )

    return RefreshResponse(
        token=token,
        access_token=token,
        subject=subject,
        role=role,
        expires_in=_session_access_ttl(),
        expires_at=exp_dt.isoformat(),
    )


@router.post(
    "/logout",
)
async def logout(
    request: Request,
    response: Response,
    authority: Any = Depends(get_runtime_authority),
) -> dict[str, bool]:
    _check_state_change_origin(
        request
    )

    cookie = request.cookies.get(
        REFRESH_COOKIE_NAME,
        "",
    )

    if not cookie:
        _clear_session_cookies(
            response
        )
        return {
            "ok": True
        }

    from ...auth.sessions import csrf_tokens_match
    from ...auth.users import get_sessionmaker

    if not csrf_tokens_match(
        request.cookies.get(
            CSRF_COOKIE_NAME
        ),
        request.headers.get(
            CSRF_HEADER_NAME
        ),
    ):
        _clear_session_cookies(
            response
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF check failed.",
        )

    try:
        sessionmaker = (
            get_sessionmaker()
        )

        async with sessionmaker() as session:
            await authority.identity.logout_session_by_refresh(
                session,
                presented_secret=cookie,
            )

    except Exception as exc:
        _clear_session_cookies(
            response
        )
        logger.error(
            "op=auth.logout revoke_failed "
            "exception_class=%s",
            type(exc).__name__,
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Logout could not revoke the server-side session."
            ),
        ) from exc

    _clear_session_cookies(
        response
    )

    return {
        "ok": True
    }


@router.get(
    "/verify",
    response_model=VerifyResponse,
)
async def verify(
    authorization: str | None = Header(
        default=None,
    ),
) -> VerifyResponse:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    parts = authorization.strip().split()

    if (
        len(parts) != 2
        or parts[0].lower()
        != "bearer"
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed authorization header.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    raw_token = parts[1].strip()

    claims = verify_jwt_token(
        raw_token
    )

    resolved = await resolve_session_subject(
        claims
    )

    if resolved is not None:
        subject, role = resolved

    else:
        subject = str(
            claims.get(
                "sub"
            )
            or ""
        ).strip()
        role = str(
            claims.get(
                "role"
            )
            or ""
        ).strip()

    exp = claims.get(
        "exp"
    )

    if not isinstance(
        exp,
        (int, float),
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
        )

    return VerifyResponse(
        valid=True,
        subject=subject,
        role=role,
        expires_at=datetime.fromtimestamp(
            exp,
            tz=timezone.utc,
        ).isoformat(),
        session_bound=(
            resolved
            is not None
        ),
    )


__all__ = [
    "CSRF_COOKIE_NAME",
    "CSRF_HEADER_NAME",
    "PASSWORD_HEADER_NAME",
    "REFRESH_COOKIE_NAME",
    "legacy_auth_is_rejected",
    "legacy_auth_request_total",
    "note_legacy_auth",
    "resolve_session_subject",
    "router",
    "token_is_session_bound",
    "validate_legacy_auth_config",
    "verify_jwt_token",
    "reverify_password",
]
