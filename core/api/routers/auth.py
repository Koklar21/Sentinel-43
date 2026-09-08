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
# =============================================================================
#
# core/api/routers/auth.py
#
# Dashboard operator authentication router.
#
# Provides:
#   POST /auth/login   — validates operator credentials, returns a signed JWT
#   GET  /auth/verify  — validates a Bearer JWT for auth.js startup checks
#
# The returned JWT is stored by auth.js in sessionStorage["SENTINEL_JWT"].
# websocket.js reads that key and sends it in the WebSocket auth frame.
# main.py's _get_operator() and dashboard_websocket() import verify_jwt_token()
# from this module rather than maintaining a second verifier.
#
# Per-request password re-verification:
#   A valid JWT is no longer sufficient on its own to reach protected
#   routes. Every protected HTTP request must also carry the operator's
#   plaintext password in the X-S43-Password header (PASSWORD_HEADER_NAME
#   below), and every WebSocket auth frame must include a "password" field
#   alongside "token". Both are checked with reverify_password(), defined
#   here and consumed by core/api/deps/deps.py's require_operator() and
#   main.py's _get_operator() / dashboard_websocket().
#
# Required .env variables:
#   S43_JWT_SECRET              — HMAC signing key
#   S43_OPERATOR_USERNAME       — operator username (default: "operator")
#   S43_OPERATOR_PASSWORD_HASH  — an Argon2id hash (argon2-cffi format,
#                                 "$argon2id$..."), generated with
#                                 `python -m core.cli.generate_secrets --password-hash`.
#                                 A legacy SHA-256 hex digest is REJECTED
#                                 outright — see _valid_argon2_hash() below
#                                 and core.api.main._validate_security_config(),
#                                 which refuses to start with one configured
#                                 outside local/dev/test. There is no
#                                 dual-scheme acceptance window: accepting
#                                 both schemes "temporarily" is the same
#                                 silent downgrade under a different name.
#                                 Rotating to Argon2id requires a NEW
#                                 break-glass password — the plaintext behind
#                                 the old SHA-256 hash is not recoverable, so
#                                 this is a manual, deliberate step, not a
#                                 background migration.
#
# Optional .env variables:
#   S43_JWT_ALGORITHM     — HS256 only (default: HS256)
#   S43_JWT_ISSUER        — default: sentinel-43
#   S43_JWT_AUDIENCE      — default: sentinel-43-dashboard
#   S43_JWT_TTL_SECONDS   — default: 28800 (8 hours), clamped 60–86400
#
# Credential setup:
#   Generate password hash:
#     python -m core.cli.generate_secrets --password-hash
#   Generate JWT secret:
#     python -c "import secrets; print(secrets.token_urlsafe(32))"
#
# Security note:
#   The break-glass operator credential is Argon2id-hashed (core.auth.users'
#   PasswordHasher, off the event loop via verify_password_async) — the same
#   scheme and parameters as every DB-backed account. All credential
#   comparisons that are NOT the password hash itself (i.e. the username)
#   still use secrets.compare_digest over fixed-width SHA-256 digests to
#   prevent length-based timing leakage; that has nothing to do with
#   credential storage and is not a "SHA-256 password hash".
# =============================================================================

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
from typing import Any, Optional

import jwt as pyjwt
from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from ...security.jwt_constants import APPROVED_JWT_ALGORITHMS

logger = logging.getLogger(__name__)


# =============================================================================
# Login brute-force throttle (Pass 3, RELEASE_FINDINGS-adjacent)
#
# /auth/login had no per-credential rate limiting: the only backstop was the
# firewall's coarse per-IP limiter (300/60s). A per-username sliding-window
# lockout raises the cost of guessing a known operator's password. In-process
# only — adequate for the single-replica beta; a multi-replica deployment
# wants this in Redis (noted in PASS3_VALIDATION.md). reverify_password()'s
# per-request path is not throttled here: it already sits behind a valid-JWT
# gate and its Argon2 verify now runs off the event loop.
# =============================================================================

def _ei_raw(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def _login_throttle_config() -> tuple[int, int, int]:
    """(max_failures, window_seconds, lockout_seconds), read at call time."""
    return (
        max(1, _ei_raw("S43_LOGIN_MAX_FAILURES", 10)),
        max(1, _ei_raw("S43_LOGIN_FAIL_WINDOW_SECONDS", 300)),
        max(1, _ei_raw("S43_LOGIN_LOCKOUT_SECONDS", 300)),
    )


_login_failures: dict[str, deque[float]] = {}
_login_lock = threading.Lock()


def _throttle_key(username: str) -> str:
    return username.strip().lower()[:MAX_USERNAME_LEN]


def _login_check_throttled(username: str) -> None:
    max_fail, window, lockout = _login_throttle_config()
    key = _throttle_key(username)
    now = time.monotonic()
    with _login_lock:
        bucket = _login_failures.get(key)
        if not bucket:
            return
        while bucket and bucket[0] < now - max(window, lockout):
            bucket.popleft()
        if not bucket:
            _login_failures.pop(key, None)
            return
        recent = [t for t in bucket if t >= now - window]
        if len(recent) >= max_fail and (now - bucket[-1]) < lockout:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Try again later.",
                headers={"Retry-After": str(lockout)},
            )


def _login_record_failure(username: str) -> None:
    _, window, lockout = _login_throttle_config()
    key = _throttle_key(username)
    now = time.monotonic()
    with _login_lock:
        bucket = _login_failures.setdefault(key, deque(maxlen=256))
        bucket.append(now)
        # opportunistic GC so the dict can't grow without bound
        if len(_login_failures) > 4096:
            cutoff = now - max(window, lockout)
            for k in [k for k, b in _login_failures.items() if not b or b[-1] < cutoff]:
                _login_failures.pop(k, None)


def _login_clear(username: str) -> None:
    with _login_lock:
        _login_failures.pop(_throttle_key(username), None)

router = APIRouter(prefix="/auth", tags=["auth"])


# =============================================================================
# Constants
# =============================================================================

MAX_USERNAME_LEN = 128
MAX_PASSWORD_LEN = 1024
MAX_TOKEN_LEN    = 4096

# Header carrying the operator's password on every protected request, in
# addition to the JWT bearer token. A valid JWT alone no longer grants
# backend access — see reverify_password().
PASSWORD_HEADER_NAME = "X-S43-Password"

# Only HS256 is permitted for now. This keeps /auth/login and /auth/verify
# aligned with the Batch 1/2 JWT consumers instead of issuing tokens that
# one path accepts while another rejects.
_ALLOWED_JWT_ALGORITHMS: frozenset[str] = APPROVED_JWT_ALGORITHMS

# Approved operator roles. If a decoded JWT's "role" claim is missing or
# outside this set, verify_jwt_token() raises 403 to match route authorization.
_APPROVED_ROLES: frozenset[str] = frozenset({"operator", "admin"})

# Three-segment base64url shape. Validated before pyjwt.decode() to reject
# obviously-malformed input without touching the decode path.
JWT_SHAPE_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")

# ---------------------------------------------------------------------------
# New-style (session-bound) access-token claims — Pass 5A foundation.
#
# The browser-session redesign (AUTH_ARCHITECTURE_PASS4.md "Model B") issues
# access tokens that additionally carry:
#   sid  — the server-side session id (canonical UUID string)
#   jti  — a unique token id
# Legacy tokens (env-var operator, DB-account login as it works today, the
# /v1 issuers, any already-minted token) carry NEITHER and are still accepted
# unchanged — _issue_token() only adds them when a caller passes sid=..., and
# verify_jwt_token() never *requires* them. Presence of a well-formed `sid`
# is the explicit new-vs-legacy discriminator (see token_is_session_bound()).
#
# Pass 5A does NOT consult the sessions table on the request hot path (no
# `sid` liveness lookup / LRU) — that is deferred (mission Pass 5A §6, §21).
# ---------------------------------------------------------------------------
_SESSION_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_JTI_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def _new_jti() -> str:
    """A unique, opaque token id for the `jti` claim (128-bit URL-safe)."""
    return secrets.token_urlsafe(16)


def token_is_session_bound(claims: dict[str, Any]) -> bool:
    """
    True iff `claims` is a new-style, session-bound access token (carries a
    well-formed `sid`). False for every legacy token. Never raises.

    Not used on the request hot path in Pass 5A — provided so Pass 5B wiring
    and tests have one canonical discriminator instead of ad-hoc `"sid" in`
    checks scattered across call sites.
    """
    try:
        sid = claims.get("sid")
    except AttributeError:
        return False
    return isinstance(sid, str) and bool(_SESSION_ID_RE.match(sid))


# =============================================================================
# Env helpers — all read at call time so Docker env injection works correctly.
# Module-level calls are intentionally avoided so import does not crash the
# process or test suite when env vars are absent.
# =============================================================================

def _e(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _ei(name: str, default: int, *, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return max(lo, min(hi, int(raw.strip())))
    except ValueError:
        return default


# =============================================================================
# Config validators — raise 503 at route time, never at import time.
# =============================================================================

def _jwt_algorithm() -> str:
    """
    Return the configured JWT algorithm, enforcing the HMAC allowlist.

    Raises HTTP 503 if S43_JWT_ALGORITHM is set to anything outside
    {HS256}. Fails loudly at the route rather than at import,
    so app startup and pytest collection are not broken by missing config.
    """
    alg = _e("S43_JWT_ALGORITHM", "HS256").upper()
    if alg not in _ALLOWED_JWT_ALGORITHMS:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT algorithm is not configured correctly on this server.",
        )
    return alg


def _valid_argon2_hash(value: str) -> bool:
    """
    Return True iff value is a well-formed Argon2id encoded hash this
    deployment would accept as S43_OPERATOR_PASSWORD_HASH.

    Thin wrapper over core.auth.users.is_valid_argon2id_hash() — that is the
    one canonical Argon2 acceptance policy for the whole codebase (this
    router and core.api.main._validate_security_config() both call it; there
    is no second copy of the parameter bounds or the base64/version checks).
    Real parsing, not a shape check: rejects Argon2i/Argon2d, unsupported
    versions, malformed base64, truncated or missing salt/hash, and
    out-of-bounds cost parameters, in addition to a legacy SHA-256 hex
    digest or garbage. No dual-scheme acceptance window.
    """
    from ...auth.users import is_valid_argon2id_hash

    return is_valid_argon2id_hash(value)


# =============================================================================
# Models
# =============================================================================

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=MAX_USERNAME_LEN)
    password: str = Field(..., min_length=1, max_length=MAX_PASSWORD_LEN)


class LoginResponse(BaseModel):
    token:      str          # the access token (kept as `token` for existing consumers)
    token_type: str = "bearer"
    subject:    str
    expires_at: str
    # New-style fields (browser-session redesign, beta-execution Phase 3).
    # Present for DB-account logins that get a server-side session; absent /
    # null for the legacy env-operator break-glass path.
    access_token:  Optional[str] = None
    expires_in:    Optional[int] = None
    role:          Optional[str] = None
    session_bound: bool = False


class RefreshResponse(BaseModel):
    token:         str
    access_token:  str
    token_type:    str = "bearer"
    subject:       str
    role:          str
    expires_in:    int
    expires_at:    str
    session_bound: bool = True


class VerifyResponse(BaseModel):
    valid:      bool = True
    subject:    str
    role:       str
    expires_at: str


# =============================================================================
# Internal helpers
# =============================================================================

def _sha256_digest(value: str) -> bytes:
    """
    Return raw SHA-256 digest bytes of value. Used ONLY for a fixed-width
    timing-safe comparison of the operator USERNAME (not a secret, and not
    the credential hash) — see _validate_env_credentials(). Never used for
    password storage or verification; that is Argon2id (core.auth.users),
    run off the event loop.
    """
    return hashlib.sha256(value.encode("utf-8")).digest()


async def _validate_env_credentials(username: str, password: str) -> str:
    """
    Validate operator credentials against env-configured values.

    S43_OPERATOR_PASSWORD_HASH must be an Argon2id hash produced by
    `python -m core.cli.generate_secrets --password-hash` (see
    _valid_argon2_hash()). A legacy SHA-256 hex digest is rejected outright
    as a config error, the same as a truncated or empty value — there is no
    dual-scheme acceptance window. core.api.main._validate_security_config()
    additionally refuses to START the server with a non-Argon2id hash
    configured outside local/dev/test, so a misconfigured production
    deployment never comes up far enough to reach this function.

    Username comparison hashes both sides to fixed-width SHA-256 digests
    before compare_digest to prevent length-based timing leakage — this is
    unrelated to credential storage, just a constant-time-compare trick for
    a value that was never secret.

    Password verification runs Argon2id (memory-hard, tens of milliseconds)
    off the event loop via core.auth.users.verify_password_async(), exactly
    like every DB-backed account.

    Both comparisons always run before any error is raised to prevent
    timing-based enumeration of which field failed.

    Returns the canonical expected_username (not the operator's typed
    casing) as the JWT subject, so the subject in the token is always
    the value from config regardless of how the operator typed it.
    """
    from ...auth.users import verify_password_async

    expected_username = _e("S43_OPERATOR_USERNAME", "operator")
    expected_hash     = _e("S43_OPERATOR_PASSWORD_HASH")

    # Validate hash format before comparison. A truncated, empty, or legacy
    # SHA-256 hash produces silent failures that look like wrong passwords —
    # surface it as a config error (503) instead.
    if not expected_hash or not _valid_argon2_hash(expected_hash):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Operator credentials are not configured correctly on this server.",
        )

    normalized = username.strip()

    # Username: hash both sides to SHA-256 digests before compare_digest.
    # This produces fixed-width 32-byte values, eliminating timing leakage
    # from variable-length string comparisons.
    username_ok = secrets.compare_digest(
        _sha256_digest(normalized.lower()),
        _sha256_digest(expected_username.lower()),
    )

    # Password: Argon2id verify, off the event loop. Always run — never
    # short-circuited by username_ok — so a wrong username doesn't respond
    # measurably faster than a wrong password.
    password_ok = await verify_password_async(password, expected_hash)

    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Return the canonical configured username, not the operator's typed
    # casing. The JWT sub claim will always reflect the config value.
    return expected_username


async def _env_operator_allowed() -> bool:
    """
    RELEASE_FINDINGS #11 (beta-execution Phase 3, AUTH_MIGRATION_PASS4 §3
    Option C — scoped break-glass), tightened this pass to remove the
    "any exception => break-glass" silent downgrade.

    The env-var operator (S43_OPERATOR_USERNAME / S43_OPERATOR_PASSWORD_HASH,
    Argon2id) is a **break-glass** credential, not a routine account. It
    authenticates only when:

      * ``S43_BREAK_GLASS_ARMED`` is truthy — an operator deliberately
        turned it on. This is checked FIRST and unconditionally, so arming
        it works even while the DB is down; it is never inferred from an
        exception, OR
      * DATABASE_URL is not configured at all — there is no DB-accounts
        feature in this deployment to "fall back" from; the env-var operator
        is this deployment's only account, not an exceptional path, OR
      * the DB is reachable AND confirms there is **no active admin** yet —
        the first-run window before ``/bootstrap/admin`` has been completed.

    Explicitly NOT a trigger: the DB being configured but erroring (down,
    unreachable, table missing, query failure). That used to silently grant
    break-glass — the exact "downgrade under a different name" this pass
    was asked to close. A DB error now DENIES break-glass unless
    S43_BREAK_GLASS_ARMED was already set, and is logged at error level by
    the caller (reverify_password / _validate_credentials) with the specific
    exception, never the credential.

    Once a DB admin exists and the DB is healthy, the env operator is inert
    unless explicitly armed.
    """
    if _e("S43_BREAK_GLASS_ARMED", "").lower() in {"1", "true", "yes", "on"}:
        return True

    from ...auth.users import count_active_admins, get_sessionmaker

    try:
        sm = get_sessionmaker()
    except RuntimeError:
        # DATABASE_URL is not configured — no DB-accounts feature exists in
        # this deployment to downgrade from.
        return True

    try:
        async with sm() as session:
            return await count_active_admins(session) == 0
    except Exception as exc:
        logger.error(
            "op=auth.env_operator_allowed.count_active_admins_failed "
            "exception_class=%s — denying break-glass. Set "
            "S43_BREAK_GLASS_ARMED=true to authenticate while the database "
            "is unavailable.",
            type(exc).__name__,
        )
        return False


async def reverify_password(username: str, password: str) -> bool:
    """
    Re-validate a password for a subject that has already passed JWT
    verification. Used by the per-request password gate (X-S43-Password
    header): a valid JWT alone is no longer sufficient to reach protected
    routes — the operator's password must accompany every request.

    Checks the DB-backed account system first. If DATABASE_URL is not
    configured at all, falls straight to the env-var operator check (that is
    this deployment's only account, not a downgrade). If the DB IS
    configured but the lookup raises (unreachable, table missing, query
    error), this is a hash-scheme downgrade in the making (Argon2 DB
    accounts -> the Argon2id break-glass operator) — it is logged at ERROR
    with the specific exception (never the credential) and raises
    HTTPException(503) UNLESS break-glass is explicitly armed
    (_env_operator_allowed()), matching the "no silent downgrade" rule: any
    remaining break-glass path must be explicitly armed, not merely
    triggered by an exception.

    Returns False on an ordinary wrong-password/unknown-account outcome (the
    caller turns that into 401); raises HTTPException(503) on a blocked DB
    operation with break-glass not armed, which FastAPI turns into a 503
    response for HTTP callers, and which the WebSocket auth path (main.py)
    catches explicitly to close with reason="service_unavailable" rather
    than misreporting it as an auth failure.
    """
    normalized = username.strip()
    if not normalized or not password:
        return False

    from ...auth.users import authenticate_user, get_sessionmaker

    try:
        sessionmaker = get_sessionmaker()
    except RuntimeError:
        # DATABASE_URL not configured: no DB-accounts feature exists in this
        # deployment to downgrade from — fall straight to the env-var check.
        sessionmaker = None

    if sessionmaker is not None:
        try:
            async with sessionmaker() as session:
                # Read-only: authenticate_user() no longer writes
                # last_login_at on any path. reverify_password() runs on
                # every protected request — it must never touch the DB
                # beyond the SELECT + Argon2 verify.
                user = await authenticate_user(session, normalized, password)
                if user is not None:
                    return True
        except HTTPException:
            raise
        except Exception as exc:
            logger.error(
                "op=auth.reverify_password.db_error exception_class=%s — "
                "refusing to silently fall back to the break-glass operator.",
                type(exc).__name__,
            )
            if not await _env_operator_allowed():
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Authentication service is temporarily unavailable.",
                )
            # Break-glass is explicitly armed — fall through and evaluate the
            # env-var credential below, same as the ordinary not-found path.

    if not await _env_operator_allowed():
        return False
    try:
        await _validate_env_credentials(normalized, password)
        return True
    except HTTPException as exc:
        if exc.status_code == status.HTTP_503_SERVICE_UNAVAILABLE:
            # Misconfigured break-glass hash (missing/malformed/legacy
            # SHA-256) is a config error, not "wrong password" — surface it
            # as 503, not a silently-collapsed 401.
            raise
        return False


async def _validate_credentials(username: str, password: str) -> tuple[str, str, str | None]:
    """
    Resolve operator credentials to (subject, role, user_id).

    Checks the DB-backed account system (core.auth.users) first.

    If DATABASE_URL is not configured at all, falls straight to the env-var
    operator check — that is this deployment's only account, not a
    downgrade. If the DB IS configured but the lookup raises (unreachable,
    table missing, query error), that is a hash-scheme downgrade in the
    making (Argon2 DB accounts -> the Argon2id break-glass operator): it is
    logged at ERROR with the specific exception (never the credential), and
    this raises HTTPException(503) UNLESS break-glass is explicitly armed
    (_env_operator_allowed()) — no more "any exception silently reaches the
    break-glass check" behavior.

    An ordinary DB miss (no matching user / wrong password, no exception)
    still falls through to the env-var break-glass check exactly as before —
    that path was never a silent downgrade, since break-glass is only
    reachable there when _env_operator_allowed() independently permits it
    (armed, or a confirmed zero-admin bootstrap window). user_id is None on
    the env-var path since it has no DB row.
    """
    normalized = username.strip()

    from ...auth.users import authenticate_user, get_sessionmaker, record_login

    try:
        sessionmaker = get_sessionmaker()
    except RuntimeError:
        # DATABASE_URL not configured: no DB-accounts feature exists in this
        # deployment to downgrade from — fall straight to the env-var check.
        sessionmaker = None

    if sessionmaker is not None:
        try:
            async with sessionmaker() as session:
                user = await authenticate_user(session, normalized, password)
                if user is not None:
                    # This IS a login — record it. authenticate_user() itself
                    # is read-only now; _validate_credentials owns this write
                    # and the commit.
                    subject, role, user_id = user.username, user.role, str(user.user_id)
                    await record_login(session, user)
                    await session.commit()
                    return subject, role, user_id
        except HTTPException:
            raise
        except Exception as exc:
            logger.error(
                "op=auth.validate_credentials.db_error exception_class=%s — "
                "refusing to silently fall back to break-glass credentials.",
                type(exc).__name__,
            )
            if not await _env_operator_allowed():
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Authentication service is temporarily unavailable.",
                )
            # Break-glass is explicitly armed — fall through to the env-var
            # check below, same as the ordinary not-found path.

    # #11: the env-var operator is break-glass only (see _env_operator_allowed).
    if not await _env_operator_allowed():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await _validate_env_credentials(normalized, password), "operator", None


def _issue_token(
    subject: str,
    role: str = "operator",
    user_id: str | None = None,
    *,
    sid: str | None = None,
    jti: str | None = None,
) -> tuple[str, datetime]:
    """
    Sign and return a JWT for the given subject.

    Token claims are designed to satisfy:
      - verify_jwt_token()      (requires sub, exp, iss, aud; checks role)
      - main.py _get_operator() and WebSocket auth path (call verify_jwt_token())
      - auth.js /auth/verify    (checks res.ok)

    user_id is only present for DB-backed accounts (see
    _validate_credentials) — env-var fallback logins omit it rather than
    fabricate one, since main.py and existing tests never require it.

    sid / jti — Pass 5A foundation. When ``sid`` is supplied (a server-side
    session id) the token becomes a *new-style, session-bound* access token:
    it gains a ``sid`` claim and a ``jti`` claim (generated if not passed),
    and its TTL drops to the short session-access TTL (approved target
    15 min; ``S43_SESSION_ACCESS_TTL_SECONDS``, default 900, clamped
    60s..1h). When ``sid`` is None — every caller today, including /auth/login
    as it currently works — the payload is byte-for-byte what it was before
    (no ``sid``, no ``jti``) and the TTL is the legacy
    ``S43_JWT_TTL_SECONDS`` (default 8h). This keeps legacy token issuance
    unchanged while the session layer is built out (mission Pass 5A §3, §6).
    """
    secret = _e("S43_JWT_SECRET")
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT signing key is not configured on this server.",
        )

    now    = int(time.time())
    if sid is not None:
        # New-style session-bound access token: short TTL (approved target =
        # 15 min). The refresh session, not the access token, is the durable
        # credential. Clamped 60s..1h; env-overridable for tuning during the
        # Pass 5B rollout. Legacy tokens (sid is None) keep the 8h default.
        ttl = _ei("S43_SESSION_ACCESS_TTL_SECONDS", 900, lo=60, hi=3600)
    else:
        ttl = _ei("S43_JWT_TTL_SECONDS", 28800, lo=60, hi=86400)
    exp    = now + ttl
    exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)

    payload: dict[str, Any] = {
        "sub":      subject,
        "username": subject,
        "iss":      _e("S43_JWT_ISSUER",   "sentinel-43"),
        "aud":      _e("S43_JWT_AUDIENCE", "sentinel-43-dashboard"),
        "iat":      now,
        "nbf":      now,
        "exp":      exp,
        # "role" is what main.py _get_operator() and the WebSocket auth path
        # check against _APPROVED_ROLES = {"operator", "admin"}.
        "role":     role,
    }
    if user_id is not None:
        payload["user_id"] = user_id

    if sid is not None:
        # New-style session-bound token. Validate the sid shape here so a
        # malformed session id can never be minted into a token.
        if not _SESSION_ID_RE.match(sid):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token generation failed.",
            )
        payload["sid"] = sid
        payload["jti"] = jti if (jti and _JTI_RE.match(jti)) else _new_jti()

    token: Any = pyjwt.encode(
        payload,
        secret,
        algorithm=_jwt_algorithm(),
    )

    # Older PyJWT versions (< 2.0) return bytes; normalize to str.
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LEN:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token generation failed.",
        )

    return token, exp_dt


def verify_jwt_token(token: str) -> dict[str, Any]:
    """
    Verify a dashboard JWT and return claims.

    Validates:
      - Input type, length, and three-segment base64url shape
      - HMAC signature against S43_JWT_SECRET
      - Required claims: sub, exp, iss, aud
      - Issuer and audience match configured values
      - Clock leeway: none; align with main.py route/WebSocket verification
      - Role claim is present and in _APPROVED_ROLES

    This is the single JWT verifier for the whole API — main.py's
    _get_operator() and dashboard_websocket() both import and call this
    function directly rather than keeping their own copy.
    """
    secret = _e("S43_JWT_SECRET")
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT verification is not configured.",
        )

    # Shape validation before decode — reject obviously-malformed input
    # without engaging the crypto path.
    if not isinstance(token, str) or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if len(token) > MAX_TOKEN_LEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not JWT_SHAPE_RE.match(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        claims = pyjwt.decode(
            token,
            secret,
            algorithms=[_jwt_algorithm()],
            issuer=_e("S43_JWT_ISSUER",   "sentinel-43"),
            audience=_e("S43_JWT_AUDIENCE", "sentinel-43-dashboard"),
            options={"require": ["sub", "exp", "iss", "aud"]},
        )
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except pyjwt.InvalidIssuerError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token issuer.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except pyjwt.InvalidAudienceError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token audience.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except pyjwt.MissingRequiredClaimError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Missing required claim: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except pyjwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    subject = str(claims.get("sub") or "").strip()
    if not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
        )

    # Role validation: the token may be cryptographically valid but not
    # authorized for operator routes. Match main.py route protection by
    # returning 403 instead of treating this as a malformed token.
    role = str(claims.get("role") or "").strip()
    if role not in _APPROVED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operator role required.",
        )

    # New-style session-bound claims (Pass 5A). NEITHER is required — a legacy
    # token carries neither and verifies exactly as before. But if a token
    # presents `sid` or `jti`, they must be well-formed: a malformed value is
    # a crafted/corrupt token, so fail closed rather than pass it through.
    # Pass 5A does NOT look `sid` up against the sessions table here (no hot-
    # path session read — mission Pass 5A §6); it only shape-checks.
    if "sid" in claims:
        sid = claims.get("sid")
        if not isinstance(sid, str) or not _SESSION_ID_RE.match(sid):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
    if "jti" in claims:
        jti = claims.get("jti")
        if not isinstance(jti, str) or not _JTI_RE.match(jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return claims


# =============================================================================
# Browser session — refresh cookie, CSRF double-submit, Phase-B dual contract
# (beta-execution Phase 3; AUTH_ARCHITECTURE_PASS4.md §3, AUTH_MIGRATION_PASS4
# Phase B). The access token stays the stateless request-hot-path credential
# (verify_jwt_token, unchanged). The refresh session is the durable one.
# =============================================================================

REFRESH_COOKIE_NAME = "s43_refresh"
CSRF_COOKIE_NAME = "s43_csrf"
CSRF_HEADER_NAME = "X-S43-CSRF"
# Path=/auth: the browser only ever sends the refresh cookie to /auth/refresh
# and /auth/logout, never to a protected data route.
_REFRESH_COOKIE_PATH = "/auth"

# legacy_auth_request_total — Phase D observability. Incremented whenever a
# protected request authenticates via X-S43-Password or an old-style
# (sid-less) token. Credential-free. Read by the metrics route / tests.
_legacy_auth_lock = threading.Lock()
_legacy_auth_counts: dict[str, int] = {}


def legacy_auth_request_total() -> dict[str, int]:
    with _legacy_auth_lock:
        return dict(_legacy_auth_counts)


def note_legacy_auth(route: str) -> None:
    key = route[:64] or "unknown"
    with _legacy_auth_lock:
        _legacy_auth_counts[key] = _legacy_auth_counts.get(key, 0) + 1
        _legacy_auth_counts["_all"] = _legacy_auth_counts.get("_all", 0) + 1


def legacy_auth_is_rejected() -> bool:
    """Beta cutover switch (AUTH_MIGRATION_PASS4 Phase E). When true, a
    protected request carrying X-S43-Password OR an old-style token is 401'd
    instead of accepted. Off by default — flip only once every consumer emits
    session tokens (the dashboard SPA + WS), per HANDOFF."""
    return _e("S43_REJECT_LEGACY_AUTH", "").lower() in {"1", "true", "yes", "on"}


def _cookie_secure() -> bool:
    """Refresh / CSRF cookies are issued Secure unless SENTINEL_ENV is local
    (so the flow is exercisable over http://localhost in dev). The deployment
    guarantees HTTPS in production (F-TLS-1); the app never infers scheme
    (AUTH_TLS_POSTURE_PASS5A §4/§8)."""
    env = _e("SENTINEL_ENV", "production").lower()
    if env in {"development", "dev", "local", "test"}:
        return _e("S43_FORCE_SECURE_COOKIES", "").lower() in {"1", "true", "yes", "on"}
    return True


def _session_access_ttl() -> int:
    return _ei("S43_SESSION_ACCESS_TTL_SECONDS", 900, lo=60, hi=3600)


def _allowed_origins() -> frozenset[str]:
    raw = _e(
        "S43_ALLOWED_ORIGINS",
        "http://127.0.0.1:5500,http://localhost:5500,"
        "http://127.0.0.1:8000,http://localhost:8000",
    )
    return frozenset(o.strip() for o in raw.split(",") if o.strip())


def _check_state_change_origin(request: Request) -> None:
    """Origin/Referer check for cookie-authenticated state changes (login /
    refresh / logout). CORS is NOT CSRF protection — this is the server-side
    half. A browser always sends Origin on a cross-site POST and on same-site
    POSTs in modern browsers; a non-browser API client sends neither and is
    not CSRF-exposed (it has no ambient cookie). So: if Origin is present it
    MUST be allow-listed; if absent, fall back to Referer; if both absent,
    allow (non-browser)."""
    origin = request.headers.get("origin", "").strip()
    allowed = _allowed_origins()
    if origin:
        if origin not in allowed:
            raise HTTPException(status_code=403, detail="Origin not allowed.")
        return
    referer = request.headers.get("referer", "").strip()
    if referer:
        from urllib.parse import urlsplit

        p = urlsplit(referer)
        base = f"{p.scheme}://{p.netloc}"
        if base not in allowed:
            raise HTTPException(status_code=403, detail="Referer not allowed.")


def _set_session_cookies(response: Response, refresh_secret: str, csrf_token: str) -> None:
    from ...auth.sessions import refresh_ttl_seconds

    ttl = refresh_ttl_seconds()
    secure = _cookie_secure()
    response.set_cookie(
        REFRESH_COOKIE_NAME, refresh_secret,
        max_age=ttl, path=_REFRESH_COOKIE_PATH,
        httponly=True, secure=secure, samesite="strict",
    )
    # CSRF cookie is readable by JS (double-submit) — NOT HttpOnly. SameSite
    # still Strict; Path=/ so the SPA can read it before calling /auth/*.
    response.set_cookie(
        CSRF_COOKIE_NAME, csrf_token,
        max_age=ttl, path="/",
        httponly=False, secure=secure, samesite="strict",
    )


def _clear_session_cookies(response: Response) -> None:
    secure = _cookie_secure()
    # Attributes must match the set call for the browser to actually drop it.
    response.set_cookie(
        REFRESH_COOKIE_NAME, "", max_age=0, path=_REFRESH_COOKIE_PATH,
        httponly=True, secure=secure, samesite="strict",
    )
    response.set_cookie(
        CSRF_COOKIE_NAME, "", max_age=0, path="/",
        httponly=False, secure=secure, samesite="strict",
    )


async def _create_login_session(
    *, user_id: str, request: Optional[Request],
) -> tuple[str, str, str]:
    """Create a server-side session for a DB account. Returns
    (sid, refresh_secret, csrf_token). Commits its own transaction."""
    from ...auth.sessions import create_session, generate_csrf_token, generate_refresh_secret
    from ...auth.users import get_sessionmaker

    refresh_secret = generate_refresh_secret()
    csrf_token = generate_csrf_token()
    client_ip = None
    user_agent = None
    if request is not None:
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
    sm = get_sessionmaker()
    async with sm() as s:
        row = await create_session(
            s, user_id=uuid.UUID(user_id), refresh_secret=refresh_secret,
            client_ip=client_ip, user_agent=user_agent,
        )
        await s.commit()
        sid = str(row.sid)
    return sid, refresh_secret, csrf_token


async def resolve_session_subject(claims: dict[str, Any]) -> Optional[tuple[str, str]]:
    """
    Phase-B request gate for a **session-bound** access token.

    Returns (subject, role) when the token's `sid` names a session that is
    still live AND whose owning account is still active — the caller then does
    NOT require X-S43-Password. Returns None when the token is NOT session-
    bound (legacy path — caller falls back to the password check). Raises 401
    when the token IS session-bound but the session is dead / the owner is
    disabled.

    One indexed PK lookup + one indexed user lookup per request, read-only
    (no write — the Pass 3 "no DB write on the hot path" rule holds). This is
    the immediate-revocation guarantee: logout / disablement / role change /
    refresh-reuse all set `revoked_at`, so the very next request 401s.
    """
    if not token_is_session_bound(claims):
        return None

    from ...auth.sessions import (
        SessionError,
        resolve_live_session,
    )
    from ...auth.users import get_sessionmaker

    sid = claims.get("sid")
    try:
        sid_uuid = uuid.UUID(str(sid))
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid session.", headers={"WWW-Authenticate": "Bearer"})

    try:
        sm = get_sessionmaker()
    except Exception:
        # No DB configured but the token claims a session — cannot verify it.
        raise HTTPException(status_code=401, detail="Session cannot be verified.", headers={"WWW-Authenticate": "Bearer"})

    try:
        async with sm() as s:
            row, owner = await resolve_live_session(s, sid_uuid)
    except SessionError:
        raise HTTPException(
            status_code=401,
            detail="Session is no longer valid. Log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    subject = str(claims.get("sub") or owner.username).strip()
    # Role: trust the access-token claim for operator-vs-admin gating (≤ the
    # 15-min access TTL stale). require_admin still re-reads the DB live.
    role = str(claims.get("role") or owner.role).strip()
    return subject, role


# =============================================================================
# Routes
# =============================================================================

@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request, response: Response) -> LoginResponse:
    """
    Exchange operator credentials for an access token.

    DB accounts additionally get a server-side session: an opaque refresh
    credential in an HttpOnly/Secure/SameSite=Strict cookie
    (Path=/auth), a JS-readable CSRF token cookie, and a `sid`-bound 15-min
    access token. The env-var break-glass operator (no DB row) gets the
    legacy 8-hour token and no cookie.

    Per-username brute-force throttle unchanged.
    """
    _check_state_change_origin(request)
    _login_check_throttled(body.username)
    try:
        subject, role, user_id = await _validate_credentials(body.username, body.password)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            _login_record_failure(body.username)
        raise
    _login_clear(body.username)

    if user_id is not None:
        try:
            sid, refresh_secret, csrf_token = await _create_login_session(
                user_id=user_id, request=request,
            )
        except Exception as exc:
            # The account is valid but the session could not be persisted
            # (sessions table missing / DB write error). This used to
            # silently degrade to a legacy 8h token + X-S43-Password — a
            # session-security downgrade for an already-authenticated user,
            # decided by an exception rather than an explicit choice. Fail
            # loudly instead: the credential was fine, the platform wasn't.
            logger.error(
                "op=auth.login.session_create_failed exception_class=%s — "
                "refusing to silently degrade to a legacy long-lived token.",
                type(exc).__name__,
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Login succeeded but the session could not be created. Try again shortly.",
            )
        token, exp_dt = _issue_token(
            subject=subject, role=role, user_id=user_id, sid=sid,
        )
        _set_session_cookies(response, refresh_secret, csrf_token)
        return LoginResponse(
            token=token, access_token=token, subject=subject,
            role=role, expires_in=_session_access_ttl(),
            expires_at=exp_dt.isoformat(), session_bound=True,
        )

    token, exp_dt = _issue_token(subject=subject, role=role, user_id=user_id)
    return LoginResponse(
        token=token, subject=subject, expires_at=exp_dt.isoformat(),
    )


@router.post("/refresh", response_model=RefreshResponse)
async def refresh(request: Request, response: Response) -> RefreshResponse:
    """
    Rotate the refresh session and mint a fresh 15-min access token.

    Requires: the `s43_refresh` cookie AND a CSRF double-submit
    (`X-S43-CSRF` header == `s43_csrf` cookie) AND an allow-listed Origin.
    Any failure clears the cookies and 401s. Presenting a superseded refresh
    value is treated as theft — the whole session is revoked.
    """
    _check_state_change_origin(request)

    cookie = request.cookies.get(REFRESH_COOKIE_NAME, "")
    if not cookie:
        _clear_session_cookies(response)
        raise HTTPException(status_code=401, detail="No session.", headers={"WWW-Authenticate": "Bearer"})

    from ...auth.sessions import (
        csrf_tokens_match,
        generate_csrf_token,
        generate_refresh_secret,
        rotate_refresh,
        RefreshInvalidError,
        RefreshReuseError,
        SessionExpiredError,
        SessionOwnerInactiveError,
        SessionRevokedError,
    )
    from ...auth.users import get_sessionmaker, get_user_by_id

    csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
    if not csrf_tokens_match(csrf_cookie, request.headers.get(CSRF_HEADER_NAME)):
        raise HTTPException(status_code=403, detail="CSRF check failed.")

    new_secret = generate_refresh_secret()
    # Keep the CSRF token stable across the session (re-issued only to refresh
    # its Max-Age) so a client does not have to re-read it after every rotate.
    new_csrf = csrf_cookie or generate_csrf_token()
    sm = get_sessionmaker()
    async with sm() as s:
        try:
            row, _outcome = await rotate_refresh(
                s, presented_secret=cookie, new_refresh_secret=new_secret,
            )
        except RefreshReuseError:
            await s.commit()  # persist the theft revoke
            _clear_session_cookies(response)
            raise HTTPException(status_code=401, detail="Session ended. Log in again.", headers={"WWW-Authenticate": "Bearer"})
        except SessionOwnerInactiveError:
            await s.commit()  # persist the owner-inactive revoke
            _clear_session_cookies(response)
            raise HTTPException(status_code=401, detail="Account is disabled.", headers={"WWW-Authenticate": "Bearer"})
        except (RefreshInvalidError, SessionRevokedError, SessionExpiredError):
            _clear_session_cookies(response)
            raise HTTPException(status_code=401, detail="Session is no longer valid. Log in again.", headers={"WWW-Authenticate": "Bearer"})

        owner = await get_user_by_id(s, row.user_id)
        if owner is None or not owner.is_active:
            await s.commit()
            _clear_session_cookies(response)
            raise HTTPException(status_code=401, detail="Account is disabled.", headers={"WWW-Authenticate": "Bearer"})
        subject, role, user_id = owner.username, owner.role, str(owner.user_id)
        await s.commit()

    token, exp_dt = _issue_token(subject=subject, role=role, user_id=user_id, sid=str(row.sid))
    _set_session_cookies(response, new_secret, new_csrf)
    return RefreshResponse(
        token=token, access_token=token, subject=subject, role=role,
        expires_in=_session_access_ttl(), expires_at=exp_dt.isoformat(),
    )


@router.post("/logout")
async def logout(request: Request, response: Response) -> dict[str, Any]:
    """
    Revoke the server-side session and clear the cookies. Idempotent: no
    cookie, an unknown value, or an already-revoked session all return 200.
    Requires the CSRF double-submit when a refresh cookie is present.
    """
    _check_state_change_origin(request)
    cookie = request.cookies.get(REFRESH_COOKIE_NAME, "")
    if cookie:
        from ...auth.sessions import csrf_tokens_match, logout_by_refresh
        from ...auth.users import get_sessionmaker

        if not csrf_tokens_match(request.cookies.get(CSRF_COOKIE_NAME), request.headers.get(CSRF_HEADER_NAME)):
            raise HTTPException(status_code=403, detail="CSRF check failed.")
        try:
            sm = get_sessionmaker()
            async with sm() as s:
                await logout_by_refresh(s, presented_secret=cookie)
                await s.commit()
        except Exception as exc:  # never let a teardown error keep a user "logged in"
            logger.warning("logout revoke error: %s", type(exc).__name__)

    _clear_session_cookies(response)
    return {"ok": True}


@router.get("/verify", response_model=VerifyResponse)
async def verify(
    authorization: str | None = Header(default=None),
) -> VerifyResponse:
    """
    Validate a Bearer JWT.

    Called by auth.js on page load to check whether a stored token is still
    valid before allowing websocket.js to connect. Returns 200 if valid,
    401 if expired or invalid.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = authorization.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_token = parts[1].strip()

    # Shape and length are also validated inside verify_jwt_token(), but
    # checking here first avoids reaching the function with obviously-bad input.
    if not raw_token or len(raw_token) > MAX_TOKEN_LEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
        )

    claims  = verify_jwt_token(raw_token)
    subject = str(claims.get("sub", "")).strip()
    role    = str(claims.get("role", "")).strip()
    exp     = claims.get("exp")
    exp_dt  = (
        datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
        if isinstance(exp, (int, float))
        else ""
    )

    return VerifyResponse(
        valid=True,
        subject=subject,
        role=role,
        expires_at=exp_dt,
    )
