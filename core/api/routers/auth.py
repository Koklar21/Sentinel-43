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
#   S43_OPERATOR_PASSWORD_HASH  — sha256(password).hexdigest() — NOT sha256 of hash
#
# Optional .env variables:
#   S43_JWT_ALGORITHM     — HS256 only (default: HS256)
#   S43_JWT_ISSUER        — default: sentinel-43
#   S43_JWT_AUDIENCE      — default: sentinel-43-dashboard
#   S43_JWT_TTL_SECONDS   — default: 28800 (8 hours), clamped 60–86400
#
# Credential setup:
#   Generate password hash:
#     python -c "import hashlib; print(hashlib.sha256(b'yourpassword').hexdigest())"
#   Generate JWT secret:
#     python -c "import secrets; print(secrets.token_urlsafe(32))"
#
# Security note:
#   SHA-256 is used here as a deployment-simple credential check for closed
#   beta. Upgrade to bcrypt or Argon2 before public release.
#   All credential comparisons use secrets.compare_digest to prevent timing
#   attacks. Username comparison hashes both sides to fixed-width digests
#   before compare_digest to prevent length-based timing leakage.
# =============================================================================

from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

import jwt as pyjwt
from fastapi import APIRouter, Header, HTTPException, status
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


def _valid_sha256_hex(value: str) -> bool:
    """
    Return True if value is a valid 64-character hex string.

    A fat-fingered or truncated S43_OPERATOR_PASSWORD_HASH causes login
    to fail silently with a misleading "Invalid credentials" response.
    Catching it here surfaces the real config problem immediately.
    """
    return len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value)


# =============================================================================
# Models
# =============================================================================

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=MAX_USERNAME_LEN)
    password: str = Field(..., min_length=1, max_length=MAX_PASSWORD_LEN)


class LoginResponse(BaseModel):
    token:      str
    token_type: str = "bearer"
    subject:    str
    expires_at: str


class VerifyResponse(BaseModel):
    valid:      bool = True
    subject:    str
    role:       str
    expires_at: str


# =============================================================================
# Internal helpers
# =============================================================================

def _sha256_hex(value: str) -> str:
    """Return lowercase hex SHA-256 digest of value."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_digest(value: str) -> bytes:
    """Return raw SHA-256 digest bytes of value. Used for fixed-width timing-safe comparisons."""
    return hashlib.sha256(value.encode("utf-8")).digest()


def _validate_env_credentials(username: str, password: str) -> str:
    """
    Validate operator credentials against env-configured values.

    Password comparison:
      sha256(typed_password).hexdigest().lower()
        compared with
      S43_OPERATOR_PASSWORD_HASH.lower()

    S43_OPERATOR_PASSWORD_HASH is already sha256(password).hexdigest().
    Do NOT double-hash it.

    Username comparison hashes both sides to fixed-width SHA-256 digests
    before compare_digest to prevent length-based timing leakage.

    Both comparisons always run before any error is raised to prevent
    timing-based enumeration of which field failed.

    Returns the canonical expected_username (not the operator's typed
    casing) as the JWT subject, so the subject in the token is always
    the value from config regardless of how the operator typed it.
    """
    expected_username = _e("S43_OPERATOR_USERNAME", "operator")
    expected_hash     = _e("S43_OPERATOR_PASSWORD_HASH")

    # Validate hash format before comparison. A truncated or malformed hash
    # produces silent failures that look like wrong passwords.
    if not expected_hash or not _valid_sha256_hex(expected_hash):
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

    # Password: compare sha256(typed_password).hexdigest() against the stored
    # hash directly. The stored hash IS sha256(password) — do not re-hash it.
    password_ok = secrets.compare_digest(
        _sha256_hex(password).lower(),
        expected_hash.lower(),
    )

    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Return the canonical configured username, not the operator's typed
    # casing. The JWT sub claim will always reflect the config value.
    return expected_username


async def reverify_password(username: str, password: str) -> bool:
    """
    Re-validate a password for a subject that has already passed JWT
    verification. Used by the per-request password gate (X-S43-Password
    header): a valid JWT alone is no longer sufficient to reach protected
    routes — the operator's password must accompany every request.

    Checks the DB-backed account system first (matching _validate_credentials),
    then falls back to the env-var operator check. Returns False rather than
    raising on any mismatch/misconfiguration reachable this way; callers are
    responsible for turning a False into the appropriate HTTP error.
    """
    normalized = username.strip()
    if not normalized or not password:
        return False

    try:
        from ...auth.users import authenticate_user, get_sessionmaker

        sessionmaker = get_sessionmaker()
        async with sessionmaker() as session:
            # Read-only: authenticate_user() no longer writes last_login_at on
            # any path. reverify_password() runs on every protected request —
            # it must never touch the DB beyond the SELECT + Argon2 verify.
            user = await authenticate_user(session, normalized, password)
            if user is not None:
                return True
    except Exception as exc:
        logger.debug("DB-backed password reverify unavailable, falling back to env-var: %s", exc)

    try:
        _validate_env_credentials(normalized, password)
        return True
    except HTTPException:
        return False


async def _validate_credentials(username: str, password: str) -> tuple[str, str, str | None]:
    """
    Resolve operator credentials to (subject, role, user_id).

    Checks the DB-backed account system (core.auth.users) first. Falls
    back to the legacy S43_OPERATOR_USERNAME / S43_OPERATOR_PASSWORD_HASH
    single-account check if DATABASE_URL is unset, the DB is unreachable,
    or no DB user matches — this is deliberate so existing deployments and
    the env-var-based test suite (test_auth_login.py) keep working
    unmodified during the migration to DB-backed accounts. user_id is None
    on the fallback path since env-var operators have no DB row.

    Both paths still run the fallback's constant-time comparison when
    reached, so a DB miss doesn't skip straight to a faster-failing check.
    """
    normalized = username.strip()

    try:
        from ...auth.users import authenticate_user, get_sessionmaker, record_login

        sessionmaker = get_sessionmaker()
        async with sessionmaker() as session:
            user = await authenticate_user(session, normalized, password)
            if user is not None:
                # This IS a login — record it. authenticate_user() itself is
                # read-only now; _validate_credentials owns this write and the
                # commit. reverify_password()'s per-request path does not
                # reach here, so last_login_at still means "last login".
                subject, role, user_id = user.username, user.role, str(user.user_id)
                await record_login(session, user)
                await session.commit()
                return subject, role, user_id
    except Exception as exc:
        # DATABASE_URL unset, DB unreachable, or table not created yet.
        # Not fatal — fall through to the env-var check below.
        logger.debug("DB-backed login unavailable, falling back to env-var credentials: %s", exc)

    return _validate_env_credentials(normalized, password), "operator", None


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
# Routes
# =============================================================================

@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest) -> LoginResponse:
    """
    Exchange operator credentials for a signed JWT.

    The JWT is consumed by auth.js (stored in sessionStorage) and then sent
    by websocket.js during the WebSocket authentication handshake.

    Per-username brute-force throttle: after S43_LOGIN_MAX_FAILURES (10)
    failures inside S43_LOGIN_FAIL_WINDOW_SECONDS (300), further attempts for
    that username get 429 for S43_LOGIN_LOCKOUT_SECONDS (300).
    """
    _login_check_throttled(body.username)
    try:
        subject, role, user_id = await _validate_credentials(body.username, body.password)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            _login_record_failure(body.username)
        raise
    _login_clear(body.username)

    token, exp_dt = _issue_token(subject=subject, role=role, user_id=user_id)
    return LoginResponse(
        token=token,
        subject=subject,
        expires_at=exp_dt.isoformat(),
    )


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
