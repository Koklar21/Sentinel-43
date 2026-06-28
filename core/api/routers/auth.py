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
# main.py's _verify_jwt_token() and _get_operator() consume the same JWT.
#
# Note: main.py currently maintains its own _verify_jwt_token(). Both paths
# use identical config so they behave the same. Future cleanup should import
# verify_jwt_token() from here instead of maintaining two paths.
#
# Required .env variables:
#   S43_JWT_SECRET              — HMAC signing key
#   S43_OPERATOR_USERNAME       — operator username (default: "operator")
#   S43_OPERATOR_PASSWORD_HASH  — sha256(password).hexdigest() — NOT sha256 of hash
#
# Optional .env variables:
#   S43_JWT_ALGORITHM     — HS256 | HS384 | HS512 (default: HS256)
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
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any

import jwt as pyjwt
from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

router = APIRouter(prefix="/auth", tags=["auth"])


# =============================================================================
# Constants
# =============================================================================

MAX_USERNAME_LEN = 128
MAX_PASSWORD_LEN = 1024
MAX_TOKEN_LEN    = 4096

# Only HMAC-family algorithms are permitted. Asymmetric algorithms and
# "none" are never allowed regardless of what S43_JWT_ALGORITHM contains.
_ALLOWED_JWT_ALGORITHMS: frozenset[str] = frozenset({"HS256", "HS384", "HS512"})

# Approved operator roles. If a decoded JWT's "role" claim is missing or
# outside this set, verify_jwt_token() raises 401.
_APPROVED_ROLES: frozenset[str] = frozenset({"operator", "admin"})

# Three-segment base64url shape. Validated before pyjwt.decode() to reject
# obviously-malformed input without touching the decode path.
JWT_SHAPE_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


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
    {HS256, HS384, HS512}. Fails loudly at the route rather than at import,
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


def _validate_credentials(username: str, password: str) -> str:
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


def _issue_token(subject: str, role: str = "operator") -> tuple[str, datetime]:
    """
    Sign and return a JWT for the given subject.

    Token claims are designed to satisfy:
      - main.py _verify_jwt_token() (requires sub, exp, iss, aud)
      - main.py _get_operator()     (checks claims["role"] against _APPROVED_ROLES)
      - main.py WebSocket auth path (same role check)
      - auth.js /auth/verify        (checks res.ok)
    """
    secret = _e("S43_JWT_SECRET")
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT signing key is not configured on this server.",
        )

    now    = int(time.time())
    ttl    = _ei("S43_JWT_TTL_SECONDS", 28800, lo=60, hi=86400)
    exp    = now + ttl
    exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)

    payload: dict[str, Any] = {
        "sub":  subject,
        "iss":  _e("S43_JWT_ISSUER",   "sentinel-43"),
        "aud":  _e("S43_JWT_AUDIENCE", "sentinel-43-dashboard"),
        "iat":  now,
        "nbf":  now,
        "exp":  exp,
        # "role" is what main.py _get_operator() and the WebSocket auth path
        # check against _APPROVED_ROLES = {"operator", "admin"}.
        "role": role,
    }

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
      - Required claims: sub, exp, iss, aud, iat, nbf
      - Issuer and audience match configured values
      - Clock leeway: 30 seconds
      - Role claim is present and in _APPROVED_ROLES

    Exported so callers outside this router can reuse the same verifier.
    main.py currently maintains its own _verify_jwt_token(); both use
    identical config. Future cleanup should consolidate to this function.
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
            options={"require": ["sub", "exp", "iss", "aud", "iat", "nbf"]},
            leeway=30,
        )
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired.",
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

    # Role validation: missing or unapproved role is a hard 401.
    # This is the same check main.py's _get_operator() applies to HTTP
    # routes and the WebSocket auth path applies to connections.
    role = str(claims.get("role") or "").strip()
    if role not in _APPROVED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
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
    """
    subject       = _validate_credentials(body.username, body.password)
    token, exp_dt = _issue_token(subject=subject, role="operator")

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
