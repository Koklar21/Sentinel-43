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
# Required environment variables:
#   S43_JWT_SECRET              — HMAC signing key (required)
#   S43_OPERATOR_USERNAME       — operator username (default: "operator")
#   S43_OPERATOR_PASSWORD_HASH  — SHA-256 hex digest of the operator password
#
# Optional environment variables:
#   S43_JWT_ALGORITHM           — default: HS256
#   S43_JWT_ISSUER              — default: sentinel-43
#   S43_JWT_AUDIENCE            — default: sentinel-43-dashboard
#   S43_JWT_TTL_SECONDS         — default: 28800 (8 hours), clamped 60–86400
#
# Credential setup:
#   Generate password hash:
#     python -c "import hashlib; print(hashlib.sha256(b'yourpassword').hexdigest())"
#   Set in .env:
#     S43_OPERATOR_USERNAME=operator
#     S43_OPERATOR_PASSWORD_HASH=<hash output>
#
# Security note:
#   SHA-256 is used here as a deployment-simple credential check for closed
#   beta. Upgrade to bcrypt or Argon2 before public release. Both legs of
#   credential comparison use secrets.compare_digest to prevent timing attacks.
# =============================================================================

from __future__ import annotations

import hashlib
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any

import jwt as pyjwt
from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

router = APIRouter(prefix="/auth", tags=["auth"])


# =============================================================================
# Config — all read at call time so Docker env injection works correctly.
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


MAX_USERNAME_LEN = 128
MAX_PASSWORD_LEN = 1024
MAX_TOKEN_LEN    = 4096


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
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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

    now     = int(time.time())
    ttl     = _ei("S43_JWT_TTL_SECONDS", 28800, lo=60, hi=86400)
    exp     = now + ttl
    exp_dt  = datetime.fromtimestamp(exp, tz=timezone.utc)

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

    token = pyjwt.encode(
        payload,
        secret,
        algorithm=_e("S43_JWT_ALGORITHM", "HS256"),
    )

    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LEN:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token generation failed.",
        )

    return token, exp_dt


def _validate_credentials(username: str, password: str) -> str:
    """
    Validate operator credentials against env-configured values.

    Both comparisons always run to prevent timing-based enumeration.
    Returns the normalized username on success; raises 401 on failure.
    """
    expected_username = _e("S43_OPERATOR_USERNAME", "operator")
    expected_hash     = _e("S43_OPERATOR_PASSWORD_HASH")

    if not expected_hash:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Operator credentials are not configured on this server.",
        )

    normalized = username.strip()

    username_ok = secrets.compare_digest(
        normalized.lower().encode("utf-8"),
        expected_username.lower().encode("utf-8"),
    )
    password_ok = secrets.compare_digest(
        _sha256_hex(password).encode("utf-8"),
        expected_hash.lower().encode("utf-8"),
    )

    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return normalized


def verify_jwt_token(token: str) -> dict[str, Any]:
    """
    Verify a dashboard JWT and return claims.

    Exported so callers outside this router can reuse the same verifier
    rather than duplicating validation logic.
    """
    secret = _e("S43_JWT_SECRET")
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT verification is not configured.",
        )

    try:
        claims = pyjwt.decode(
            token,
            secret,
            algorithms=[_e("S43_JWT_ALGORITHM", "HS256")],
            issuer=_e("S43_JWT_ISSUER", "sentinel-43"),
            audience=_e("S43_JWT_AUDIENCE", "sentinel-43-dashboard"),
            options={"require": ["sub", "exp", "iss", "aud", "iat"]},
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
            detail="Invalid token subject.",
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
    subject        = _validate_credentials(body.username, body.password)
    token, exp_dt  = _issue_token(subject=subject, role="operator")

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
    if not raw_token or len(raw_token) > MAX_TOKEN_LEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
        )

    claims  = verify_jwt_token(raw_token)
    subject = str(claims.get("sub", "")).strip()
    role    = str(claims.get("role") or claims.get("scope") or "").strip()
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
