# =============================================================================
# Sentinel-43
#
# core/api/routers/auth.py
#
# Dashboard operator authentication router.
#
# Provides:
#   POST /auth/login   -> validates operator credentials and returns a JWT
#   GET  /auth/verify  -> validates a Bearer JWT for auth.js startup checks
#
# Expected frontend:
#   dashboard auth.js stores returned token as sessionStorage["SENTINEL_JWT"]
#   websocket.js then sends that token in the WebSocket auth frame.
#
# Required environment:
#   S43_JWT_SECRET              required
#   S43_OPERATOR_USERNAME       required
#   S43_OPERATOR_PASSWORD       required
#
# Optional environment:
#   S43_JWT_ALGORITHM           default: HS256
#   S43_JWT_TTL_SECONDS         default: 28800  # 8 hours
#   S43_JWT_ISSUER              default: sentinel-43
#   S43_JWT_AUDIENCE            default: sentinel-43-dashboard
# =============================================================================

from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field


router = APIRouter(prefix="/auth", tags=["auth"])


# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------

JWT_SECRET = os.getenv("S43_JWT_SECRET", "").strip()
JWT_ALGORITHM = os.getenv("S43_JWT_ALGORITHM", "HS256").strip() or "HS256"
JWT_ISSUER = os.getenv("S43_JWT_ISSUER", "sentinel-43").strip() or "sentinel-43"
JWT_AUDIENCE = (
    os.getenv("S43_JWT_AUDIENCE", "sentinel-43-dashboard").strip()
    or "sentinel-43-dashboard"
)

try:
    JWT_TTL_SECONDS = int(os.getenv("S43_JWT_TTL_SECONDS", "28800"))
except ValueError:
    JWT_TTL_SECONDS = 28800

JWT_TTL_SECONDS = max(60, min(JWT_TTL_SECONDS, 86_400))

OPERATOR_USERNAME = os.getenv("S43_OPERATOR_USERNAME", "").strip()
OPERATOR_PASSWORD = os.getenv("S43_OPERATOR_PASSWORD", "")

MAX_USERNAME_LEN = 128
MAX_PASSWORD_LEN = 1024
MAX_TOKEN_CHARS = 4096


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=MAX_USERNAME_LEN)
    password: str = Field(..., min_length=1, max_length=MAX_PASSWORD_LEN)


class LoginResponse(BaseModel):
    token: str
    token_type: str = "bearer"
    subject: str
    expires_at: str


class VerifyResponse(BaseModel):
    valid: bool = True
    subject: str
    expires_at: int | None = None


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _auth_not_configured() -> bool:
    return not JWT_SECRET or not OPERATOR_USERNAME or not OPERATOR_PASSWORD


def _unauthorized(message: str = "Invalid username or password.") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=message,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _constant_time_equal(left: str, right: str) -> bool:
    return secrets.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _validate_credentials(username: str, password: str) -> str:
    """
    Validate dashboard operator credentials.

    This intentionally uses environment-provided credentials for the first S43
    dashboard gate. Replace this function later with database-backed operators,
    password hashing, lockout policy, and audit logging when the user/account
    system comes online.
    """
    if _auth_not_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured.",
        )

    normalized_username = username.strip()

    username_ok = _constant_time_equal(normalized_username, OPERATOR_USERNAME)
    password_ok = _constant_time_equal(password, OPERATOR_PASSWORD)

    if not (username_ok and password_ok):
        raise _unauthorized()

    return normalized_username


def _create_access_token(subject: str) -> tuple[str, datetime]:
    if not JWT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT signing secret is not configured.",
        )

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=JWT_TTL_SECONDS)

    claims: dict[str, Any] = {
        "sub": subject,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "typ": "access",
        "scope": "dashboard",
    }

    token = jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)

    if not isinstance(token, str) or len(token) > MAX_TOKEN_CHARS:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Generated token is invalid.",
        )

    return token, expires_at


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise _unauthorized("Missing bearer token.")

    parts = authorization.strip().split()

    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise _unauthorized("Malformed bearer token.")

    token = parts[1].strip()

    if not token or len(token) > MAX_TOKEN_CHARS:
        raise _unauthorized("Invalid bearer token.")

    return token


def verify_jwt_token(token: str) -> dict[str, Any]:
    """
    Verify a dashboard JWT and return claims.

    Exported intentionally so WebSocket auth can reuse the same verifier instead
    of growing a second auth path like a mold colony.
    """
    if not JWT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT verification is not configured.",
        )

    try:
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={
                "require": ["sub", "exp", "iat", "nbf", "iss", "aud"],
            },
        )
    except jwt.ExpiredSignatureError:
        raise _unauthorized("Token expired.")
    except jwt.InvalidTokenError:
        raise _unauthorized("Invalid token.")

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise _unauthorized("Invalid token subject.")

    if claims.get("typ") != "access":
        raise _unauthorized("Invalid token type.")

    return claims


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest) -> LoginResponse:
    subject = _validate_credentials(payload.username, payload.password)
    token, expires_at = _create_access_token(subject)

    return LoginResponse(
        token=token,
        subject=subject,
        expires_at=expires_at.isoformat(),
    )


@router.get("/verify", response_model=VerifyResponse)
async def verify(authorization: str | None = Header(default=None)) -> VerifyResponse:
    token = _extract_bearer_token(authorization)
    claims = verify_jwt_token(token)

    exp = claims.get("exp")
    return VerifyResponse(
        valid=True,
        subject=str(claims["sub"]),
        expires_at=exp if isinstance(exp, int) else None,
    )
'''

path = Path("/mnt/data/auth.py")
path.write_text(code, encoding="utf-8")
print(f"created {path}")
