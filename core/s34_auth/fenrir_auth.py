# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
# =============================================================================

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt


class FenrirAuthError(RuntimeError):
    """Raised when Fenrir authentication or authorization fails."""


@dataclass(frozen=True)
class FenrirAuthConfig:
    jwt_secret: str
    issuer: str = "sentinel-43"
    audience: str = "fenrir"
    algorithm: str = "HS256"
    token_ttl_minutes: int = 15
    require_auth: bool = True

    @classmethod
    def from_env(cls) -> "FenrirAuthConfig":
        secret = os.getenv("SENTINEL_FENRIR_JWT_SECRET") or os.getenv("FENRIR_JWT_SECRET")
        require_auth = (os.getenv("SENTINEL_FENRIR_REQUIRE_AUTH", "true").lower() == "true")

        if require_auth and (not secret or secret.strip() in {"dev", "changeme", "CHANGE_ME", "orion-jwt-secret"}):
            raise FenrirAuthError("Fenrir JWT secret is missing or unsafe. Refusing to start.")

        return cls(
            jwt_secret=secret or "local-dev-disabled-auth",
            issuer=os.getenv("SENTINEL_JWT_ISSUER", "sentinel-43"),
            audience=os.getenv("SENTINEL_FENRIR_JWT_AUDIENCE", "fenrir"),
            algorithm=os.getenv("SENTINEL_JWT_ALGORITHM", "HS256"),
            token_ttl_minutes=int(os.getenv("SENTINEL_FENRIR_TOKEN_TTL_MINUTES", "15")),
            require_auth=require_auth,
        )


def create_fenrir_token(
    subject: str,
    config: FenrirAuthConfig,
    *,
    scopes: Optional[list[str]] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "sub": subject,
        "iss": config.issuer,
        "aud": config.audience,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=config.token_ttl_minutes)).timestamp()),
        "scope": " ".join(scopes or ["fenrir:read"]),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, config.jwt_secret, algorithm=config.algorithm)


def verify_fenrir_token(token: str, config: FenrirAuthConfig, *, required_scope: Optional[str] = None) -> Dict[str, Any]:
    if not config.require_auth:
        return {"sub": "local-auth-disabled", "scope": "*", "iat": int(time.time())}

    if not token or not isinstance(token, str):
        raise FenrirAuthError("Missing bearer token.")

    try:
        payload = jwt.decode(
            token,
            config.jwt_secret,
            algorithms=[config.algorithm],
            issuer=config.issuer,
            audience=config.audience,
            options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise FenrirAuthError(f"Invalid Fenrir JWT: {exc}") from exc

    if required_scope:
        scopes = set(str(payload.get("scope", "")).split())
        if required_scope not in scopes and "*" not in scopes:
            raise FenrirAuthError(f"Missing required scope: {required_scope}")

    return payload


def extract_bearer_token(header_value: Optional[str]) -> Optional[str]:
    if not header_value or not isinstance(header_value, str):
        return None
    scheme, _, token = header_value.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()
