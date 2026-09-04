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

import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt

logger = logging.getLogger("sentinel43.fenrir.auth")


# =============================================================================
# Constants
# =============================================================================

# Fix #2: explicit server-side algorithm allowlist.
# "none" and asymmetric algorithms (RS256, ES256, etc.) are excluded.
# RS256 in particular enables algorithm-confusion attacks where the attacker
# uses the public key as the HMAC secret to forge tokens.
_ALLOWED_ALGORITHMS: frozenset[str] = frozenset({"HS256", "HS384", "HS512"})

# Fix #3: reserved JWT claims that extra_claims must never override.
_RESERVED_CLAIMS: frozenset[str] = frozenset(
    {"sub", "iss", "aud", "iat", "nbf", "exp", "scope"}
)

# Fix #3: minimum JWT secret length for HMAC-SHA256 (32 bytes = 256 bits).
_MIN_SECRET_LENGTH = 32

# Fix #3: known-weak secrets blocked regardless of length.
# Checked case-insensitively so "CHANGEME", "Changeme", etc. are all caught.
_BLOCKED_SECRETS: frozenset[str] = frozenset({
    "dev", "changeme", "change_me", "secret", "password", "test",
    "orion-jwt-secret", "dev-only-change-me", "local-dev-disabled-auth",
    "1234", "12345678", "abcdefgh",
})


# =============================================================================
# Utilities
# =============================================================================

def _env_bool(name_primary: str, name_fallback: str, default: bool) -> bool:
    """
    Fix #4: replaces the original `.lower() == "true"` pattern which treated
    empty string, "yes", "1", "on" as False — silently disabling auth when
    any truthy-but-not-"true" value was set, or when the var was blank.
    """
    for name in (name_primary, name_fallback):
        raw = os.getenv(name, "").strip().lower()
        if raw == "":
            continue
        if raw in {"1", "true", "yes", "y", "on"}:
            return True
        if raw in {"0", "false", "no", "n", "off"}:
            return False
        logger.warning(
            "fenrir_auth: unrecognised bool for %s=%r; using default %s",
            name, os.getenv(name), default,
        )
    return default


def _env_int(name_primary: str, name_fallback: str, default: int) -> int:
    """
    Fix #5: replaces bare int(os.getenv(...)) which raises ValueError on any
    non-numeric env var value, crashing the application at startup.
    """
    for name in (name_primary, name_fallback):
        raw = os.getenv(name, "").strip()
        if raw:
            try:
                return int(raw)
            except ValueError:
                logger.warning(
                    "fenrir_auth: invalid integer for %s=%r; using default %s",
                    name, raw, default,
                )
    return default


def _validate_jwt_secret(secret: str, require_auth: bool) -> None:
    """
    Fix #3: moved secret validation into a standalone function so it can be
    called from both from_env() and __post_init__, closing the bypass where
    FenrirAuthConfig(jwt_secret="dev", require_auth=True) skipped the check.

    Enforces:
      - minimum length (32 chars / 256 bits for HMAC-SHA256)
      - blocked-value list (case-insensitive)
    """
    if not require_auth:
        return

    if not secret or len(secret) < _MIN_SECRET_LENGTH:
        raise FenrirAuthError(
            f"Fenrir JWT secret is too short (got {len(secret) if secret else 0} chars; "
            f"minimum is {_MIN_SECRET_LENGTH}). Use a cryptographically random secret "
            f"of at least {_MIN_SECRET_LENGTH} characters."
        )

    if secret.strip().lower() in _BLOCKED_SECRETS:
        raise FenrirAuthError(
            "Fenrir JWT secret matches a known-weak value. "
            "Use a cryptographically random secret."
        )


# =============================================================================
# Exceptions
# =============================================================================

class FenrirAuthError(RuntimeError):
    """Raised when Fenrir authentication or authorization fails."""


# =============================================================================
# Config
# =============================================================================

@dataclass(frozen=True)
class FenrirAuthConfig:
    jwt_secret:         str
    issuer:             str   = "sentinel-43"
    audience:           str   = "fenrir"
    algorithm:          str   = "HS256"
    token_ttl_minutes:  int   = 15
    require_auth:       bool  = True

    def __post_init__(self) -> None:
        # Fix #2: algorithm must be in the server-side allowlist.
        if self.algorithm not in _ALLOWED_ALGORITHMS:
            raise FenrirAuthError(
                f"Fenrir JWT algorithm {self.algorithm!r} is not in the "
                f"allowed list {sorted(_ALLOWED_ALGORITHMS)}. "
                "Algorithm confusion attacks are possible with asymmetric algorithms."
            )

        # Fix #3: validate secret strength here (not only in from_env) so
        # direct construction can't bypass the check.
        _validate_jwt_secret(self.jwt_secret, self.require_auth)

    @classmethod
    def from_env(cls) -> "FenrirAuthConfig":
        """
        Build from environment variables.

        Fix #4: boolean flags use _env_bool (not .lower() == "true") so empty
        string and non-"true" truthy values don't silently disable auth.
        Fix #5: int cast uses _env_int so invalid values use the default.
        Fix #7: the fallback jwt_secret when auth is disabled is a fresh random
        value per process start, not the predictable "local-dev-disabled-auth".
        """
        require_auth = _env_bool(
            "SENTINEL_FENRIR_REQUIRE_AUTH", "FENRIR_REQUIRE_AUTH", True
        )
        secret_raw = (
            os.getenv("SENTINEL_FENRIR_JWT_SECRET", "").strip()
            or os.getenv("FENRIR_JWT_SECRET", "").strip()
        )

        if require_auth:
            # Validate before constructing — gives a clear startup error.
            if not secret_raw:
                raise FenrirAuthError(
                    "SENTINEL_FENRIR_JWT_SECRET (or FENRIR_JWT_SECRET) is required "
                    "when SENTINEL_FENRIR_REQUIRE_AUTH is true."
                )
            _validate_jwt_secret(secret_raw, require_auth)
            jwt_secret = secret_raw
        else:
            # Fix #7: random secret per process so if require_auth is ever
            # flipped to True without setting a real secret, the ephemeral
            # random value is worthless to an attacker.
            jwt_secret = secret_raw or os.urandom(32).hex()

        algorithm = os.getenv("SENTINEL_JWT_ALGORITHM", "HS256").strip().upper()

        return cls(
            jwt_secret=jwt_secret,
            issuer=os.getenv("SENTINEL_JWT_ISSUER", "sentinel-43").strip(),
            audience=os.getenv("SENTINEL_FENRIR_JWT_AUDIENCE", "fenrir").strip(),
            algorithm=algorithm,
            token_ttl_minutes=_env_int(
                "SENTINEL_FENRIR_TOKEN_TTL_MINUTES",
                "FENRIR_TOKEN_TTL_MINUTES",
                15,
            ),
            require_auth=require_auth,
        )


# =============================================================================
# Token creation
# =============================================================================

def create_fenrir_token(
    subject: str,
    config: FenrirAuthConfig,
    *,
    scopes: Optional[list[str]] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Issue a signed Fenrir JWT.

    Fix #1: extra_claims are applied BEFORE the authoritative standard claims
    so callers cannot override exp, sub, scope, or any other reserved field.
    Attempting to pass reserved claims in extra_claims raises ValueError.

    Fix #6: individual scope strings are validated to contain no spaces,
    preventing scope injection (e.g. scopes=["fenrir:read admin:root"] would
    otherwise split into two distinct scopes on verification).

    Fix #9: extra_claims serialisability is validated before calling jwt.encode
    so callers receive a clear error rather than an uncaught TypeError from
    deep inside the JWT library.
    """
    # Fix #1: block extra_claims that overlap with reserved claims.
    if extra_claims:
        forbidden = _RESERVED_CLAIMS & set(extra_claims)
        if forbidden:
            raise ValueError(
                f"extra_claims cannot override reserved JWT claims: {sorted(forbidden)}. "
                "Remove these keys from extra_claims."
            )

    # Fix #6: validate scope strings before joining.
    validated_scopes: list[str] = []
    for scope_str in (scopes or ["fenrir:read"]):
        if not isinstance(scope_str, str) or " " in scope_str:
            raise ValueError(
                f"Invalid scope value {scope_str!r}: scope strings must not "
                "contain spaces. Pass each scope as a separate list element."
            )
        validated_scopes.append(scope_str)

    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {}

    # Fix #1: apply extra_claims first so standard claims always win.
    if extra_claims:
        payload.update(extra_claims)

    # Standard claims overwrite anything in extra_claims.
    payload.update(
        {
            "sub":   subject,
            "iss":   config.issuer,
            "aud":   config.audience,
            "iat":   int(now.timestamp()),
            "nbf":   int(now.timestamp()),
            "exp":   int((now + timedelta(minutes=config.token_ttl_minutes)).timestamp()),
            "scope": " ".join(validated_scopes),
        }
    )

    # Fix #9: verify serializability before handing to jwt.encode.
    import json as _json
    try:
        _json.dumps(payload, default=str)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"extra_claims contains a value that cannot be serialised to JSON: {exc}"
        ) from exc

    return jwt.encode(payload, config.jwt_secret, algorithm=config.algorithm)


# =============================================================================
# Token verification
# =============================================================================

def verify_fenrir_token(
    token: str,
    config: FenrirAuthConfig,
    *,
    required_scope: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Verify a Fenrir JWT and return the validated claims.

    Fix #2: algorithm is validated against _ALLOWED_ALGORITHMS before decode
    so algorithm-confusion attacks are rejected at the config level.

    Fix #8: PyJWT exception details are logged but not returned to callers.
    Callers receive a generic "Invalid Fenrir token" message so internal
    diagnostic details are not exposed in HTTP 401 responses.
    """
    if not config.require_auth:
        return {"sub": "local-auth-disabled", "scope": "*", "iat": int(time.time())}

    # Explicit guard — caller should have checked via extract_bearer_token,
    # but verify_fenrir_token itself also fails closed on empty/non-string input.
    if not token or not isinstance(token, str):
        raise FenrirAuthError("Missing bearer token.")

    try:
        payload = jwt.decode(
            token,
            config.jwt_secret,
            # Fix #2: use allowlist, not raw config.algorithm string.
            # Even though config.__post_init__ already validates the algorithm,
            # an explicit allowlist here provides defence-in-depth.
            algorithms=sorted(_ALLOWED_ALGORITHMS),
            issuer=config.issuer,
            audience=config.audience,
            options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise FenrirAuthError("Fenrir token has expired.") from None
    except jwt.InvalidIssuerError:
        raise FenrirAuthError("Invalid token issuer.") from None
    except jwt.InvalidAudienceError:
        raise FenrirAuthError("Invalid token audience.") from None
    except jwt.MissingRequiredClaimError as exc:
        raise FenrirAuthError(f"Missing required claim: {exc.claim}.") from None
    except jwt.PyJWTError as exc:
        # Fix #8: log the full diagnostic detail; return a generic message.
        logger.warning(
            "Fenrir JWT verification failed: %s — returning generic error to caller",
            exc,
        )
        raise FenrirAuthError("Invalid Fenrir token.") from None

    if required_scope:
        scopes = set(str(payload.get("scope", "")).split())
        if required_scope not in scopes and "*" not in scopes:
            raise FenrirAuthError(f"Missing required scope: {required_scope!r}.")

    return payload


# =============================================================================
# Token extraction
# =============================================================================

def extract_bearer_token(header_value: Optional[str]) -> Optional[str]:
    """
    Extract the raw token string from an Authorization: Bearer header.
    Returns None if the header is absent, malformed, or empty.
    """
    if not header_value or not isinstance(header_value, str):
        return None
    scheme, _, token = header_value.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()
