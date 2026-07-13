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
# Unauthorized copying, redistribution, relicensing, reverse engineering,
# or commercial exploitation outside the terms of the applicable license
# is strictly prohibited.
#
# By accessing, modifying, distributing, or using this software, you agree
# to comply with the terms of the applicable license.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
#
# Commercial Licensing:
# Contact the copyright holder for commercial licensing terms.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

"""
File: core/bootstrap.py

Sentinel-43 startup expectations.

NAMING NOTE: there is a second, unrelated module also named bootstrap.py at
core/guards/expectations/bootstrap.py (Watchtower expectation registration).
They do different jobs and are not interchangeable. If both are ever imported
in the same file, alias at least one explicitly — do not rely on import
order to keep them apart.

CHANGE FROM PREVIOUS VERSION: the JWT algorithm allowlist is no longer
hardcoded here, and the deferred cross-import "sync check"
(_verify_jwt_algorithm_sync) has been removed entirely. That check could
silently no-op via a caught ImportError if core.api.main was still
partially initialized when this module's bootstrap_expectations() ran —
exactly the startup path where a real mismatch would matter most. A
security check that can silently skip itself is worse than not having it,
because it creates false confidence.

The fix is structural, not cleverer error handling: APPROVED_JWT_ALGORITHMS
now lives in core.security.jwt_constants, a module with zero dependencies on
bootstrap, main, or any router. core/api/main.py and
core/api/routers/auth.py must both be updated to import
APPROVED_JWT_ALGORITHMS from that same module instead of hardcoding their
own copies (_APPROVED_ALGORITHMS / _ALLOWED_JWT_ALGORITHMS respectively).
That consolidation is NOT done by this file alone — it requires updating
those two files as well. Until they're updated, this file is correct on its
own, but the three-way duplication this was meant to solve isn't actually
gone yet.

Responsibilities:
  - Fail closed in production when security-critical configuration is missing.
  - Keep local/dev/test environments permissive for most checks — except
    boolean-parsing strictness and the identical-secret check, which are
    plain code-correctness/config-sanity checks and run everywhere.
  - Verify JWT signing configuration before the server accepts traffic.
  - Verify WebSocket auth enforcement before production startup.
  - Verify test injection is disabled in production.
  - Verify auth pepper exists and meets minimum length before the first
    auth-key verification call.
  - Verify JWT secret and auth pepper are not the same value.
  - Never silently mutate secret values (no implicit whitespace stripping).
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Final

from core.security.jwt_constants import APPROVED_JWT_ALGORITHMS

# Key set by scripts/generate_secrets.py every time it actually writes or
# rotates a secret (see _update_rotation_timestamp there). Never hand-edit
# this value — it must reflect when generation actually ran, not a claim.
_ROTATION_TIMESTAMP_KEY: Final[str] = "S43_SECRETS_ROTATED_AT"

# How old S43_SECRETS_ROTATED_AT can be before production refuses to start.
# Overridable via S43_SECRET_MAX_AGE_DAYS for deployments with a different
# rotation policy; the override is parsed strictly (see _env_int) so a typo
# fails startup rather than silently falling back to the default.
_DEFAULT_MAX_SECRET_AGE_DAYS: Final[int] = 90

LOCAL_TEST_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"development", "dev", "local", "test"}
)

# Minimum pepper length enforced at startup. Must match or exceed the
# effective entropy floor used by AuthKeyStore._hash_token().
_MIN_PEPPER_BYTES: Final[int] = 32

# Minimum JWT signing secret length enforced at startup. Named constant so
# it can't silently drift out of sync with _MIN_PEPPER_BYTES — both
# represent the same 32-byte entropy floor and should change together.
_MIN_JWT_SECRET_BYTES: Final[int] = 32

_TRUE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES: Final[frozenset[str]] = frozenset({"0", "false", "no", "off"})


# =============================================================================
# Environment helpers
# =============================================================================

def _env_text(name: str, default: str = "") -> str:
    """
    For non-secret config values (issuer, audience, algorithm name) where
    trimming incidental whitespace is harmless and expected.
    """
    return os.getenv(name, default).strip()


def _env_secret(name: str) -> str:
    """
    For secret values (JWT signing secret, auth pepper) where whitespace must
    NOT be silently stripped. A secret with accidental leading/trailing
    whitespace (common with Docker secrets files, which often have a
    trailing newline) may not match the value another code path uses to
    sign or verify — silently normalizing it here would validate a
    different value than the one actually in use. Callers should reject
    whitespace-wrapped secrets explicitly instead of cleaning them.
    """
    return os.getenv(name, "")


def _env_bool(name: str, *, default: bool) -> bool:
    """
    Strict boolean parser. Unrecognized values raise rather than silently
    resolving to False. A typo like S43_ENABLE_TEST_INJECTION=treu must not
    be interpreted as "disabled" — for security gates, malformed
    configuration should fail startup, not quietly select whichever
    behavior happens to look safe today.
    """
    raw = os.getenv(name)
    if raw is None:
        return default

    normalized = raw.strip().lower()

    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False

    raise RuntimeError(
        f"{name} must be one of {sorted(_TRUE_VALUES | _FALSE_VALUES)}; "
        f"got {raw!r}."
    )


def _env_int(name: str, default: int) -> int:
    """
    Strict integer parser, same philosophy as _env_bool: an unparseable or
    non-positive override is a config bug and should fail startup rather
    than silently falling back to the default.
    """
    raw = os.getenv(name)
    if raw is None:
        return default

    raw = raw.strip()
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(f"{name} must be an integer; got {raw!r}.")

    if value <= 0:
        raise RuntimeError(f"{name} must be a positive integer; got {value}.")

    return value


# =============================================================================
# Secret rotation freshness
# =============================================================================

def _verify_secret_rotation_freshness(max_age_days: int) -> list[str]:
    """
    Confirm secrets were actually generated by scripts/generate_secrets.py,
    and recently enough to satisfy the configured rotation policy.

    Returns a list of error strings (empty if all good) rather than raising
    directly, so callers can fold this into the same accumulated error
    report as the other production checks instead of failing on the first
    problem found.

    Production-only by design: rotation-age policy is a deployment
    requirement, not a code-correctness invariant, so it doesn't belong in
    the unconditional checks (unlike strict boolean parsing or the
    identical-secret check, which run everywhere).
    """
    errors: list[str] = []

    rotated_at_raw = _env_text(_ROTATION_TIMESTAMP_KEY)
    if not rotated_at_raw:
        errors.append(
            f"{_ROTATION_TIMESTAMP_KEY} is missing. Secrets appear to have "
            "never been generated via this project's secret generator. Run: "
            "python scripts/generate_secrets.py --write .env --force"
        )
        return errors

    try:
        rotated_at = datetime.fromisoformat(rotated_at_raw)
    except ValueError:
        errors.append(
            f"{_ROTATION_TIMESTAMP_KEY}={rotated_at_raw!r} is not a valid "
            "ISO 8601 timestamp. This value is set automatically by "
            "scripts/generate_secrets.py — do not hand-edit it. Re-run: "
            "python scripts/generate_secrets.py --write .env --force"
        )
        return errors

    if rotated_at.tzinfo is None:
        errors.append(
            f"{_ROTATION_TIMESTAMP_KEY}={rotated_at_raw!r} has no timezone "
            "info. The generator always writes a UTC-aware timestamp — this "
            "value was likely hand-edited. Re-run: "
            "python scripts/generate_secrets.py --write .env --force"
        )
        return errors

    age = datetime.now(timezone.utc) - rotated_at
    if age > timedelta(days=max_age_days):
        errors.append(
            f"Secrets were last rotated {age.days} day(s) ago "
            f"({_ROTATION_TIMESTAMP_KEY}={rotated_at_raw}), exceeding the "
            f"{max_age_days}-day maximum (override with "
            "S43_SECRET_MAX_AGE_DAYS if intentional). Rotate with: "
            "python scripts/generate_secrets.py --write .env --force"
        )

    return errors


# =============================================================================
# Bootstrap gate
# =============================================================================

def bootstrap_expectations() -> None:
    """
    Validate Sentinel-43 startup expectations.

    Boolean parsing strictness and the JWT-secret/pepper identity check run
    in every environment, including dev/test — these are config-sanity
    checks, not deployment-secret requirements, and a malformed or
    accidentally duplicated value is a bug regardless of environment.

    Production environments additionally fail closed when security-sensitive
    configuration is missing or unsafe.

    Production refuses startup when:
      - S43_JWT_SECRET is missing, contains surrounding whitespace, or is
        shorter than _MIN_JWT_SECRET_BYTES when UTF-8 encoded
      - S43_JWT_ALGORITHM is not in APPROVED_JWT_ALGORITHMS
      - S43_JWT_ISSUER is missing
      - S43_JWT_AUDIENCE is missing
      - S43_AUTH_PEPPER is missing, contains surrounding whitespace, or is
        shorter than _MIN_PEPPER_BYTES when UTF-8 encoded
      - S43_JWT_SECRET and S43_AUTH_PEPPER are identical
      - S43_WS_REQUIRE_AUTH is not true
      - S43_ENABLE_TEST_INJECTION is true
      - S43_SECRETS_ROTATED_AT is missing, malformed, or older than
        S43_SECRET_MAX_AGE_DAYS (default 90) — i.e. secrets were never
        generated via scripts/generate_secrets.py, or haven't been rotated
        recently enough

    Any environment (including dev/test) refuses startup when:
      - S43_WS_REQUIRE_AUTH or S43_ENABLE_TEST_INJECTION is set to an
        unrecognized value (strict boolean parsing)

    Generate secrets:
        JWT:    python -c "import secrets; print(secrets.token_urlsafe(32))"
        Pepper: python -c "import secrets; print(secrets.token_hex(32))"

    Store in deployment environment. Never commit secrets to version control.
    """
    errors: list[str] = []

    # Strict boolean parsing runs unconditionally — a malformed flag value
    # is a config bug in any environment, not just production. Let
    # RuntimeError propagate immediately rather than folding it into the
    # accumulated error list, since it indicates the environment itself
    # can't be trusted enough to evaluate further.
    ws_require_auth = _env_bool("S43_WS_REQUIRE_AUTH", default=False)
    test_injection_enabled = _env_bool("S43_ENABLE_TEST_INJECTION", default=False)

    sentinel_env = _env_text("SENTINEL_ENV", "production").lower()

    jwt_secret = _env_secret("S43_JWT_SECRET")
    auth_pepper = _env_secret("S43_AUTH_PEPPER")

    # JWT secret and auth pepper should be independently generated. Checked
    # regardless of environment, since a duplicated value is a setup mistake
    # (e.g. copy-pasted from the same generated value) worth catching early,
    # not something that only matters in production.
    if jwt_secret and auth_pepper and jwt_secret == auth_pepper:
        errors.append(
            "S43_JWT_SECRET and S43_AUTH_PEPPER must be independently "
            "generated and must not contain the same value."
        )

    if sentinel_env in LOCAL_TEST_ENVIRONMENTS:
        if errors:
            error_block = "\n".join(f"  - {error}" for error in errors)
            raise RuntimeError(
                "Sentinel-43 refused to start — configuration error "
                f"({len(errors)} error(s) found):\n{error_block}"
            )
        return

    jwt_algorithm = _env_text("S43_JWT_ALGORITHM", "HS256")
    jwt_issuer = _env_text("S43_JWT_ISSUER")
    jwt_audience = _env_text("S43_JWT_AUDIENCE")

    # JWT secret — presence, no surrounding whitespace, minimum length.
    if not jwt_secret:
        errors.append(
            "S43_JWT_SECRET is missing. "
            'Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )
    else:
        if jwt_secret != jwt_secret.strip():
            errors.append(
                "S43_JWT_SECRET must not contain surrounding whitespace. "
                "Check for a trailing newline if this came from a Docker "
                "secrets file."
            )
        secret_bytes = jwt_secret.encode("utf-8")
        if len(secret_bytes) < _MIN_JWT_SECRET_BYTES:
            errors.append(
                f"S43_JWT_SECRET must be at least {_MIN_JWT_SECRET_BYTES} bytes "
                f"when encoded as UTF-8 (current: {len(secret_bytes)} bytes)."
            )

    # JWT algorithm
    if jwt_algorithm not in APPROVED_JWT_ALGORITHMS:
        errors.append(
            f"S43_JWT_ALGORITHM must be one of {sorted(APPROVED_JWT_ALGORITHMS)}. "
            f"Got: {jwt_algorithm!r}. "
            "Never accept an algorithm from the incoming token header."
        )

    # JWT issuer and audience
    if not jwt_issuer:
        errors.append(
            "S43_JWT_ISSUER is missing. "
            "Set to a stable identifier for this deployment, e.g. 'sentinel-43'."
        )

    if not jwt_audience:
        errors.append(
            "S43_JWT_AUDIENCE is missing. "
            "Set to 'sentinel-43-dashboard' or your deployment-specific audience."
        )

    # Auth key-store pepper — presence, no surrounding whitespace, minimum
    # length. AuthKeyStore._pepper() raises on first key verification if
    # this is missing. Catching it here ensures the server refuses to start
    # rather than failing mid-request on the first auth attempt.
    if not auth_pepper:
        errors.append(
            "S43_AUTH_PEPPER is missing. "
            "The PBKDF2 auth key store requires a pepper in production. "
            'Generate with: python -c "import secrets; print(secrets.token_hex(32))"'
        )
    else:
        if auth_pepper != auth_pepper.strip():
            errors.append(
                "S43_AUTH_PEPPER must not contain surrounding whitespace. "
                "Check for a trailing newline if this came from a Docker "
                "secrets file."
            )
        pepper_bytes = auth_pepper.encode("utf-8")
        if len(pepper_bytes) < _MIN_PEPPER_BYTES:
            errors.append(
                f"S43_AUTH_PEPPER is too short ({len(pepper_bytes)} bytes UTF-8 encoded). "
                f"Must be at least {_MIN_PEPPER_BYTES} bytes. "
                'Generate with: python -c "import secrets; print(secrets.token_hex(32))"'
            )

    # WebSocket auth enforcement
    if not ws_require_auth:
        errors.append(
            "S43_WS_REQUIRE_AUTH must be true in production. "
            "The WebSocket endpoint must not allow unauthenticated connections."
        )

    # Test injection gate
    if test_injection_enabled:
        errors.append(
            "S43_ENABLE_TEST_INJECTION must be false or unset in production. "
            "This endpoint exists only for local end-to-end testing."
        )

    # Secret rotation freshness — hard gate. max_age_days parsed strictly
    # regardless of whether the check itself ends up failing, so a garbage
    # override value is caught even if rotation happens to still be fresh.
    max_secret_age_days = _env_int(
        "S43_SECRET_MAX_AGE_DAYS", default=_DEFAULT_MAX_SECRET_AGE_DAYS
    )
    errors.extend(_verify_secret_rotation_freshness(max_secret_age_days))

    if errors:
        error_block = "\n".join(f"  - {error}" for error in errors)
        raise RuntimeError(
            "Sentinel-43 refused to start — unsafe production configuration "
            f"({len(errors)} error(s) found):\n{error_block}"
        )


__all__ = [
    "LOCAL_TEST_ENVIRONMENTS",
    "bootstrap_expectations",
]
