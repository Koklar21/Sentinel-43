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
Sentinel-43 startup expectations.

Responsibilities:
  - Fail closed in production when security-critical configuration is missing.
  - Keep local/dev/test environments permissive so development stays usable.
  - Verify JWT signing configuration before the server accepts traffic.
  - Verify WebSocket auth enforcement before production startup.
  - Verify test injection is disabled in production.
  - Verify auth pepper exists and meets minimum length before the first
    auth-key verification call.
"""

from __future__ import annotations

import os
from typing import Final


# =============================================================================
# Approved JWT algorithms
#
# Hardcoded here intentionally — importing from core.security.auth.constants
# at module level causes circular import failures because bootstrap.py is
# loaded during core.api.main initialization before core.security is fully
# initialized.
#
# SYNC RULE: this set must match ALLOWED_ALGORITHMS in:
#   - core/security/auth/constants.py
#   - core/api/main.py  (_APPROVED_ALGORITHMS)
# Update all three together when adding RS256 support.
# =============================================================================

APPROVED_JWT_ALGORITHMS: Final[frozenset[str]] = frozenset({"HS256"})

LOCAL_TEST_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"development", "dev", "local", "test"}
)

# Minimum pepper length enforced at startup. Must match or exceed the
# effective entropy floor used by AuthKeyStore._hash_token().
_MIN_PEPPER_BYTES: Final[int] = 32


# =============================================================================
# Environment helpers
# =============================================================================

def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_text(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


# =============================================================================
# Bootstrap gate
# =============================================================================

def bootstrap_expectations() -> None:
    """
    Validate Sentinel-43 startup expectations.

    Local/test environments are permissive so development stays usable.
    Production environments fail closed when security-sensitive configuration
    is missing or unsafe.

    Production refuses startup when:
      - S43_JWT_SECRET is missing or < 32 bytes
      - S43_JWT_ALGORITHM is not in APPROVED_JWT_ALGORITHMS
      - S43_JWT_ISSUER is missing
      - S43_JWT_AUDIENCE is missing
      - S43_AUTH_PEPPER is missing or < 32 bytes (UTF-8 encoded)
      - S43_WS_REQUIRE_AUTH is not true
      - S43_ENABLE_TEST_INJECTION is true

    Generate secrets:
        JWT:    python -c "import secrets; print(secrets.token_urlsafe(32))"
        Pepper: python -c "import secrets; print(secrets.token_hex(32))"

    Store in deployment environment. Never commit secrets to version control.
    """
    sentinel_env = _env_text("SENTINEL_ENV", "production").lower()
    if sentinel_env in LOCAL_TEST_ENVIRONMENTS:
        return

    jwt_secret             = _env_text("S43_JWT_SECRET")
    jwt_algorithm          = _env_text("S43_JWT_ALGORITHM", "HS256")
    jwt_issuer             = _env_text("S43_JWT_ISSUER")
    jwt_audience           = _env_text("S43_JWT_AUDIENCE")
    auth_pepper            = _env_text("S43_AUTH_PEPPER")
    ws_require_auth        = _env_bool("S43_WS_REQUIRE_AUTH",        default=False)
    test_injection_enabled = _env_bool("S43_ENABLE_TEST_INJECTION",  default=False)

    errors: list[str] = []

    # JWT secret
    if not jwt_secret:
        errors.append(
            "S43_JWT_SECRET is missing. "
            'Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )
    else:
        secret_bytes = jwt_secret.encode("utf-8")
        if len(secret_bytes) < 32:
            errors.append(
                "S43_JWT_SECRET must be at least 32 bytes when encoded as UTF-8 "
                f"(current: {len(secret_bytes)} bytes)."
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

    # Auth key-store pepper — presence and minimum length.
    # AuthKeyStore._pepper() raises on first key verification if this is
    # missing. Catching it here ensures the server refuses to start rather
    # than failing mid-request on the first auth attempt.
    # Fix (scrub): also enforce minimum length so a short/weak pepper cannot
    # be used in production. The threshold matches _MIN_PEPPER_BYTES (32).
    if not auth_pepper:
        errors.append(
            "S43_AUTH_PEPPER is missing. "
            "The PBKDF2 auth key store requires a pepper in production. "
            'Generate with: python -c "import secrets; print(secrets.token_hex(32))"'
        )
    else:
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

    if errors:
        error_block = "\n".join(f"  - {error}" for error in errors)
        raise RuntimeError(
            "Sentinel-43 refused to start — unsafe production configuration "
            f"({len(errors)} error(s) found):\n{error_block}"
        )


__all__ = [
    "APPROVED_JWT_ALGORITHMS",
    "LOCAL_TEST_ENVIRONMENTS",
    "bootstrap_expectations",
]
