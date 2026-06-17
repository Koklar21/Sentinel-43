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

Changes from previous version:
  - Fix (MEDIUM): APPROVED_JWT_ALGORITHMS was a duplicate of
    ALLOWED_ALGORITHMS in core/security/auth/constants.py. Now imported
    from there so all three enforcement points (bootstrap, constants,
    main.py) share one source of truth. Adding RS256 in constants.py
    now automatically reflects here without a manual sync step.
  - Fix (MEDIUM): Added S43_AUTH_PEPPER check. Previously a missing pepper
    would only surface on the first key verification call, potentially
    mid-request under load. Bootstrap is the right place to catch missing
    security-critical secrets before the server accepts connections.
  - Fix (LOW): jwt_secret.encode("utf-8") was called twice — once for
    the length check and once inside the error message. Now encoded once.
"""

from __future__ import annotations

import os

# Fix (MEDIUM): import from the canonical source instead of duplicating.
# If ALLOWED_ALGORITHMS in constants.py changes, bootstrap reflects it
# automatically without a separate manual update here.
from core.security.auth.constants import ALLOWED_ALGORITHMS as APPROVED_JWT_ALGORITHMS

LOCAL_TEST_ENVIRONMENTS: frozenset[str] = frozenset(
    {"development", "dev", "local", "test"}
)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_text(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def bootstrap_expectations() -> None:
    """
    Validate Sentinel-43 startup expectations.

    LOCAL_TEST_ENVIRONMENTS remain permissive so development stays usable.
    Production environments fail closed when security-sensitive configuration
    is missing or unsafe. This prevents an internet-facing deployment from
    starting with:
      - anonymous WebSocket access
      - test injection enabled
      - missing or undersized JWT signing material
      - unconfigured issuer or audience
      - missing PBKDF2 pepper for the auth key store

    Generate the JWT secret with:
        python -c "import secrets; print(secrets.token_urlsafe(32))"

    Store the result in the environment file. Never commit it to version control.
    """
    sentinel_env = _env_text("SENTINEL_ENV", "production").lower()
    if sentinel_env in LOCAL_TEST_ENVIRONMENTS:
        return

    jwt_secret    = _env_text("S43_JWT_SECRET")
    jwt_algorithm = _env_text("S43_JWT_ALGORITHM", "HS256")
    jwt_issuer    = _env_text("S43_JWT_ISSUER")
    jwt_audience  = _env_text("S43_JWT_AUDIENCE")
    auth_pepper   = _env_text("S43_AUTH_PEPPER")         # Fix (MEDIUM)

    ws_require_auth        = _env_bool("S43_WS_REQUIRE_AUTH",       default=False)
    test_injection_enabled = _env_bool("S43_ENABLE_TEST_INJECTION",  default=False)

    errors: list[str] = []

    # ------------------------------------------------------------------
    # JWT secret
    # Length is what we can measure; entropy is the operator's responsibility
    # via the generation command above.
    # ------------------------------------------------------------------
    if not jwt_secret:
        errors.append(
            "S43_JWT_SECRET is missing. "
            'Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )
    else:
        # Fix (LOW): encode once, use twice.
        secret_bytes = jwt_secret.encode("utf-8")
        if len(secret_bytes) < 32:
            errors.append(
                f"S43_JWT_SECRET must be at least 32 bytes when encoded as UTF-8 "
                f"(current: {len(secret_bytes)} bytes)."
            )

    # ------------------------------------------------------------------
    # JWT algorithm
    # ------------------------------------------------------------------
    if jwt_algorithm not in APPROVED_JWT_ALGORITHMS:
        errors.append(
            f"S43_JWT_ALGORITHM must be one of {sorted(APPROVED_JWT_ALGORITHMS)}. "
            f"Got: {jwt_algorithm!r}. "
            "Never accept an algorithm from the incoming token header."
        )

    # ------------------------------------------------------------------
    # JWT issuer and audience
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Fix (MEDIUM): Auth key store pepper
    # AuthKeyStore._pepper() raises on first key verification if this is
    # missing. Catching it here ensures the server refuses to start rather
    # than failing mid-request on the first authentication attempt.
    # ------------------------------------------------------------------
    if not auth_pepper:
        errors.append(
            "S43_AUTH_PEPPER is missing. "
            "The PBKDF2 auth key store requires a pepper in production. "
            'Generate with: python -c "import secrets; print(secrets.token_hex(32))"'
        )

    # ------------------------------------------------------------------
    # WebSocket auth enforcement
    # ------------------------------------------------------------------
    if not ws_require_auth:
        errors.append(
            "S43_WS_REQUIRE_AUTH must be true in production. "
            "The WebSocket endpoint is currently open to unauthenticated connections."
        )

    # ------------------------------------------------------------------
    # Test injection gate
    # ------------------------------------------------------------------
    if test_injection_enabled:
        errors.append(
            "S43_ENABLE_TEST_INJECTION must be false or unset in production. "
            "This endpoint exists only for local end-to-end testing."
        )

    # ------------------------------------------------------------------
    # Raise with all errors collected
    # ------------------------------------------------------------------
    if errors:
        error_block = "\n".join(f"  - {e}" for e in errors)
        raise RuntimeError(
            f"Sentinel-43 refused to start — unsafe production configuration "
            f"({len(errors)} error(s) found):\n{error_block}"
        )
