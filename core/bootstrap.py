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
in the same file, alias at least one explicitly
(e.g. `from core.guards.expectations.bootstrap import bootstrap_expectations
as bootstrap_watchtower_expectations`) — do not rely on import order to keep
them apart.

Responsibilities:
  - Fail closed in production when security-critical configuration is missing.
  - Keep local/dev/test environments permissive so development stays usable.
  - Verify JWT signing configuration before the server accepts traffic.
  - Verify WebSocket auth enforcement before production startup.
  - Verify test injection is disabled in production.
  - Verify auth pepper exists and meets minimum length before the first
    auth-key verification call.
  - Verify the JWT algorithm allowlist is identical across every module that
    hardcodes it (see _verify_jwt_algorithm_sync below).
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
#   - core/api/main.py         (_APPROVED_ALGORITHMS)
#   - core/api/routers/auth.py (_ALLOWED_JWT_ALGORITHMS)
# Update all locations together when adding RS256 support.
#
# This is now enforced, not just documented — see _verify_jwt_algorithm_sync().
# That function does a deferred (function-scope) import of the other two
# modules, which is safe because by the time bootstrap_expectations() runs,
# all three modules have finished loading. It would NOT be safe as a
# module-level import here, which is exactly the circular-import problem this
# constant duplication exists to avoid in the first place.
# =============================================================================

APPROVED_JWT_ALGORITHMS: Final[frozenset[str]] = frozenset({"HS256"})

LOCAL_TEST_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"development", "dev", "local", "test"}
)

# Minimum pepper length enforced at startup. Must match or exceed the
# effective entropy floor used by AuthKeyStore._hash_token().
_MIN_PEPPER_BYTES: Final[int] = 32

# Minimum JWT signing secret length enforced at startup. Kept as a named
# constant rather than an inline literal so it can't silently drift out of
# sync with _MIN_PEPPER_BYTES — both represent the same 32-byte entropy floor
# and should be changed together if that floor ever changes.
_MIN_JWT_SECRET_BYTES: Final[int] = 32


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
# Cross-module JWT algorithm consistency check
# =============================================================================

def _verify_jwt_algorithm_sync() -> None:
    """
    Confirm APPROVED_JWT_ALGORITHMS here matches the allowlists hardcoded in
    core.api.main and core.api.routers.auth.

    Deferred (function-scope) import is deliberate: this function is only
    ever called from bootstrap_expectations(), which runs during app
    startup after core.api.main and core.api.routers.auth have already
    loaded. A module-level import of either would recreate the exact
    circular-import failure that caused this constant to be duplicated in
    the first place.

    Runs regardless of environment (dev/test included) because a drifted
    allowlist is a code-correctness bug, not a missing-secret problem — it
    should be caught immediately, not only in production.
    """
    try:
        from core.api.main import _APPROVED_ALGORITHMS as main_algorithms
        from core.api.routers.auth import _ALLOWED_JWT_ALGORITHMS as auth_algorithms
    except ImportError:
        # Either module hasn't finished loading yet — e.g. this is being
        # called from a narrow unit test harness that only imports
        # core.bootstrap in isolation. Skip rather than fail startup on an
        # import-ordering artifact unrelated to the actual check.
        return

    if main_algorithms != APPROVED_JWT_ALGORITHMS or auth_algorithms != APPROVED_JWT_ALGORITHMS:
        raise RuntimeError(
            "JWT algorithm allowlist mismatch across modules — all three "
            "copies must be identical:\n"
            f"  - core/bootstrap.py                = {sorted(APPROVED_JWT_ALGORITHMS)}\n"
            f"  - core/api/main.py                  = {sorted(main_algorithms)}\n"
            f"  - core/api/routers/auth.py          = {sorted(auth_algorithms)}\n"
            "Update all three locations together when changing the allowlist."
        )


# =============================================================================
# Bootstrap gate
# =============================================================================

def bootstrap_expectations() -> None:
    """
    Validate Sentinel-43 startup expectations.

    Local/test environments are permissive so development stays usable,
    EXCEPT for the JWT algorithm sync check, which always runs — it's a
    code-drift bug check, not a deployment-secret check.

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
    # Runs in every environment, including dev/test — see docstring above.
    _verify_jwt_algorithm_sync()

    sentinel_env = _env_text("SENTINEL_ENV", "production").lower()
    if sentinel_env in LOCAL_TEST_ENVIRONMENTS:
        return

    jwt_secret             = _env_text("S43_JWT_SECRET")
    jwt_algorithm          = _env_text("S43_JWT_ALGORITHM", "HS256")
    jwt_issuer             = _env_text("S43_JWT_ISSUER")
    jwt_audience           = _env_text("S43_JWT_AUDIENCE")
    auth_pepper            = _env_text("S43_AUTH_PEPPER")
    ws_require_auth        = _env_bool("S43_WS_REQUIRE_AUTH",       default=False)
    test_injection_enabled = _env_bool("S43_ENABLE_TEST_INJECTION", default=False)

    errors: list[str] = []

    # JWT secret
    if not jwt_secret:
        errors.append(
            "S43_JWT_SECRET is missing. "
            'Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )
    else:
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

    # Auth key-store pepper — presence and minimum length.
    # AuthKeyStore._pepper() raises on first key verification if this is
    # missing. Catching it here ensures the server refuses to start rather
    # than failing mid-request on the first auth attempt.
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
