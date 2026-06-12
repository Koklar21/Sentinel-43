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

from __future__ import annotations

import os


LOCAL_TEST_ENVIRONMENTS: frozenset[str] = frozenset(
    {"development", "dev", "local", "test"}
)

APPROVED_JWT_ALGORITHMS: frozenset[str] = frozenset({"HS256"})


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

    Local/test environments remain permissive so development stays usable.

    Non-local environments fail closed when security-sensitive configuration is
    missing or unsafe. This prevents an internet-facing deployment from starting
    with anonymous WebSocket access, test injection enabled, or missing JWT
    validation material.
    """
    sentinel_env = _env_text("SENTINEL_ENV", "production").lower()

    if sentinel_env in LOCAL_TEST_ENVIRONMENTS:
        return

    jwt_secret = _env_text("S43_JWT_SECRET")
    jwt_algorithm = _env_text("S43_JWT_ALGORITHM", "HS256")
    jwt_issuer = _env_text("S43_JWT_ISSUER")
    jwt_audience = _env_text("S43_JWT_AUDIENCE")

    ws_require_auth = _env_bool("S43_WS_REQUIRE_AUTH", default=False)
    test_injection_enabled = _env_bool("S43_ENABLE_TEST_INJECTION", default=False)

    errors: list[str] = []

    if not jwt_secret:
        errors.append(
            "S43_JWT_SECRET is missing. Generate one with: "
            "python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    elif len(jwt_secret.encode("utf-8")) < 32:
        errors.append(
            "S43_JWT_SECRET must be at least 32 bytes when encoded as UTF-8."
        )

    if jwt_algorithm not in APPROVED_JWT_ALGORITHMS:
        errors.append(
            f"S43_JWT_ALGORITHM must be one of {sorted(APPROVED_JWT_ALGORITHMS)}. "
            f"Current value: {jwt_algorithm!r}."
        )

    if not jwt_issuer:
        errors.append("S43_JWT_ISSUER is missing.")

    if not jwt_audience:
        errors.append("S43_JWT_AUDIENCE is missing.")

    if not ws_require_auth:
        errors.append("S43_WS_REQUIRE_AUTH must be true outside local/test environments.")

    if test_injection_enabled:
        errors.append(
            "S43_ENABLE_TEST_INJECTION must be false outside local/test environments."
        )

    if errors:
        error_block = "\n".join(f"  - {error}" for error in errors)
        raise RuntimeError(
            "Sentinel-43 refused to start because production security "
            f"configuration is unsafe:\n{error_block}"
        )
