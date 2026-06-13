# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
# =============================================================================

from __future__ import annotations

import os


LOCAL_TEST_ENVIRONMENTS: frozenset[str] = frozenset(
    {"development", "dev", "local", "test"}
)

# Must match _APPROVED_ALGORITHMS in core/api/main.py.
# Add RS256 here and there together when key rotation is needed.
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

    LOCAL_TEST_ENVIRONMENTS remain permissive so development stays usable.

    Production environments fail closed when security-sensitive configuration
    is missing or unsafe. This prevents an internet-facing deployment from
    starting with:
      - anonymous WebSocket access
      - test injection enabled
      - missing or undersized JWT signing material
      - unconfigured issuer or audience

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

    ws_require_auth        = _env_bool("S43_WS_REQUIRE_AUTH",        default=False)
    test_injection_enabled = _env_bool("S43_ENABLE_TEST_INJECTION",  default=False)

    errors: list[str] = []

    # JWT secret — length is what we can measure; entropy is the operator's
    # responsibility via the generation command above.
    if not jwt_secret:
        errors.append(
            "S43_JWT_SECRET is missing. "
            "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
    elif len(jwt_secret.encode("utf-8")) < 32:
        errors.append(
            f"S43_JWT_SECRET must be at least 32 bytes when encoded as UTF-8 "
            f"(current: {len(jwt_secret.encode('utf-8'))} bytes)."
        )

    if jwt_algorithm not in APPROVED_JWT_ALGORITHMS:
        errors.append(
            f"S43_JWT_ALGORITHM must be one of {sorted(APPROVED_JWT_ALGORITHMS)}. "
            f"Got: {jwt_algorithm!r}. "
            f"Never accept an algorithm from the incoming token header."
        )

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

    if not ws_require_auth:
        errors.append(
            "S43_WS_REQUIRE_AUTH must be true in production. "
            "The WebSocket endpoint is currently open to unauthenticated connections."
        )

    if test_injection_enabled:
        errors.append(
            "S43_ENABLE_TEST_INJECTION must be false or unset in production. "
            "This endpoint exists only for local end-to-end testing."
        )

    if errors:
        error_block = "\n".join(f"  - {error}" for error in errors)
        raise RuntimeError(
            f"Sentinel-43 refused to start — unsafe production configuration "
            f"({len(errors)} error(s) found):\n{error_block}"
        )
