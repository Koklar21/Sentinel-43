# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sentinel-43 startup security expectations.

This module validates an already-loaded canonical settings object.

It intentionally performs:
    - no environment reads
    - no filesystem mutation
    - no network I/O
    - no secret generation
    - no secret rotation timestamp checks
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from core.security.jwt_constants import APPROVED_JWT_ALGORITHMS


LOCAL_TEST_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {
        "development",
        "dev",
        "local",
        "test",
    }
)

_MIN_PEPPER_BYTES: Final[int] = 32
_MIN_JWT_SECRET_BYTES: Final[int] = 32


def _get(
    settings: Any,
    name: str,
    default: Any = None,
) -> Any:
    if isinstance(
        settings,
        Mapping,
    ):
        return settings.get(
            name,
            default,
        )

    return getattr(
        settings,
        name,
        default,
    )


def _text(
    settings: Any,
    name: str,
    default: str = "",
) -> str:
    value = _get(
        settings,
        name,
        default,
    )

    if value is None:
        return default

    return str(
        value
    ).strip()


def _secret(
    settings: Any,
    name: str,
) -> str:
    value = _get(
        settings,
        name,
        "",
    )

    if value is None:
        return ""

    if not isinstance(
        value,
        str,
    ):
        raise RuntimeError(
            f"{name} must be a string"
        )

    return value


def _bool(
    settings: Any,
    name: str,
    *,
    default: bool,
) -> bool:
    value = _get(
        settings,
        name,
        default,
    )

    if isinstance(
        value,
        bool,
    ):
        return value

    raise RuntimeError(
        f"{name} must be boolean"
    )


def validate_bootstrap_expectations(
    settings: Any,
) -> None:
    """Fail closed when startup security prerequisites are not satisfied."""
    errors: list[str] = []

    environment = _text(
        settings,
        "env",
        "production",
    ).lower()

    jwt_secret = _secret(
        settings,
        "jwt_secret",
    )

    auth_pepper = _secret(
        settings,
        "auth_pepper",
    )

    ws_require_auth = _bool(
        settings,
        "ws_require_auth",
        default=False,
    )

    test_injection_enabled = _bool(
        settings,
        "enable_test_injection",
        default=False,
    )

    if (
        jwt_secret
        and auth_pepper
        and jwt_secret == auth_pepper
    ):
        errors.append(
            "jwt_secret and auth_pepper must be independently generated"
        )

    if environment in LOCAL_TEST_ENVIRONMENTS:
        if errors:
            raise RuntimeError(
                "Sentinel-43 refused startup: "
                + "; ".join(
                    errors
                )
            )

        return

    jwt_algorithm = _text(
        settings,
        "jwt_algorithm",
        "HS256",
    )

    jwt_issuer = _text(
        settings,
        "jwt_issuer",
    )

    jwt_audience = _text(
        settings,
        "jwt_audience",
    )

    if not jwt_secret:
        errors.append(
            "jwt_secret is required"
        )
    else:
        if jwt_secret != jwt_secret.strip():
            errors.append(
                "jwt_secret must not contain surrounding whitespace"
            )

        if len(
            jwt_secret.encode(
                "utf-8"
            )
        ) < _MIN_JWT_SECRET_BYTES:
            errors.append(
                f"jwt_secret must be at least {_MIN_JWT_SECRET_BYTES} bytes"
            )

    if jwt_algorithm not in APPROVED_JWT_ALGORITHMS:
        errors.append(
            "jwt_algorithm must be one of "
            f"{sorted(APPROVED_JWT_ALGORITHMS)}"
        )

    if not jwt_issuer:
        errors.append(
            "jwt_issuer is required"
        )

    if not jwt_audience:
        errors.append(
            "jwt_audience is required"
        )

    if not auth_pepper:
        errors.append(
            "auth_pepper is required"
        )
    else:
        if auth_pepper != auth_pepper.strip():
            errors.append(
                "auth_pepper must not contain surrounding whitespace"
            )

        if len(
            auth_pepper.encode(
                "utf-8"
            )
        ) < _MIN_PEPPER_BYTES:
            errors.append(
                f"auth_pepper must be at least {_MIN_PEPPER_BYTES} bytes"
            )

    if not ws_require_auth:
        errors.append(
            "ws_require_auth must be true outside local/test environments"
        )

    if test_injection_enabled:
        errors.append(
            "enable_test_injection must be false outside local/test environments"
        )

    if errors:
        raise RuntimeError(
            "Sentinel-43 refused startup due to unsafe configuration: "
            + "; ".join(
                errors
            )
        )


bootstrap_expectations = validate_bootstrap_expectations


__all__ = [
    "LOCAL_TEST_ENVIRONMENTS",
    "bootstrap_expectations",
    "validate_bootstrap_expectations",
]
