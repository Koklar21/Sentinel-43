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

"""Canonical Sentinel-43 firewall middleware exports.

This module owns environment parsing for FirewallConfig and re-exports the
firewall middleware implementation without runtime monkey-patching.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import replace
from typing import Final

from core.api.middleware.sentinel_firewall_middleware import (
    BlockReason,
    FirewallConfig as _FirewallConfig,
    SentinelFirewall,
)


logger = logging.getLogger("sentinel43.firewall")


_TRUE_VALUES: Final[frozenset[str]] = frozenset(
    {"1", "true", "yes", "on", "enabled"}
)

_FALSE_VALUES: Final[frozenset[str]] = frozenset(
    {"0", "false", "no", "off", "disabled"}
)


def _env_bool(
    name: str,
) -> bool:
    raw = os.getenv(
        name
    )

    if raw is None:
        raise RuntimeError(
            f"{name} is not set"
        )

    normalized = raw.strip().lower()

    if normalized in _TRUE_VALUES:
        return True

    if normalized in _FALSE_VALUES:
        return False

    raise ValueError(
        f"{name}={raw!r} is not a valid boolean"
    )


def _env_int(
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = os.getenv(
        name
    )

    if raw is None:
        raise RuntimeError(
            f"{name} is not set"
        )

    try:
        value = int(
            raw.strip()
        )
    except ValueError as exc:
        raise ValueError(
            f"{name}={raw!r} is not a valid integer"
        ) from exc

    if not minimum <= value <= maximum:
        raise ValueError(
            f"{name} must be between {minimum} and {maximum}"
        )

    return value


def _env_csv(
    name: str,
) -> tuple[str, ...]:
    raw = os.getenv(
        name
    )

    if raw is None:
        raise RuntimeError(
            f"{name} is not set"
        )

    return tuple(
        part.strip()
        for part in raw.split(",")
        if part.strip()
    )


def _env_cidrs(
    name: str,
) -> tuple[str, ...]:
    values = _env_csv(
        name
    )

    normalized: list[str] = []

    for value in values:
        try:
            network = ipaddress.ip_network(
                value,
                strict=False,
            )
        except ValueError as exc:
            raise ValueError(
                f"{name} contains invalid IP/CIDR {value!r}"
            ) from exc

        normalized.append(
            str(
                network
            )
        )

    return tuple(
        normalized
    )


def firewall_config_from_env(
) -> _FirewallConfig:
    """Build FirewallConfig from explicitly set Sentinel-43 environment values.

    Unset values preserve the implementation's own safe defaults.
    """
    config = _FirewallConfig()

    updates: dict[
        str,
        object,
    ] = {}

    if os.getenv(
        "S43_FIREWALL_ENABLED"
    ) is not None:
        updates[
            "enabled"
        ] = _env_bool(
            "S43_FIREWALL_ENABLED"
        )

    if os.getenv(
        "S43_FIREWALL_MAX_BODY_BYTES"
    ) is not None:
        updates[
            "max_content_length_bytes"
        ] = _env_int(
            "S43_FIREWALL_MAX_BODY_BYTES",
            minimum=1,
            maximum=1024 * 1024 * 1024,
        )

    if os.getenv(
        "S43_FIREWALL_MAX_HEADER_BYTES"
    ) is not None:
        updates[
            "max_total_header_bytes"
        ] = _env_int(
            "S43_FIREWALL_MAX_HEADER_BYTES",
            minimum=1,
            maximum=16 * 1024 * 1024,
        )

    if os.getenv(
        "S43_FIREWALL_ALLOWED_IP_CIDRS"
    ) is not None:
        updates[
            "allowed_ip_cidrs"
        ] = _env_cidrs(
            "S43_FIREWALL_ALLOWED_IP_CIDRS"
        )

    if os.getenv(
        "S43_FIREWALL_BLOCKED_IPS"
    ) is not None:
        updates[
            "blocked_ip_cidrs"
        ] = _env_cidrs(
            "S43_FIREWALL_BLOCKED_IPS"
        )

    if os.getenv(
        "S43_TRUSTED_PROXIES"
    ) is not None:
        updates[
            "trusted_proxy_cidrs"
        ] = _env_cidrs(
            "S43_TRUSTED_PROXIES"
        )

    if os.getenv(
        "S43_FIREWALL_BLOCKED_PATHS"
    ) is not None:
        blocked_paths = _env_csv(
            "S43_FIREWALL_BLOCKED_PATHS"
        )

        if blocked_paths:
            updates[
                "blocked_path_prefixes"
            ] = blocked_paths
        else:
            logger.warning(
                "S43_FIREWALL_BLOCKED_PATHS is set but empty; "
                "preserving FirewallConfig's built-in blocked-path defaults."
            )

    try:
        return replace(
            config,
            **updates,
        )

    except TypeError as exc:
        raise ImportError(
            "FirewallConfig no longer matches the canonical Sentinel-43 "
            "firewall configuration contract."
        ) from exc


FirewallConfig = _FirewallConfig


__all__ = [
    "BlockReason",
    "FirewallConfig",
    "SentinelFirewall",
    "firewall_config_from_env",
]
