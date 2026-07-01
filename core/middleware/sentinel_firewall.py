# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
# =============================================================================

"""
Sentinel-43 firewall middleware compatibility module.

This file is the canonical import location used by:

    from core.middleware import SentinelFirewall, FirewallConfig, BlockReason

The relocated implementation currently lives at:

    core.api.middleware.sentinel_firewall_middleware

That relocated copy is usable, but its FirewallConfig does not expose the
from_env() classmethod expected by core.api.main. This module restores that
interface at the original import location without changing router behavior or
rewiring unrelated middleware.
"""

from __future__ import annotations

import inspect
import logging
import os
from typing import Any

from core.api.middleware.sentinel_firewall_middleware import (  # noqa: F401
    BlockReason,
    FirewallConfig,
    SentinelFirewall,
)

logger = logging.getLogger("SentinelFirewall")


_TRUE_VALUES = {"1", "true", "yes", "on", "enabled"}
_FALSE_VALUES = {"0", "false", "no", "off", "disabled"}


def _env_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default

    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False

    logger.warning("Invalid bool for %s=%r; using default %r", name, raw, default)
    return default


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        return int(raw.strip())
    except ValueError:
        logger.warning("Invalid int for %s=%r; using default %r", name, raw, default)
        return default


def _env_csv(name: str, default: str = "") -> tuple[str, ...]:
    raw = os.getenv(name, default)
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _constructor_accepts(cls: type[Any], field: str) -> bool:
    try:
        return field in inspect.signature(cls).parameters
    except (TypeError, ValueError):
        return False


def _build_config_kwargs(cls: type[Any]) -> dict[str, Any]:
    """
    Build kwargs only for constructor parameters that actually exist.

    This keeps the shim compatible with the relocated FirewallConfig even if
    that dataclass/class changes field names later.
    """
    kwargs: dict[str, Any] = {}

    candidates: dict[str, Any] = {
        # Common enable/disable field names.
        "enabled": _env_bool("S43_FIREWALL_ENABLED", True),
        "enable_firewall": _env_bool("S43_FIREWALL_ENABLED", True),

        # Common request/body limits.
        "max_body_bytes": _env_int("S43_FIREWALL_MAX_BODY_BYTES", 1024 * 1024),
        "max_request_bytes": _env_int("S43_FIREWALL_MAX_BODY_BYTES", 1024 * 1024),
        "max_header_bytes": _env_int("S43_FIREWALL_MAX_HEADER_BYTES", 16 * 1024),

        # Common origin/path/IP style fields.
        "allowed_origins": _env_csv("S43_ALLOWED_ORIGINS"),
        "allowed_hosts": _env_csv("S43_ALLOWED_HOSTS"),
        "blocked_paths": _env_csv("S43_FIREWALL_BLOCKED_PATHS"),
        "blocked_ips": _env_csv("S43_FIREWALL_BLOCKED_IPS"),
        "trusted_proxies": _env_csv("S43_TRUSTED_PROXIES"),

        # Common behavior toggles.
        "block_private_networks": _env_bool("S43_FIREWALL_BLOCK_PRIVATE_NETWORKS", False),
        "log_blocked": _env_bool("S43_FIREWALL_LOG_BLOCKED", True),
        "strict_mode": _env_bool("S43_FIREWALL_STRICT_MODE", False),
    }

    for field, value in candidates.items():
        if _constructor_accepts(cls, field):
            kwargs[field] = value

    return kwargs


def _firewall_config_from_env(cls: type[Any]) -> Any:
    """
    Recreate the expected FirewallConfig.from_env() classmethod.

    Prefer constructor kwargs when the relocated config supports known field
    names. If it does not, fall back to the class defaults. If required
    constructor arguments exist with no defaults, raise a clear ImportError
    instead of failing later during FastAPI middleware registration.
    """
    kwargs = _build_config_kwargs(cls)

    try:
        return cls(**kwargs)
    except TypeError as first_error:
        try:
            return cls()
        except TypeError as second_error:
            raise ImportError(
                "FirewallConfig.from_env() compatibility shim could not "
                "construct FirewallConfig from the relocated implementation. "
                f"Constructor kwargs attempted: {sorted(kwargs)}. "
                f"First error: {first_error}. Second error: {second_error}."
            ) from second_error


if not hasattr(FirewallConfig, "from_env"):
    setattr(FirewallConfig, "from_env", classmethod(_firewall_config_from_env))


if not hasattr(FirewallConfig, "from_env"):
    raise ImportError(
        "FirewallConfig compatibility repair failed: from_env() is still missing."
    )


__all__ = [
    "SentinelFirewall",
    "FirewallConfig",
    "BlockReason",
]
