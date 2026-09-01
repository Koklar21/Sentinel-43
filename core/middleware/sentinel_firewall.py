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

    # Keys below are the *actual* FirewallConfig constructor parameter names
    # (see core/api/middleware/sentinel_firewall_middleware.py). Earlier
    # versions of this table guessed plausible-sounding names ("enable_firewall",
    # "max_body_bytes", "allowed_hosts", "blocked_paths", "blocked_ips",
    # "block_private_networks", "log_blocked", "strict_mode") that never
    # matched the real dataclass fields, so _constructor_accepts() silently
    # dropped 8 of 10 candidates below and those knobs did nothing — the same
    # bug class that left trusted_proxy_cidrs permanently empty. "allowed_origins"
    # was removed outright: it's a CORS setting (see S43_ALLOWED_ORIGINS in
    # core/api/main.py), not a FirewallConfig field, and never belonged here.
    candidates: dict[str, Any] = {
        "enabled": _env_bool("S43_FIREWALL_ENABLED", True),

        # Real field names: max_content_length_bytes / max_total_header_bytes.
        # Defaults match FirewallConfig's own dataclass defaults so leaving
        # these env vars unset preserves prior (unconfigurable) behavior.
        "max_content_length_bytes": _env_int("S43_FIREWALL_MAX_BODY_BYTES", 10 * 1024 * 1024),
        "max_total_header_bytes": _env_int("S43_FIREWALL_MAX_HEADER_BYTES", 32 * 1024),

        # Real field names: allowed_ip_cidrs / blocked_ip_cidrs / blocked_path_prefixes.
        "allowed_ip_cidrs": _env_csv("S43_FIREWALL_ALLOWED_IP_CIDRS"),
        "blocked_ip_cidrs": _env_csv("S43_FIREWALL_BLOCKED_IPS"),
        "blocked_path_prefixes": _env_csv("S43_FIREWALL_BLOCKED_PATHS"),

        # See docs/security/trusted_proxy_handling.md.
        "trusted_proxy_cidrs": _env_csv("S43_TRUSTED_PROXIES"),
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
