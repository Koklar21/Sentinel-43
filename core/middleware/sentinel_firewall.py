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
import ipaddress
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


def _env_bool(name: str) -> bool:
    """
    Parse a set env var as a bool. Caller must only invoke this when the var
    is actually present (os.getenv(name) is not None). A malformed value is a
    hard error, not a silent fall-back to a default: this shim exists to stop
    the firewall silently weakening, and "S43_FIREWALL_ENABLED=maybe quietly
    becomes True" is exactly that failure mode. The error propagates through
    FirewallConfig.from_env() to core/api/main.py, which fails startup closed
    outside local/test environments.
    """
    raw = os.getenv(name, "")
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ValueError(
        f"SentinelFirewall: {name}={raw!r} is not a valid boolean "
        f"(expected one of {sorted(_TRUE_VALUES | _FALSE_VALUES)})"
    )


def _env_int(name: str) -> int:
    """As _env_bool: only call when the var is set; malformed => hard error."""
    raw = os.getenv(name, "")
    try:
        return int(raw.strip())
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"SentinelFirewall: {name}={raw!r} is not a valid integer"
        ) from exc


def _env_csv(name: str) -> tuple[str, ...]:
    """Split a set env var on commas. '' -> (). Only call when the var is set."""
    raw = os.getenv(name, "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _env_cidr_csv(name: str) -> tuple[str, ...]:
    """
    As _env_csv, but every entry must parse as an IP or CIDR now, at config
    load time -- not silently later. A malformed entry in an IP allow/block or
    trusted-proxy list changes security behavior in every direction; catching
    it here means it surfaces as a fail-closed startup error (via
    core/api/main.py) rather than a warning nobody reads. SentinelFirewall's
    own _parse_networks() re-validates as defense-in-depth for callers that
    build FirewallConfig directly.
    """
    values = _env_csv(name)
    for value in values:
        try:
            ipaddress.ip_network(value, strict=False)
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"SentinelFirewall: {name} contains an invalid IP/CIDR "
                f"{value!r}: {exc}"
            ) from exc
    return values


def _constructor_accepts(cls: type[Any], field: str) -> bool:
    try:
        return field in inspect.signature(cls).parameters
    except (TypeError, ValueError):
        return False


# (FirewallConfig constructor field, env var, parser kind). The field names
# are the *actual* dataclass parameters — see
# core/api/middleware/sentinel_firewall_middleware.py. Earlier versions of
# this table guessed plausible-sounding names ("enable_firewall",
# "max_body_bytes", "blocked_paths", "trusted_proxies", ...) that never
# matched the real fields; 3f65ca1 corrected the names. "allowed_origins" is
# not here — it's a CORS setting (S43_ALLOWED_ORIGINS in core/api/main.py),
# not a FirewallConfig field.
# (FirewallConfig field, env var, parser kind, keep_default_when_blank).
# keep_default_when_blank=True: a set-but-empty value ("", whitespace, ",")
# is treated as "not configured" and FirewallConfig's built-in default is
# kept, with a warning. Only blocked_path_prefixes needs this — its default
# is a non-empty security baseline and there is no legitimate reason to want
# zero path prefixes with the firewall otherwise on (use S43_FIREWALL_ENABLED
# =false for that). For the other CSV fields an empty value == the default
# (empty) anyway, so the flag is a no-op.
_ENV_FIELD_MAP: tuple[tuple[str, str, str, bool], ...] = (
    ("enabled", "S43_FIREWALL_ENABLED", "bool", False),
    ("max_content_length_bytes", "S43_FIREWALL_MAX_BODY_BYTES", "int", False),
    ("max_total_header_bytes", "S43_FIREWALL_MAX_HEADER_BYTES", "int", False),
    ("allowed_ip_cidrs", "S43_FIREWALL_ALLOWED_IP_CIDRS", "cidr_csv", False),
    ("blocked_ip_cidrs", "S43_FIREWALL_BLOCKED_IPS", "cidr_csv", False),
    ("blocked_path_prefixes", "S43_FIREWALL_BLOCKED_PATHS", "csv", True),
    ("trusted_proxy_cidrs", "S43_TRUSTED_PROXIES", "cidr_csv", False),
)


def _build_config_kwargs(cls: type[Any]) -> dict[str, Any]:
    """
    Build FirewallConfig kwargs ONLY for env vars that are actually set (and,
    for blocked_path_prefixes, only when set to a non-empty value).

    Invariant: an absent or blank environment variable must never override a
    FirewallConfig default. Previously every field was passed
    unconditionally, so an unset S43_FIREWALL_BLOCKED_PATHS handed
    FirewallConfig `blocked_path_prefixes=()` — silently replacing the
    built-in list of dangerous path prefixes (/.git, /.env, /wp-admin,
    /actuator, ...) with nothing. Now an absent var is skipped, a blank
    blocked_path_prefixes is skipped with a warning, and a present-but-
    malformed bool/int raises (see _env_bool / _env_int) rather than falling
    back to a default.

    _constructor_accepts() still guards each field so the shim tolerates the
    relocated FirewallConfig renaming a field later.
    """
    kwargs: dict[str, Any] = {}

    for field, env_var, kind, keep_default_when_blank in _ENV_FIELD_MAP:
        if os.getenv(env_var) is None:
            continue
        if not _constructor_accepts(cls, field):
            continue
        if kind == "bool":
            kwargs[field] = _env_bool(env_var)
        elif kind == "int":
            kwargs[field] = _env_int(env_var)
        else:
            value = _env_cidr_csv(env_var) if kind == "cidr_csv" else _env_csv(env_var)
            if not value and keep_default_when_blank:
                logger.warning(
                    "%s is set but empty -- keeping FirewallConfig's built-in "
                    "%s default. Unset the variable to silence this, or give a "
                    "real comma-separated value to replace the default list.",
                    env_var,
                    field,
                )
                continue
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
