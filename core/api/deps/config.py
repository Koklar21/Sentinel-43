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

"""Sentinel-43 API dependency configuration.

Scope is deliberately narrow: the environment (local vs production-like) and
the engine/store factory specs that ``core.api.deps.deps`` resolves. Parsing
is deterministic and side-effect free -- no Watchtower calls, no logging, no
filesystem. Watchtower module/dependency registration for this process is
owned by ``core.api.main`` and ``core.api.deps.deps``, not here.

Broader API configuration (host/port/CORS/docs/logging) is owned elsewhere
and is intentionally not duplicated here.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Final

# =============================================================================
# Constants
# =============================================================================

_LOCAL_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"development", "dev", "local", "test"}
)

_PRODUCTION_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"production", "prod", "staging", "stage"}
)

_FACTORY_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$"
)

DEFAULT_ENGINE_FACTORY: Final[str] = "core.api.deps:dev_engine_factory"
DEFAULT_STORE_FACTORY: Final[str] = "core.api.deps:dev_store_factory"

DEFAULT_CONFIG_VERSION: Final[str] = "0.1.0"


# =============================================================================
# Errors
# =============================================================================

class ConfigError(RuntimeError):
    """Raised when Sentinel-43 dependency configuration is invalid."""


# =============================================================================
# Helpers
# =============================================================================

def _env(name: str, default: str | None = None) -> str | None:
    raw = os.getenv(name)
    if raw is None:
        return default

    value = raw.strip()
    return value if value else default


def _resolve_environment_name() -> str:
    """Read the deployment environment from the same variables the API
    composition root uses.

    core/api/main.py reads SENTINEL_ENV; Fenrir/Sparta/Watchtower read
    S43_ENV. Both are accepted so the dependency layer's local/production
    decision cannot silently disagree with the rest of the process. The
    default is "production" so an unset environment fails closed (dev
    factories forbidden) rather than open.
    """
    for name in ("SENTINEL_ENV", "SENTINEL_ENVIRONMENT", "S43_ENV"):
        value = _env(name)
        if value:
            return value
    return "production"


def _normalize_environment(value: str | None) -> str:
    normalized = (value or "production").strip().lower()

    aliases = {
        "dev": "development",
        "local": "development",
        "stage": "staging",
        "prod": "production",
    }
    return aliases.get(normalized, normalized or "production")


def _validate_factory(name: str, value: str) -> str:
    cleaned = value.strip()
    if not _FACTORY_RE.fullmatch(cleaned):
        raise ConfigError(
            f"{name} must use 'module.path:callable' syntax; got {value!r}"
        )
    return cleaned


# =============================================================================
# Configuration model
# =============================================================================

@dataclass(frozen=True, slots=True)
class ApiConfig:
    version: str
    environment: str
    engine_factory: str
    store_factory: str

    @property
    def is_local(self) -> bool:
        return self.environment in _LOCAL_ENVIRONMENTS

    @property
    def is_production_like(self) -> bool:
        return self.environment in _PRODUCTION_ENVIRONMENTS

    def safe_dict(self) -> dict[str, Any]:
        """Configuration values safe for logs/status reporting.

        Internal factory paths are omitted deliberately.
        """
        return {
            "version": self.version,
            "environment": self.environment,
        }


def _validate_config(config: ApiConfig) -> None:
    if not config.version.strip():
        raise ConfigError("SENTINEL_VERSION must not be empty")

    if config.is_production_like:
        if config.engine_factory == DEFAULT_ENGINE_FACTORY:
            raise ConfigError(
                "Production-like environments may not use the development "
                "engine factory (dev_engine_factory)"
            )

        if config.store_factory == DEFAULT_STORE_FACTORY:
            raise ConfigError(
                "Production-like environments may not use the development "
                "store factory (dev_store_factory)"
            )


# =============================================================================
# Public loader
# =============================================================================

def load_config() -> ApiConfig:
    """Load and validate Sentinel-43 API dependency configuration.

    Deterministic and side-effect free. Production-like environments fail
    closed on an invalid factory spec or a development factory rather than
    silently falling back to a stub.
    """
    environment = _normalize_environment(_resolve_environment_name())

    version = _env("SENTINEL_VERSION", DEFAULT_CONFIG_VERSION) or DEFAULT_CONFIG_VERSION

    engine_factory = _validate_factory(
        "SENTINEL_ENGINE_FACTORY",
        _env("SENTINEL_ENGINE_FACTORY", DEFAULT_ENGINE_FACTORY)
        or DEFAULT_ENGINE_FACTORY,
    )

    store_factory = _validate_factory(
        "SENTINEL_STORE_FACTORY",
        _env("SENTINEL_STORE_FACTORY", DEFAULT_STORE_FACTORY)
        or DEFAULT_STORE_FACTORY,
    )

    config = ApiConfig(
        version=version,
        environment=environment,
        engine_factory=engine_factory,
        store_factory=store_factory,
    )

    _validate_config(config)
    return config


__all__ = [
    "ApiConfig",
    "ConfigError",
    "DEFAULT_ENGINE_FACTORY",
    "DEFAULT_STORE_FACTORY",
    "load_config",
]
