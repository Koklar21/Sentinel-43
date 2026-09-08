from pathlib import Path

code = r'''# =============================================================================
# Copyright (c) 2026 Justin Armstrong
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sentinel-43 API configuration.

Configuration parsing is intentionally deterministic and side-effect free.
Watchtower reporting is best-effort and happens only after a complete config
object has been built and validated.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Final

from ...monitoring.watchtower_client import watchtower_request

logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

_VALID_LOG_LEVELS: Final[frozenset[str]] = frozenset(
    {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
)

_TRUE_VALUES: Final[frozenset[str]] = frozenset(
    {"1", "true", "t", "yes", "y", "on"}
)

_FALSE_VALUES: Final[frozenset[str]] = frozenset(
    {"0", "false", "f", "no", "n", "off"}
)

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

CONFIG_MODULE_ID: Final[str] = "sentinel43-api-config"
DEFAULT_CONFIG_VERSION: Final[str] = "0.1.0"

DEFAULT_LOCAL_CORS: Final[tuple[str, ...]] = (
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
)


# =============================================================================
# Errors
# =============================================================================

class ConfigError(RuntimeError):
    """Raised when Sentinel-43 configuration is invalid."""


# =============================================================================
# Utility helpers
# =============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env(name: str, default: str | None = None) -> str | None:
    raw = os.getenv(name)
    if raw is None:
        return default

    value = raw.strip()
    return value if value else default


def _parse_bool(
    name: str,
    *,
    default: bool,
    strict: bool,
) -> bool:
    raw = _env(name)
    if raw is None:
        return default

    normalized = raw.lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False

    if strict:
        raise ConfigError(
            f"{name} must be a boolean value; got {raw!r}. "
            f"Accepted true values={sorted(_TRUE_VALUES)}, "
            f"false values={sorted(_FALSE_VALUES)}"
        )

    logger.warning(
        "Invalid boolean for %s=%r; using default %s",
        name,
        raw,
        default,
    )
    return default


def _parse_int(
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
    strict: bool,
) -> int:
    raw = _env(name)
    if raw is None:
        return default

    try:
        value = int(raw)
    except ValueError as exc:
        if strict:
            raise ConfigError(
                f"{name} must be an integer; got {raw!r}"
            ) from exc

        logger.warning(
            "Invalid integer for %s=%r; using default %d",
            name,
            raw,
            default,
        )
        return default

    if not minimum <= value <= maximum:
        if strict:
            raise ConfigError(
                f"{name} must be between {minimum} and {maximum}; got {value}"
            )

        logger.warning(
            "%s=%d is outside allowed range %d..%d; using default %d",
            name,
            value,
            minimum,
            maximum,
            default,
        )
        return default

    return value


def _normalize_environment(value: str | None) -> str:
    normalized = (value or "development").strip().lower()

    aliases = {
        "dev": "development",
        "local": "development",
        "test": "test",
        "stage": "staging",
        "prod": "production",
    }
    return aliases.get(normalized, normalized or "development")


def _normalize_log_level(
    value: str | None,
    *,
    strict: bool,
    default: str = "INFO",
) -> str:
    level = (value or default).strip().upper()

    if level in _VALID_LOG_LEVELS:
        return level

    if strict:
        raise ConfigError(
            f"SENTINEL_LOG_LEVEL={value!r} is invalid; "
            f"allowed={sorted(_VALID_LOG_LEVELS)}"
        )

    logger.warning(
        "Invalid log level %r; using default %s",
        value,
        default,
    )
    return default


def _normalize_cors_origins(
    value: str | None,
    *,
    environment: str,
) -> tuple[str, ...]:
    raw = (value or "").strip()

    if not raw:
        if environment in _LOCAL_ENVIRONMENTS:
            return DEFAULT_LOCAL_CORS
        raise ConfigError(
            "SENTINEL_CORS_ALLOW_ORIGINS must be explicitly configured "
            "outside development/test"
        )

    if raw == "*":
        if environment in _LOCAL_ENVIRONMENTS:
            return ("*",)
        raise ConfigError(
            "Wildcard CORS origin '*' is not permitted outside "
            "development/test"
        )

    origins = tuple(
        dict.fromkeys(
            item.strip()
            for item in raw.split(",")
            if item.strip()
        )
    )

    if not origins:
        raise ConfigError(
            "SENTINEL_CORS_ALLOW_ORIGINS did not contain any valid origins"
        )

    if environment not in _LOCAL_ENVIRONMENTS:
        insecure = [
            origin
            for origin in origins
            if origin.startswith("http://")
            and not origin.startswith("http://localhost")
            and not origin.startswith("http://127.0.0.1")
        ]
        if insecure:
            raise ConfigError(
                "Non-local environments require HTTPS CORS origins; "
                f"found plaintext origins={insecure}"
            )

    return origins


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
    service_name: str
    version: str

    host: str
    port: int

    log_level: str
    docs_enabled: bool
    cors_allow_origins: tuple[str, ...]

    engine_factory: str
    store_factory: str

    environment: str

    @property
    def is_local(self) -> bool:
        return self.environment in _LOCAL_ENVIRONMENTS

    @property
    def is_production_like(self) -> bool:
        return self.environment in _PRODUCTION_ENVIRONMENTS

    def safe_dict(self) -> dict[str, Any]:
        """Return configuration safe for logs/status reporting.

        Internal factory paths are deliberately omitted because they expose
        implementation details without helping operators assess runtime health.
        """
        return {
            "service_name": self.service_name,
            "version": self.version,
            "host": self.host,
            "port": self.port,
            "log_level": self.log_level,
            "docs_enabled": self.docs_enabled,
            "cors_allow_origins": list(self.cors_allow_origins),
            "environment": self.environment,
        }


# =============================================================================
# Validation
# =============================================================================

def _validate_config(config: ApiConfig) -> None:
    if not config.service_name.strip():
        raise ConfigError("SENTINEL_SERVICE_NAME must not be empty")

    if not config.version.strip():
        raise ConfigError("SENTINEL_VERSION must not be empty")

    if not config.host.strip():
        raise ConfigError("SENTINEL_HOST must not be empty")

    if config.is_production_like:
        if config.docs_enabled:
            raise ConfigError(
                "Interactive API documentation must be disabled in "
                "production-like environments. Set "
                "SENTINEL_DOCS_ENABLED=false."
            )

        if config.engine_factory == DEFAULT_ENGINE_FACTORY:
            raise ConfigError(
                "Production-like environments may not use "
                "DEFAULT_ENGINE_FACTORY/dev_engine_factory"
            )

        if config.store_factory == DEFAULT_STORE_FACTORY:
            raise ConfigError(
                "Production-like environments may not use "
                "DEFAULT_STORE_FACTORY/dev_store_factory"
            )

        if config.cors_allow_origins == ("*",):
            raise ConfigError(
                "Wildcard CORS is not permitted in production-like environments"
            )


# =============================================================================
# Watchtower telemetry
# =============================================================================

def _watchtower_request_best_effort(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    try:
        return watchtower_request(method, path, payload)
    except Exception:
        logger.warning(
            "Config Watchtower telemetry failed: %s %s",
            method,
            path,
            exc_info=True,
        )
        return None


def _report_loaded_config(config: ApiConfig) -> None:
    """Register and report one coherent config-load event.

    Telemetry failure must never mutate the already-validated configuration
    result or cause configuration parsing to recurse into additional reports.
    """
    module_id = _env("S43_CONFIG_MODULE_ID", CONFIG_MODULE_ID) or CONFIG_MODULE_ID
    version = config.version or DEFAULT_CONFIG_VERSION
    timestamp = utc_now()

    register_payload = {
        "module_id": module_id,
        "module_type": "api-config",
        "version": version,
        "endpoint": None,
        "capabilities": [
            "environment_loading",
            "env_validation",
            "log_level_validation",
            "cors_normalization",
            "production_fail_closed_validation",
            "config_drift_reporting",
        ],
        "metadata": {
            "timestamp": timestamp,
            "environment": config.environment,
        },
    }

    _watchtower_request_best_effort(
        "POST",
        "/watchtower/modules/register",
        register_payload,
    )

    dependency_payload = {
        "name": module_id,
        "status": "online",
        "version": version,
        "details": {
            "event": "config_loaded",
            "timestamp": timestamp,
            "config": config.safe_dict(),
        },
    }

    _watchtower_request_best_effort(
        "POST",
        "/watchtower/dependencies/report",
        dependency_payload,
    )

    analyze_payload = {
        "event": {
            "kind": "config",
            "source": module_id,
            "status": "online",
            "drift_detected": False,
            "details": {
                "event": "config_loaded",
                "timestamp": timestamp,
                "config": config.safe_dict(),
            },
        }
    }

    _watchtower_request_best_effort(
        "POST",
        "/watchtower/analyze",
        analyze_payload,
    )


# =============================================================================
# Public loader
# =============================================================================

def load_config(*, report_to_watchtower: bool = True) -> ApiConfig:
    """Load and validate Sentinel-43 API configuration.

    Local/test environments are forgiving for malformed booleans/integers and
    use documented defaults. Production-like environments fail closed rather
    than silently replacing invalid operator input with defaults.
    """
    environment = _normalize_environment(
        _env("SENTINEL_ENVIRONMENT", "development")
    )
    strict = environment not in _LOCAL_ENVIRONMENTS

    service_name = _env(
        "SENTINEL_SERVICE_NAME",
        "sentinel-43-api",
    ) or "sentinel-43-api"

    version = _env(
        "SENTINEL_VERSION",
        DEFAULT_CONFIG_VERSION,
    ) or DEFAULT_CONFIG_VERSION

    host = _env(
        "SENTINEL_HOST",
        "0.0.0.0",
    ) or "0.0.0.0"

    port = _parse_int(
        "SENTINEL_PORT",
        default=8000,
        minimum=1,
        maximum=65535,
        strict=strict,
    )

    log_level = _normalize_log_level(
        _env("SENTINEL_LOG_LEVEL", "INFO"),
        strict=strict,
    )

    docs_enabled = _parse_bool(
        "SENTINEL_DOCS_ENABLED",
        default=environment in _LOCAL_ENVIRONMENTS,
        strict=strict,
    )

    cors_allow_origins = _normalize_cors_origins(
        _env("SENTINEL_CORS_ALLOW_ORIGINS"),
        environment=environment,
    )

    engine_factory = _validate_factory(
        "SENTINEL_ENGINE_FACTORY",
        _env(
            "SENTINEL_ENGINE_FACTORY",
            DEFAULT_ENGINE_FACTORY,
        )
        or DEFAULT_ENGINE_FACTORY,
    )

    store_factory = _validate_factory(
        "SENTINEL_STORE_FACTORY",
        _env(
            "SENTINEL_STORE_FACTORY",
            DEFAULT_STORE_FACTORY,
        )
        or DEFAULT_STORE_FACTORY,
    )

    config = ApiConfig(
        service_name=service_name,
        version=version,
        host=host,
        port=port,
        log_level=log_level,
        docs_enabled=docs_enabled,
        cors_allow_origins=cors_allow_origins,
        engine_factory=engine_factory,
        store_factory=store_factory,
        environment=environment,
    )

    _validate_config(config)

    if report_to_watchtower:
        _report_loaded_config(config)

    return config


__all__ = [
    "ApiConfig",
    "ConfigError",
    "DEFAULT_ENGINE_FACTORY",
    "DEFAULT_STORE_FACTORY",
    "load_config",
]
'''

path = Path("/mnt/data/sentinel43_api_config_recode.py")
path.write_text(code, encoding="utf-8")
print(path)
