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

"""Canonical Sentinel-43 runtime configuration.

Design rules:
    - deterministic parsing
    - no filesystem mutation during import or validation
    - no secret generation
    - no environment mutation
    - no migration execution policy
    - no autonomous enforcement feature flags
    - safe summaries never expose credential-bearing URLs or secret material

Runtime directory creation and subsystem startup belong to application lifespan.
"""

from __future__ import annotations

import ipaddress
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_TRUE_VALUES: Final[frozenset[str]] = frozenset(
    {"1", "true", "yes", "on", "enabled"}
)
_FALSE_VALUES: Final[frozenset[str]] = frozenset(
    {"0", "false", "no", "off", "disabled"}
)

_ALLOWED_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"development", "test", "staging", "production"}
)

_ALLOWED_LOG_LEVELS: Final[frozenset[str]] = frozenset(
    {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
)

_ALLOWED_GOVERNANCE_MODES: Final[frozenset[str]] = frozenset(
    {"shadow", "human_gated"}
)

_TENANT_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9_-]{2,64}$"
)


def _parse_csv(value: Any) -> list[str]:
    if value is None:
        return []

    if isinstance(value, str):
        return [
            item.strip()
            for item in value.split(",")
            if item.strip()
        ]

    return [
        str(item).strip()
        for item in value
        if str(item).strip()
    ]


def _normalize_environment(value: str) -> str:
    normalized = value.strip().lower()

    aliases = {
        "dev": "development",
        "local": "development",
        "prod": "production",
        "stage": "staging",
    }

    normalized = aliases.get(
        normalized,
        normalized,
    )

    if normalized not in _ALLOWED_ENVIRONMENTS:
        raise ValueError(
            f"environment must be one of {sorted(_ALLOWED_ENVIRONMENTS)}"
        )

    return normalized


def _is_https_url(value: str) -> bool:
    try:
        parsed = urlparse(
            value
        )
    except ValueError:
        return False

    return (
        parsed.scheme == "https"
        and bool(parsed.netloc)
    )


def _origin_is_local_http(value: str) -> bool:
    try:
        parsed = urlparse(
            value
        )
    except ValueError:
        return False

    if parsed.scheme != "http":
        return False

    host = (
        parsed.hostname
        or ""
    ).lower()

    return host in {
        "localhost",
        "127.0.0.1",
        "::1",
    }


def _database_scheme(value: str) -> str:
    return value.split(
        ":",
        1,
    )[0].lower()


class Settings(BaseSettings):
    """Validated Sentinel-43 runtime settings."""

    model_config = SettingsConfigDict(
        env_prefix="S43_",
        env_file=os.getenv(
            "S43_ENV_FILE",
            ".env",
        ),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Identity / runtime
    # ------------------------------------------------------------------

    environment: str = Field(
        default="development",
        validation_alias="S43_ENV",
    )

    service_name: str = "sentinel-43"
    node_name: str = "sentinel-43"

    debug: bool = False
    log_level: str = "INFO"

    data_dir: Path = Path("./data")
    log_dir: Path = Path("./logs")
    tmp_dir: Path = Path("./tmp")

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------

    api_host: str = "0.0.0.0"
    api_port: int = Field(
        default=8000,
        ge=1,
        le=65535,
    )
    api_root_path: str = ""

    cors_allow_origins: list[str] = Field(
        default_factory=list
    )
    trusted_proxies: list[str] = Field(
        default_factory=list
    )

    max_request_bytes: int = Field(
        default=2_000_000,
        ge=1_024,
        le=100_000_000,
    )

    # ------------------------------------------------------------------
    # Authentication / session security
    # ------------------------------------------------------------------

    jwt_secret: SecretStr | None = None
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "sentinel-43"
    jwt_audience: str = "sentinel-43"

    auth_pepper: SecretStr | None = None
    operator_password_hash: SecretStr | None = None

    session_hash_pepper: SecretStr | None = None
    session_refresh_ttl_seconds: int = Field(
        default=7 * 24 * 3600,
        ge=300,
        le=30 * 24 * 3600,
    )

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------

    database_url: SecretStr | None = Field(
        default=None,
        validation_alias="DATABASE_URL",
    )

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    audit_enabled: bool = True
    audit_sqlite_path: Path = Path(
        "./sentinel43_state/audit.sqlite3"
    )
    audit_jsonl_path: Path | None = Path(
        "./logs/audit.jsonl"
    )
    audit_signing_key: SecretStr | None = None

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    logging_json: bool = True
    metrics_enabled: bool = True
    metrics_path: str = "/metrics"
    tracing_enabled: bool = False
    otel_exporter_otlp_endpoint: str | None = None

    # ------------------------------------------------------------------
    # Abuse controls
    # ------------------------------------------------------------------

    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = Field(
        default=120,
        ge=1,
        le=100_000,
    )
    rate_limit_burst: int = Field(
        default=60,
        ge=0,
        le=100_000,
    )

    # ------------------------------------------------------------------
    # Governance
    # ------------------------------------------------------------------

    governance_mode: str = "human_gated"

    # ------------------------------------------------------------------
    # Optional integrations
    # ------------------------------------------------------------------

    redis_enabled: bool = False
    redis_url: SecretStr | None = None

    fenrir_enabled: bool = False
    fenrir_api_token: SecretStr | None = None

    watchtower_enabled: bool = True
    watchtower_service_token: SecretStr | None = None

    remote_gateway_enabled: bool = False

    webhooks_enabled: bool = False
    webhook_require_signature: bool = True
    webhook_signing_secret: SecretStr | None = None

    slack_webhook_url: str | None = None
    discord_webhook_url: str | None = None

    # ------------------------------------------------------------------
    # Policy thresholds
    # ------------------------------------------------------------------

    severity_low_threshold: int = Field(
        default=25,
        ge=0,
        le=100,
    )
    severity_medium_threshold: int = Field(
        default=50,
        ge=0,
        le=100,
    )
    severity_high_threshold: int = Field(
        default=75,
        ge=0,
        le=100,
    )
    severity_critical_threshold: int = Field(
        default=90,
        ge=0,
        le=100,
    )

    incident_dedupe_window_seconds: int = Field(
        default=300,
        ge=0,
        le=86_400,
    )

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @field_validator(
        "environment",
        mode="before",
    )
    @classmethod
    def validate_environment(
        cls,
        value: Any,
    ) -> str:
        return _normalize_environment(
            str(value)
        )

    @field_validator(
        "log_level",
        mode="before",
    )
    @classmethod
    def validate_log_level(
        cls,
        value: Any,
    ) -> str:
        normalized = str(
            value
        ).strip().upper()

        if normalized not in _ALLOWED_LOG_LEVELS:
            raise ValueError(
                f"log_level must be one of {sorted(_ALLOWED_LOG_LEVELS)}"
            )

        return normalized

    @field_validator(
        "cors_allow_origins",
        "trusted_proxies",
        mode="before",
    )
    @classmethod
    def parse_list_fields(
        cls,
        value: Any,
    ) -> list[str]:
        return _parse_csv(
            value
        )

    @field_validator(
        "governance_mode",
        mode="before",
    )
    @classmethod
    def validate_governance_mode(
        cls,
        value: Any,
    ) -> str:
        normalized = str(
            value
        ).strip().lower()

        if normalized not in _ALLOWED_GOVERNANCE_MODES:
            raise ValueError(
                f"governance_mode must be one of "
                f"{sorted(_ALLOWED_GOVERNANCE_MODES)}"
            )

        return normalized

    @field_validator(
        "trusted_proxies",
    )
    @classmethod
    def validate_trusted_proxies(
        cls,
        values: list[str],
    ) -> list[str]:
        for value in values:
            try:
                ipaddress.ip_network(
                    value,
                    strict=False,
                )
            except ValueError as exc:
                raise ValueError(
                    f"invalid trusted proxy CIDR/address: {value!r}"
                ) from exc

        return values

    @field_validator(
        "metrics_path",
    )
    @classmethod
    def validate_metrics_path(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized.startswith("/"):
            raise ValueError(
                "metrics_path must begin with '/'"
            )

        return normalized

    @model_validator(
        mode="after",
    )
    def validate_security_posture(
        self,
    ) -> "Settings":
        thresholds = (
            self.severity_low_threshold,
            self.severity_medium_threshold,
            self.severity_high_threshold,
            self.severity_critical_threshold,
        )

        if not (
            thresholds[0]
            <= thresholds[1]
            <= thresholds[2]
            <= thresholds[3]
        ):
            raise ValueError(
                "severity thresholds must be non-decreasing"
            )

        non_local = (
            self.environment
            not in {
                "development",
                "test",
            }
        )

        if non_local and self.debug:
            raise ValueError(
                "debug must be disabled outside development/test"
            )

        if (
            self.environment == "production"
            and self.log_level == "DEBUG"
        ):
            raise ValueError(
                "DEBUG logging is not permitted in production"
            )

        if non_local:
            if not self.jwt_secret:
                raise ValueError(
                    "S43_JWT_SECRET is required outside development/test"
                )

            if len(
                self.jwt_secret.get_secret_value().encode(
                    "utf-8"
                )
            ) < 32:
                raise ValueError(
                    "S43_JWT_SECRET must contain at least 32 bytes"
                )

            if not self.database_url:
                raise ValueError(
                    "DATABASE_URL is required outside development/test"
                )

            if not self.audit_signing_key:
                raise ValueError(
                    "S43_AUDIT_SIGNING_KEY is required outside development/test"
                )

            if len(
                self.audit_signing_key.get_secret_value().encode(
                    "utf-8"
                )
            ) < 32:
                raise ValueError(
                    "S43_AUDIT_SIGNING_KEY must contain at least 32 bytes"
                )

            if not self.watchtower_service_token:
                raise ValueError(
                    "S43_WATCHTOWER_SERVICE_TOKEN is required outside development/test"
                )

        if self.database_url:
            database_value = (
                self.database_url.get_secret_value()
            )

            scheme = _database_scheme(
                database_value
            )

            if self.environment in {
                "staging",
                "production",
            } and scheme != "postgresql+asyncpg":
                raise ValueError(
                    "staging/production DATABASE_URL must use postgresql+asyncpg"
                )

            if scheme not in {
                "postgresql+asyncpg",
                "sqlite+aiosqlite",
            }:
                raise ValueError(
                    "DATABASE_URL must use postgresql+asyncpg or sqlite+aiosqlite"
                )

        if self.environment in {
            "staging",
            "production",
        }:
            for origin in self.cors_allow_origins:
                if origin == "*":
                    raise ValueError(
                        "wildcard CORS is not permitted outside development/test"
                    )

                if not (
                    _is_https_url(
                        origin
                    )
                    or _origin_is_local_http(
                        origin
                    )
                ):
                    raise ValueError(
                        f"CORS origin must be HTTPS outside local development: {origin!r}"
                    )

        if self.webhooks_enabled:
            if (
                self.webhook_require_signature
                and not self.webhook_signing_secret
            ):
                raise ValueError(
                    "webhook signing secret is required for signed webhooks"
                )

        if self.fenrir_enabled and not self.fenrir_api_token:
            raise ValueError(
                "Fenrir token is required when Fenrir is enabled"
            )

        if self.redis_enabled and not self.redis_url:
            raise ValueError(
                "redis_url is required when Redis is enabled"
            )

        if (
            self.slack_webhook_url
            and not _is_https_url(
                self.slack_webhook_url
            )
        ):
            raise ValueError(
                "Slack webhook URL must use HTTPS"
            )

        if (
            self.discord_webhook_url
            and not _is_https_url(
                self.discord_webhook_url
            )
        ):
            raise ValueError(
                "Discord webhook URL must use HTTPS"
            )

        if (
            self.tracing_enabled
            and self.otel_exporter_otlp_endpoint
        ):
            parsed = urlparse(
                self.otel_exporter_otlp_endpoint
            )

            if parsed.scheme not in {
                "http",
                "https",
            } or not parsed.netloc:
                raise ValueError(
                    "OTLP endpoint must be a valid HTTP(S) URL"
                )

        return self

    # ------------------------------------------------------------------
    # Derived helpers
    # ------------------------------------------------------------------

    @property
    def is_local(self) -> bool:
        return self.environment in {
            "development",
            "test",
        }

    def tenant_id_is_valid(
        self,
        tenant_id: str,
    ) -> bool:
        return bool(
            _TENANT_RE.fullmatch(
                tenant_id
                or ""
            )
        )

    def safe_dict(
        self,
    ) -> dict[str, Any]:
        """Return configuration safe for protected diagnostics."""
        return {
            "environment": self.environment,
            "service_name": self.service_name,
            "node_name": self.node_name,
            "debug": self.debug,
            "log_level": self.log_level,
            "api": {
                "host": self.api_host,
                "port": self.api_port,
                "root_path": self.api_root_path,
            },
            "database": {
                "configured": self.database_url is not None,
            },
            "audit": {
                "enabled": self.audit_enabled,
                "jsonl_mirror": self.audit_jsonl_path is not None,
            },
            "governance": {
                "mode": self.governance_mode,
            },
            "integrations": {
                "redis": self.redis_enabled,
                "fenrir": self.fenrir_enabled,
                "watchtower": self.watchtower_enabled,
                "remote_gateway": self.remote_gateway_enabled,
                "webhooks": self.webhooks_enabled,
            },
            "metrics": {
                "enabled": self.metrics_enabled,
                "path": self.metrics_path,
            },
            "rate_limit": {
                "enabled": self.rate_limit_enabled,
                "per_minute": self.rate_limit_per_minute,
                "burst": self.rate_limit_burst,
            },
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-local validated settings singleton."""
    return Settings()


def clear_settings_cache() -> None:
    """Clear the cached settings singleton for tests."""
    get_settings.cache_clear()


__all__ = [
    "Settings",
    "clear_settings_cache",
    "get_settings",
]
