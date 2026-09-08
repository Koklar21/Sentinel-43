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

"""Sentinel-43 modern runtime settings.

This module is deterministic configuration only.

It does NOT:
    - create directories
    - contact Watchtower or any other service
    - mutate os.environ
    - generate secrets
    - run migrations
    - enable autonomous enforcement modes

Telemetry/reporting belongs to application startup after settings validate.
"""

from __future__ import annotations

import ipaddress
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_ALLOWED_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"development", "test", "staging", "production"}
)

_ALLOWED_MODES: Final[frozenset[str]] = frozenset(
    {"shadow", "human_gated"}
)

_ALLOWED_LOG_LEVELS: Final[frozenset[str]] = frozenset(
    {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
)


def _normalize_environment(
    value: str,
) -> str:
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


def _parse_csv(
    value: Any,
) -> list[str]:
    if value is None:
        return []

    if isinstance(
        value,
        str,
    ):
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


def _database_scheme(
    value: str,
) -> str:
    return value.split(
        ":",
        1,
    )[0].lower()


class Settings(BaseSettings):
    """Validated Sentinel-43 settings."""

    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=os.getenv(
            "SENTINEL_ENV_FILE",
            ".env",
        ),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    environment: str = Field(
        default="development",
        validation_alias="SENTINEL_ENV",
    )

    system_id: str = "SENTINEL-43"
    service_name: str = "sentinel-43"
    node_name: str = "sentinel-43"

    # ------------------------------------------------------------------
    # Paths
    # ------------------------------------------------------------------

    base_dir: Path = Path(".")
    data_dir: Path = Path("./data")
    log_dir: Path = Path("./logs")
    tmp_dir: Path = Path("./tmp")

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------

    database_url: SecretStr | None = Field(
        default=None,
        validation_alias="DATABASE_URL",
    )

    db_pool_size: int = Field(
        default=10,
        ge=1,
        le=200,
    )
    db_max_overflow: int = Field(
        default=20,
        ge=0,
        le=500,
    )
    db_pool_timeout_seconds: int = Field(
        default=30,
        ge=1,
        le=300,
    )
    db_echo_sql: bool = False

    # ------------------------------------------------------------------
    # API / gateway
    # ------------------------------------------------------------------

    gateway_enabled: bool = True
    gateway_host: str = "127.0.0.1"
    gateway_port: int = Field(
        default=8000,
        ge=1,
        le=65535,
    )
    allow_remote_access: bool = False

    cors_allow_origins: list[str] = Field(
        default_factory=list
    )
    trusted_proxies: list[str] = Field(
        default_factory=list
    )

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    auth_enabled: bool = True

    jwt_secret: SecretStr | None = None
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "sentinel-43"
    jwt_audience: str = "sentinel-43"

    # ------------------------------------------------------------------
    # Governance
    # ------------------------------------------------------------------

    governance_mode: str = "human_gated"
    strict_mode: bool = True

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
    # Logging
    # ------------------------------------------------------------------

    log_level: str = "INFO"
    log_json: bool = True
    log_to_file: bool = True

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

        if normalized not in _ALLOWED_MODES:
            raise ValueError(
                f"governance_mode must be one of {sorted(_ALLOWED_MODES)}"
            )

        return normalized

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

    @model_validator(
        mode="after",
    )
    def validate_security_posture(
        self,
    ) -> "Settings":
        non_local = (
            self.environment
            not in {
                "development",
                "test",
            }
        )

        if non_local and self.db_echo_sql:
            raise ValueError(
                "db_echo_sql must be disabled outside development/test"
            )

        if (
            self.environment == "production"
            and self.log_level == "DEBUG"
        ):
            raise ValueError(
                "DEBUG logging is not permitted in production"
            )

        if self.gateway_host in {
            "0.0.0.0",
            "::",
            "*",
        }:
            if not self.allow_remote_access:
                raise ValueError(
                    "all-interface gateway bind requires explicit allow_remote_access"
                )

        if non_local:
            if not self.database_url:
                raise ValueError(
                    "DATABASE_URL is required outside development/test"
                )

            if not self.jwt_secret:
                raise ValueError(
                    "SENTINEL_JWT_SECRET is required outside development/test"
                )

            if len(
                self.jwt_secret.get_secret_value().encode(
                    "utf-8"
                )
            ) < 32:
                raise ValueError(
                    "SENTINEL_JWT_SECRET must contain at least 32 bytes"
                )

            if not self.audit_signing_key:
                raise ValueError(
                    "SENTINEL_AUDIT_SIGNING_KEY is required outside development/test"
                )

            if len(
                self.audit_signing_key.get_secret_value().encode(
                    "utf-8"
                )
            ) < 32:
                raise ValueError(
                    "SENTINEL_AUDIT_SIGNING_KEY must contain at least 32 bytes"
                )

        if self.database_url:
            database_value = (
                self.database_url.get_secret_value()
            )
            scheme = _database_scheme(
                database_value
            )

            if scheme not in {
                "sqlite+aiosqlite",
                "postgresql+asyncpg",
            }:
                raise ValueError(
                    "DATABASE_URL must use sqlite+aiosqlite or postgresql+asyncpg"
                )

            if (
                self.environment
                in {
                    "staging",
                    "production",
                }
                and scheme
                != "postgresql+asyncpg"
            ):
                raise ValueError(
                    "staging/production DATABASE_URL must use postgresql+asyncpg"
                )

        if (
            self.environment
            in {
                "staging",
                "production",
            }
        ):
            for origin in self.cors_allow_origins:
                if origin == "*":
                    raise ValueError(
                        "wildcard CORS is not permitted outside development/test"
                    )

                parsed = urlparse(
                    origin
                )

                if (
                    parsed.scheme != "https"
                    or not parsed.netloc
                ):
                    raise ValueError(
                        f"CORS origin must be HTTPS outside local development: {origin!r}"
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

    def safe_dict(
        self,
    ) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "system_id": self.system_id,
            "service_name": self.service_name,
            "node_name": self.node_name,
            "paths": {
                "base_dir": str(
                    self.base_dir
                ),
                "data_dir": str(
                    self.data_dir
                ),
                "log_dir": str(
                    self.log_dir
                ),
                "tmp_dir": str(
                    self.tmp_dir
                ),
            },
            "database": {
                "configured": self.database_url is not None,
                "pool_size": self.db_pool_size,
                "max_overflow": self.db_max_overflow,
            },
            "gateway": {
                "enabled": self.gateway_enabled,
                "host": self.gateway_host,
                "port": self.gateway_port,
                "allow_remote_access": self.allow_remote_access,
            },
            "auth": {
                "enabled": self.auth_enabled,
                "issuer": self.jwt_issuer,
                "audience": self.jwt_audience,
            },
            "governance": {
                "mode": self.governance_mode,
                "strict": self.strict_mode,
            },
            "audit": {
                "enabled": self.audit_enabled,
                "jsonl_mirror": self.audit_jsonl_path is not None,
            },
            "logging": {
                "level": self.log_level,
                "json": self.log_json,
                "to_file": self.log_to_file,
            },
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-local validated settings singleton."""
    return Settings()


def clear_settings_cache() -> None:
    """Clear cached settings for tests."""
    get_settings.cache_clear()


__all__ = [
    "Settings",
    "clear_settings_cache",
    "get_settings",
]
