"""
Sentinel-43 Settings (modern config)

- Environment variable driven (prefix: SENTINEL_)
- Strict typing + validation
- Safe defaults
- Optional secrets directory support
- Optional AEGIS_* back-compat
- Watchtower config reporting
"""

from __future__ import annotations

import os
import re
import secrets
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from core.monitoring.watchtower_client import watchtower_request


_ALLOWED_MODES = {"SHADOW", "HUMAN_GATED", "AUTONOMOUS_VETO"}
_TRUE = {"1", "true", "t", "yes", "y", "on"}
_FALSE = {"0", "false", "f", "no", "n", "off"}

SETTINGS_MODULE_ID = os.getenv("S43_SETTINGS_MODULE_ID", "sentinel43-settings")
SETTINGS_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _watchtower_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # DEFECT_INVENTORY.md D-16: this used to build the request without the
    # internal service token, so every call here 401'd against Watchtower
    # and every settings-validation branch below silently believed its
    # report had succeeded. Delegates to the canonical client, which
    # attaches Authorization and never swallows a failure without logging it.
    return watchtower_request(method, path, payload)


def _register_settings_with_watchtower() -> None:
    payload = {
        "module_id": SETTINGS_MODULE_ID,
        "module_type": "settings",
        "version": SETTINGS_VERSION,
        "endpoint": None,
        "capabilities": [
            "settings_load",
            "strict_validation",
            "secret_validation",
            "gateway_bind_safety",
            "production_security_rails",
            "config_failure_reporting",
        ],
        "metadata": {"timestamp": utc_now()},
    }

    _watchtower_request("POST", "/watchtower/modules/register", payload)


def _report_settings_status(
    status: str,
    event: str,
    details: dict[str, Any] | None = None,
) -> None:
    _register_settings_with_watchtower()

    payload = {
        "name": SETTINGS_MODULE_ID,
        "status": status,
        "version": SETTINGS_VERSION,
        "details": {
            "event": event,
            "timestamp": utc_now(),
            **(details or {}),
        },
    }

    _watchtower_request("POST", "/watchtower/dependencies/report", payload)


def _report_settings_event(
    status: str,
    event: str,
    details: dict[str, Any] | None = None,
) -> None:
    payload = {
        "event": {
            "kind": "config",
            "source": SETTINGS_MODULE_ID,
            "status": status,
            "drift_detected": status in {"degraded", "failed"},
            "details": {
                "event": event,
                "timestamp": utc_now(),
                **(details or {}),
            },
        }
    }

    _watchtower_request("POST", "/watchtower/analyze", payload)


def _as_bool(v: Any, default: bool = False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v

    s = str(v).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False

    _report_settings_status(
        "degraded",
        "invalid_boolean_value",
        {"raw_value": str(v), "default_used": default},
    )
    return default


def _parse_csv(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    s = str(v).strip()
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]


def _ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


def _env_get(*keys: str, default: Optional[str] = None) -> Optional[str]:
    for k in keys:
        val = os.getenv(k)
        if val is not None:
            return val
    return default


def load_secrets_into_env(secrets_dir: Optional[Path], *, prefix: str = "SENTINEL_") -> None:
    if not secrets_dir:
        return

    p = Path(secrets_dir)
    if not p.exists() or not p.is_dir():
        _report_settings_status(
            "degraded",
            "secrets_dir_missing_or_invalid",
            {"secrets_dir": str(secrets_dir)},
        )
        return

    loaded = 0
    failed = 0

    for f in p.iterdir():
        if not f.is_file():
            continue

        name = f.name.strip()
        if not name:
            continue

        try:
            value = f.read_text(encoding="utf-8").strip()
        except Exception as exc:
            failed += 1
            _report_settings_status(
                "degraded",
                "secret_file_read_failed",
                {"file": f.name, "error": str(exc)},
            )
            continue

        if not value:
            continue

        env_name = prefix + name
        if env_name not in os.environ:
            os.environ[env_name] = value
            loaded += 1

    _report_settings_status(
        "online",
        "secrets_loaded",
        {"secrets_dir": str(secrets_dir), "loaded": loaded, "failed": failed},
    )


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=os.getenv("SENTINEL_ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    env: str = Field(default="dev", description="dev|test|staging|prod")
    system_id: str = Field(default="SENTINEL-43-NEXUS-01")
    service_name: str = Field(default="sentinel-43")
    instance_id: str = Field(default_factory=lambda: secrets.token_hex(8))

    base_dir: Path = Field(default=Path("."))
    data_dir: Path = Field(default=Path("./data"))
    log_dir: Path = Field(default=Path("./logs"))
    tmp_dir: Path = Field(default=Path("./tmp"))
    secrets_dir: Optional[Path] = Field(default=None)

    db_dialect: str = Field(default="sqlite")
    db_url: str = Field(default="sqlite:///./data/sentinel43.db")
    db_pool_size: int = Field(default=10, ge=1, le=200)
    db_max_overflow: int = Field(default=20, ge=0, le=500)
    db_pool_timeout_sec: int = Field(default=30, ge=1, le=300)
    db_echo_sql: bool = Field(default=False)

    gateway_enabled: bool = Field(default=True)
    gateway_host: str = Field(default="127.0.0.1")
    gateway_port: int = Field(default=8080, ge=1, le=65535)
    allow_remote_access: bool = Field(default=False)
    cors_allow_origins: List[str] = Field(default_factory=list)

    auth_enabled: bool = Field(default=True)
    jwt_enabled: bool = Field(default=False)
    jwt_secret: str = Field(default="")
    jwt_issuer: str = Field(default="sentinel")
    jwt_audience: str = Field(default="sentinel-remote")

    default_mode: str = Field(default="SHADOW")
    strict_mode: bool = Field(default=True)

    audit_enabled: bool = Field(default=True)
    audit_hash_chain: bool = Field(default=True)
    audit_sign_events: bool = Field(default=True)
    audit_signing_key: str = Field(default="")

    log_level: str = Field(default="INFO")
    log_json: bool = Field(default=True)
    log_to_file: bool = Field(default=True)

    @model_validator(mode="before")
    @classmethod
    def _apply_backcompat_env(cls, data: Any) -> Any:
        d = dict(data or {})

        def fill(key: str, *legacy_keys: str) -> None:
            if key in d and d[key] not in (None, ""):
                return
            v = _env_get(*legacy_keys)
            if v is not None:
                d[key] = v
                _report_settings_status(
                    "online",
                    "legacy_env_mapped",
                    {"target": key, "legacy_keys": list(legacy_keys)},
                )

        fill("env", "AEGIS_ENV")
        fill("system_id", "AEGIS_SYSTEM_ID")
        fill("db_url", "AEGIS_DB_URL", "AEGIS_DB_PATH")
        fill("gateway_host", "AEGIS_GATEWAY_HOST")
        fill("gateway_port", "AEGIS_GATEWAY_PORT")
        fill("jwt_secret", "AEGIS_JWT_SECRET")
        fill("jwt_issuer", "AEGIS_JWT_ISSUER")
        fill("jwt_audience", "AEGIS_JWT_AUDIENCE")
        fill("default_mode", "AEGIS_DEFAULT_MODE")
        fill("log_level", "AEGIS_LOG_LEVEL")

        return d

    @field_validator(
        "db_echo_sql",
        "gateway_enabled",
        "allow_remote_access",
        "auth_enabled",
        "jwt_enabled",
        "strict_mode",
        "audit_enabled",
        "audit_hash_chain",
        "audit_sign_events",
        "log_json",
        "log_to_file",
        mode="before",
    )
    @classmethod
    def _coerce_bools(cls, v: Any) -> Any:
        if isinstance(v, str):
            return _as_bool(v)
        return v

    @field_validator("cors_allow_origins", mode="before")
    @classmethod
    def _coerce_cors(cls, v: Any) -> List[str]:
        return _parse_csv(v)

    @field_validator("env")
    @classmethod
    def _validate_env(cls, v: str) -> str:
        vv = (v or "").strip().lower()
        if vv not in {"dev", "test", "staging", "prod"}:
            _report_settings_status("failed", "invalid_env", {"raw_value": v})
            raise ValueError("env must be one of: dev|test|staging|prod")
        return vv

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        vv = (v or "").strip().upper()
        if vv not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            _report_settings_status("failed", "invalid_log_level", {"raw_value": v})
            raise ValueError("log_level must be DEBUG|INFO|WARNING|ERROR|CRITICAL")
        return vv

    @field_validator("db_dialect")
    @classmethod
    def _validate_db_dialect(cls, v: str) -> str:
        vv = (v or "").strip().lower()
        if vv not in {"sqlite", "postgres"}:
            _report_settings_status("failed", "invalid_db_dialect", {"raw_value": v})
            raise ValueError("db_dialect must be sqlite|postgres")
        return vv

    @field_validator("default_mode")
    @classmethod
    def _validate_mode(cls, v: str) -> str:
        vv = (v or "").strip().upper()
        if vv not in _ALLOWED_MODES:
            _report_settings_status("failed", "invalid_default_mode", {"raw_value": v})
            raise ValueError(f"default_mode must be one of: {sorted(_ALLOWED_MODES)}")
        return vv

    @model_validator(mode="after")
    def _post_validate(self) -> "Settings":
        self.base_dir = self.base_dir.expanduser().resolve()
        self.data_dir = (self.data_dir if self.data_dir.is_absolute() else (self.base_dir / self.data_dir)).resolve()
        self.log_dir = (self.log_dir if self.log_dir.is_absolute() else (self.base_dir / self.log_dir)).resolve()
        self.tmp_dir = (self.tmp_dir if self.tmp_dir.is_absolute() else (self.base_dir / self.tmp_dir)).resolve()

        _ensure_dir(self.data_dir)
        _ensure_dir(self.log_dir)
        _ensure_dir(self.tmp_dir)

        if self.strict_mode:
            if self.db_dialect == "sqlite" and not self.db_url.startswith("sqlite"):
                _report_settings_status(
                    "failed",
                    "db_dialect_url_mismatch",
                    {"db_dialect": self.db_dialect, "db_url_prefix": self.db_url.split(":")[0]},
                )
                raise ValueError("db_url must be sqlite://... when db_dialect=sqlite")

            if self.db_dialect == "postgres" and not (
                self.db_url.startswith("postgresql") or self.db_url.startswith("postgres")
            ):
                _report_settings_status(
                    "failed",
                    "db_dialect_url_mismatch",
                    {"db_dialect": self.db_dialect, "db_url_prefix": self.db_url.split(":")[0]},
                )
                raise ValueError("db_url must be postgresql://... when db_dialect=postgres")

        if self.gateway_host in ("0.0.0.0", "::", "*"):
            if self.env != "dev" and not self.allow_remote_access:
                _report_settings_status(
                    "failed",
                    "unsafe_gateway_bind_blocked",
                    {
                        "env": self.env,
                        "gateway_host": self.gateway_host,
                        "allow_remote_access": self.allow_remote_access,
                    },
                )
                raise RuntimeError(
                    "Refusing to bind gateway to all interfaces in non-dev without explicit opt-in. "
                    "Set SENTINEL_ALLOW_REMOTE_ACCESS=1."
                )

        if self.env == "prod":
            if self.db_echo_sql:
                _report_settings_status("failed", "db_echo_sql_enabled_in_prod", {})
                raise ValueError("db_echo_sql must be False in prod")

            if self.log_level == "DEBUG" and self.strict_mode:
                _report_settings_status("failed", "debug_log_level_in_prod_strict", {})
                raise ValueError("log_level DEBUG not allowed in prod with strict_mode=True")

        if self.jwt_enabled:
            _require_strong_secret(
                "SENTINEL_JWT_SECRET",
                self.jwt_secret,
                env=self.env,
                strict=self.strict_mode,
                min_length=32,
            )

        if self.audit_enabled and self.audit_sign_events:
            if not self.audit_signing_key:
                if self.env in {"dev", "test"}:
                    self.audit_signing_key = secrets.token_hex(32)
                    _report_settings_status(
                        "degraded",
                        "ephemeral_audit_signing_key_generated",
                        {"env": self.env},
                    )
                elif self.strict_mode:
                    _report_settings_status(
                        "failed",
                        "audit_signing_key_missing",
                        {"env": self.env},
                    )
                    raise RuntimeError("audit_signing_key required for audit_sign_events in staging/prod")

        _report_settings_status(
            "online",
            "settings_validated",
            {"summary": self.summary_safe()},
        )

        return self

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"

    def summary_safe(self) -> Dict[str, Any]:
        return {
            "env": self.env,
            "system_id": self.system_id,
            "service_name": self.service_name,
            "instance_id": self.instance_id,
            "paths": {
                "base_dir": str(self.base_dir),
                "data_dir": str(self.data_dir),
                "log_dir": str(self.log_dir),
                "tmp_dir": str(self.tmp_dir),
            },
            "db": {
                "dialect": self.db_dialect,
                "url": self.db_url,
                "pool_size": self.db_pool_size,
            },
            "gateway": {
                "enabled": self.gateway_enabled,
                "host": self.gateway_host,
                "port": self.gateway_port,
                "allow_remote_access": self.allow_remote_access,
            },
            "auth": {
                "enabled": self.auth_enabled,
                "jwt_enabled": self.jwt_enabled,
                "issuer": self.jwt_issuer,
                "audience": self.jwt_audience,
            },
            "policy": {
                "default_mode": self.default_mode,
                "strict_mode": self.strict_mode,
            },
            "audit": {
                "enabled": self.audit_enabled,
                "hash_chain": self.audit_hash_chain,
                "sign_events": self.audit_sign_events,
            },
            "logging": {
                "level": self.log_level,
                "json": self.log_json,
                "to_file": self.log_to_file,
            },
        }


def _require_strong_secret(
    name: str,
    value: str,
    *,
    env: str,
    strict: bool,
    min_length: int = 32,
) -> None:
    stripped = (value or "").strip()
    weak = {
        "dev-only-change-me",
        "change-me",
        "changeme",
        "password",
        "secret",
        "default",
        "test",
        "admin",
        "sentinel",
        "aegis",
    }

    is_weak = (not stripped) or (len(stripped) < min_length) or (stripped.lower() in weak)

    if is_weak:
        msg = (
            f"{name} is weak/missing (len={len(stripped)}, min={min_length}). "
            "Generate: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )

        _report_settings_status(
            "failed" if env != "dev" and strict else "degraded",
            "weak_or_missing_secret",
            {
                "secret_name": name,
                "env": env,
                "strict": strict,
                "min_length": min_length,
                "actual_length": len(stripped),
            },
        )

        if env != "dev" and strict:
            raise RuntimeError(msg)

        import logging as _logging
        _logging.warning("[SECURITY] %s", msg)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    _report_settings_status("online", "settings_load_started", {})

    sd = os.getenv("SENTINEL_SECRETS_DIR")
    if sd:
        load_secrets_into_env(Path(sd))

    try:
        s = Settings()

        if s.secrets_dir:
            load_secrets_into_env(Path(s.secrets_dir))

        _report_settings_event(
            "online",
            "settings_loaded",
            {"summary": s.summary_safe()},
        )

        return s

    except Exception as exc:
        _report_settings_status(
            "failed",
            "settings_load_failed",
            {
                "error": str(exc),
                "exception_type": type(exc).__name__,
            },
        )
        raise