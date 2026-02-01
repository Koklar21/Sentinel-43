"""
Sentinel-43 Settings (modern config)

- Environment variable driven (prefix: SENTINEL_)
- Strict typing + validation (pydantic)
- Safe defaults (localhost bind, no surprise remote exposure)
- Optional secrets directory support (Docker/K8s)
- Optional back-compat read for AEGIS_* env vars (non-invasive)

Install:
    pip install pydantic pydantic-settings
"""

from __future__ import annotations

import os
import re
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_ALLOWED_MODES = {"SHADOW", "HUMAN_GATED", "AUTONOMOUS_VETO"}
_TRUE = {"1", "true", "t", "yes", "y", "on"}
_FALSE = {"0", "false", "f", "no", "n", "off"}


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
    """Back-compat helper: read first set env var among keys."""
    for k in keys:
        val = os.getenv(k)
        if val is not None:
            return val
    return default


def load_secrets_into_env(secrets_dir: Optional[Path], *, prefix: str = "SENTINEL_") -> None:
    """
    Load secrets from a directory into env vars.

    Each file name is treated as ENV VAR NAME WITHOUT PREFIX.
    Example:
        /run/secrets/JWT_SECRET -> sets SENTINEL_JWT_SECRET

    Does NOT overwrite existing env vars (explicit env wins).
    """
    if not secrets_dir:
        return
    p = Path(secrets_dir)
    if not p.exists() or not p.is_dir():
        return

    for f in p.iterdir():
        if not f.is_file():
            continue
        name = f.name.strip()
        if not name:
            continue
        try:
            value = f.read_text(encoding="utf-8").strip()
        except Exception:
            continue
        if not value:
            continue
        os.environ.setdefault(prefix + name, value)


class Settings(BaseSettings):
    """
    Main config object.

    Env vars:
      SENTINEL_ENV=dev|test|staging|prod
      SENTINEL_DB_URL=sqlite:///...
      SENTINEL_GATEWAY_HOST=127.0.0.1
      SENTINEL_GATEWAY_PORT=8080
      SENTINEL_DEFAULT_MODE=SHADOW|HUMAN_GATED|AUTONOMOUS_VETO
      SENTINEL_ALLOW_REMOTE_ACCESS=1 (required for 0.0.0.0 in non-dev)
      SENTINEL_SECRETS_DIR=/run/secrets (optional)
    """

    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=os.getenv("SENTINEL_ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------
    # Identity / environment
    # -------------------------
    env: str = Field(default="dev", description="dev|test|staging|prod")
    system_id: str = Field(default="SENTINEL-43-NEXUS-01", description="System identifier")
    service_name: str = Field(default="sentinel-43", description="Service name for logs/metrics")
    instance_id: str = Field(default_factory=lambda: secrets.token_hex(8), description="Unique instance id")

    # -------------------------
    # Paths
    # -------------------------
    base_dir: Path = Field(default=Path("."), description="Base directory for local runs")
    data_dir: Path = Field(default=Path("./data"), description="Data directory")
    log_dir: Path = Field(default=Path("./logs"), description="Log directory")
    tmp_dir: Path = Field(default=Path("./tmp"), description="Temp directory")
    secrets_dir: Optional[Path] = Field(default=None, description="Secret files directory (optional)")

    # -------------------------
    # Database
    # -------------------------
    db_dialect: str = Field(default="sqlite", description="sqlite|postgres")
    db_url: str = Field(default="sqlite:///./data/sentinel43.db", description="SQLAlchemy DB URL")
    db_pool_size: int = Field(default=10, ge=1, le=200)
    db_max_overflow: int = Field(default=20, ge=0, le=500)
    db_pool_timeout_sec: int = Field(default=30, ge=1, le=300)
    db_echo_sql: bool = Field(default=False, description="Do not enable in prod")

    # -------------------------
    # Gateway / API
    # -------------------------
    gateway_enabled: bool = Field(default=True, description="Enable gateway API")
    gateway_host: str = Field(default="127.0.0.1", description="Bind host (safe default)")
    gateway_port: int = Field(default=8080, ge=1, le=65535)
    allow_remote_access: bool = Field(default=False, description="Opt-in to bind 0.0.0.0 in non-dev")
    cors_allow_origins: List[str] = Field(default_factory=list)

    # -------------------------
    # Auth / tokens (prototype)
    # -------------------------
    auth_enabled: bool = Field(default=True)
    jwt_enabled: bool = Field(default=False)
    jwt_secret: str = Field(default="", description="JWT HMAC secret")
    jwt_issuer: str = Field(default="sentinel", description="JWT issuer")
    jwt_audience: str = Field(default="sentinel-remote", description="JWT audience")

    # -------------------------
    # Operation modes / policy
    # -------------------------
    default_mode: str = Field(default="SHADOW", description="SHADOW|HUMAN_GATED|AUTONOMOUS_VETO")
    strict_mode: bool = Field(default=True, description="Fail closed on unsafe config")

    # -------------------------
    # Audit / Vault (hooks)
    # -------------------------
    audit_enabled: bool = Field(default=True)
    audit_hash_chain: bool = Field(default=True)
    audit_sign_events: bool = Field(default=True)
    audit_signing_key: str = Field(default="", description="HMAC signing key for audit events")

    # -------------------------
    # Logging
    # -------------------------
    log_level: str = Field(default="INFO", description="DEBUG|INFO|WARNING|ERROR|CRITICAL")
    log_json: bool = Field(default=True)
    log_to_file: bool = Field(default=True)

    # -------------------------
    # Back-compat: optional AEGIS_* read-in
    # (We only apply if SENTINEL_* not set)
    # -------------------------
    @model_validator(mode="before")
    @classmethod
    def _apply_backcompat_env(cls, data: Any) -> Any:
        # This runs before parsing. We can map AEGIS_* -> SENTINEL_* if needed.
        # Do it conservatively: only fill missing keys.
        # Note: 'data' can be dict-like or None.
        d = dict(data or {})

        def fill(key: str, *legacy_keys: str) -> None:
            if key in d and d[key] not in (None, ""):
                return
            v = _env_get(*legacy_keys)
            if v is not None:
                d[key] = v

        fill("env", "AEGIS_ENV")
        fill("system_id", "AEGIS_SYSTEM_ID")
        fill("db_url", "AEGIS_DB_URL", "AEGIS_DB_PATH")  # accept either
        fill("gateway_host", "AEGIS_GATEWAY_HOST")
        fill("gateway_port", "AEGIS_GATEWAY_PORT")
        fill("jwt_secret", "AEGIS_JWT_SECRET")
        fill("jwt_issuer", "AEGIS_JWT_ISSUER")
        fill("jwt_audience", "AEGIS_JWT_AUDIENCE")
        fill("default_mode", "AEGIS_DEFAULT_MODE")
        fill("log_level", "AEGIS_LOG_LEVEL")

        return d

    # -------------------------
    # Coercions
    # -------------------------
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
            raise ValueError("env must be one of: dev|test|staging|prod")
        return vv

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        vv = (v or "").strip().upper()
        if vv not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("log_level must be DEBUG|INFO|WARNING|ERROR|CRITICAL")
        return vv

    @field_validator("db_dialect")
    @classmethod
    def _validate_db_dialect(cls, v: str) -> str:
        vv = (v or "").strip().lower()
        if vv not in {"sqlite", "postgres"}:
            raise ValueError("db_dialect must be sqlite|postgres")
        return vv

    @field_validator("default_mode")
    @classmethod
    def _validate_mode(cls, v: str) -> str:
        vv = (v or "").strip().upper()
        if vv not in _ALLOWED_MODES:
            raise ValueError(f"default_mode must be one of: {sorted(_ALLOWED_MODES)}")
        return vv

    # -------------------------
    # Post-validation rules
    # -------------------------
    @model_validator(mode="after")
    def _post_validate(self) -> "Settings":
        # normalize dirs
        self.base_dir = self.base_dir.expanduser().resolve()
        self.data_dir = (self.data_dir if self.data_dir.is_absolute() else (self.base_dir / self.data_dir)).resolve()
        self.log_dir = (self.log_dir if self.log_dir.is_absolute() else (self.base_dir / self.log_dir)).resolve()
        self.tmp_dir = (self.tmp_dir if self.tmp_dir.is_absolute() else (self.base_dir / self.tmp_dir)).resolve()

        _ensure_dir(self.data_dir)
        _ensure_dir(self.log_dir)
        _ensure_dir(self.tmp_dir)

        # ensure db_url matches dialect if strict
        if self.strict_mode:
            if self.db_dialect == "sqlite" and not self.db_url.startswith("sqlite"):
                raise ValueError("db_url must be sqlite://... when db_dialect=sqlite")
            if self.db_dialect == "postgres" and not (self.db_url.startswith("postgresql") or self.db_url.startswith("postgres")):
                raise ValueError("db_url must be postgresql://... when db_dialect=postgres")

        # Gateway bind safety
        if self.gateway_host in ("0.0.0.0", "::", "*"):
            if self.env != "dev" and not self.allow_remote_access:
                raise RuntimeError(
                    "Refusing to bind gateway to all interfaces in non-dev without explicit opt-in. "
                    "Set SENTINEL_ALLOW_REMOTE_ACCESS=1 (and put behind TLS + firewall)."
                )

        # Security rails in prod
        if self.env == "prod":
            if self.db_echo_sql:
                raise ValueError("db_echo_sql must be False in prod (leaks sensitive data)")
            if self.log_level == "DEBUG" and self.strict_mode:
                raise ValueError("log_level DEBUG not allowed in prod with strict_mode=True")

        # JWT: if enabled, secret must be strong
        if self.jwt_enabled:
            _require_strong_secret(
                "SENTINEL_JWT_SECRET",
                self.jwt_secret,
                env=self.env,
                strict=self.strict_mode,
                min_length=32,
            )

        # Audit signing: if enabled, signing key must exist
        if self.audit_enabled and self.audit_sign_events:
            if not self.audit_signing_key:
                if self.env in {"dev", "test"}:
                    self.audit_signing_key = secrets.token_hex(32)  # ephemeral dev ok
                else:
                    if self.strict_mode:
                        raise RuntimeError("audit_signing_key required for audit_sign_events in staging/prod")

        return self

    # -------------------------
    # Convenience
    # -------------------------
    @property
    def is_prod(self) -> bool:
        return self.env == "prod"

    def summary_safe(self) -> Dict[str, Any]:
        """Safe-to-print summary (no secrets)."""
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
        "dev-only-change-me", "change-me", "changeme", "password", "secret", "default",
        "test", "admin", "sentinel", "aegis"
    }
    is_weak = (not stripped) or (len(stripped) < min_length) or (stripped.lower() in weak)

    if is_weak:
        msg = (
            f"{name} is weak/missing (len={len(stripped)}, min={min_length}). "
            "Generate: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
        if env != "dev" and strict:
            raise RuntimeError(msg)
        # dev or non-strict: warn only
        import logging as _logging
        _logging.warning(f"[SECURITY] {msg}")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Cached singleton settings.
    Loads secrets directory (if provided) before parsing env.
    """
    # Load secrets dir from env first (so settings can see it)
    sd = os.getenv("SENTINEL_SECRETS_DIR")
    if sd:
        load_secrets_into_env(Path(sd))

    s = Settings()

    # If settings includes secrets_dir, load it too (non-clobber)
    if s.secrets_dir:
        load_secrets_into_env(Path(s.secrets_dir))

    return s