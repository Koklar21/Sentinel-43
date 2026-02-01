"""
Sentinel-43 Configuration

Goals:
- Single source of truth for configuration
- Environment variable driven (12-factor friendly)
- Strong typing + validation
- Safe defaults (secure-by-default)
- Split "core runtime" vs "optional integrations"

Usage:
    from sentinel43.config import get_settings
    settings = get_settings()

Environment:
- Reads .env automatically if present (ENV_FILE)
- Supports secrets directory (e.g., Docker/K8s mounted secrets)

Notes:
- Keep secrets OUT of git. Use env vars or secrets dir.
"""

from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# -----------------------------
# Helpers
# -----------------------------

_TRUE = {"1", "true", "t", "yes", "y", "on"}
_FALSE = {"0", "false", "f", "no", "n", "off"}


def _as_bool(v: Any, default: bool = False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    s = str(v).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def _ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


def _is_https_url(url: str) -> bool:
    try:
        u = urlparse(url)
        return u.scheme == "https" and bool(u.netloc)
    except Exception:
        return False


def _mask_secret(s: Optional[str]) -> str:
    if not s:
        return ""
    if len(s) <= 8:
        return "*" * len(s)
    return s[:3] + "*" * (len(s) - 6) + s[-3:]


def _parse_csv(s: str) -> List[str]:
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]


# -----------------------------
# Settings
# -----------------------------

class Settings(BaseSettings):
    """
    Sentinel-43 settings.

    Naming convention:
    - Environment variables use prefix: S43_
    - Example: S43_ENV=prod
    """

    model_config = SettingsConfigDict(
        env_prefix="S43_",
        env_file=os.getenv("S43_ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # ignore unknown env vars (prevents surprises)
    )

    # ---------- Identity / Environment ----------
    env: str = Field(default="dev", description="Environment: dev|test|staging|prod")
    service_name: str = Field(default="sentinel-43", description="Service name for logs/metrics")
    instance_id: str = Field(default_factory=lambda: secrets.token_hex(8), description="Unique instance id")

    # ---------- Runtime ----------
    timezone: str = Field(default="UTC", description="Default timezone (IANA, ex: UTC)")
    data_dir: Path = Field(default=Path("./data"), description="Base data directory")
    log_dir: Path = Field(default=Path("./logs"), description="Log directory")
    tmp_dir: Path = Field(default=Path("./tmp"), description="Temp directory")
    debug: bool = Field(default=False, description="Debug mode (never enable in prod)")
    quiet_mode: bool = Field(default=True, description="No dashboard / minimal surface area")

    # ---------- API / Server ----------
    api_enabled: bool = Field(default=True, description="Enable API server")
    api_host: str = Field(default="0.0.0.0", description="Bind host")
    api_port: int = Field(default=8080, ge=1, le=65535, description="Bind port")
    api_root_path: str = Field(default="", description="Root path behind proxy (optional)")
    cors_allow_origins: List[str] = Field(default_factory=list, description="CORS allowlist")
    cors_allow_methods: List[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    cors_allow_headers: List[str] = Field(default_factory=lambda: ["*"])
    trusted_proxies: List[str] = Field(default_factory=list, description="Trusted proxy IPs/CIDRs")
    request_id_header: str = Field(default="X-Request-ID", description="Request ID header name")

    # ---------- Auth / Security ----------
    auth_enabled: bool = Field(default=True, description="Require auth on API")
    api_key_header: str = Field(default="X-API-Key", description="Header used for API keys")
    api_keys: List[str] = Field(default_factory=list, description="Allowed API keys (use secrets dir in prod)")
    jwt_enabled: bool = Field(default=False, description="Enable JWT auth (optional)")
    jwt_issuer: str = Field(default="sentinel-43", description="JWT issuer")
    jwt_audience: str = Field(default="sentinel-43", description="JWT audience")
    jwt_public_key_path: Optional[Path] = Field(default=None, description="Path to JWT public key for verify")
    hmac_signing_secret: Optional[str] = Field(default=None, description="HMAC secret for webhook/event signing")
    allowed_tenant_pattern: str = Field(default=r"^[a-zA-Z0-9_\-]{2,64}$", description="Tenant id regex")
    allow_anonymous_read: bool = Field(default=False, description="Allow unauthenticated read-only endpoints")
    max_request_bytes: int = Field(default=2_000_000, ge=1_024, description="Max request size in bytes")

    # ---------- Database ----------
    db_enabled: bool = Field(default=True, description="Enable persistent DB")
    db_dialect: str = Field(default="sqlite", description="sqlite|postgres")
    db_url: str = Field(default="sqlite:///./data/sentinel43.db", description="SQLAlchemy-style DB URL")
    db_pool_size: int = Field(default=10, ge=1, le=200, description="DB pool size")
    db_max_overflow: int = Field(default=20, ge=0, le=500, description="DB pool overflow")
    db_pool_timeout_sec: int = Field(default=30, ge=1, le=300, description="DB pool timeout seconds")
    db_echo_sql: bool = Field(default=False, description="Echo SQL (do not enable in prod)")
    migrations_enabled: bool = Field(default=True, description="Allow migrations on startup (optional)")

    # ---------- Cache / Queue ----------
    redis_enabled: bool = Field(default=False, description="Enable Redis")
    redis_url: str = Field(default="redis://localhost:6379/0", description="Redis URL")
    job_queue_enabled: bool = Field(default=False, description="Enable background jobs")
    job_queue_name: str = Field(default="sentinel43", description="Queue name")

    # ---------- Observability ----------
    logging_level: str = Field(default="INFO", description="DEBUG|INFO|WARNING|ERROR|CRITICAL")
    logging_json: bool = Field(default=True, description="JSON logs recommended for prod")
    log_to_file: bool = Field(default=True, description="Write logs to file")
    log_rotation_mb: int = Field(default=50, ge=1, le=1024, description="Rotate log file after N MB")
    log_retention_days: int = Field(default=14, ge=1, le=3650, description="Log retention days")

    metrics_enabled: bool = Field(default=True, description="Expose metrics")
    metrics_path: str = Field(default="/metrics", description="Metrics endpoint path")
    tracing_enabled: bool = Field(default=False, description="Enable tracing (OTel)")
    otel_exporter_otlp_endpoint: Optional[str] = Field(default=None, description="OTLP endpoint")
    otel_service_name: Optional[str] = Field(default=None, description="Override OTel service name")

    # ---------- Rate limiting / Abuse control ----------
    rate_limit_enabled: bool = Field(default=True, description="Enable rate limiting")
    rate_limit_per_minute: int = Field(default=120, ge=1, le=100000, description="Requests/minute per client")
    rate_limit_burst: int = Field(default=60, ge=0, le=100000, description="Extra burst capacity")

    # ---------- Audit / Data Vault ----------
    audit_enabled: bool = Field(default=True, description="Enable audit trail")
    audit_sign_events: bool = Field(default=True, description="Sign audit events (tamper evidence)")
    audit_signing_key: Optional[str] = Field(default=None, description="Key for signing audit events (HMAC)")
    audit_hash_chain: bool = Field(default=True, description="Hash-chain audit events (append-only style)")
    audit_flush_interval_sec: int = Field(default=5, ge=1, le=60, description="Audit flush interval")

    datavault_enabled: bool = Field(default=True, description="Enable Data Vault storage")
    datavault_backend: str = Field(default="filesystem", description="filesystem|s3 (optional)")
    datavault_path: Path = Field(default=Path("./data/vault"), description="Filesystem vault path")
    datavault_compress: bool = Field(default=True, description="Compress vault entries")
    datavault_encrypt: bool = Field(default=False, description="Encrypt vault entries (optional)")
    datavault_encryption_key: Optional[str] = Field(default=None, description="Encryption key (if enabled)")

    # ---------- Integrations / Webhooks ----------
    webhooks_enabled: bool = Field(default=False, description="Enable inbound webhooks")
    webhook_require_signature: bool = Field(default=True, description="Require signed webhooks")
    webhook_signature_header: str = Field(default="X-S43-Signature", description="Webhook signature header")
    outbound_notifications_enabled: bool = Field(default=False, description="Enable outbound notifications")

    slack_webhook_url: Optional[str] = Field(default=None, description="Slack incoming webhook URL")
    discord_webhook_url: Optional[str] = Field(default=None, description="Discord webhook URL")
    email_enabled: bool = Field(default=False, description="Enable SMTP email alerts")
    smtp_host: Optional[str] = Field(default=None)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_user: Optional[str] = Field(default=None)
    smtp_password: Optional[str] = Field(default=None)
    smtp_use_tls: bool = Field(default=True)
    alert_email_from: Optional[str] = Field(default=None)
    alert_email_to: List[str] = Field(default_factory=list)

    # ---------- Feature Flags ----------
    ff_auto_escalation: bool = Field(default=True, description="Allow automatic escalation actions")
    ff_auto_quarantine: bool = Field(default=False, description="Allow quarantine actions (dangerous)")
    ff_self_heal: bool = Field(default=False, description="Enable self-healing routines (careful)")
    ff_strict_mode: bool = Field(default=True, description="Fail closed on config/security issues")

    # ---------- Thresholds / Policy defaults ----------
    severity_low_threshold: int = Field(default=25, ge=0, le=100)
    severity_medium_threshold: int = Field(default=50, ge=0, le=100)
    severity_high_threshold: int = Field(default=75, ge=0, le=100)
    severity_critical_threshold: int = Field(default=90, ge=0, le=100)

    escalation_cooldown_sec: int = Field(default=60, ge=0, le=86400)
    incident_dedupe_window_sec: int = Field(default=300, ge=0, le=86400)
    max_open_incidents_per_tenant: int = Field(default=5000, ge=1, le=10_000_000)

    # ---------- Secrets handling ----------
    secrets_dir: Optional[Path] = Field(default=None, description="Directory containing secret files (optional)")

    # -----------------------------
    # Validators / Coercions
    # -----------------------------

    @field_validator("env")
    @classmethod
    def _validate_env(cls, v: str) -> str:
        vv = v.strip().lower()
        if vv not in {"dev", "test", "staging", "prod"}:
            raise ValueError("env must be one of: dev|test|staging|prod")
        return vv

    @field_validator("logging_level")
    @classmethod
    def _validate_logging_level(cls, v: str) -> str:
        vv = v.strip().upper()
        if vv not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("logging_level must be DEBUG|INFO|WARNING|ERROR|CRITICAL")
        return vv

    @field_validator("cors_allow_origins", mode="before")
    @classmethod
    def _coerce_cors(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return _parse_csv(v)
        return list(v)

    @field_validator("trusted_proxies", mode="before")
    @classmethod
    def _coerce_proxies(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return _parse_csv(v)
        return list(v)

    @field_validator("api_keys", mode="before")
    @classmethod
    def _coerce_api_keys(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [x for x in _parse_csv(v)]
        return list(v)

    @field_validator("alert_email_to", mode="before")
    @classmethod
    def _coerce_email_to(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return _parse_csv(v)
        return list(v)

    @field_validator("debug", "quiet_mode", "api_enabled", "auth_enabled",
                     "jwt_enabled", "allow_anonymous_read", "db_enabled",
                     "db_echo_sql", "redis_enabled", "job_queue_enabled",
                     "logging_json", "log_to_file", "metrics_enabled",
                     "tracing_enabled", "rate_limit_enabled", "audit_enabled",
                     "audit_sign_events", "audit_hash_chain", "datavault_enabled",
                     "datavault_compress", "datavault_encrypt", "webhooks_enabled",
                     "webhook_require_signature", "outbound_notifications_enabled",
                     "email_enabled", "smtp_use_tls", "ff_auto_escalation",
                     "ff_auto_quarantine", "ff_self_heal", "ff_strict_mode",
                     mode="before")
    @classmethod
    def _coerce_bools(cls, v: Any) -> Any:
        # Pydantic handles bools pretty well, but env vars can get weird.
        return _as_bool(v, default=False) if isinstance(v, str) else v

    @model_validator(mode="after")
    def _post_validate(self) -> "Settings":
        # Make directories
        _ensure_dir(self.data_dir)
        _ensure_dir(self.log_dir)
        _ensure_dir(self.tmp_dir)
        _ensure_dir(self.datavault_path)

        # Basic thresholds sanity
        thr = [
            self.severity_low_threshold,
            self.severity_medium_threshold,
            self.severity_high_threshold,
            self.severity_critical_threshold,
        ]
        if any(x < 0 or x > 100 for x in thr):
            raise ValueError("Severity thresholds must be 0..100")
        if not (thr[0] <= thr[1] <= thr[2] <= thr[3]):
            raise ValueError("Severity thresholds must be non-decreasing: low<=med<=high<=critical")

        # Prod safety rails
        if self.env == "prod":
            if self.debug:
                raise ValueError("debug must be False in prod")
            if self.db_echo_sql:
                raise ValueError("db_echo_sql must be False in prod")
            if self.jwt_enabled and not self.jwt_public_key_path:
                raise ValueError("jwt_public_key_path required when jwt_enabled=True")
            if self.logging_level == "DEBUG":
                # Not fatal, but questionable
                if self.ff_strict_mode:
                    raise ValueError("logging_level DEBUG not allowed in prod with ff_strict_mode=True")

        # DB dialect sanity
        dd = self.db_dialect.strip().lower()
        if dd not in {"sqlite", "postgres"}:
            raise ValueError("db_dialect must be sqlite|postgres")
        self.db_dialect = dd

        # If sqlite but db_url not sqlite, fix or fail
        if self.db_dialect == "sqlite" and not self.db_url.startswith("sqlite"):
            if self.ff_strict_mode:
                raise ValueError("db_url must be sqlite://... when db_dialect=sqlite")
        if self.db_dialect == "postgres" and not (self.db_url.startswith("postgresql") or self.db_url.startswith("postgres")):
            if self.ff_strict_mode:
                raise ValueError("db_url must be postgresql://... when db_dialect=postgres")

        # Auth checks
        if self.auth_enabled and not self.allow_anonymous_read:
            # Ensure there is at least one auth mechanism configured
            if not self.api_keys and not self.jwt_enabled:
                if self.ff_strict_mode:
                    raise ValueError("auth_enabled=True requires api_keys or jwt_enabled")

        # Audit signing defaults
        if self.audit_enabled and self.audit_sign_events and not self.audit_signing_key:
            # If no explicit key, fall back to hmac_signing_secret, else generate ephemeral in dev
            if self.hmac_signing_secret:
                self.audit_signing_key = self.hmac_signing_secret
            elif self.env in {"dev", "test"}:
                self.audit_signing_key = secrets.token_hex(32)
            else:
                if self.ff_strict_mode:
                    raise ValueError("audit_signing_key is required for audit_sign_events in staging/prod")

        # Webhook signature requires key
        if self.webhooks_enabled and self.webhook_require_signature and not self.hmac_signing_secret:
            if self.ff_strict_mode:
                raise ValueError("hmac_signing_secret required when webhook_require_signature=True")

        # Validate URLs if provided
        if self.slack_webhook_url and not _is_https_url(self.slack_webhook_url):
            raise ValueError("slack_webhook_url must be a valid https URL")
        if self.discord_webhook_url and not _is_https_url(self.discord_webhook_url):
            raise ValueError("discord_webhook_url must be a valid https URL")
        if self.tracing_enabled and self.otel_exporter_otlp_endpoint:
            if not (self.otel_exporter_otlp_endpoint.startswith("http://") or self.otel_exporter_otlp_endpoint.startswith("https://")):
                raise ValueError("otel_exporter_otlp_endpoint must be http(s)://...")

        # Email config
        if self.email_enabled:
            req = [self.smtp_host, self.smtp_user, self.smtp_password, self.alert_email_from]
            if any(x is None or str(x).strip() == "" for x in req) or not self.alert_email_to:
                if self.ff_strict_mode:
                    raise ValueError("email_enabled=True requires smtp_host, smtp_user, smtp_password, alert_email_from, and alert_email_to")

        return self

    # -----------------------------
    # Convenience / Derived
    # -----------------------------

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"

    @property
    def otel_name(self) -> str:
        return self.otel_service_name or self.service_name

    @property
    def effective_audit_key_masked(self) -> str:
        return _mask_secret(self.audit_signing_key)

    def tenant_id_is_valid(self, tenant_id: str) -> bool:
        return bool(re.match(self.allowed_tenant_pattern, tenant_id or ""))

    def summary_safe(self) -> Dict[str, Any]:
        """
        Safe-to-print summary (no secrets).
        """
        return {
            "env": self.env,
            "service_name": self.service_name,
            "instance_id": self.instance_id,
            "debug": self.debug,
            "quiet_mode": self.quiet_mode,
            "api": {"enabled": self.api_enabled, "host": self.api_host, "port": self.api_port},
            "auth": {
                "enabled": self.auth_enabled,
                "api_keys_count": len(self.api_keys),
                "jwt_enabled": self.jwt_enabled,
            },
            "db": {"enabled": self.db_enabled, "dialect": self.db_dialect, "url": self.db_url},
            "redis": {"enabled": self.redis_enabled},
            "audit": {
                "enabled": self.audit_enabled,
                "sign_events": self.audit_sign_events,
                "hash_chain": self.audit_hash_chain,
                "audit_key": self.effective_audit_key_masked,
            },
            "datavault": {
                "enabled": self.datavault_enabled,
                "backend": self.datavault_backend,
                "path": str(self.datavault_path),
                "encrypt": self.datavault_encrypt,
            },
            "rate_limit": {"enabled": self.rate_limit_enabled, "rpm": self.rate_limit_per_minute},
            "metrics": {"enabled": self.metrics_enabled, "path": self.metrics_path},
            "tracing": {"enabled": self.tracing_enabled},
            "feature_flags": {
                "auto_escalation": self.ff_auto_escalation,
                "auto_quarantine": self.ff_auto_quarantine,
                "self_heal": self.ff_self_heal,
                "strict_mode": self.ff_strict_mode,
            },
        }


# -----------------------------
# Secrets directory loader (optional)
# -----------------------------

def load_secrets_into_env(secrets_dir: Optional[Path]) -> None:
    """
    If secrets_dir is provided, load each file as an env var.
    File name = ENV VAR NAME (without prefix), content = value.
    Example file: API_KEYS -> "key1,key2"
    This will set S43_API_KEYS accordingly.
    """
    if not secrets_dir:
        return
    p = Path(secrets_dir)
    if not p.exists() or not p.is_dir():
        return

    for f in p.iterdir():
        if not f.is_file():
            continue
        key = f.name.strip()
        if not key:
            continue
        try:
            val = f.read_text(encoding="utf-8").strip()
        except Exception:
            continue
        if val == "":
            continue
        env_key = f"S43_{key}"
        # don't clobber existing explicit env vars
        os.environ.setdefault(env_key, val)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Cached settings singleton.
    """
    # Load secrets directory if provided via environment variable
    secrets_dir = os.getenv("S43_SECRETS_DIR")
    if secrets_dir:
        load_secrets_into_env(Path(secrets_dir))

    s = Settings()

    # If secrets_dir is set in parsed settings, load it too (second pass, non-clobber)
    if s.secrets_dir:
        load_secrets_into_env(s.secrets_dir)

    return s