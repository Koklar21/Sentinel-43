"""
SENTINEL-43 Package Initialization

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Justin

Purpose:
- Safe, side-effect-free package bootstrap helpers
- Config + logging bootstrap
- Factories for runtime nexus + gateway app
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence, Tuple, Any

__all__ = [
    "__version__",
    "SentinelConfig",
    "resolve_base_dir",
    "load_config",
    "configure_logging",
    "create_nexus",
    "create_gateway_app",
]

__version__ = "0.1.2"

SYSTEM_ID_DEFAULT = "SENTINEL-43-NEXUS-01"
DB_FILENAME_DEFAULT = "sentinel_secure.db"
LOG_FILENAME_DEFAULT = "sentinel_system.log"

_ALLOWED_MODES = {"SHADOW", "HUMAN_GATED", "AUTONOMOUS_VETO"}


# ----------------------------
# Back-compat env read
# ----------------------------

def _env_get(*keys: str, default: Optional[str] = None) -> Optional[str]:
    for k in keys:
        v = os.getenv(k)
        if v is not None:
            return v
    return default


# ----------------------------
# Legacy Config (fallback only)
# ----------------------------

@dataclass(frozen=True)
class SentinelConfig:
    system_id: str
    base_dir: Path
    db_path: Path
    log_path: Path

    gateway_host: str
    gateway_port: int

    jwt_secret: str
    jwt_issuer: str
    jwt_audience: str

    default_mode: str


def resolve_base_dir() -> Path:
    env = _env_get("SENTINEL_BASE_DIR", "AEGIS_BASE_DIR")
    if env:
        return Path(env).expanduser().resolve()

    # default to package directory
    try:
        return Path(__file__).resolve().parent
    except Exception:
        return Path.cwd().resolve()


def _is_safe_path(path: Path, allowed_bases: Optional[Sequence[Path]] = None) -> bool:
    try:
        resolved = path.expanduser().resolve()

        forbidden = [
            Path("/etc"),
            Path("/sys"),
            Path("/proc"),
            Path("/dev"),
            Path("/boot"),
            Path("/root"),
        ]
        for base in forbidden:
            try:
                resolved.relative_to(base)
                return False
            except ValueError:
                pass

        if allowed_bases:
            for base in allowed_bases:
                try:
                    resolved.relative_to(base.expanduser().resolve())
                    return True
                except ValueError:
                    pass
            return False

        return True
    except Exception:
        return False


def _resolve_path(
    env_key: str,
    default_path: Path,
    *,
    legacy_env_key: Optional[str] = None,
    allowed_bases: Optional[Sequence[Path]] = None,
) -> Path:
    raw = _env_get(env_key, legacy_env_key) if legacy_env_key else os.getenv(env_key)
    if raw:
        candidate = Path(raw).expanduser().resolve()
        if not _is_safe_path(candidate, allowed_bases):
            raise ValueError(f"Unsafe path in {env_key}: {raw}")
        return candidate
    return default_path.expanduser().resolve()


def _require_secret(name: str, value: str, *, min_length: int = 32) -> None:
    env = (_env_get("SENTINEL_ENV", "AEGIS_ENV", default="prod") or "prod").lower()
    stripped = value.strip() if value else ""

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
        if env != "dev":
            raise RuntimeError(msg)
        logging.warning(f"[SECURITY] {msg}")


def _load_config_legacy() -> SentinelConfig:
    base_dir = resolve_base_dir()

    allowed_bases = [
        base_dir,
        Path.cwd().resolve(),
        (Path.home() / ".sentinel").expanduser().resolve(),
        Path("/var/lib/sentinel"),
    ]

    system_id = _env_get("SENTINEL_SYSTEM_ID", "AEGIS_SYSTEM_ID", default=SYSTEM_ID_DEFAULT) or SYSTEM_ID_DEFAULT

    db_path = _resolve_path(
        "SENTINEL_DB_PATH",
        base_dir / DB_FILENAME_DEFAULT,
        legacy_env_key="AEGIS_DB_PATH",
        allowed_bases=allowed_bases,
    )
    log_path = _resolve_path(
        "SENTINEL_LOG_PATH",
        base_dir / LOG_FILENAME_DEFAULT,
        legacy_env_key="AEGIS_LOG_PATH",
        allowed_bases=allowed_bases,
    )

    env = (_env_get("SENTINEL_ENV", "AEGIS_ENV", default="prod") or "prod").lower()
    gateway_host = _env_get("SENTINEL_GATEWAY_HOST", "AEGIS_GATEWAY_HOST", default="127.0.0.1") or "127.0.0.1"
    gateway_port = int(_env_get("SENTINEL_GATEWAY_PORT", "AEGIS_GATEWAY_PORT", default="8080") or "8080")

    if gateway_host in ("0.0.0.0", "::", "*"):
        if env != "dev":
            if not (_env_get("SENTINEL_ALLOW_REMOTE_ACCESS", default="") or "").strip():
                raise RuntimeError(
                    "Remote bind requires explicit opt-in: set SENTINEL_ALLOW_REMOTE_ACCESS=1 "
                    "(and put it behind TLS + firewall)."
                )
            logging.critical(
                f"[SECURITY] Gateway binding to all interfaces: {gateway_host}:{gateway_port}. "
                "Ensure TLS + firewall."
            )
        else:
            logging.warning(
                f"[SECURITY] Dev binding to all interfaces: {gateway_host}:{gateway_port}. "
                "Do not do this on a real network."
            )

    jwt_secret = _env_get("SENTINEL_JWT_SECRET", "AEGIS_JWT_SECRET", default="") or ""
    jwt_issuer = _env_get("SENTINEL_JWT_ISSUER", "AEGIS_JWT_ISSUER", default="sentinel") or "sentinel"
    jwt_audience = _env_get("SENTINEL_JWT_AUDIENCE", "AEGIS_JWT_AUDIENCE", default="sentinel-remote") or "sentinel-remote"

    default_mode = (_env_get("SENTINEL_DEFAULT_MODE", "AEGIS_DEFAULT_MODE", default="SHADOW") or "SHADOW").upper()
    if default_mode not in _ALLOWED_MODES:
        raise ValueError(f"SENTINEL_DEFAULT_MODE invalid: {default_mode}. Allowed: {sorted(_ALLOWED_MODES)}")

    _require_secret("SENTINEL_JWT_SECRET", jwt_secret, min_length=32)

    return SentinelConfig(
        system_id=system_id,
        base_dir=base_dir,
        db_path=db_path,
        log_path=log_path,
        gateway_host=gateway_host,
        gateway_port=gateway_port,
        jwt_secret=jwt_secret,
        jwt_issuer=jwt_issuer,
        jwt_audience=jwt_audience,
        default_mode=default_mode,
    )


def load_config() -> Any:
    """
    Prefer new settings system (core.config.get_settings).
    Fall back to legacy env-based SentinelConfig for back-compat.
    """
    # Try the new settings (pydantic) first
    try:
        from .core.config import get_settings  # type: ignore
        return get_settings()
    except Exception:
        return _load_config_legacy()


# ----------------------------
# Logging Bootstrap (thread-safe)
# ----------------------------

_LOGGING_LOCK = threading.Lock()
_LOGGING_CONFIGURED = False


def configure_logging(config: Optional[Any] = None) -> None:
    """
    Idempotent logging setup. Safe to call multiple times.
    If new settings exists, honors it. Otherwise uses legacy paths.
    """
    global _LOGGING_CONFIGURED
    if _LOGGING_CONFIGURED:
        return

    with _LOGGING_LOCK:
        if _LOGGING_CONFIGURED:
            return

        cfg = config or load_config()

        handlers = [logging.StreamHandler()]

        # Determine log path if available
        log_path: Optional[Path] = None
        try:
            # new Settings has log_dir; legacy has log_path
            if hasattr(cfg, "log_dir"):
                log_path = Path(getattr(cfg, "log_dir")) / "sentinel43.log"
            elif hasattr(cfg, "log_path"):
                log_path = Path(getattr(cfg, "log_path"))
        except Exception:
            log_path = None

        if log_path:
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                handlers.insert(0, logging.FileHandler(log_path, encoding="utf-8"))
            except Exception as e:
                import sys
                print(f"Warning: file logging unavailable: {e}", file=sys.stderr)

        level = (_env_get("SENTINEL_LOG_LEVEL", "AEGIS_LOG_LEVEL", default="INFO") or "INFO").upper()

        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)-8s | %(name)-18s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            handlers=handlers,
        )

        # Keep uvicorn logs reasonable if used
        logging.getLogger("uvicorn").setLevel(logging.INFO)
        logging.getLogger("uvicorn.error").setLevel(logging.INFO)
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

        _LOGGING_CONFIGURED = True
        logging.getLogger(__name__).info("[BOOT] Logging configured.")


# ----------------------------
# Import helpers + Factories
# ----------------------------

def _try_import_candidates(
    base_pkg: str,
    candidates: Sequence[Tuple[str, str]],
) -> object:
    """
    candidates: [(module_path, symbol_name), ...]
    module_path is absolute-from-base, e.g. ".sentinel_node"
    """
    import_errors = []
    for module_path, symbol in candidates:
        try:
            module = __import__(base_pkg + module_path, fromlist=[symbol])
            return getattr(module, symbol)
        except Exception as exc:
            import_errors.append(f"{module_path}.{symbol}: {exc}")

    raise ImportError("Could not import runtime object. Tried:\n- " + "\n- ".join(import_errors))


def create_nexus(config: Optional[Any] = None):
    """
    Creates your Sentinel runtime object.
    Tries multiple known names for back-compat.
    """
    cfg = config or load_config()
    configure_logging(cfg)

    base_pkg = __package__ or __name__  # safer than __name__ alone

    RuntimeClass = _try_import_candidates(
        base_pkg,
        candidates=(
            (".sentinel43_orchestrator", "SentinelNode"),
            (".sentinel43_nexus", "SecurityNexus"),
            (".sentinel_nexus_node", "SecurityNexus"),
            (".sentinel_node", "SentinelNode"),
            (".sentinel_nexus", "SecurityNexus"),
            (".sentinel43", "SentinelNode"),
            (".sentinel43", "SecurityNexus"),
            (".aegis_remote_legacy", "SecurityNode"),
        ),
    )

    # Prefer explicit db path if supported
    db_path = None
    if hasattr(cfg, "db_path"):
        db_path = getattr(cfg, "db_path")
    elif hasattr(cfg, "db_url"):
        db_path = getattr(cfg, "db_url")

    try:
        node = RuntimeClass(audit_db_path=db_path) if db_path else RuntimeClass()
    except Exception:
        node = RuntimeClass()

    logging.getLogger(__name__).info("[BOOT] Nexus created.")
    return node


def create_gateway_app(config: Optional[Any] = None):
    """
    Returns the FastAPI app for remote access.
    Supports either:
    - factory: create_app(config)
    - module-level: app
    """
    cfg = config or load_config()
    configure_logging(cfg)

    # NON-SECRETS env bridging only
    def _set(k: str, v: str) -> None:
        if v:
            os.environ.setdefault(k, v)

    # Legacy config fields
    if hasattr(cfg, "system_id"):
        _set("SENTINEL_SYSTEM_ID", str(getattr(cfg, "system_id")))
        _set("AEGIS_SYSTEM_ID", str(getattr(cfg, "system_id")))

    if hasattr(cfg, "db_path"):
        _set("SENTINEL_DB_PATH", str(getattr(cfg, "db_path")))
        _set("AEGIS_DB_PATH", str(getattr(cfg, "db_path")))

    # New settings fields
    if hasattr(cfg, "db_url"):
        _set("SENTINEL_DB_URL", str(getattr(cfg, "db_url")))

    base_pkg = __package__ or __name__

    try:
        from .sentinel_remote_gateway import create_app  # type: ignore
        logging.getLogger(__name__).info("[BOOT] Remote Gateway app created (factory).")
        return create_app(cfg)
    except Exception:
        from .sentinel_remote_gateway import app  # type: ignore
        logging.getLogger(__name__).info("[BOOT] Remote Gateway app loaded (module-level app).")
        return app