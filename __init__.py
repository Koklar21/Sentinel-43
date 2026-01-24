"""
SENTINEL-43 Package Initialization

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Justin

Purpose:
- Single place to bootstrap config, paths, and logging
- Provide factory functions for:
  - Sentinel Nexus runtime (SentinelNode / SecurityNexus depending on your build)
  - Remote Access Gateway (FastAPI) app
- Avoid side effects on import (no demo runs, no network binds, no sleeps)
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence, Tuple

__all__ = [
    "__version__",
    "SentinelConfig",
    "resolve_base_dir",
    "load_config",
    "configure_logging",
    "create_nexus",
    "create_gateway_app",
]

__version__ = "0.1.1"

SYSTEM_ID_DEFAULT = "SENTINEL-43-NEXUS-01"
DB_FILENAME_DEFAULT = "sentinel_secure.db"
LOG_FILENAME_DEFAULT = "sentinel_system.log"

_ALLOWED_MODES = {"SHADOW", "HUMAN_GATED", "AUTONOMOUS_VETO"}  # validated strings


# ----------------------------
# Back-compat env read (optional)
# ----------------------------

def _env_get(*keys: str, default: Optional[str] = None) -> Optional[str]:
    """
    Read first found env var in keys list.
    Supports back-compat: SENTINEL_* preferred, AEGIS_* accepted.
    """
    for k in keys:
        v = os.getenv(k)
        if v is not None:
            return v
    return default


# ----------------------------
# Config
# ----------------------------

@dataclass(frozen=True)
class SentinelConfig:
    system_id: str
    base_dir: Path
    db_path: Path
    log_path: Path

    # Remote gateway settings
    gateway_host: str
    gateway_port: int

    # Auth settings (prototype)
    jwt_secret: str
    jwt_issuer: str
    jwt_audience: str

    # Operational defaults
    default_mode: str  # validated string


def resolve_base_dir() -> Path:
    """
    Path policy:
    - Default: base_dir is the directory containing this package.
    - Override with SENTINEL_BASE_DIR env var (AEGIS_BASE_DIR accepted for back-compat).
    """
    env = _env_get("SENTINEL_BASE_DIR", "AEGIS_BASE_DIR")
    if env:
        return Path(env).expanduser().resolve()

    try:
        return Path(__file__).resolve().parent
    except NameError:
        return Path.cwd().resolve()


def _is_safe_path(path: Path, allowed_bases: Optional[Sequence[Path]] = None) -> bool:
    """
    Guardrail for env-controlled paths.
    - Reject paths under system-critical directories.
    - If allowed_bases is provided, require the path to be under one of them.
    """
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
    """
    Stronger secret validation:
    - Fail-closed: default env is 'prod'
    - Always validate; dev only warns, non-dev raises
    - Strips whitespace to block bypass via trailing spaces
    - Enforces minimum length and blocks known weak/default values
    """
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
            f"{name} is weak or missing (length={len(stripped)}, min={min_length}). "
            "Generate a strong secret: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
        if env != "dev":
            raise RuntimeError(msg)
        logging.warning(f"[SECURITY] {msg}")


def load_config() -> SentinelConfig:
    base_dir = resolve_base_dir()

    # Allowed bases for db/log overrides
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

    # Safer default: localhost
    env = (_env_get("SENTINEL_ENV", "AEGIS_ENV", default="prod") or "prod").lower()
    gateway_host = _env_get("SENTINEL_GATEWAY_HOST", "AEGIS_GATEWAY_HOST", default="127.0.0.1") or "127.0.0.1"
    gateway_port = int(_env_get("SENTINEL_GATEWAY_PORT", "AEGIS_GATEWAY_PORT", default="8080") or "8080")

    # Non-dev: require explicit opt-in to bind to all interfaces
    if gateway_host in ("0.0.0.0", "::", "*"):
        if env != "dev":
            if not (_env_get("SENTINEL_ALLOW_REMOTE_ACCESS", default="") or "").strip():
                raise RuntimeError(
                    "Remote gateway bind to all interfaces requires explicit opt-in. "
                    "Set SENTINEL_ALLOW_REMOTE_ACCESS=1 (and put it behind TLS + firewall)."
                )
            logging.critical(
                f"[SECURITY] Gateway binding to {gateway_host}:{gateway_port} (all interfaces). "
                "Ensure TLS and firewall rules are configured."
            )
        else:
            logging.warning(
                f"[SECURITY] Dev gateway binding to {gateway_host}:{gateway_port} (all interfaces). "
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


# ----------------------------
# Logging Bootstrap (thread-safe)
# ----------------------------

_LOGGING_LOCK = threading.Lock()
_LOGGING_CONFIGURED = False


def configure_logging(config: Optional[SentinelConfig] = None) -> None:
    """
    Thread-safe, idempotent logging setup. Safe to call multiple times.
    Writes to both file + console when possible.
    """
    global _LOGGING_CONFIGURED
    if _LOGGING_CONFIGURED:
        return

    with _LOGGING_LOCK:
        if _LOGGING_CONFIGURED:
            return

        cfg = config or load_config()

        handlers = [logging.StreamHandler()]

        # Try file logging; if it fails, console-only is fine.
        try:
            cfg.log_path.parent.mkdir(parents=True, exist_ok=True)
            handlers.insert(0, logging.FileHandler(cfg.log_path, encoding="utf-8"))
        except Exception as e:
            import sys
            print(f"Warning: Could not configure file logging: {e}", file=sys.stderr)

        level = (_env_get("SENTINEL_LOG_LEVEL", "AEGIS_LOG_LEVEL", default="INFO") or "INFO").upper()

        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)-8s | %(module)-18s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            handlers=handlers,
        )

        # Keep server logs readable if you use uvicorn
        logging.getLogger("uvicorn").setLevel(logging.INFO)
        logging.getLogger("uvicorn.error").setLevel(logging.INFO)
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

        _LOGGING_CONFIGURED = True
        logging.info(f"[BOOT] Logging configured. system_id={cfg.system_id} log={cfg.log_path}")


# ----------------------------
# Factories
# ----------------------------

def _try_import_candidates(
    base_pkg: str,
    candidates: Sequence[Tuple[str, str]],
) -> object:
    """
    candidates: [(module_suffix, symbol_name), ...]
    Returns the first matching symbol imported successfully.
    """
    import_errors = []
    for mod_suffix, symbol in candidates:
        try:
            module = __import__(base_pkg + mod_suffix, fromlist=[symbol])
            return getattr(module, symbol)
        except Exception as exc:
            import_errors.append(f"{mod_suffix}.{symbol}: {exc}")

    raise ImportError("Could not import runtime object. Tried:\n- " + "\n- ".join(import_errors))


def create_nexus(config: Optional[SentinelConfig] = None):
    """
    Returns your Sentinel runtime object.

    Preference order:
    1) SentinelNode (SOC orchestrator)
    2) SecurityNexus (older nexus controller)
    3) SecurityNode (legacy name)
    """
    cfg = config or load_config()
    configure_logging(cfg)

    RuntimeClass = _try_import_candidates(
        __name__,
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

    # Prefer passing paths explicitly if your constructor supports it.
    try:
        node = RuntimeClass(audit_db_path=cfg.db_path)
    except Exception:
        node = RuntimeClass()

    logging.info(f"[BOOT] Nexus created. system_id={cfg.system_id} db={cfg.db_path} mode={cfg.default_mode}")
    return node


def create_gateway_app(config: Optional[SentinelConfig] = None):
    """
    Returns the FastAPI app for remote access.
    Supports either:
    - module-level `app`
    - factory `create_app(config)`
    """
    cfg = config or load_config()
    configure_logging(cfg)

    # Minimal env bridging for NON-SECRETS only.
    # Secrets must travel via config objects or secret managers, not env mutation here.
    os.environ.setdefault("SENTINEL_DB_PATH", str(cfg.db_path))
    os.environ.setdefault("SENTINEL_SYSTEM_ID", cfg.system_id)
    os.environ.setdefault("SENTINEL_JWT_ISSUER", cfg.jwt_issuer)
    os.environ.setdefault("SENTINEL_JWT_AUDIENCE", cfg.jwt_audience)

    # Back-compat mapping for NON-SECRETS only
    os.environ.setdefault("AEGIS_DB_PATH", os.environ["SENTINEL_DB_PATH"])
    os.environ.setdefault("AEGIS_SYSTEM_ID", os.environ["SENTINEL_SYSTEM_ID"])
    os.environ.setdefault("AEGIS_JWT_ISSUER", os.environ["SENTINEL_JWT_ISSUER"])
    os.environ.setdefault("AEGIS_JWT_AUDIENCE", os.environ["SENTINEL_JWT_AUDIENCE"])

    # DO NOT set SENTINEL_JWT_SECRET / AEGIS_JWT_SECRET here.

    # Prefer factory that accepts config (with secret) explicitly.
    try:
        from .sentinel_remote_gateway import create_app  # type: ignore
        logging.info("[BOOT] Remote Gateway app created (factory).")
        return create_app(cfg)
    except Exception:
        from .sentinel_remote_gateway import app  # type: ignore
        logging.info("[BOOT] Remote Gateway app loaded (module-level app).")
        return app