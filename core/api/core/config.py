# =============================================================================
# Sentinel-43 Security Platform
# Core Configuration Module
# =============================================================================

from __future__ import annotations

import os
import socket
import platform
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


# =============================================================================
# Root Resolution
# =============================================================================

def _resolve_project_root() -> Path:
    """
    Resolves the Sentinel-43 project root dynamically.
    """
    current = Path(__file__).resolve()

    # Expected structure: sentinel_43/api/core/config.py
    # We want sentinel_43/
    for parent in current.parents:
        if parent.name == "sentinel_43":
            return parent

    # fallback
    return current.parent.parent.parent


PROJECT_ROOT: Path = _resolve_project_root()
API_ROOT: Path = PROJECT_ROOT / "api"
DATA_ROOT: Path = PROJECT_ROOT / "data"
LOG_ROOT: Path = PROJECT_ROOT / "logs"

LOG_ROOT.mkdir(parents=True, exist_ok=True)
DATA_ROOT.mkdir(parents=True, exist_ok=True)


# =============================================================================
# Environment Detection
# =============================================================================

def _get_env(name: str, default: Optional[str] = None) -> str:
    return os.getenv(name, default) if default is not None else os.environ[name]


def _get_env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.lower() in ("1", "true", "yes", "on")


# =============================================================================
# Node Identity
# =============================================================================

def _generate_node_name() -> str:
    hostname = socket.gethostname()
    system = platform.system().lower()
    return f"sentinel-{system}-{hostname}"


# =============================================================================
# Core Settings Dataclass
# =============================================================================

@dataclass(slots=True)
class Settings:

    # --------------------------------------------------
    # API Identity
    # --------------------------------------------------

    API_NAME: str = "Sentinel-43 API"
    API_VERSION: str = "0.1.0"
    API_PREFIX: str = "/api"

    NODE_NAME: str = field(default_factory=_generate_node_name)

    # --------------------------------------------------
    # Runtime Mode
    # --------------------------------------------------

    ENVIRONMENT: str = os.getenv("SENTINEL_ENV", "development")

    DEBUG: bool = _get_env_bool("SENTINEL_DEBUG", True)

    # --------------------------------------------------
    # Logging
    # --------------------------------------------------

    LOG_LEVEL: str = os.getenv("SENTINEL_LOG_LEVEL", "INFO")

    LOG_FILE: Path = LOG_ROOT / "sentinel_api.log"

    # --------------------------------------------------
    # Database
    # --------------------------------------------------

    DATABASE_PATH: Path = DATA_ROOT / "sentinel.db"

    # --------------------------------------------------
    # Security
    # --------------------------------------------------

    KEY_ROTATION_SECONDS: int = int(
        os.getenv("SENTINEL_KEY_ROTATION", "86400")
    )

    TOKEN_EXPIRY_SECONDS: int = int(
        os.getenv("SENTINEL_TOKEN_EXPIRY", "3600")
    )

    # --------------------------------------------------
    # Platform Info
    # --------------------------------------------------

    PLATFORM: str = platform.system()
    PLATFORM_RELEASE: str = platform.release()

    HOSTNAME: str = socket.gethostname()


# =============================================================================
# Singleton Settings Instance
# =============================================================================

settings = Settings()


# =============================================================================
# Export
# =============================================================================

__all__ = [
    "settings",
    "Settings",
    "PROJECT_ROOT",
    "API_ROOT",
    "DATA_ROOT",
    "LOG_ROOT",
]