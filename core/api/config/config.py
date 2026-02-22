# =============================================================================
# Copyright (c) 2026 Justin [LastName or Entity]
#
# Sentinel is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
#
# See LICENSE.md and COMMERCIAL_LICENSE.md at the repository root.
# =============================================================================

"""Sentinel-43 API layer: configuration.

File: api/config.py

This module centralizes environment-driven settings.

Goals:
- One place to read env vars.
- Strict, predictable types.
- No heavy dependencies required.

Note on defaults:
- Binding host to 0.0.0.0 is convenient for containers, but broad for a laptop.
  Override with SENTINEL_HOST in production or local runs if needed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import os


# -----------------------------------------------------------------------------
# Shared defaults (prefer to source from deps.py to avoid drift)
# -----------------------------------------------------------------------------

try:
    # Normal package import
    from .deps import DEFAULT_ENGINE_FACTORY as _DEFAULT_ENGINE_FACTORY  # type: ignore
    from .deps import DEFAULT_STORE_FACTORY as _DEFAULT_STORE_FACTORY  # type: ignore
except Exception:  # pragma: no cover
    try:
        # Absolute import fallback
        from api.deps import DEFAULT_ENGINE_FACTORY as _DEFAULT_ENGINE_FACTORY  # type: ignore
        from api.deps import DEFAULT_STORE_FACTORY as _DEFAULT_STORE_FACTORY  # type: ignore
    except Exception:
        # Last resort: keep local copies (should match deps.py)
        _DEFAULT_ENGINE_FACTORY = "api.deps:dev_engine_factory"
        _DEFAULT_STORE_FACTORY = "api.deps:dev_store_factory"


_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def _env(key: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(key)
    if v is None:
        return default
    v = v.strip()
    return v if v else default


def _env_bool(key: str, default: bool = False) -> bool:
    v = _env(key)
    if v is None:
        return default
    return v.lower() in {"1", "true", "t", "yes", "y", "on"}


def _env_int(key: str, default: int) -> int:
    v = _env(key)
    if v is None:
        return default
    try:
        return int(v)
    except ValueError:
        return default


def _normalize_log_level(level: str, *, default: str = "INFO") -> str:
    lvl = (level or "").strip().upper()
    return lvl if lvl in _VALID_LOG_LEVELS else default


def _parse_cors_origins(raw: str) -> str:
    """Normalize CORS origins.

    Input is a comma-separated string or '*'.
    Output is either '*', or a comma-separated list with whitespace stripped.

    We keep it as a string because Starlette's CORSMiddleware accepts both a
    list and a string-like source in app code; we'll parse to list there.
    """
    r = (raw or "").strip()
    if not r:
        return "*"
    if r == "*":
        return "*"
    parts = [p.strip() for p in r.split(",")]
    parts = [p for p in parts if p]
    return ",".join(parts) if parts else "*"


@dataclass(frozen=True)
class ApiConfig:
    """Runtime config for the API service."""

    # Service identity
    service_name: str = "sentinel-43-api"
    version: str = "0.1.0"

    # HTTP server
    # 0.0.0.0 is container-friendly; override with SENTINEL_HOST if you want tighter binding.
    host: str = "0.0.0.0"
    port: int = 8080

    # Logging
    log_level: str = "INFO"

    # OpenAPI / docs
    docs_enabled: bool = True

    # CORS (comma-separated list). "*" allowed in dev.
    cors_allow_origins: str = "*"

    # Factory wiring (mirrors deps.py). These are informational unless your app
    # entrypoint uses them to set env vars or pass into deps.
    engine_factory: str = _DEFAULT_ENGINE_FACTORY
    store_factory: str = _DEFAULT_STORE_FACTORY


def load_config() -> ApiConfig:
    """Load ApiConfig from environment variables."""
    service_name = _env("SENTINEL_SERVICE_NAME", "sentinel-43-api")
    version = _env("SENTINEL_VERSION", "0.1.0")
    host = _env("SENTINEL_HOST", "0.0.0.0")
    port = _env_int("SENTINEL_PORT", 8080)

    log_level_raw = _env("SENTINEL_LOG_LEVEL", "INFO") or "INFO"
    log_level = _normalize_log_level(log_level_raw, default="INFO")

    docs_enabled = _env_bool("SENTINEL_DOCS_ENABLED", True)
    cors_allow_origins = _parse_cors_origins(_env("SENTINEL_CORS_ALLOW_ORIGINS", "*") or "*")

    # These mirror deps.py defaults and should not drift.
    engine_factory = _env("SENTINEL_ENGINE_FACTORY", _DEFAULT_ENGINE_FACTORY) or _DEFAULT_ENGINE_FACTORY
    store_factory = _env("SENTINEL_STORE_FACTORY", _DEFAULT_STORE_FACTORY) or _DEFAULT_STORE_FACTORY

    return ApiConfig(
        service_name=service_name or "sentinel-43-api",
        version=version or "0.1.0",
        host=host or "0.0.0.0",
        port=port,
        log_level=log_level,
        docs_enabled=docs_enabled,
        cors_allow_origins=cors_allow_origins,
        engine_factory=engine_factory,
        store_factory=store_factory,
    )


# -----------------------------------------------------------------------------
# Minimal tests
# -----------------------------------------------------------------------------


def _run_self_tests() -> None:  # pragma: no cover
    import unittest
    from unittest.mock import patch

    class ConfigTests(unittest.TestCase):
        def test_defaults(self):
            with patch.dict(os.environ, {}, clear=False):
                cfg = load_config()
            self.assertTrue(cfg.service_name)
            self.assertTrue(isinstance(cfg.port, int))
            self.assertIn(cfg.log_level, _VALID_LOG_LEVELS)

        def test_bool_parse_does_not_pollute_env(self):
            with patch.dict(os.environ, {"SENTINEL_DOCS_ENABLED": "false"}, clear=False):
                cfg = load_config()
                self.assertFalse(cfg.docs_enabled)
            # After context exit, env should be restored (patch.dict guarantees that).

        def test_log_level_validation(self):
            with patch.dict(os.environ, {"SENTINEL_LOG_LEVEL": "BLORP"}, clear=False):
                cfg = load_config()
                self.assertEqual(cfg.log_level, "INFO")

        def test_cors_parse_strips_spaces(self):
            with patch.dict(
                os.environ,
                {"SENTINEL_CORS_ALLOW_ORIGINS": " https://foo.com , https://bar.com  ,"},
                clear=False,
            ):
                cfg = load_config()
                self.assertEqual(cfg.cors_allow_origins, "https://foo.com,https://bar.com")

        def test_cors_empty_becomes_star(self):
            with patch.dict(os.environ, {"SENTINEL_CORS_ALLOW_ORIGINS": "   "}, clear=False):
                cfg = load_config()
                self.assertEqual(cfg.cors_allow_origins, "*")

    unittest.main(argv=["config.py"], exit=False)


if __name__ == "__main__":  # pragma: no cover
    _run_self_tests()
