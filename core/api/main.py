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

"""Sentinel-43 API service entrypoint.

File: api/main.py

This builds the FastAPI app.

Wires:
- api/config.py (env-driven settings)
- api/routes.py (HTTP endpoints)
- api/deps.py (engine/store factories)

Recommended run commands (when FastAPI is installed):
- uvicorn api.main:app --host 0.0.0.0 --port 8080
- python -m uvicorn api.main:app

Notes:
- We avoid mutating process environment variables here.
- Dependency factory wiring is validated at startup via lifespan.

IMPORTANT:
- This file is import-safe even if FastAPI isn't installed, so tools (linters,
  packaging, repo scanners) don't crash.
- If you try to *create the app* without FastAPI installed, we raise a clear
  error at that time.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, List, Optional


# -----------------------------------------------------------------------------
# Local imports with fallback for non-package execution contexts.
# -----------------------------------------------------------------------------

try:
    from .config import ApiConfig, load_config
    from .routes import router as api_router
except ImportError:  # pragma: no cover
    from api.config import ApiConfig, load_config  # type: ignore
    from api.routes import router as api_router  # type: ignore


def _import_fastapi():
    """Import FastAPI runtime deps lazily.

    Why:
    - Importing this module should not explode in minimal environments.
    - Creating the app should *require* FastAPI.

    Returns:
        (FastAPI, CORSMiddleware)
    """
    try:
        from fastapi import FastAPI  # type: ignore
        from fastapi.middleware.cors import CORSMiddleware  # type: ignore

        return FastAPI, CORSMiddleware
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "FastAPI is required to create the API app. Install fastapi + pydantic."
        ) from e


def _cors_origins_from_config(raw: str) -> List[str]:
    """Convert config.cors_allow_origins to CORSMiddleware allow_origins list."""
    r = (raw or "").strip()
    if not r or r == "*":
        return ["*"]
    parts = [p.strip() for p in r.split(",")]
    return [p for p in parts if p]


def _cors_allow_credentials_for(allow_origins: List[str]) -> bool:
    """CORS rule: credentials cannot be used with wildcard origin."""
    if allow_origins == ["*"]:
        return False
    return True


def _import_deps():
    """Import deps with package-friendly fallbacks."""
    try:
        from .deps import get_engine, get_store  # type: ignore

        return get_engine, get_store
    except ImportError:  # pragma: no cover
        from api.deps import get_engine, get_store  # type: ignore

        return get_engine, get_store


def create_app(cfg: Optional[ApiConfig] = None) -> Any:
    """Create and return the ASGI app.

    Expected behavior:
    - If FastAPI is installed: returns a FastAPI instance.
    - If FastAPI is missing: raises RuntimeError with install guidance.
    """
    FastAPI, CORSMiddleware = _import_fastapi()

    cfg = cfg or load_config()

    @asynccontextmanager
    async def lifespan(app: Any):
        # Validate dependency wiring at startup.
        # We intentionally create instances once to ensure factories work and
        # interfaces validate; we keep them on app.state so the work isn't wasted.
        get_engine, get_store = _import_deps()

        app.state.config = cfg
        app.state.startup_engine = None
        app.state.startup_store = None

        app.state.startup_engine = get_engine()
        app.state.startup_store = get_store()

        try:
            yield
        finally:
            # If you add closers later (e.g., DB engines), do it here.
            app.state.startup_engine = None
            app.state.startup_store = None

    # Docs toggles
    docs_url = "/docs" if cfg.docs_enabled else None
    redoc_url = "/redoc" if cfg.docs_enabled else None
    openapi_url = "/openapi.json" if cfg.docs_enabled else None

    app = FastAPI(
        title=cfg.service_name,
        version=cfg.version,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )

    # CORS
    allow_origins = _cors_origins_from_config(cfg.cors_allow_origins)
    allow_credentials = _cors_allow_credentials_for(allow_origins)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routers
    app.include_router(api_router)

    return app


# Default ASGI app.
# Import-time creation is standard for ASGI servers, but we keep this module
# import-safe when FastAPI isn't present.
try:
    app = create_app()
except RuntimeError:  # pragma: no cover
    # FastAPI missing in this environment. Leave app as None.
    app = None  # type: ignore


# -----------------------------------------------------------------------------
# Minimal tests
# -----------------------------------------------------------------------------


def _run_self_tests() -> None:  # pragma: no cover
    import unittest
    from unittest.mock import patch

    # If FastAPI isn't installed, we skip rather than crash.
    try:
        from fastapi.testclient import TestClient  # type: ignore
    except Exception:
        TestClient = None  # type: ignore

    class MainTests(unittest.TestCase):
        def setUp(self) -> None:
            if TestClient is None:
                self.skipTest("fastapi[test] is not installed in this environment")

        def test_health_has_request_id(self):
            cfg = ApiConfig(docs_enabled=False)
            test_app = create_app(cfg)
            client = TestClient(test_app)
            r = client.get("/health")
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertEqual(data.get("status"), "ok")
            self.assertTrue(isinstance(data.get("request_id"), str))
            self.assertTrue(len(data.get("request_id")) > 0)

        def test_health_uses_header_request_id(self):
            cfg = ApiConfig(docs_enabled=False)
            test_app = create_app(cfg)
            client = TestClient(test_app)
            r = client.get("/health", headers={"X-Request-ID": "abc-123"})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json().get("request_id"), "abc-123")

        def test_docs_disabled(self):
            cfg = ApiConfig(docs_enabled=False)
            test_app = create_app(cfg)
            client = TestClient(test_app)
            self.assertEqual(client.get("/docs").status_code, 404)

        def test_cors_parsing(self):
            self.assertEqual(_cors_origins_from_config("*"), ["*"])
            self.assertEqual(
                _cors_origins_from_config(" https://a.com , https://b.com "),
                ["https://a.com", "https://b.com"],
            )

        def test_cors_credentials_rule(self):
            self.assertFalse(_cors_allow_credentials_for(["*"]))
            self.assertTrue(_cors_allow_credentials_for(["https://a.com"]))

        def test_no_env_mutation(self):
            # create_app should not set or modify env vars.
            with patch.dict("os.environ", {}, clear=True):
                cfg = ApiConfig(docs_enabled=False)
                _ = create_app(cfg)
                self.assertIsNone(os.environ.get("SENTINEL_ENGINE_FACTORY"))
                self.assertIsNone(os.environ.get("SENTINEL_STORE_FACTORY"))

    unittest.main(argv=["main.py"], exit=False)


if __name__ == "__main__":  # pragma: no cover
    _run_self_tests()
