# =============================================================================
# Copyright (c) 2026 Justin [LastName or Entity]
#
# Sentinel is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sentinel-43 API service entrypoint.

Docker-safe FastAPI app factory for core.api.main.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any, Optional

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
except Exception as exc:  # pragma: no cover
    raise RuntimeError(
        "FastAPI is required. Install fastapi and uvicorn inside the Docker image."
    ) from exc

try:
    from core.api.config import ApiConfig, load_config
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "Could not import core.api.config. Run from the project root where 'core/' exists."
    ) from exc


def _cors_origins_from_config(raw: str | None) -> list[str]:
    value = (raw or "").strip()
    if not value or value == "*":
        return ["*"]
    return [item.strip() for item in value.split(",") if item.strip()]


def _cors_allow_credentials_for(origins: list[str]) -> bool:
    return origins != ["*"]


def _load_router(app: FastAPI) -> None:
    try:
        from core.api.routes import router as api_router

        app.include_router(api_router)
    except Exception as exc:
        # Do not kill Docker just because routes are still being repaired.
        @app.get("/routes/status")
        def routes_status() -> dict[str, Any]:
            return {
                "routes_loaded": False,
                "error": str(exc),
            }


def _load_startup_dependencies(app: Any, cfg: ApiConfig) -> None:
    app.state.config = cfg
    app.state.startup_engine = None
    app.state.startup_store = None

    try:
        from core.api.deps import get_engine, get_store

        app.state.startup_engine = get_engine()
        app.state.startup_store = get_store()
    except Exception as exc:
        # Keep API alive while dependency wiring is being fixed.
        app.state.dependency_error = str(exc)


def create_app(cfg: Optional[ApiConfig] = None) -> FastAPI:
    cfg = cfg or load_config()

    @asynccontextmanager
    async def lifespan(app: Any):
        _load_startup_dependencies(app, cfg)
        try:
            yield
        finally:
            app.state.startup_engine = None
            app.state.startup_store = None

    docs_enabled = bool(getattr(cfg, "docs_enabled", True))

    app = FastAPI(
        title=getattr(cfg, "service_name", "Sentinel-43 API"),
        version=getattr(cfg, "version", "0.1.0"),
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
        lifespan=lifespan,
    )

    origins = _cors_origins_from_config(getattr(cfg, "cors_allow_origins", "*"))

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=_cors_allow_credentials_for(origins),
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/")
    def root() -> dict[str, Any]:
        return {
            "service": getattr(cfg, "service_name", "Sentinel-43 API"),
            "version": getattr(cfg, "version", "0.1.0"),
            "status": "online",
        }

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": getattr(cfg, "service_name", "Sentinel-43 API"),
        }

    @app.get("/ready")
    def ready() -> dict[str, Any]:
        dependency_error = getattr(app.state, "dependency_error", None)

        return {
            "status": "degraded" if dependency_error else "ready",
            "dependency_error": dependency_error,
        }

    _load_router(app)

    return app


app = create_app()


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(
        "core.api.main:app",
        host=os.getenv("S43_API_HOST", "0.0.0.0"),
        port=int(os.getenv("S43_API_PORT", "8080")),
        reload=os.getenv("S43_RELOAD", "false").lower() == "true",
    )
