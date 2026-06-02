# =============================================================================
# Copyright (c) 2026 Justin [LastName or Entity]
#
# Sentinel is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sentinel-43 API service entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, Iterable

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.api.config import ApiConfig, load_config

logger = logging.getLogger(__name__)


def _cors_origins_from_config(raw: str | Iterable[str] | None) -> list[str]:
    if raw is None:
        return ["*"]

    if isinstance(raw, str):
        value = raw.strip()
        if not value or value == "*":
            return ["*"]
        return [item.strip() for item in value.split(",") if item.strip()]

    origins = [str(item).strip() for item in raw if str(item).strip()]
    return origins or ["*"]


def _cors_allow_credentials_for(origins: list[str]) -> bool:
    return origins != ["*"]


def _load_router(app: FastAPI) -> None:
    router_error: str | None = None

    try:
        from core.api.routers import router as api_router

        app.include_router(api_router)
        app.state.routes_loaded = True
        return
    except Exception as exc:
        router_error = f"core.api.routers failed: {exc}"
        logger.warning(router_error)

    try:
        from core.api.routes import router as api_router

        app.include_router(api_router)
        app.state.routes_loaded = True
        return
    except Exception as exc:
        router_error = f"{router_error}; core.api.routes failed: {exc}"
        logger.warning(router_error)

    app.state.routes_loaded = False
    app.state.routes_error = router_error

    @app.get("/routes/status")
    def routes_status() -> dict[str, Any]:
        return {
            "routes_loaded": False,
            "error": getattr(app.state, "routes_error", "unknown route error"),
        }


def _load_startup_dependencies(app: FastAPI, cfg: ApiConfig) -> None:
    app.state.config = cfg
    app.state.startup_engine = None
    app.state.startup_store = None
    app.state.dependency_error = None

    try:
        from core.api.deps import get_engine, get_store

        app.state.startup_engine = get_engine()
        app.state.startup_store = get_store()
    except Exception as exc:
        app.state.dependency_error = str(exc)
        logger.warning("API dependency startup degraded: %s", exc)


def create_app(cfg: ApiConfig | None = None) -> FastAPI:
    cfg = cfg or load_config()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        _load_startup_dependencies(app, cfg)
        try:
            yield
        finally:
            app.state.startup_engine = None
            app.state.startup_store = None

    docs_enabled = bool(cfg.docs_enabled)

    app = FastAPI(
        title=cfg.service_name,
        version=cfg.version,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
        lifespan=lifespan,
    )

    origins = _cors_origins_from_config(cfg.cors_allow_origins)

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
            "service": cfg.service_name,
            "version": cfg.version,
            "status": "online",
        }

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": cfg.service_name,
        }

    @app.get("/ready")
    def ready() -> dict[str, Any]:
        dependency_error = getattr(app.state, "dependency_error", None)
        routes_loaded = getattr(app.state, "routes_loaded", False)

        return {
            "status": "ready" if not dependency_error else "degraded",
            "routes_loaded": routes_loaded,
            "dependency_error": dependency_error,
        }

    _load_router(app)

    return app


app = create_app()


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    cfg = load_config()

    uvicorn.run(
        app,
        host=cfg.host,
        port=cfg.port,
        reload=False,
        log_level=cfg.log_level.lower(),
    )
