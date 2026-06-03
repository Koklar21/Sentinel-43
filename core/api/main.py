from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, FastAPI
from fastapi.responses import JSONResponse

APP_NAME = "sentinel-43-api"
APP_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")

START_TIME = time.time()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def uptime_seconds() -> float:
    return round(time.time() - START_TIME, 3)


app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Sentinel-43 API control surface",
)


# ============================================================
# Root Router
# ============================================================

root_router = APIRouter(tags=["root"])


@root_router.get("/")
def root() -> dict[str, Any]:
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "uptime_seconds": uptime_seconds(),
        "timestamp": utc_now(),
    }


@root_router.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": APP_NAME,
        "timestamp": utc_now(),
    }


@root_router.get("/ready")
def ready() -> dict[str, Any]:
    return {
        "ready": True,
        "service": APP_NAME,
        "timestamp": utc_now(),
    }


@root_router.get("/status")
def status() -> dict[str, Any]:
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "uptime_seconds": uptime_seconds(),
        "timestamp": utc_now(),
    }


@root_router.get("/version")
def version() -> dict[str, Any]:
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "timestamp": utc_now(),
    }


@root_router.get("/metrics")
def metrics() -> dict[str, Any]:
    return {
        "service": APP_NAME,
        "uptime_seconds": uptime_seconds(),
        "status": "online",
        "timestamp": utc_now(),
    }


# ============================================================
# Watchtower Router
# ============================================================

watchtower_router = APIRouter(prefix="/watchtower", tags=["watchtower"])


@watchtower_router.get("/status")
def watchtower_status() -> dict[str, Any]:
    return {
        "service": "watchtower",
        "state": "ACTIVE",
        "mode": "monitoring",
        "guard": "enabled",
        "uptime_seconds": uptime_seconds(),
        "timestamp": utc_now(),
    }


@watchtower_router.get("/health")
def watchtower_health() -> dict[str, Any]:
    return {
        "service": "watchtower",
        "status": "ok",
        "state": "ACTIVE",
        "timestamp": utc_now(),
    }


@watchtower_router.get("/check")
def watchtower_check() -> dict[str, Any]:
    return {
        "service": "watchtower",
        "checks": {
            "api": "ok",
            "core": "unknown",
            "redis": "unknown",
            "postgres": "unknown",
            "rules": "unknown",
        },
        "timestamp": utc_now(),
    }


# ============================================================
# Core Router
# ============================================================

core_router = APIRouter(prefix="/core", tags=["core"])


@core_router.get("/status")
def core_status() -> dict[str, Any]:
    return {
        "service": "s43_core",
        "status": "online",
        "state": "ACTIVE",
        "timestamp": utc_now(),
    }


@core_router.get("/health")
def core_health() -> dict[str, Any]:
    return {
        "service": "s43_core",
        "status": "ok",
        "timestamp": utc_now(),
    }


# ============================================================
# Rules Router
# ============================================================

rules_router = APIRouter(prefix="/rules", tags=["rules"])


@rules_router.get("/status")
def rules_status() -> dict[str, Any]:
    return {
        "service": "rules",
        "status": "loaded",
        "active": True,
        "timestamp": utc_now(),
    }


@rules_router.get("/")
def rules_root() -> dict[str, Any]:
    return {
        "service": "rules",
        "message": "Rules registry endpoint active",
        "timestamp": utc_now(),
    }


# ============================================================
# Config Router
# ============================================================

config_router = APIRouter(prefix="/config", tags=["config"])


@config_router.get("/status")
def config_status() -> dict[str, Any]:
    return {
        "service": "config",
        "status": "loaded",
        "environment": os.getenv("SENTINEL_ENV", "development"),
        "timestamp": utc_now(),
    }


@config_router.get("/")
def config_root() -> dict[str, Any]:
    return {
        "service": "config",
        "environment": os.getenv("SENTINEL_ENV", "development"),
        "timestamp": utc_now(),
    }


# ============================================================
# Dependencies Router
# ============================================================

dependencies_router = APIRouter(prefix="/dependencies", tags=["dependencies"])


@dependencies_router.get("/status")
def dependencies_status() -> dict[str, Any]:
    return {
        "service": "dependencies",
        "checks": {
            "redis": "unknown",
            "postgres": "unknown",
            "core": "unknown",
            "watchtower": "ok",
            "api": "ok",
        },
        "timestamp": utc_now(),
    }


# ============================================================
# System Router
# ============================================================

system_router = APIRouter(prefix="/system", tags=["system"])


@system_router.get("/status")
def system_status() -> dict[str, Any]:
    return {
        "system": "sentinel-43",
        "status": "online",
        "version": APP_VERSION,
        "uptime_seconds": uptime_seconds(),
        "components": {
            "api": "online",
            "core": "online",
            "watchtower": "ACTIVE",
            "rules": "loaded",
            "config": "loaded",
            "redis": "unknown",
            "postgres": "unknown",
        },
        "timestamp": utc_now(),
    }


@system_router.get("/routes")
def system_routes() -> dict[str, Any]:
    route_list = []

    for route in app.routes:
        methods = sorted(route.methods) if hasattr(route, "methods") else []
        path = getattr(route, "path", None)
        name = getattr(route, "name", None)

        if path:
            route_list.append(
                {
                    "path": path,
                    "name": name,
                    "methods": methods,
                }
            )

    return {
        "service": APP_NAME,
        "route_count": len(route_list),
        "routes": route_list,
        "timestamp": utc_now(),
    }


# Existing compatibility route
@system_router.get("/routes/status")
def routes_status() -> dict[str, Any]:
    return {
        "service": "routes",
        "status": "ok",
        "message": "Route system active",
        "timestamp": utc_now(),
    }


# ============================================================
# API Prefix Compatibility Router
# ============================================================

api_router = APIRouter(prefix="/api", tags=["api-compat"])


@api_router.get("/health")
def api_health() -> dict[str, Any]:
    return health()


@api_router.get("/status")
def api_status() -> dict[str, Any]:
    return status()


@api_router.get("/version")
def api_version() -> dict[str, Any]:
    return version()


@api_router.get("/config")
def api_config() -> dict[str, Any]:
    return config_root()


@api_router.get("/rules")
def api_rules() -> dict[str, Any]:
    return rules_root()


@api_router.get("/watchtower/status")
def api_watchtower_status() -> dict[str, Any]:
    return watchtower_status()


@api_router.get("/watchtower/health")
def api_watchtower_health() -> dict[str, Any]:
    return watchtower_health()


# ============================================================
# Register Routers
# ============================================================

app.include_router(root_router)
app.include_router(watchtower_router)
app.include_router(core_router)
app.include_router(rules_router)
app.include_router(config_router)
app.include_router(dependencies_router)
app.include_router(system_router)
app.include_router(api_router)


# ============================================================
# Error Handling
# ============================================================

@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={
            "error": "route_not_found",
            "path": str(request.url.path),
            "message": "Requested route is not registered in Sentinel-43 API.",
            "timestamp": utc_now(),
        },
    )
