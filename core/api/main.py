from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse

from .routers.remote_gateway import router as remote_gateway_router
from .routers.audit import router as audit_router
from core.bootstrap import bootstrap_expectations 

APP_NAME = "sentinel-43-api"
APP_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")
SENTINEL_ENV = os.getenv("SENTINEL_ENV", "development")

WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-core:9100").rstrip("/")
WATCHTOWER_TIMEOUT = float(os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0"))
WATCHTOWER_HEARTBEAT_SECONDS = int(os.getenv("S43_WATCHTOWER_HEARTBEAT_SECONDS", "15"))

START_TIME = time.time()

_watchtower_lock = threading.Lock()
_watchtower_last_status: dict[str, Any] = {
    "reachable": False,
    "registered": False,
    "last_register_ts": None,
    "last_heartbeat_ts": None,
    "last_error": None,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def uptime_seconds() -> float:
    return round(time.time() - START_TIME, 3)


def _watchtower_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = f"{WATCHTOWER_URL}{path}"
    data = None
    headers = {"Content-Type": "application/json"}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        url=url,
        data=data,
        headers=headers,
        method=method.upper(),
    )

    try:
        with urllib.request.urlopen(request, timeout=WATCHTOWER_TIMEOUT) as response:
            body = response.read().decode("utf-8")
            if not body:
                return {"status_code": response.status}
            result = json.loads(body)
            if isinstance(result, dict):
                result.setdefault("status_code", response.status)
            return result

    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8")
        except Exception:
            detail = str(exc)

        return {
            "error": "watchtower_http_error",
            "status_code": exc.code,
            "detail": detail,
        }

    except Exception as exc:
        return {
            "error": "watchtower_unreachable",
            "detail": str(exc),
        }


def watchtower_health_check() -> dict[str, Any]:
    result = _watchtower_request("GET", "/watchtower/health")
    reachable = "error" not in result

    with _watchtower_lock:
        _watchtower_last_status["reachable"] = reachable
        _watchtower_last_status["last_error"] = None if reachable else result

    return {
        "reachable": reachable,
        "url": WATCHTOWER_URL,
        "response": result,
    }


def register_api_with_watchtower() -> dict[str, Any]:
    payload = {
        "module_id": APP_NAME,
        "module_type": "api",
        "version": APP_VERSION,
        "endpoint": os.getenv("S43_API_PUBLIC_URL", "http://s43-api:8000"),
        "capabilities": [
            "health",
            "ready",
            "status",
            "routes",
            "metrics",
            "core_bridge",
            "watchtower_bridge",
            "remote_gateway",
            "remote_operations",
        ],
        "metadata": {
            "environment": SENTINEL_ENV,
            "started_ts": START_TIME,
            "timestamp": utc_now(),
        },
    }

    result = _watchtower_request("POST", "/watchtower/modules/register", payload)
    registered = "error" not in result

    with _watchtower_lock:
        _watchtower_last_status["reachable"] = registered
        _watchtower_last_status["registered"] = registered
        _watchtower_last_status["last_register_ts"] = utc_now() if registered else None
        _watchtower_last_status["last_error"] = None if registered else result

    return {
        "registered": registered,
        "watchtower_url": WATCHTOWER_URL,
        "response": result,
    }


def send_api_heartbeat() -> dict[str, Any]:
    payload = {
        "module_id": APP_NAME,
        "status": "online",
        "metrics": {
            "uptime_seconds": uptime_seconds(),
            "timestamp": utc_now(),
        },
        "message": "Sentinel-43 API heartbeat online",
    }

    result = _watchtower_request("POST", "/watchtower/modules/heartbeat", payload)
    ok = "error" not in result

    with _watchtower_lock:
        _watchtower_last_status["reachable"] = ok
        _watchtower_last_status["last_heartbeat_ts"] = utc_now() if ok else _watchtower_last_status["last_heartbeat_ts"]
        _watchtower_last_status["last_error"] = None if ok else result

    return {
        "heartbeat_sent": ok,
        "watchtower_url": WATCHTOWER_URL,
        "response": result,
    }


def report_dependency_to_watchtower(name: str, status: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {
        "name": name,
        "status": status,
        "details": details or {},
    }
    return _watchtower_request("POST", "/watchtower/dependencies/report", payload)


def heartbeat_loop(stop_event: threading.Event) -> None:
    while not stop_event.wait(WATCHTOWER_HEARTBEAT_SECONDS):
        send_api_heartbeat()


_stop_heartbeat = threading.Event()
_heartbeat_thread: threading.Thread | None = None


@asynccontextmanager
async def lifespan(api: FastAPI):
    global _heartbeat_thread

    bootstrap_expectations()   # <-- INSERT HERE

    register_api_with_watchtower()
    send_api_heartbeat()

    report_dependency_to_watchtower(
        "sentinel-43-api",
        "online",
        {"version": APP_VERSION, "environment": SENTINEL_ENV},
    )

    _stop_heartbeat.clear()
    _heartbeat_thread = threading.Thread(
        target=heartbeat_loop,
        args=(_stop_heartbeat,),
        daemon=True,
        name="sentinel43-api-watchtower-heartbeat",
    )
    _heartbeat_thread.start()

    yield

    _stop_heartbeat.set()
    send_api_heartbeat()


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
        "watchtower_url": WATCHTOWER_URL,
        "uptime_seconds": uptime_seconds(),
        "timestamp": utc_now(),
    }


@root_router.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": APP_NAME,
        "version": APP_VERSION,
        "timestamp": utc_now(),
    }


@root_router.get("/ready")
def ready() -> JSONResponse:
    wt = watchtower_health_check()

    with _watchtower_lock:
        wt_local = dict(_watchtower_last_status)

    is_ready = wt["reachable"] and wt_local.get("registered", False)

    return JSONResponse(
        status_code=200 if is_ready else 503,
        content={
            "ready": is_ready,
            "service": APP_NAME,
            "watchtower": wt,
            "watchtower_local_state": wt_local,
            "timestamp": utc_now(),
        },
    )


@root_router.get("/status")
def status() -> dict[str, Any]:
    with _watchtower_lock:
        wt_local = dict(_watchtower_last_status)

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "environment": SENTINEL_ENV,
        "uptime_seconds": uptime_seconds(),
        "watchtower_url": WATCHTOWER_URL,
        "watchtower_local_state": wt_local,
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
        "watchtower_heartbeat_seconds": WATCHTOWER_HEARTBEAT_SECONDS,
        "timestamp": utc_now(),
    }


# ============================================================
# Watchtower Bridge Router
# ============================================================

watchtower_router = APIRouter(prefix="/watchtower", tags=["watchtower"])


@watchtower_router.get("/health")
def api_watchtower_health() -> dict[str, Any]:
    return watchtower_health_check()


@watchtower_router.get("/status")
def api_watchtower_status() -> dict[str, Any]:
    result = _watchtower_request("GET", "/watchtower/status")
    return {
        "bridge": "api_to_watchtower",
        "watchtower_url": WATCHTOWER_URL,
        "reachable": "error" not in result,
        "watchtower": result,
        "timestamp": utc_now(),
    }


@watchtower_router.get("/ready")
def api_watchtower_ready() -> dict[str, Any]:
    result = _watchtower_request("GET", "/watchtower/ready")
    return {
        "bridge": "api_to_watchtower",
        "watchtower_url": WATCHTOWER_URL,
        "reachable": "error" not in result,
        "watchtower": result,
        "timestamp": utc_now(),
    }


@watchtower_router.post("/register")
def api_register_watchtower() -> dict[str, Any]:
    return register_api_with_watchtower()


@watchtower_router.post("/heartbeat")
def api_heartbeat_watchtower() -> dict[str, Any]:
    return send_api_heartbeat()


@watchtower_router.get("/modules")
def api_watchtower_modules() -> dict[str, Any]:
    result = _watchtower_request("GET", "/watchtower/modules")
    return {
        "bridge": "api_to_watchtower",
        "reachable": "error" not in result,
        "watchtower": result,
        "timestamp": utc_now(),
    }


@watchtower_router.get("/check")
def watchtower_check() -> dict[str, Any]:
    health_result = watchtower_health_check()
    ready_result = _watchtower_request("GET", "/watchtower/ready")
    status_result = _watchtower_request("GET", "/watchtower/status")

    return {
        "service": "watchtower_bridge",
        "watchtower_url": WATCHTOWER_URL,
        "checks": {
            "health": "ok" if health_result["reachable"] else "failed",
            "ready": "ok" if "error" not in ready_result else "failed",
            "status": "ok" if "error" not in status_result else "failed",
            "api_registered": _watchtower_last_status.get("registered", False),
        },
        "responses": {
            "health": health_result,
            "ready": ready_result,
            "status": status_result,
        },
        "timestamp": utc_now(),
    }


# ============================================================
# Core Router
# ============================================================

core_router = APIRouter(prefix="/core", tags=["core"])


@core_router.get("/status")
def core_status() -> dict[str, Any]:
    report_dependency_to_watchtower(
        "sentinel-43-core",
        "online",
        {"source": "api-core-status-route"},
    )

    return {
        "service": "s43_core",
        "status": "online",
        "state": "ACTIVE",
        "watchtower_reported": True,
        "timestamp": utc_now(),
    }


@core_router.get("/health")
def core_health() -> dict[str, Any]:
    report_dependency_to_watchtower(
        "sentinel-43-core-health",
        "online",
        {"source": "api-core-health-route"},
    )

    return {
        "service": "s43_core",
        "status": "ok",
        "watchtower_reported": True,
        "timestamp": utc_now(),
    }


@core_router.post("/heartbeat")
def core_heartbeat() -> dict[str, Any]:
    result = report_dependency_to_watchtower(
        "sentinel-43-core",
        "online",
        {
            "heartbeat_source": "api",
            "uptime_seconds": uptime_seconds(),
            "timestamp": utc_now(),
        },
    )

    return {
        "service": "s43_core",
        "heartbeat": "sent",
        "watchtower_response": result,
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
        "environment": SENTINEL_ENV,
        "timestamp": utc_now(),
    }


@config_router.get("/")
def config_root() -> dict[str, Any]:
    return {
        "service": "config",
        "environment": SENTINEL_ENV,
        "timestamp": utc_now(),
    }


# ============================================================
# Dependencies Router
# ============================================================

dependencies_router = APIRouter(prefix="/dependencies", tags=["dependencies"])


@dependencies_router.get("/status")
def dependencies_status() -> dict[str, Any]:
    wt = watchtower_health_check()

    checks = {
        "api": "ok",
        "core": "ok",
        "watchtower": "ok" if wt["reachable"] else "failed",
        "redis": "unknown",
        "postgres": "unknown",
    }

    return {
        "service": "dependencies",
        "checks": checks,
        "watchtower_url": WATCHTOWER_URL,
        "timestamp": utc_now(),
    }


@dependencies_router.post("/report/{name}/{state}")
def report_dependency(name: str, state: str) -> dict[str, Any]:
    result = report_dependency_to_watchtower(
        name,
        state,
        {"source": "api-dependency-report-route"},
    )

    return {
        "dependency": name,
        "state": state,
        "watchtower_response": result,
        "timestamp": utc_now(),
    }


# ============================================================
# System Router
# ============================================================

system_router = APIRouter(prefix="/system", tags=["system"])


@system_router.get("/status")
def system_status() -> dict[str, Any]:
    wt = _watchtower_request("GET", "/watchtower/status")

    return {
        "system": "sentinel-43",
        "status": "online",
        "version": APP_VERSION,
        "uptime_seconds": uptime_seconds(),
        "components": {
            "api": "online",
            "core": "online",
            "watchtower": "online" if "error" not in wt else "unreachable",
            "rules": "loaded",
            "config": "loaded",
            "redis": "unknown",
            "postgres": "unknown",
        },
        "watchtower": wt,
        "timestamp": utc_now(),
    }


@system_router.get("/routes")
def system_routes() -> dict[str, Any]:
    route_list = []

    for route in app.routes:
        methods_raw = getattr(route, "methods", None)
        methods = sorted(methods_raw) if methods_raw else []

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

@system_router.get("/routes/status")
def routes_status() -> dict[str, Any]:
    return {
        "service": "routes",
        "status": "ok",
        "message": "Route system active",
        "timestamp": utc_now(),
    }


@system_router.get("/intercom/status")
def intercom_status() -> dict[str, Any]:
    wt_health = watchtower_health_check()
    wt_modules = _watchtower_request("GET", "/watchtower/modules")

    return {
        "service": "sentinel-43-intercom",
        "api": "online",
        "watchtower": "online" if wt_health["reachable"] else "unreachable",
        "watchtower_url": WATCHTOWER_URL,
        "modules": wt_modules,
        "timestamp": utc_now(),
    }


# ============================================================
# API Prefix Compatibility Router
# ============================================================

api_router = APIRouter(prefix="/api", tags=["api-compat"])


@api_router.get("/health")
def compat_api_health() -> dict[str, Any]:
    return health()


@api_router.get("/ready")
def compat_api_ready() -> JSONResponse:
    return ready()


@api_router.get("/status")
def compat_api_status() -> dict[str, Any]:
    return status()


@api_router.get("/version")
def compat_api_version() -> dict[str, Any]:
    return version()


@api_router.get("/config")
def compat_api_config() -> dict[str, Any]:
    return config_root()


@api_router.get("/rules")
def compat_api_rules() -> dict[str, Any]:
    return rules_root()


@api_router.get("/watchtower/status")
def compat_api_watchtower_status() -> dict[str, Any]:
    return api_watchtower_status()


@api_router.get("/watchtower/health")
def compat_api_watchtower_health() -> dict[str, Any]:
    return api_watchtower_health()


@api_router.get("/watchtower/ready")
def compat_api_watchtower_ready() -> dict[str, Any]:
    return api_watchtower_ready()


# ============================================================
# Register Routers
# ============================================================

app.include_router(root_router)
app.include_router(remote_gateway_router)
app.include_router(watchtower_router)
app.include_router(core_router)
app.include_router(rules_router)
app.include_router(config_router)
app.include_router(dependencies_router)
app.include_router(system_router)
app.include_router(api_router)
app.include_router(audit_router)

# ============================================================
# Error Handling
# ============================================================

@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={
            "error": "route_not_found",
            "path": str(request.url.path),
            "message": "Requested route is not registered in Sentinel-43 API.",
            "timestamp": utc_now(),
        },
    )
L
