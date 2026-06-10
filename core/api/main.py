# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
#
# Sentinel-43 is distributed under a dual-license model:
#
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
#
# Unauthorized copying, redistribution, relicensing, reverse engineering,
# or commercial exploitation outside the terms of the applicable license
# is strictly prohibited.
#
# By accessing, modifying, distributing, or using this software, you agree
# to comply with the terms of the applicable license.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
#
# Commercial Licensing:
# Contact the copyright holder for commercial licensing terms.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
import urllib.error
import urllib.request
import copy
import re
from uuid import uuid4
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import (
    APIRouter,
    FastAPI,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import JSONResponse

from .routers.remote_gateway import router as remote_gateway_router
from .routers.audit import router as audit_router
from ..bootstrap import bootstrap_expectations
from fastapi.middleware.cors import CORSMiddleware

APP_NAME = "sentinel-43-api"
APP_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")
SENTINEL_ENV = os.getenv("SENTINEL_ENV", "development")

WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-core:9100").rstrip("/")
WATCHTOWER_TIMEOUT = float(os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0"))
WATCHTOWER_HEARTBEAT_SECONDS = int(os.getenv("S43_WATCHTOWER_HEARTBEAT_SECONDS", "15"))

START_TIME = time.time()

# ============================================================
# Dashboard End-to-End Test Harness
# ============================================================

LOCAL_TEST_ENVIRONMENTS = frozenset({
    "development",
    "dev",
    "local",
    "test",
})

TEST_INJECTION_ENABLED = (
    os.getenv("S43_ENABLE_TEST_INJECTION", "false")
    .lower()
    .strip()
    in {"1", "true", "yes", "on"}
)

MAX_DASHBOARD_ACTIONS = 500
ACTION_ID_RE = re.compile(r"^[A-Z0-9_-]{1,64}$")

_action_store_lock = threading.Lock()
_action_store: dict[str, dict[str, Any]] = {}
_vault_record_count = 0

_dashboard_ws_clients: set[WebSocket] = set()


def _validate_action_id(action_id: str) -> str:
    if not isinstance(action_id, str):
        raise HTTPException(
            status_code=422,
            detail="action_id must be a string",
        )

    cleaned = action_id.strip().upper()

    if not ACTION_ID_RE.fullmatch(cleaned):
        raise HTTPException(
            status_code=422,
            detail="action_id has an invalid format",
        )

    return cleaned


def _require_reason(body: dict[str, Any]) -> str:
    if not isinstance(body, dict):
        raise HTTPException(
            status_code=422,
            detail="request body must be an object",
        )

    reason = body.get("reason")

    if not isinstance(reason, str):
        raise HTTPException(
            status_code=422,
            detail="reason must be a string",
        )

    cleaned = reason.strip()

    if len(cleaned) < 10:
        raise HTTPException(
            status_code=422,
            detail="reason must contain at least 10 characters",
        )

    if len(cleaned) > 500:
        raise HTTPException(
            status_code=422,
            detail="reason must not exceed 500 characters",
        )

    return cleaned


def _create_synthetic_action() -> dict[str, Any]:
    return {
        "id": f"ACT-TEST-{uuid4().hex[:10].upper()}",
        "action_type": "THREAT_ACTION",
        "status": "STAGED",
        "created_at": utc_now(),
        "decision_reason": "",
        "operator": "",
        "payload": {
            "source_ip": "203.0.113.88",
            "ip": "203.0.113.88",
            "threat": "Synthetic end-to-end Sentinel-43 test incident",
            "synthetic": True,
        },
    }


def _store_action(action: dict[str, Any]) -> dict[str, Any]:
    global _vault_record_count

    safe_action = copy.deepcopy(action)

    with _action_store_lock:
        _action_store[safe_action["id"]] = safe_action
        _vault_record_count += 1

        if len(_action_store) > MAX_DASHBOARD_ACTIONS:
            oldest_ids = [
                action_id
                for action_id, _ in sorted(
                    _action_store.items(),
                    key=lambda item: item[1]["created_at"],
                )[: len(_action_store) - MAX_DASHBOARD_ACTIONS]
            ]

            for action_id in oldest_ids:
                del _action_store[action_id]

        return copy.deepcopy(safe_action)


def _list_actions(limit: int = 250) -> list[dict[str, Any]]:
    safe_limit = max(1, min(limit, 500))

    with _action_store_lock:
        actions = [
            copy.deepcopy(action)
            for action in _action_store.values()
        ]

    return sorted(
        actions,
        key=lambda action: action["created_at"],
        reverse=True,
    )[:safe_limit]


def _vault_records() -> int:
    with _action_store_lock:
        return _vault_record_count


def _update_action_status(
    action_id: str,
    *,
    allowed_statuses: set[str],
    new_status: str,
    reason: str,
) -> dict[str, Any]:
    global _vault_record_count

    cleaned_id = _validate_action_id(action_id)

    with _action_store_lock:
        action = _action_store.get(cleaned_id)

        if action is None:
            raise HTTPException(
                status_code=404,
                detail="action not found",
            )

        if action["status"] not in allowed_statuses:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"action status is {action['status']}; "
                    f"expected one of {sorted(allowed_statuses)}"
                ),
            )

        action["status"] = new_status
        action["decision_reason"] = reason
        action["operator"] = "dashboard-test-operator"
        _vault_record_count += 1

        return copy.deepcopy(action)


async def _broadcast_dashboard_event(
    event_type: str,
    payload: dict[str, Any],
) -> None:
    dead_clients: list[WebSocket] = []

    for client in tuple(_dashboard_ws_clients):
        try:
            await client.send_json(
                {
                    "type": event_type,
                    "payload": payload,
                }
            )
        except Exception:
            dead_clients.append(client)

    for client in dead_clients:
        _dashboard_ws_clients.discard(client)


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
        _watchtower_last_status["last_heartbeat_ts"] = (
            utc_now() if ok else _watchtower_last_status["last_heartbeat_ts"]
        )
        _watchtower_last_status["last_error"] = None if ok else result

    return {
        "heartbeat_sent": ok,
        "watchtower_url": WATCHTOWER_URL,
        "response": result,
    }


def report_dependency_to_watchtower(
    name: str,
    status: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
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


# FIX #4: All blocking urllib calls wrapped in asyncio.to_thread so they
# don't block the event loop during startup and shutdown.
@asynccontextmanager
async def lifespan(api: FastAPI):
    global _heartbeat_thread

    bootstrap_expectations()

    await asyncio.to_thread(register_api_with_watchtower)
    await asyncio.to_thread(send_api_heartbeat)
    await asyncio.to_thread(
        report_dependency_to_watchtower,
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
    await asyncio.to_thread(send_api_heartbeat)


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


app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.websocket("/ws")
async def dashboard_websocket(websocket: WebSocket) -> None:
    """
    Dashboard WebSocket bridge.

    Supports:
    - initial connection confirmation
    - actions and vault subscriptions
    - current-state snapshots
    - heartbeat pong replies
    - live action broadcasts
    """

    await websocket.accept()
    _dashboard_ws_clients.add(websocket)

    try:
        await websocket.send_json(
            {
                "type": "connected",
                "payload": {
                    "status": "ok",
                    "service": APP_NAME,
                    "timestamp": utc_now(),
                },
            }
        )

        while True:
            message = await websocket.receive_json()

            if not isinstance(message, dict):
                await websocket.send_json(
                    {
                        "type": "error",
                        "payload": {
                            "error": "WebSocket message must be an object",
                        },
                    }
                )
                continue

            event_type = message.get("type")
            payload = message.get("payload")

            if not isinstance(payload, dict):
                payload = {}

            if event_type == "ping":
                await websocket.send_json(
                    {
                        "type": "pong",
                        "payload": {
                            "timestamp": utc_now(),
                        },
                    }
                )
                continue

            if event_type == "subscribe":
                channel = str(payload.get("channel") or "").strip()

                await websocket.send_json(
                    {
                        "type": "subscribed",
                        "payload": {
                            "channel": channel,
                            "timestamp": utc_now(),
                        },
                    }
                )

                if channel == "actions":
                    await websocket.send_json(
                        {
                            "type": "actions_snapshot",
                            "payload": {
                                "actions": _list_actions(),
                            },
                        }
                    )

                if channel == "vault":
                    await websocket.send_json(
                        {
                            "type": "vault_stats",
                            "payload": {
                                "records": _vault_records(),
                            },
                        }
                    )

                continue

            if event_type == "unsubscribe":
                await websocket.send_json(
                    {
                        "type": "unsubscribed",
                        "payload": {
                            "channel": payload.get("channel"),
                            "timestamp": utc_now(),
                        },
                    }
                )
                continue

            await websocket.send_json(
                {
                    "type": "error",
                    "payload": {
                        "error": f"Unsupported WebSocket event: {event_type!r}",
                    },
                }
            )

    except WebSocketDisconnect:
        return

    finally:
        _dashboard_ws_clients.discard(websocket)


@root_router.get("/actions")
def dashboard_actions(limit: int = 250) -> list[dict[str, Any]]:
    return _list_actions(limit)


@root_router.get("/vault/stats")
def dashboard_vault_stats() -> dict[str, Any]:
    return {
        "records": _vault_records(),
        "timestamp": utc_now(),
    }


@root_router.post("/actions/test-inject")
async def dashboard_test_inject() -> dict[str, Any]:
    """
    Create one fixed synthetic incident for local end-to-end testing.

    This route must never be enabled in production.
    """
    environment = SENTINEL_ENV.lower().strip()

    if (
        environment not in LOCAL_TEST_ENVIRONMENTS
        or not TEST_INJECTION_ENABLED
    ):
        raise HTTPException(
            status_code=403,
            detail="test injection is disabled",
        )

    action = _store_action(
        _create_synthetic_action()
    )

    await _broadcast_dashboard_event(
        "action_created",
        {
            "action": action,
        },
    )

    await _broadcast_dashboard_event(
        "vault_stats",
        {
            "records": _vault_records(),
        },
    )

    return {
        "ok": True,
        "action": action,
        "vault_records": _vault_records(),
        "timestamp": utc_now(),
    }


@root_router.post("/actions/{action_id}/approve")
async def dashboard_approve_action(
    action_id: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    reason = _require_reason(body)

    action = _update_action_status(
        action_id,
        allowed_statuses={"STAGED"},
        new_status="APPROVED",
        reason=reason,
    )

    await _broadcast_dashboard_event(
        "action_status_changed",
        {
            "action": action,
        },
    )

    await _broadcast_dashboard_event(
        "vault_stats",
        {
            "records": _vault_records(),
        },
    )

    return {
        "ok": True,
        "action": action,
        "timestamp": utc_now(),
    }


@root_router.post("/actions/{action_id}/veto")
async def dashboard_veto_action(
    action_id: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    reason = _require_reason(body)

    action = _update_action_status(
        action_id,
        allowed_statuses={"PENDING", "STAGED"},
        new_status="VETOED",
        reason=reason,
    )

    await _broadcast_dashboard_event(
        "action_status_changed",
        {
            "action": action,
        },
    )

    await _broadcast_dashboard_event(
        "vault_stats",
        {
            "records": _vault_records(),
        },
    )

    return {
        "ok": True,
        "action": action,
        "timestamp": utc_now(),
    }


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

    # FIX #3: snapshot under lock before reading — heartbeat thread writes
    # _watchtower_last_status concurrently.
    with _watchtower_lock:
        wt_snapshot = dict(_watchtower_last_status)

    return {
        "service": "watchtower_bridge",
        "watchtower_url": WATCHTOWER_URL,
        "checks": {
            "health": "ok" if health_result["reachable"] else "failed",
            "ready": "ok" if "error" not in ready_result else "failed",
            "status": "ok" if "error" not in status_result else "failed",
            "api_registered": wt_snapshot.get("registered", False),
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


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": APP_NAME,
        "version": APP_VERSION,
        "environment": SENTINEL_ENV,
    }


@app.get("/ready")
def ready() -> dict[str, str]:
    return {
        "status": "ready",
        "service": APP_NAME,
    }


# FIX #5: return type corrected from JSONResponse to dict[str, str].
@api_router.get("/ready")
def compat_api_ready() -> dict[str, str]:
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
