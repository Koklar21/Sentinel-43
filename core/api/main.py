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
import base64
import copy
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import jwt as pyjwt

from fastapi import (
    APIRouter,
    FastAPI,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ..bootstrap import bootstrap_expectations
from .routers.audit import router as audit_router
from .routers.remote_gateway import router as remote_gateway_router

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================

APP_NAME = "sentinel-43-api"
APP_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")

# FIX #17: Default changed from "development" to "production".
# "development" placed unset deployments inside LOCAL_TEST_ENVIRONMENTS,
# leaving TEST_INJECTION_ENABLED as the only real safety net.
SENTINEL_ENV: str = os.getenv("SENTINEL_ENV", "production")

WATCHTOWER_URL: str = os.getenv("S43_WATCHTOWER_URL", "http://s43-core:9100").rstrip("/")
WATCHTOWER_TIMEOUT: float = float(os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0"))
WATCHTOWER_HEARTBEAT_SECONDS: int = int(os.getenv("S43_WATCHTOWER_HEARTBEAT_SECONDS", "15"))

# FIX #11: Allowed origins from environment variable.
# Set S43_ALLOWED_ORIGINS as a comma-separated list for staging/production.
# Example: S43_ALLOWED_ORIGINS=https://dashboard.example.com,https://ops.example.com
_ALLOWED_ORIGINS: frozenset[str] = frozenset(
    o.strip()
    for o in os.getenv(
        "S43_ALLOWED_ORIGINS",
        "http://127.0.0.1:5500,http://localhost:5500,"
        "http://127.0.0.1:8000,http://localhost:8000",
    ).split(",")
    if o.strip()
)

# FIX #6: Hard cap on concurrent WebSocket connections.
# Prevents connection exhaustion; every broadcast iterates the full set.
MAX_WS_CLIENTS: int = int(os.getenv("S43_MAX_WS_CLIENTS", "50"))

# FIX #5: Maximum incoming WebSocket frame size in bytes.
# Matches the 64 KB cap enforced by the dashboard frontend.
MAX_WS_FRAME_BYTES: int = int(os.getenv("S43_MAX_WS_FRAME_BYTES", str(64 * 1024)))

# FIX #1: WebSocket auth gate.
# Set S43_WS_REQUIRE_AUTH=true in production once the dashboard frontend
# sends {"type":"auth","payload":{"token":"..."}} as its first message.
# Default is false so existing local dev flow is not broken.
WS_REQUIRE_AUTH: bool = (
    os.getenv("S43_WS_REQUIRE_AUTH", "false").lower().strip()
    in {"1", "true", "yes", "on"}
)

# JWT configuration — all values must come from server environment.
# Never accept an algorithm from the incoming token header.
JWT_SECRET:    str = os.getenv("S43_JWT_SECRET",    "")
JWT_ALGORITHM: str = os.getenv("S43_JWT_ALGORITHM", "HS256")
JWT_ISSUER:    str = os.getenv("S43_JWT_ISSUER",    "sentinel-43")
JWT_AUDIENCE:  str = os.getenv("S43_JWT_AUDIENCE",  "sentinel-43-dashboard")

# Must match bootstrap.py APPROVED_JWT_ALGORITHMS.
# HS256 only for initial deployment — add RS256 when key rotation is needed.
_APPROVED_ALGORITHMS: frozenset[str] = frozenset({"HS256"})

# Roles that are allowed to approve or veto actions.
_APPROVED_ROLES: frozenset[str] = frozenset({"operator", "admin"})

START_TIME: float = time.time()

LOCAL_TEST_ENVIRONMENTS: frozenset[str] = frozenset(
    {"development", "dev", "local", "test"}
)

TEST_INJECTION_ENABLED: bool = (
    os.getenv("S43_ENABLE_TEST_INJECTION", "false").lower().strip()
    in {"1", "true", "yes", "on"}
)

MAX_DASHBOARD_ACTIONS: int = 500
ACTION_ID_RE = re.compile(r"^[A-Z0-9_-]{1,64}$")

# =============================================================================
# Module-level State
# =============================================================================

_action_store_lock = threading.Lock()
_action_store: dict[str, dict[str, Any]] = {}

# FIX #14: Vault record count now tracks actual records created only.
# _update_action_status no longer increments this counter — status changes
# (approve, veto) are not new records.
_vault_record_count: int = 0

# FIX #15: Per-client subscription tracking.
# Maps each WebSocket → set of channel names it has subscribed to.
# Only accessed from async context (single event-loop thread), no asyncio.Lock needed.
_dashboard_ws_clients: dict[WebSocket, set[str]] = {}

# FIX #7: Async heartbeat replaces background daemon thread.
_stop_heartbeat_event: asyncio.Event | None = None
_heartbeat_task: asyncio.Task[None] | None = None

# Watchtower state tracking — shared with heartbeat thread via lock.
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


# =============================================================================
# Auth Helpers
# =============================================================================

def _verify_jwt_token(token: str) -> dict[str, Any]:
    """
    Verify a JWT token and return the validated claims.

    The algorithm is always taken from server configuration, never from
    the incoming token header. An attacker sending "alg": "none" or
    switching algorithms cannot bypass signature verification.

    PyJWT's options={"require": [...]} forces claims to exist — not just
    validates them when present. A token with no expiration claim is
    rejected, not treated as non-expiring.

    Raises pyjwt.PyJWTError subclasses on any validation failure.
    Callers map these to HTTP 401/403 or WebSocket close(1008).
    """
    if not JWT_SECRET:
        raise pyjwt.InvalidKeyError("JWT signing key is not configured on this server")

    return pyjwt.decode(
        token,
        JWT_SECRET,
        algorithms=[JWT_ALGORITHM],       # Server config only — never from token
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
        options={
            "require": ["exp", "iss", "aud", "sub"],
        },
    )


def _get_operator(request: Request) -> str:
    """
    Extract and verify operator identity from the Authorization Bearer header.

    Replaces the previous unverified payload decode. PyJWT now validates:
      - Signature (using server-side key and algorithm)
      - Expiration (exp claim required and checked)
      - Issuer (iss claim required and matched)
      - Audience (aud claim required and matched)
      - Subject (sub claim required — becomes the operator identity)
      - Role (operator or admin — checked separately after decode)

    In LOCAL_TEST_ENVIRONMENTS with no token: returns "dev-operator" so
    local development keeps working without a configured JWT stack.

    In production with no valid token: raises HTTP 401 or 403.
    """
    auth = request.headers.get("Authorization", "").strip()

    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        if token:
            try:
                claims = _verify_jwt_token(token)
            except pyjwt.ExpiredSignatureError:
                raise HTTPException(status_code=401, detail="Token has expired")
            except pyjwt.InvalidIssuerError:
                raise HTTPException(status_code=401, detail="Invalid token issuer")
            except pyjwt.InvalidAudienceError:
                raise HTTPException(status_code=401, detail="Invalid token audience")
            except pyjwt.MissingRequiredClaimError as exc:
                raise HTTPException(
                    status_code=401, detail=f"Missing required claim: {exc}"
                )
            except pyjwt.InvalidKeyError:
                raise HTTPException(
                    status_code=503,
                    detail="JWT validation is not configured on this server",
                )
            except pyjwt.PyJWTError:
                raise HTTPException(status_code=401, detail="Invalid token")

            # Role check is separate from claim validation.
            role = str(claims.get("role") or claims.get("scope") or "").strip()
            if role not in _APPROVED_ROLES:
                raise HTTPException(
                    status_code=403,
                    detail="Operator role required",
                )

            subject = str(claims.get("sub") or "").strip()
            return subject if subject else f"bearer:{token[:16]}"

    env = SENTINEL_ENV.lower().strip()
    if env in LOCAL_TEST_ENVIRONMENTS:
        return "dev-operator"

    raise HTTPException(status_code=401, detail="Authentication required")




# =============================================================================
# Validation Helpers
# =============================================================================

def _validate_action_id(action_id: str) -> str:
    if not isinstance(action_id, str):
        raise HTTPException(status_code=422, detail="action_id must be a string")
    cleaned = action_id.strip().upper()
    if not ACTION_ID_RE.fullmatch(cleaned):
        raise HTTPException(status_code=422, detail="action_id has an invalid format")
    return cleaned


def _require_reason(body: dict[str, Any]) -> str:
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="request body must be an object")
    reason = body.get("reason")
    if not isinstance(reason, str):
        raise HTTPException(status_code=422, detail="reason must be a string")
    cleaned = reason.strip()
    if len(cleaned) < 10:
        raise HTTPException(
            status_code=422, detail="reason must contain at least 10 characters"
        )
    if len(cleaned) > 500:
        raise HTTPException(
            status_code=422, detail="reason must not exceed 500 characters"
        )
    return cleaned


# =============================================================================
# Action Store
# =============================================================================

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
        _vault_record_count += 1  # FIX #14: only incremented here

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
        actions = [copy.deepcopy(a) for a in _action_store.values()]
    return sorted(actions, key=lambda a: a["created_at"], reverse=True)[:safe_limit]


def _vault_records() -> int:
    with _action_store_lock:
        return _vault_record_count


def _update_action_status(
    action_id: str,
    *,
    allowed_statuses: set[str],
    new_status: str,
    reason: str,
    operator: str,  # FIX #3: caller supplies real identity; no longer hardcoded
) -> dict[str, Any]:
    cleaned_id = _validate_action_id(action_id)

    with _action_store_lock:
        action = _action_store.get(cleaned_id)

        if action is None:
            raise HTTPException(status_code=404, detail="action not found")

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
        action["operator"] = operator
        # FIX #14: _vault_record_count is NOT incremented on status changes.

        return copy.deepcopy(action)


# =============================================================================
# WebSocket Broadcast
# =============================================================================

async def _broadcast_dashboard_event(
    event_type: str,
    payload: dict[str, Any],
    *,
    channel: str | None = None,
) -> None:
    """
    FIX #4:  asyncio.gather delivers to all clients concurrently.
             A slow or hung client no longer blocks delivery to others.

    FIX #15: When channel is specified, only clients subscribed to that channel
             receive the frame. Pass channel=None to reach all connected clients.

    FIX #20: Dropped clients are logged at DEBUG level instead of being silently
             discarded.
    """
    if not _dashboard_ws_clients:
        return

    targets = (
        [ws for ws, channels in _dashboard_ws_clients.items() if channel in channels]
        if channel is not None
        else list(_dashboard_ws_clients.keys())
    )

    if not targets:
        return

    frame = {"type": event_type, "payload": payload}

    results = await asyncio.gather(
        *[ws.send_json(frame) for ws in targets],
        return_exceptions=True,
    )

    for ws, result in zip(targets, results):
        if isinstance(result, Exception):
            logger.debug(
                "Dropped dead WebSocket client during %r broadcast: %s",
                event_type,
                result,
            )
            _dashboard_ws_clients.pop(ws, None)


# =============================================================================
# WebSocket Frame Reader
# =============================================================================

async def _receive_ws_message(websocket: WebSocket) -> dict[str, Any]:
    """
    FIX #5:  Reads as text and checks encoded byte length before parsing.
             Frames exceeding MAX_WS_FRAME_BYTES are rejected.

    FIX #12: Raises ValueError on malformed JSON so the caller can send an
             error frame and keep the connection alive instead of crashing out.
    """
    raw = await websocket.receive_text()

    if len(raw.encode("utf-8")) > MAX_WS_FRAME_BYTES:
        raise ValueError(
            f"WebSocket frame exceeds the {MAX_WS_FRAME_BYTES}-byte limit"
        )

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON in WebSocket frame: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValueError("WebSocket message must be a JSON object")

    return parsed


# =============================================================================
# Watchtower HTTP Helpers
# =============================================================================

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

    req = urllib.request.Request(
        url=url, data=data, headers=headers, method=method.upper()
    )

    try:
        with urllib.request.urlopen(req, timeout=WATCHTOWER_TIMEOUT) as response:
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
        return {"error": "watchtower_unreachable", "detail": str(exc)}


def watchtower_health_check() -> dict[str, Any]:
    result = _watchtower_request("GET", "/watchtower/health")
    reachable = "error" not in result
    with _watchtower_lock:
        _watchtower_last_status["reachable"] = reachable
        _watchtower_last_status["last_error"] = None if reachable else result
    return {"reachable": reachable, "url": WATCHTOWER_URL, "response": result}


def register_api_with_watchtower() -> dict[str, Any]:
    payload = {
        "module_id": APP_NAME,
        "module_type": "api",
        "version": APP_VERSION,
        "endpoint": os.getenv("S43_API_PUBLIC_URL", "http://s43-api:8000"),
        "capabilities": [
            "health", "ready", "status", "routes", "metrics",
            "core_bridge", "watchtower_bridge", "remote_gateway",
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


def send_api_heartbeat(status: str = "online") -> dict[str, Any]:
    """
    FIX #10: Accepts a status parameter.
    Shutdown lifespan passes "stopping" so the final heartbeat does not
    report "online" while the process is exiting.
    """
    payload = {
        "module_id": APP_NAME,
        "status": status,
        "metrics": {
            "uptime_seconds": uptime_seconds(),
            "timestamp": utc_now(),
        },
        "message": f"Sentinel-43 API heartbeat: {status}",
    }
    result = _watchtower_request("POST", "/watchtower/modules/heartbeat", payload)
    ok = "error" not in result
    with _watchtower_lock:
        _watchtower_last_status["reachable"] = ok
        if ok:
            _watchtower_last_status["last_heartbeat_ts"] = utc_now()
        _watchtower_last_status["last_error"] = None if ok else result
    return {"heartbeat_sent": ok, "watchtower_url": WATCHTOWER_URL, "response": result}


def report_dependency_to_watchtower(
    name: str,
    status: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {"name": name, "status": status, "details": details or {}}
    return _watchtower_request("POST", "/watchtower/dependencies/report", payload)


# =============================================================================
# Async Heartbeat Loop  (FIX #7 — replaces background daemon thread)
# =============================================================================

async def _async_heartbeat_loop() -> None:
    """
    FIX #7:  Runs on the main event loop as an asyncio Task.
             _broadcast_dashboard_event can be awaited directly without
             scheduling across thread boundaries.

    FIX #8:  Broadcasts watchtower_state only on reachability transitions,
             not on every tick. Prevents the dashboard log from becoming
             a scrolling wall of "still alive" messages.

    FIX #9:  Dependency state is reported and broadcast from the same loop
             when the heartbeat detects a state change.
    """
    assert _stop_heartbeat_event is not None
    prev_reachable: bool | None = None

    while not _stop_heartbeat_event.is_set():
        # Wait for the heartbeat interval or a stop signal, whichever comes first.
        try:
            await asyncio.wait_for(
                _stop_heartbeat_event.wait(),
                timeout=float(WATCHTOWER_HEARTBEAT_SECONDS),
            )
            break  # Stop event fired — exit cleanly.
        except asyncio.TimeoutError:
            pass  # Normal — interval elapsed.

        if _stop_heartbeat_event.is_set():
            break

        try:
            result = await asyncio.to_thread(send_api_heartbeat)
            reachable = result.get("heartbeat_sent", False)

            # FIX #8: Broadcast only on transition.
            if prev_reachable is None or reachable != prev_reachable:
                prev_reachable = reachable
                await _broadcast_dashboard_event(
                    "watchtower_state",
                    {
                        "reachable": reachable,
                        "url": WATCHTOWER_URL,
                        "timestamp": utc_now(),
                    },
                    channel="watchtower",
                )

            # FIX #9: Broadcast dependency state on every successful heartbeat.
            if reachable:
                await _broadcast_dashboard_event(
                    "dependency_state",
                    {
                        "name": "watchtower",
                        "status": "online",
                        "timestamp": utc_now(),
                    },
                    channel="dependencies",
                )

        except Exception as exc:
            logger.warning("Heartbeat loop error: %s", exc)


# =============================================================================
# Lifespan
# =============================================================================

@asynccontextmanager
async def lifespan(api: FastAPI):
    global _stop_heartbeat_event, _heartbeat_task

    bootstrap_expectations()

    await asyncio.to_thread(register_api_with_watchtower)
    await asyncio.to_thread(send_api_heartbeat)
    await asyncio.to_thread(
        report_dependency_to_watchtower,
        "sentinel-43-api",
        "online",
        {"version": APP_VERSION, "environment": SENTINEL_ENV},
    )

    # FIX #7: Async task instead of daemon thread.
    _stop_heartbeat_event = asyncio.Event()
    _heartbeat_task = asyncio.create_task(
        _async_heartbeat_loop(), name="sentinel43-api-heartbeat"
    )

    yield

    # FIX #10: Signal the heartbeat task to stop and wait for it to exit.
    if _stop_heartbeat_event is not None:
        _stop_heartbeat_event.set()
    if _heartbeat_task is not None:
        try:
            await asyncio.wait_for(_heartbeat_task, timeout=5.0)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            _heartbeat_task.cancel()

    # FIX #10: Report "stopping" — not "online" — as the final heartbeat.
    await asyncio.to_thread(send_api_heartbeat, "stopping")


# =============================================================================
# Root Router
# =============================================================================

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


@root_router.get("/actions")
def dashboard_actions(limit: int = 250) -> list[dict[str, Any]]:
    return _list_actions(limit)


@root_router.get("/vault/stats")
def dashboard_vault_stats() -> dict[str, Any]:
    return {"records": _vault_records(), "timestamp": utc_now()}


@root_router.post("/actions/test-inject")
async def dashboard_test_inject() -> dict[str, Any]:
    """
    Create one fixed synthetic incident for local end-to-end testing.
    This route must never be enabled in production.
    Requires both SENTINEL_ENV in LOCAL_TEST_ENVIRONMENTS and
    S43_ENABLE_TEST_INJECTION=true.
    """
    environment = SENTINEL_ENV.lower().strip()
    if environment not in LOCAL_TEST_ENVIRONMENTS or not TEST_INJECTION_ENABLED:
        raise HTTPException(status_code=403, detail="test injection is disabled")

    action = _store_action(_create_synthetic_action())

    await _broadcast_dashboard_event("action_created", {"action": action})
    await _broadcast_dashboard_event("vault_stats", {"records": _vault_records()})

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
    request: Request,
) -> dict[str, Any]:
    reason = _require_reason(body)
    operator = _get_operator(request)  # FIX #2 / #3

    action = _update_action_status(
        action_id,
        allowed_statuses={"STAGED"},
        new_status="APPROVED",
        reason=reason,
        operator=operator,
    )

    await _broadcast_dashboard_event("action_status_changed", {"action": action})
    await _broadcast_dashboard_event("vault_stats", {"records": _vault_records()})

    return {"ok": True, "action": action, "timestamp": utc_now()}


@root_router.post("/actions/{action_id}/veto")
async def dashboard_veto_action(
    action_id: str,
    body: dict[str, Any],
    request: Request,
) -> dict[str, Any]:
    reason = _require_reason(body)
    operator = _get_operator(request)  # FIX #2 / #3

    action = _update_action_status(
        action_id,
        allowed_statuses={"PENDING", "STAGED"},
        new_status="VETOED",
        reason=reason,
        operator=operator,
    )

    await _broadcast_dashboard_event("action_status_changed", {"action": action})
    await _broadcast_dashboard_event("vault_stats", {"records": _vault_records()})

    return {"ok": True, "action": action, "timestamp": utc_now()}


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan)

# FIX #11: Origins read from _ALLOWED_ORIGINS (environment-driven, not hardcoded).
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(_ALLOWED_ORIGINS),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# WebSocket Endpoint
# =============================================================================

@app.websocket("/ws")
async def dashboard_websocket(websocket: WebSocket) -> None:
    """
    Dashboard WebSocket bridge.

    FIX #1:  Origin validated against _ALLOWED_ORIGINS before the upgrade
             is accepted. Rejected connections receive close code 1008.

    FIX #5:  All incoming frames are read via _receive_ws_message(), which
             enforces MAX_WS_FRAME_BYTES before JSON parsing.

    FIX #6:  New connections are rejected when _dashboard_ws_clients is at
             MAX_WS_CLIENTS capacity.

    FIX #12: ValueError from malformed JSON or oversized frames is caught
             inside the message loop. The handler sends an error frame and
             continues — the connection is not dropped.

    FIX #13: event_type is truncated to 64 chars before inclusion in error
             responses so arbitrary-length strings are not reflected back.

    FIX #15: Per-client subscription set is initialised on connect and
             populated via "subscribe" messages. Broadcasts respect it.

    Auth gate (S43_WS_REQUIRE_AUTH=true):
    When enabled the client must send:
        {"type": "auth", "payload": {"token": "<bearer-token>"}}
    as its first message before any subscriptions are processed.
    The dashboard frontend must send this frame on connection open when
    WS_REQUIRE_AUTH is active. Default is false for local dev compatibility.
    """

    # FIX #1: Reject connections from disallowed origins before accepting.
    origin = websocket.headers.get("origin", "")
    if _ALLOWED_ORIGINS and origin not in _ALLOWED_ORIGINS:
        await websocket.close(code=1008)
        return

    # FIX #6: Reject at capacity before accepting.
    if len(_dashboard_ws_clients) >= MAX_WS_CLIENTS:
        await websocket.accept()
        await websocket.send_json({
            "type": "error",
            "payload": {"error": "Server is at maximum dashboard capacity"},
        })
        await websocket.close(code=1008)
        return

    await websocket.accept()

    # FIX #1: Optional auth gate. Enabled via S43_WS_REQUIRE_AUTH=true.
    if WS_REQUIRE_AUTH:
        await websocket.send_json({
            "type": "auth_required",
            "payload": {
                "message": (
                    'Send {"type":"auth","payload":{"token":"<bearer>"}} to continue'
                ),
            },
        })
        try:
            auth_msg = await asyncio.wait_for(
                _receive_ws_message(websocket), timeout=15.0
            )
        except (asyncio.TimeoutError, ValueError, WebSocketDisconnect):
            await websocket.close(code=1008)
            return

        if auth_msg.get("type") != "auth":
            await websocket.send_json({
                "type": "error",
                "payload": {"error": "First message must be an auth frame"},
            })
            await websocket.close(code=1008)
            return

        token = str(auth_msg.get("payload", {}).get("token") or "").strip()
        if not token:
            await websocket.send_json({
                "type": "error",
                "payload": {"error": "Token missing from auth message"},
            })
            await websocket.close(code=1008)
            return

        # Verify the JWT using the same logic as HTTP endpoints.
        try:
            ws_claims = _verify_jwt_token(token)
        except pyjwt.ExpiredSignatureError:
            await websocket.send_json({
                "type": "error",
                "payload": {"error": "Token has expired"},
            })
            await websocket.close(code=1008)
            return
        except pyjwt.InvalidKeyError:
            await websocket.send_json({
                "type": "error",
                "payload": {"error": "JWT validation is not configured on this server"},
            })
            await websocket.close(code=1008)
            return
        except pyjwt.PyJWTError:
            await websocket.send_json({
                "type": "error",
                "payload": {"error": "Invalid token"},
            })
            await websocket.close(code=1008)
            return

        role = str(ws_claims.get("role") or ws_claims.get("scope") or "").strip()
        if role not in _APPROVED_ROLES:
            await websocket.send_json({
                "type": "error",
                "payload": {"error": "Operator role required"},
            })
            await websocket.close(code=1008)
            return

        ws_operator = str(ws_claims.get("sub") or "").strip() or f"bearer:{token[:16]}"
        logger.debug("WebSocket authenticated: %s", ws_operator)

    # FIX #15: Register client with an empty subscription set.
    _dashboard_ws_clients[websocket] = set()

    try:
        await websocket.send_json({
            "type": "connected",
            "payload": {
                "status": "ok",
                "service": APP_NAME,
                "timestamp": utc_now(),
            },
        })

        while True:
            # FIX #5 / #12: Size-checked, error-raising frame reader.
            try:
                message = await _receive_ws_message(websocket)
            except ValueError as exc:
                # FIX #12: Bad frame — send error and stay alive.
                await websocket.send_json({
                    "type": "error",
                    "payload": {"error": str(exc)},
                })
                continue

            event_type = message.get("type")
            payload = message.get("payload")
            if not isinstance(payload, dict):
                payload = {}

            if event_type == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "payload": {"timestamp": utc_now()},
                })
                continue

            if event_type == "subscribe":
                # FIX #19: Cap channel string length before storing or echoing.
                channel = str(payload.get("channel") or "").strip()[:64]
                _dashboard_ws_clients[websocket].add(channel)

                await websocket.send_json({
                    "type": "subscribed",
                    "payload": {"channel": channel, "timestamp": utc_now()},
                })

                if channel == "actions":
                    await websocket.send_json({
                        "type": "actions_snapshot",
                        "payload": {"actions": _list_actions()},
                    })

                if channel == "vault":
                    await websocket.send_json({
                        "type": "vault_stats",
                        "payload": {"records": _vault_records()},
                    })

                continue

            if event_type == "unsubscribe":
                channel = str(payload.get("channel") or "").strip()[:64]
                _dashboard_ws_clients[websocket].discard(channel)
                await websocket.send_json({
                    "type": "unsubscribed",
                    "payload": {"channel": channel, "timestamp": utc_now()},
                })
                continue

            # FIX #13: Truncate event_type before reflecting in error response.
            safe_type = repr(str(event_type or "")[:64])
            await websocket.send_json({
                "type": "error",
                "payload": {"error": f"Unsupported WebSocket event: {safe_type}"},
            })

    except WebSocketDisconnect:
        return

    finally:
        _dashboard_ws_clients.pop(websocket, None)


# =============================================================================
# Watchtower Bridge Router
# =============================================================================

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


# =============================================================================
# Core Router
# =============================================================================

core_router = APIRouter(prefix="/core", tags=["core"])


@core_router.get("/status")
async def core_status() -> dict[str, Any]:
    await asyncio.to_thread(
        report_dependency_to_watchtower,
        "sentinel-43-core",
        "online",
        {"source": "api-core-status-route"},
    )
    # FIX #9: Broadcast dependency state change so the dashboard receives it
    # immediately rather than waiting for the next poll cycle.
    await _broadcast_dashboard_event(
        "dependency_state",
        {"name": "sentinel-43-core", "status": "online", "timestamp": utc_now()},
        channel="dependencies",
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
async def core_heartbeat() -> dict[str, Any]:
    result = await asyncio.to_thread(
        report_dependency_to_watchtower,
        "sentinel-43-core",
        "online",
        {
            "heartbeat_source": "api",
            "uptime_seconds": uptime_seconds(),
            "timestamp": utc_now(),
        },
    )
    # FIX #9: Broadcast on explicit core heartbeat.
    await _broadcast_dashboard_event(
        "dependency_state",
        {"name": "sentinel-43-core", "status": "online", "timestamp": utc_now()},
        channel="dependencies",
    )
    return {
        "service": "s43_core",
        "heartbeat": "sent",
        "watchtower_response": result,
        "timestamp": utc_now(),
    }


# =============================================================================
# Rules Router
# =============================================================================

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


# =============================================================================
# Config Router
# =============================================================================

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


# =============================================================================
# Dependencies Router
# =============================================================================

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
        name, state, {"source": "api-dependency-report-route"}
    )
    return {
        "dependency": name,
        "state": state,
        "watchtower_response": result,
        "timestamp": utc_now(),
    }


# =============================================================================
# System Router
# =============================================================================

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
            route_list.append({"path": path, "name": name, "methods": methods})
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


# =============================================================================
# Health / Ready (top-level, no prefix)
# =============================================================================

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
    return {"status": "ready", "service": APP_NAME}


# =============================================================================
# API Prefix Compatibility Router
# =============================================================================

api_router = APIRouter(prefix="/api", tags=["api-compat"])


@api_router.get("/ready")
def compat_api_ready() -> dict[str, str]:
    return ready()


@api_router.get("/status")
def compat_api_status() -> dict[str, Any]:
    return status()  # type: ignore[name-defined]  # resolved via root_router


@api_router.get("/version")
def compat_api_version() -> dict[str, Any]:
    return version()  # type: ignore[name-defined]


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


# =============================================================================
# Status / Version (root-level, used by compat router above)
# =============================================================================

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


# =============================================================================
# Register Routers
# =============================================================================

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


# =============================================================================
# Error Handling
# =============================================================================

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
