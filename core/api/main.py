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
# Sentinel-43\u2122
# Original Work and Protected Intellectual Property.
# =============================================================================
from __future__ import annotations
import asyncio
import copy
import json
import logging
import os
import re
import secrets
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
from ..monitoring.watchtower_client import (
    WATCHTOWER_URL,
    WATCHTOWER_TIMEOUT,
    watchtower_request as _canonical_watchtower_request,
)
from ..security.jwt_constants import APPROVED_JWT_ALGORITHMS
from fastapi import (
    APIRouter,
    FastAPI,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from ..bootstrap import bootstrap_expectations
from ..logging.health_check_filter import install_health_check_access_filter
from .routers.audit import router as audit_router
from .routers.auth import router as auth_router
# core/api/routers/bootstrap.py is a THIRD, unrelated module also named
# bootstrap — see the naming note in core/bootstrap.py. This one is the
# first-run admin account setup router (GET /bootstrap/status,
# POST /bootstrap/admin), not startup expectations. Aliased to avoid
# colliding with bootstrap_expectations imported above.
from .routers.users import router as users_router
from .routers.bootstrap import router as bootstrap_router
from .routers.remote_gateway import router as remote_gateway_router
from .routers.routers import router as watchgate_router

logger = logging.getLogger(__name__)

# =============================================================================
# Env helpers
# =============================================================================
def _env_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()

def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError:
        logger.warning("Invalid int for %s=%r; using default %s", name, raw, default)
        return default

def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw.strip())
    except ValueError:
        logger.warning("Invalid float for %s=%r; using default %s", name, raw, default)
        return default

def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}

def _env_any_bool(names: tuple[str, ...], default: bool = False) -> bool:
    for name in names:
        raw = os.getenv(name)
        if raw is not None:
            return raw.strip().lower() in {"1", "true", "yes", "on"}
    return default

def _env_frozenset(name: str, default: str = "") -> frozenset[str]:
    raw = os.getenv(name, default)
    return frozenset(o.strip() for o in raw.split(",") if o.strip())

# =============================================================================
# Configuration
# =============================================================================
APP_NAME    = "sentinel-43-api"
APP_VERSION = _env_str("SENTINEL_VERSION", "0.1.0")
SENTINEL_ENV = _env_str("SENTINEL_ENV", "production")

WATCHTOWER_HEARTBEAT_SECONDS = _env_int("S43_WATCHTOWER_HEARTBEAT_SECONDS", 15)

_ALLOWED_ORIGINS: frozenset[str] = _env_frozenset(
    "S43_ALLOWED_ORIGINS",
    "http://127.0.0.1:5500,http://localhost:5500,"
    "http://127.0.0.1:8000,http://localhost:8000",
)

MAX_WS_CLIENTS     = _env_int("S43_MAX_WS_CLIENTS", 50)
MAX_WS_FRAME_BYTES = _env_int("S43_MAX_WS_FRAME_BYTES", 64 * 1024)
WS_REQUIRE_AUTH = _env_bool("S43_WS_REQUIRE_AUTH", True)

JWT_SECRET    = _env_str("S43_JWT_SECRET")
JWT_ALGORITHM = _env_str("S43_JWT_ALGORITHM", "HS256")

_APPROVED_ALGORITHMS: frozenset[str] = APPROVED_JWT_ALGORITHMS

START_TIME: float = time.time()

LOCAL_TEST_ENVIRONMENTS: frozenset[str] = frozenset(
    {"development", "dev", "local", "test"}
)
TEST_INJECTION_ENABLED: bool = _env_bool("S43_ENABLE_TEST_INJECTION", False)

MAX_DASHBOARD_ACTIONS = 500
ACTION_ID_RE = re.compile(r"^[A-Z0-9_-]{1,64}$")

# =============================================================================
# Optional module-level singletons
# =============================================================================
_monitoring_manager: Any | None = None
try:
    from core.monitoring import MonitoringManager, WatchtowerConfig
    _monitoring_manager = MonitoringManager(
        WatchtowerConfig.default_sentinel_octagon("sentinel43-api")
    )
    logger.info("MonitoringManager created (will start in lifespan)")
except Exception as _mm_exc:
    logger.warning("MonitoringManager unavailable: %s -- running without it", _mm_exc)

_orchestrator:    Any | None               = None
_sparta_instance: Any | None               = None
_sparta_task:     asyncio.Task | None      = None  # type: ignore[type-arg]
_fenrir_instance: Any | None               = None

# _fenrir_task is no longer used \u2014 FenrirHunter manages its own internal task.
# Kept here for backward compatibility with any tooling that checks this name.
_fenrir_task:     asyncio.Task | None      = None  # type: ignore[type-arg]

# =============================================================================
# Module-level state
# =============================================================================
_action_store_lock = threading.Lock()
_action_store: dict[str, dict[str, Any]] = {}
_vault_record_count: int = 0

_dashboard_ws_clients: dict[WebSocket, set[str]] = {}

_stop_heartbeat_event: asyncio.Event | None = None
_heartbeat_task: asyncio.Task[None] | None = None

_watchtower_lock = threading.Lock()
_watchtower_last_status: dict[str, Any] = {
    "reachable":        False,
    "registered":       False,
    "last_register_ts": None,
    "last_heartbeat_ts": None,
    "last_error":       None,
}

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def uptime_seconds() -> float:
    return round(time.time() - START_TIME, 3)

# =============================================================================
# Auth helpers
#
# JWT verification itself lives in core.api.routers.auth.verify_jwt_token() \u2014
# this module no longer keeps its own copy. _get_operator() and
# dashboard_websocket() both import and call that function directly.
# =============================================================================
async def _get_operator(
    request: Request,
    *,
    allow_local_fallback: bool = True,
) -> str:
    auth = request.headers.get("Authorization", "").strip()
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        if token:
            from .routers.auth import (
                PASSWORD_HEADER_NAME,
                legacy_auth_is_rejected,
                note_legacy_auth,
                resolve_session_subject,
                reverify_password,
                verify_jwt_token,
            )

            # verify_jwt_token() validates signature, claims, and role, and
            # raises the appropriate HTTPException (401/403/503) itself.
            claims = verify_jwt_token(token)

            subject = str(claims.get("sub") or "").strip()
            subject = subject if subject else f"bearer:{token[:16]}"

            # Phase B (beta-execution): a session-bound token whose sid names a
            # live session authenticates by itself. resolve_session_subject()
            # raises 401 if the session is dead / owner disabled.
            resolved = await resolve_session_subject(claims)
            if resolved is not None:
                return resolved[0]

            # Legacy path: old-style token still needs the per-request password.
            if legacy_auth_is_rejected():
                raise HTTPException(
                    status_code=401,
                    detail="Legacy authentication is no longer accepted. Log in again.",
                )
            note_legacy_auth("dashboard")
            password = request.headers.get(PASSWORD_HEADER_NAME, "")
            if not password:
                raise HTTPException(status_code=401, detail="Password required")
            if not await reverify_password(subject, password):
                raise HTTPException(status_code=401, detail="Invalid password")

            return subject

    if allow_local_fallback and SENTINEL_ENV.lower() in LOCAL_TEST_ENVIRONMENTS:
        return "dev-operator"

    raise HTTPException(status_code=401, detail="Authentication required")


async def _require_operator(request: Request) -> str:
    """
    Require explicit operator authentication.

    Unlike _get_operator(), this does not allow the development/local/test
    fallback. Use this for endpoints that must never become unauthenticated
    just because SENTINEL_ENV is permissive.
    """
    return await _get_operator(request, allow_local_fallback=False)


def _require_fenrir_service_token(request: Request) -> None:
    """
    Internal-service authentication for /internal/events/broadcast.

    This route has exactly one caller: FenrirHunter
    (core/detection/feniri_hunter.py), which sends
    `Authorization: Bearer <S43_FENRIR_API_TOKEN>` and never an operator
    JWT or X-S43-Password header \u2014 those belong to the dashboard's
    human-operator auth model, not a machine caller. The route previously
    called _require_operator() here, which meant every real call from
    Fenrir was silently rejected with 401 (missing X-S43-Password) before
    the bearer token was ever inspected \u2014 the dashboard-broadcast half of
    Fenrir's reporting has effectively never worked. This checks the
    dedicated shared-secret service token instead, with a constant-time
    comparison, and fails closed if the token isn't configured at all.
    """
    expected = _env_str("S43_FENRIR_API_TOKEN")
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Internal service authentication is not configured on this server.",
        )

    auth = request.headers.get("Authorization", "").strip()
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")

    token = auth[7:].strip()
    if not token or not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Invalid service token")


def _is_local_environment() -> bool:
    return SENTINEL_ENV.lower() in LOCAL_TEST_ENVIRONMENTS


def _validate_security_config() -> None:
    """
    Fail closed when auth is misconfigured.

    Public/release environments must not start without JWT validation and
    WebSocket auth enabled. Local development can still run with explicit
    development/local/test environment settings.
    """
    algorithm = JWT_ALGORITHM.strip()

    if algorithm not in _APPROVED_ALGORITHMS:
        raise RuntimeError(
            f"S43_JWT_ALGORITHM={algorithm!r} is not approved; "
            f"allowed={sorted(_APPROVED_ALGORITHMS)}"
        )

    if WS_REQUIRE_AUTH and not JWT_SECRET:
        raise RuntimeError(
            "S43_WS_REQUIRE_AUTH=true but S43_JWT_SECRET is not configured"
        )

    if not _is_local_environment():
        if not JWT_SECRET:
            raise RuntimeError(
                "Production Sentinel-43 API requires S43_JWT_SECRET"
            )
        if not WS_REQUIRE_AUTH:
            raise RuntimeError(
                "Production Sentinel-43 API requires S43_WS_REQUIRE_AUTH=true"
            )
        # F-TLS-1 (beta-execution Phase 2): a browser-facing CORS origin over
        # plain http:// means the refresh cookie / access token cross the wire
        # in cleartext. Loopback origins are exempt (browsers treat
        # http://localhost as a secure context). Opt out for a TLS-terminating
        # proxy on a trusted private network with S43_ALLOW_INSECURE_ORIGINS=true.
        if not _env_bool("S43_ALLOW_INSECURE_ORIGINS"):
            _loopback = re.compile(r"^http://(localhost|127\.0\.0\.1)(:\d+)?$")
            insecure = sorted(
                o for o in _ALLOWED_ORIGINS
                if o.startswith("http://") and not _loopback.match(o)
            )
            if insecure:
                raise RuntimeError(
                    "Non-local Sentinel-43 API requires HTTPS origins in "
                    f"S43_ALLOWED_ORIGINS; found plaintext: {insecure}. Put the "
                    "API behind a TLS terminator and use https:// origins, or "
                    "set S43_ALLOW_INSECURE_ORIGINS=true for a proxy on a "
                    "trusted private network."
                )

        # P0-1 (Argon2id migration): a legacy SHA-256 S43_OPERATOR_PASSWORD_HASH
        # must never be accepted outside local/dev/test. Checked at startup —
        # not first login attempt — so a misconfigured non-local deployment
        # never comes up at all. No dual-scheme grace period: a value that
        # isn't a well-formed Argon2id hash is rejected the same way whether
        # it's a legacy SHA-256 digest, empty, or garbage.
        operator_hash = os.getenv("S43_OPERATOR_PASSWORD_HASH", "").strip()
        if operator_hash:
            from .routers.auth import _valid_argon2_hash

            if not _valid_argon2_hash(operator_hash):
                raise RuntimeError(
                    "S43_OPERATOR_PASSWORD_HASH is not a well-formed Argon2id "
                    "hash. The legacy SHA-256 break-glass hash is no longer "
                    "accepted outside local/dev/test environments. This "
                    "requires rotating the break-glass password (the old "
                    "hash cannot be converted without the original "
                    "plaintext) — generate a new one with: "
                    "python -m core.cli.generate_secrets --password-hash"
                )


# =============================================================================
# Validation helpers
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
        raise HTTPException(status_code=422, detail="reason must be at least 10 characters")
    if len(cleaned) > 500:
        raise HTTPException(status_code=422, detail="reason must not exceed 500 characters")
    return cleaned

# =============================================================================
# Action store
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
    safe = copy.deepcopy(action)
    with _action_store_lock:
        _action_store[safe["id"]] = safe
        _vault_record_count += 1
        if len(_action_store) > MAX_DASHBOARD_ACTIONS:
            oldest = sorted(
                _action_store.items(), key=lambda kv: kv[1]["created_at"]
            )[: len(_action_store) - MAX_DASHBOARD_ACTIONS]
            for aid, _ in oldest:
                del _action_store[aid]
        return copy.deepcopy(safe)

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
    operator: str,
) -> dict[str, Any]:
    cleaned_id = _validate_action_id(action_id)
    with _action_store_lock:
        action = _action_store.get(cleaned_id)
        if action is None:
            raise HTTPException(status_code=404, detail="action not found")
        if action["status"] not in allowed_statuses:
            raise HTTPException(
                status_code=409,
                detail=f"action status is {action['status']}; expected one of {sorted(allowed_statuses)}",
            )
        action["status"]          = new_status
        action["decision_reason"] = reason
        action["operator"]        = operator
        return copy.deepcopy(action)

# =============================================================================
# WebSocket broadcast
# =============================================================================
async def _broadcast_dashboard_event(
    event_type: str,
    payload: dict[str, Any],
    *,
    channel: str | None = None,
) -> None:
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
            logger.debug("Dropped dead WebSocket during %r broadcast: %s", event_type, result)
            _dashboard_ws_clients.pop(ws, None)

# =============================================================================
# WebSocket frame reader
# =============================================================================
async def _receive_ws_message(websocket: WebSocket) -> dict[str, Any]:
    raw = await websocket.receive_text()
    if len(raw.encode("utf-8")) > MAX_WS_FRAME_BYTES:
        raise ValueError(f"WebSocket frame exceeds {MAX_WS_FRAME_BYTES}-byte limit")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON in WebSocket frame: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("WebSocket message must be a JSON object")
    return parsed

# =============================================================================
# Watchtower HTTP helpers
# =============================================================================
def _watchtower_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # Delegates to the canonical client (core/monitoring/watchtower_client.py,
    # DEFECT_INVENTORY.md D-15/D-16) so this, MonitoringManager's, and every
    # other internal caller's token handling, URL, and failure logging stay
    # in exactly one place instead of three copies that happen to agree today.
    return _canonical_watchtower_request(method, path, payload)

def watchtower_health_check() -> dict[str, Any]:
    result = _watchtower_request("GET", "/watchtower/health")
    reachable = "error" not in result
    with _watchtower_lock:
        _watchtower_last_status["reachable"]   = reachable
        _watchtower_last_status["last_error"]  = None if reachable else result
    return {"reachable": reachable, "url": WATCHTOWER_URL, "response": result}

def register_api_with_watchtower() -> dict[str, Any]:
    capabilities = [
        "health", "ready", "status", "routes", "metrics",
        "core_bridge", "watchtower_bridge", "remote_gateway",
        "remote_operations",
    ]
    if _monitoring_manager is not None:
        capabilities.append("monitoring_manager")
    if _sparta_instance is not None:
        capabilities.append("sparta_integrity_watchdog")
    if _env_bool("S43_JORM_ENABLED"):
        capabilities.append("jormungandr_audit")
    if _fenrir_instance is not None or _env_any_bool(
        ("S43_FENRIR_ENABLED", "SENTINEL_FENRIR_ENABLED", "FENRIR_ENABLED")
    ):
        capabilities.append("fenrir_hunter")
    try:
        from core.middleware import SentinelFirewall  # noqa: F401
        capabilities.append("sentinel_firewall")
    except ImportError:
        pass
    payload = {
        "module_id":   APP_NAME,
        "module_type": "api",
        "version":     APP_VERSION,
        "endpoint":    _env_str("S43_API_PUBLIC_URL", "http://s43-api:8000"),
        "capabilities": capabilities,
        "metadata": {
            "environment": SENTINEL_ENV,
            "started_ts":  START_TIME,
            "timestamp":   utc_now(),
        },
    }
    result = _watchtower_request("POST", "/watchtower/modules/register", payload)
    registered = "error" not in result
    with _watchtower_lock:
        _watchtower_last_status["reachable"]        = registered
        _watchtower_last_status["registered"]       = registered
        _watchtower_last_status["last_register_ts"] = utc_now() if registered else None
        _watchtower_last_status["last_error"]       = None if registered else result
    return {"registered": registered, "watchtower_url": WATCHTOWER_URL, "response": result}

def send_api_heartbeat(status: str = "online") -> dict[str, Any]:
    payload = {
        "module_id": APP_NAME,
        "status":    status,
        "metrics":   {"uptime_seconds": uptime_seconds(), "timestamp": utc_now()},
        "message":   f"Sentinel-43 API heartbeat: {status}",
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
    return _watchtower_request(
        "POST", "/watchtower/dependencies/report",
        {"name": name, "status": status, "details": details or {}},
    )

# =============================================================================
# Async heartbeat loop
# =============================================================================
async def _async_heartbeat_loop() -> None:
    assert _stop_heartbeat_event is not None
    prev_reachable: bool | None = None
    while not _stop_heartbeat_event.is_set():
        try:
            await asyncio.wait_for(
                _stop_heartbeat_event.wait(),
                timeout=float(WATCHTOWER_HEARTBEAT_SECONDS),
            )
            break
        except asyncio.TimeoutError:
            pass
        if _stop_heartbeat_event.is_set():
            break
        try:
            result    = await asyncio.to_thread(send_api_heartbeat)
            reachable = result.get("heartbeat_sent", False)
            if prev_reachable is None or reachable != prev_reachable:
                prev_reachable = reachable
                await _broadcast_dashboard_event(
                    "watchtower_state",
                    {"reachable": reachable, "url": WATCHTOWER_URL, "timestamp": utc_now()},
                    channel="watchtower",
                )
            if reachable:
                await _broadcast_dashboard_event(
                    "dependency_state",
                    {"name": "watchtower", "status": "online", "timestamp": utc_now()},
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
    global _orchestrator, _sparta_instance, _sparta_task
    global _fenrir_instance

    _validate_security_config()
    bootstrap_expectations()

    # --- MonitoringManager ---
    if _monitoring_manager is not None:
        try:
            await asyncio.to_thread(_monitoring_manager.start)
            logger.info("MonitoringManager started")
        except Exception as exc:
            logger.error("MonitoringManager failed to start: %s", exc)
        try:
            from core.monitoring import set_monitoring_manager
            set_monitoring_manager(_monitoring_manager)
            logger.info("MonitoringManager wired into remote gateway")
        except Exception as exc:
            logger.warning("Could not wire MonitoringManager into remote gateway: %s", exc)

    # --- Remote gateway dispatch handlers (APPROVE/VETO mobile workflow) ---
    try:
        from .routers.remote_gateway import (
            register_dispatch_handler,
            RemoteEventType,
            RemoteEventActivationRequest,
        )

        async def _rg_approve_handler(body: RemoteEventActivationRequest) -> str:
            decision_id = str(body.payload.get("decision_id") or "").strip()
            action = _update_action_status(
                decision_id,
                allowed_statuses={"STAGED"},
                new_status="APPROVED",
                reason=body.reason,
                operator=body.operator_id,
            )
            if _orchestrator is not None:
                try:
                    await asyncio.to_thread(
                        _orchestrator.resolve_human_decision,
                        decision_id,
                        approved=True,
                        operator_id=body.operator_id,
                        reason=body.reason,
                    )
                except KeyError:
                    pass
            await _broadcast_dashboard_event("action_status_changed", {"action": action})
            return f"Decision {decision_id} approved via remote gateway by {body.operator_id}."

        async def _rg_veto_handler(body: RemoteEventActivationRequest) -> str:
            decision_id = str(body.payload.get("decision_id") or "").strip()
            action = _update_action_status(
                decision_id,
                allowed_statuses={"PENDING", "STAGED"},
                new_status="VETOED",
                reason=body.reason,
                operator=body.operator_id,
            )
            if _orchestrator is not None:
                try:
                    await asyncio.to_thread(
                        _orchestrator.resolve_human_decision,
                        decision_id,
                        approved=False,
                        operator_id=body.operator_id,
                        reason=body.reason,
                    )
                except KeyError:
                    pass
            await _broadcast_dashboard_event("action_status_changed", {"action": action})
            return f"Decision {decision_id} vetoed via remote gateway by {body.operator_id}."

        register_dispatch_handler(RemoteEventType.APPROVE_DECISION, _rg_approve_handler)
        register_dispatch_handler(RemoteEventType.VETO_DECISION, _rg_veto_handler)
        logger.info("Remote gateway APPROVE/VETO dispatch handlers registered.")
    except Exception as _rg_exc:
        logger.error("Remote gateway dispatch handler registration failed: %s", _rg_exc)

    # --- Optional: SpartaCore file integrity watchdog ---
    if _env_bool("S43_SPARTA_ENABLED"):
        try:
            from core.monitoring import SpartaCore, IntegrityConfig
            _watched_files: dict[str, str] = {}
            for key, val in os.environ.items():
                if key.startswith("S43_SPARTA_HASH_"):
                    file_key = key[len("S43_SPARTA_HASH_"):].lower().replace("_", "/")
                    _watched_files[file_key] = val
            if _watched_files:
                sparta_cfg       = IntegrityConfig.from_env(_watched_files)
                _sparta_instance = SpartaCore(sparta_cfg, monitoring_manager=_monitoring_manager)
                _sparta_task     = asyncio.create_task(
                    _sparta_instance.run(), name="sentinel43-sparta-watchdog"
                )
                logger.info("SpartaCore watchdog started: watching %d files", len(_watched_files))
            else:
                logger.warning(
                    "S43_SPARTA_ENABLED=true but no S43_SPARTA_HASH_* vars found; "
                    "watchdog not started"
                )
        except Exception as exc:
            logger.error("SpartaCore failed to start: %s", exc)

    # --- Optional: FenrirHunter (threat detection + statistical anomaly layer) ---
    if _env_any_bool(("S43_FENRIR_ENABLED", "SENTINEL_FENRIR_ENABLED", "FENRIR_ENABLED")):
        try:
            from core.detection.feniri_hunter import FenrirHunter
            _fenrir_instance = FenrirHunter()
            await _fenrir_instance.start()
            logger.info(
                "FenrirHunter started: node_id=%s min_severity=%s anomaly_zscore=%.1f",
                _fenrir_instance.config.node_id,
                _fenrir_instance.config.min_report_severity,
                _fenrir_instance.config.anomaly_zscore_threshold,
            )
        except Exception as exc:
            logger.error("Fenrir failed to start: %s", exc)

    # --- Optional: SystemOrchestrator (governance) ---
    if _env_bool("S43_GOVERNANCE_ENABLED"):
        try:
            from core.governance import build_orchestrator_from_settings

            class _Settings:
                env         = SENTINEL_ENV
                strict_mode = _env_bool("S43_GOVERNANCE_STRICT", True)
                data_dir    = _env_str("S43_DATA_DIR", "/var/sentinel43/data")
                audit_signing_key            = _env_str("S43_GOVERNANCE_SIGNING_KEY")
                audit_jsonl_path             = _env_str("S43_GOVERNANCE_JSONL_PATH")
                default_mode                 = _env_str("S43_GOVERNANCE_DEFAULT_MODE", "SHADOW")
                hash_device_ids              = _env_bool("S43_GOVERNANCE_HASH_DEVICE_IDS", False)
                velocity_window_seconds      = _env_int("S43_VELOCITY_WINDOW_SECONDS", 60)
                velocity_limit               = _env_int("S43_VELOCITY_LIMIT", 10)
                velocity_gc_interval_seconds = _env_int("S43_VELOCITY_GC_INTERVAL", 300)
                velocity_max_entries_per_user = _env_int("S43_VELOCITY_MAX_ENTRIES", 1000)

            _orchestrator = build_orchestrator_from_settings(
                _Settings(),
                monitoring_manager=_monitoring_manager,
            )
            logger.info(
                "SystemOrchestrator started (mode=%s jorm=%s)",
                _Settings.default_mode,
                _env_bool("S43_JORM_ENABLED"),
            )
        except Exception as exc:
            logger.error("SystemOrchestrator failed to start: %s", exc)

    # --- Watchtower registration + initial heartbeat ---
    await asyncio.to_thread(register_api_with_watchtower)
    await asyncio.to_thread(send_api_heartbeat)
    await asyncio.to_thread(
        report_dependency_to_watchtower,
        "sentinel-43-api", "online",
        {"version": APP_VERSION, "environment": SENTINEL_ENV},
    )

    # --- Heartbeat task ---
    _stop_heartbeat_event = asyncio.Event()
    _heartbeat_task = asyncio.create_task(
        _async_heartbeat_loop(), name="sentinel43-api-heartbeat"
    )

    yield

    # --- Shutdown ---
    if _stop_heartbeat_event is not None:
        _stop_heartbeat_event.set()
    if _heartbeat_task is not None:
        try:
            await asyncio.wait_for(_heartbeat_task, timeout=5.0)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            _heartbeat_task.cancel()

    if _fenrir_instance is not None:
        try:
            await asyncio.wait_for(_fenrir_instance.shutdown(), timeout=5.0)
            logger.info("FenrirHunter shutdown complete.")
        except asyncio.TimeoutError:
            logger.warning("FenrirHunter shutdown timed out.")
        except Exception as exc:
            logger.warning("FenrirHunter shutdown error: %s", exc)

    if _sparta_instance is not None:
        _sparta_instance.stop()
    if _sparta_task is not None:
        try:
            await asyncio.wait_for(_sparta_task, timeout=5.0)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            _sparta_task.cancel()

    await asyncio.to_thread(send_api_heartbeat, "stopping")

    if _monitoring_manager is not None:
        try:
            await asyncio.to_thread(_monitoring_manager.stop)
        except Exception as exc:
            logger.warning("MonitoringManager stop error: %s", exc)

# =============================================================================
# Root router
# =============================================================================
root_router = APIRouter(tags=["root"])

@root_router.get("/")
def root() -> dict[str, Any]:
    return {
        "service":        APP_NAME,
        "version":        APP_VERSION,
        "status":         "online",
        "watchtower_url": WATCHTOWER_URL,
        "uptime_seconds": uptime_seconds(),
        "timestamp":      utc_now(),
    }

@root_router.get("/actions")
async def dashboard_actions(request: Request, limit: int = 250) -> list[dict[str, Any]]:
    await _require_operator(request)
    return _list_actions(limit)

@root_router.get("/vault/stats")
async def dashboard_vault_stats(request: Request) -> dict[str, Any]:
    await _require_operator(request)
    return {"records": _vault_records(), "timestamp": utc_now()}

@root_router.post("/actions/test-inject")
async def dashboard_test_inject(request: Request) -> dict[str, Any]:
    """Synthetic incident injection \u2014 dev/test only, operator-gated."""
    if SENTINEL_ENV.lower() not in LOCAL_TEST_ENVIRONMENTS or not TEST_INJECTION_ENABLED:
        raise HTTPException(status_code=403, detail="test injection is disabled")
    await _require_operator(request)
    action = _store_action(_create_synthetic_action())
    await _broadcast_dashboard_event("action_created", {"action": action})
    await _broadcast_dashboard_event("vault_stats", {"records": _vault_records()})
    return {"ok": True, "action": action, "vault_records": _vault_records(), "timestamp": utc_now()}

@root_router.post("/actions/{action_id}/approve")
async def dashboard_approve_action(
    action_id: str, body: dict[str, Any], request: Request,
) -> dict[str, Any]:
    reason   = _require_reason(body)
    operator = await _require_operator(request)
    action = _update_action_status(
        action_id,
        allowed_statuses={"STAGED"},
        new_status="APPROVED",
        reason=reason,
        operator=operator,
    )
    decision_id = body.get("decision_id") or action.get("payload", {}).get("decision_id")
    if _orchestrator is not None and decision_id:
        try:
            await asyncio.to_thread(
                _orchestrator.resolve_human_decision,
                decision_id,
                approved=True,
                operator_id=operator,
                reason=reason,
            )
        except KeyError:
            logger.debug("approve_action: decision_id=%s not in pending reviews", decision_id)
    await _broadcast_dashboard_event("action_status_changed", {"action": action})
    await _broadcast_dashboard_event("vault_stats", {"records": _vault_records()})
    return {"ok": True, "action": action, "timestamp": utc_now()}

@root_router.post("/actions/{action_id}/veto")
async def dashboard_veto_action(
    action_id: str, body: dict[str, Any], request: Request,
) -> dict[str, Any]:
    reason   = _require_reason(body)
    operator = await _require_operator(request)
    action = _update_action_status(
        action_id,
        allowed_statuses={"PENDING", "STAGED"},
        new_status="VETOED",
        reason=reason,
        operator=operator,
    )
    decision_id = body.get("decision_id") or action.get("payload", {}).get("decision_id")
    if _orchestrator is not None and decision_id:
        try:
            await asyncio.to_thread(
                _orchestrator.resolve_human_decision,
                decision_id,
                approved=False,
                operator_id=operator,
                reason=reason,
            )
        except KeyError:
            logger.debug("veto_action: decision_id=%s not in pending reviews", decision_id)
    await _broadcast_dashboard_event("action_status_changed", {"action": action})
    await _broadcast_dashboard_event("vault_stats", {"records": _vault_records()})
    return {"ok": True, "action": action, "timestamp": utc_now()}

@root_router.get("/governance/pending")
async def governance_pending_reviews(request: Request) -> dict[str, Any]:
    await _require_operator(request)
    if _orchestrator is None:
        return {"enabled": False, "pending": [], "timestamp": utc_now()}
    return {
        "enabled": True,
        "pending": _orchestrator.list_pending_reviews(),
        "timestamp": utc_now(),
    }

# =============================================================================
# FastAPI application
# =============================================================================
app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(_ALLOWED_ORIGINS),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SentinelFirewall is a required security control. A failure to import,
# configure (FirewallConfig.from_env()), or register it must NOT leave the
# API silently serving requests unprotected. Outside an explicit
# development/local/test environment (SENTINEL_ENV), this is a fatal,
# fail-closed startup error -- the same posture as _validate_security_config().
# In a local/test environment it degrades to a loud error and continues, so a
# developer can still iterate without the firewall's config plumbing.
# To run without the firewall on purpose, set S43_FIREWALL_ENABLED=false
# (the middleware still mounts, as a pass-through) -- do not rely on this
# exception path.
try:
    from core.middleware import SentinelFirewall, FirewallConfig
    app.add_middleware(
        SentinelFirewall,
        config=FirewallConfig.from_env(),
        monitoring_manager=_monitoring_manager,
    )
    logger.info("SentinelFirewall middleware registered")
except Exception as _fw_exc:  # noqa: BLE001 - deliberately broad; re-raised below outside local envs
    if _is_local_environment():
        logger.error(
            "SentinelFirewall middleware failed to register (%s: %s) -- "
            "continuing WITHOUT the firewall because SENTINEL_ENV=%r is a "
            "local/test environment. This would be a fatal error in production.",
            type(_fw_exc).__name__, _fw_exc, SENTINEL_ENV,
        )
    else:
        raise RuntimeError(
            f"SentinelFirewall middleware failed to register "
            f"({type(_fw_exc).__name__}: {_fw_exc}). The firewall is a "
            f"required security control outside development/local/test "
            f"environments; refusing to start unprotected."
        ) from _fw_exc

# --- Transport-security response headers (beta-execution Phase 2, F-TLS-1) ---
# HSTS (only when the request actually arrived over HTTPS, or via a trusted
# proxy that says so), plus static hardening headers. Cookies stay Secure
# unconditionally regardless (AUTH_TLS_POSTURE_PASS5A §8). Added AFTER the
# firewall so it also decorates the firewall's own block responses.
from .middleware.security_headers import SecurityHeadersMiddleware
app.add_middleware(SecurityHeadersMiddleware)

# --- Explicit Host allow-list (beta-execution Phase 2) ---
# S43_TRUSTED_HOSTS is a comma-separated list of the exact Host values this
# deployment answers on (e.g. "beta.example.com,.example.com"). Unset => no
# Host check (dev / behind a proxy that already validates Host). Probe paths
# (/health, /ready, ...) are always exempt so Kubernetes / Docker / LB health
# checks — which send Host: <podIP> or Host: localhost — keep working
# (see TrustedHostGuard). In a non-local env an unset value is logged loudly.
from .middleware.security_headers import TrustedHostGuard
app.add_middleware(TrustedHostGuard)
_TRUSTED_HOSTS: list[str] = [
    h.strip() for h in _env_str("S43_TRUSTED_HOSTS").split(",") if h.strip()
]
if _TRUSTED_HOSTS:
    logger.info("Host allow-list active: %s (probe paths exempt)", _TRUSTED_HOSTS)
elif not _is_local_environment():
    logger.warning(
        "S43_TRUSTED_HOSTS is not set in a non-local environment — the API "
        "will answer on any Host header. Set it to this deployment's public "
        "hostname(s) for defence against Host-header attacks."
    )

# The /node router is part of the SpartaCore subsystem, which is opt-in
# (S43_SPARTA_ENABLED, default false — same gate as the file-integrity
# watchdog above and the k8s/compose defaults). Registering it only when
# Sparta is enabled keeps the default deployment's route surface unchanged.
# When enabled, /node/* is still fail-closed: every route except the coarse
# /node/health returns 503 until S43_SPARTA_NODE_TOKEN is set, then 401 for a
# wrong token (constant-time compare, per-client lockout).
if _env_bool("S43_SPARTA_ENABLED"):
    try:
        from core.monitoring import SpartaCore as _SC, IntegrityConfig as _IC, create_node_router
        _node_router_sparta = _SC(
            _IC(
                watched_files={},
                node_signature="sentinel43-api",
                token_secret=_env_str("S43_SPARTA_TOKEN_SECRET"),
                node_api_token=_env_str("S43_SPARTA_NODE_TOKEN", ""),
            )
        )
        app.include_router(create_node_router(_node_router_sparta))
        logger.info("SpartaCore node API router registered at /node")
    except Exception as _nr_exc:
        logger.warning("SpartaCore node router not registered: %s", _nr_exc)

# =============================================================================
# Dashboard static file serving
# Serves sentinel_43_dashboard.html and all assets from dashboard/assets/.
# S43_DASHBOARD_DIR defaults to "dashboard" (relative to CWD / Docker WORKDIR).
# =============================================================================
DASHBOARD_DIR        = _env_str("S43_DASHBOARD_DIR", "dashboard")
DASHBOARD_ASSETS_DIR = os.path.join(DASHBOARD_DIR, "assets")
DASHBOARD_HTML       = os.path.join(DASHBOARD_DIR, "sentinel_43_dashboard.html")

if os.path.isdir(DASHBOARD_ASSETS_DIR):
    app.mount(
        "/assets",
        StaticFiles(directory=DASHBOARD_ASSETS_DIR),
        name="dashboard-assets",
    )
else:
    logger.warning(
        "Dashboard assets directory not found: %s -- /assets will 404", DASHBOARD_ASSETS_DIR
    )

@app.get("/dashboard", include_in_schema=False)
def serve_dashboard() -> FileResponse:
    return FileResponse(DASHBOARD_HTML)

@app.get("/dashboard.html", include_in_schema=False)
def serve_dashboard_html() -> FileResponse:
    return FileResponse(DASHBOARD_HTML)

# =============================================================================
# WebSocket endpoint
# =============================================================================
async def _ws_safe_close(
    websocket: WebSocket, code: int = 1008, reason: str = ""
) -> None:
    """
    Close a WebSocket, swallowing RuntimeError if already closed.
    Starlette/uvicorn raises RuntimeError when close() is attempted on a
    connection that was rejected before accept(), or when the client
    already disconnected. This helper guards every auth-rejection path.

    ``reason`` is a short machine string (e.g. "invalid_token",
    "invalid_password", "session_revoked", "token_expired",
    "origin_rejected", "capacity"). dashboard/assets/js/websocket.js
    classifies a 1008 close as an auth failure vs a generic policy error by
    matching this string (finding #6) \u2014 auth-related reasons contain one of
    auth|token|password|credential|session|login.
    """
    try:
        await websocket.close(code=code, reason=reason)
    except RuntimeError:
        pass
    except TypeError:  # very old starlette: close() had no reason kwarg
        try:
            await websocket.close(code=code)
        except RuntimeError:
            pass


def _ws_session_recheck_seconds() -> int:
    return _env_int("S43_WS_SESSION_RECHECK_SECONDS", 60)


@app.websocket("/ws")
async def dashboard_websocket(websocket: WebSocket) -> None:
    origin = websocket.headers.get("origin", "")
    if _ALLOWED_ORIGINS and origin and origin not in _ALLOWED_ORIGINS:
        await _ws_safe_close(websocket, reason="origin_rejected")
        return

    if len(_dashboard_ws_clients) >= MAX_WS_CLIENTS:
        await websocket.accept()
        await websocket.send_json({
            "type": "error",
            "payload": {"error": "Server is at maximum dashboard capacity"},
        })
        await _ws_safe_close(websocket, reason="capacity")
        return

    await websocket.accept()

    # Session-bound WS connections carry these so the message loop can drop
    # the connection when the access token expires or the session is revoked
    # mid-stream (beta-execution Phase B: "no infinite WS session").
    ws_sid: str | None = None
    ws_exp: float | None = None

    if WS_REQUIRE_AUTH:
        await websocket.send_json({
            "type": "auth_required",
            "payload": {
                "message": (
                    'Send {"type":"auth","payload":{"token":"<bearer>"}} to continue'
                )
            },
        })
        try:
            auth_msg = await asyncio.wait_for(
                _receive_ws_message(websocket), timeout=15.0
            )
        except WebSocketDisconnect:
            return
        except (asyncio.TimeoutError, ValueError):
            await _ws_safe_close(websocket, reason="auth_timeout")
            return

        if auth_msg.get("type") != "auth":
            await websocket.send_json({
                "type": "error",
                "payload": {"error": "First message must be an auth frame"},
            })
            await _ws_safe_close(websocket, reason="invalid_auth_frame")
            return

        token = str(auth_msg.get("payload", {}).get("token") or "").strip()
        if not token:
            await websocket.send_json({
                "type": "error",
                "payload": {"error": "Token missing"},
            })
            await _ws_safe_close(websocket, reason="invalid_token")
            return

        from .routers.auth import (
            legacy_auth_is_rejected,
            note_legacy_auth,
            resolve_session_subject,
            reverify_password,
            verify_jwt_token,
        )

        try:
            # verify_jwt_token() validates signature, claims, and role, and
            # raises HTTPException(401/403/503) itself on any failure.
            ws_claims = verify_jwt_token(token)
        except HTTPException as exc:
            await websocket.send_json({"type": "error", "payload": {"error": str(exc.detail)}})
            await _ws_safe_close(websocket, reason="invalid_token")
            return

        ws_subject = str(ws_claims.get("sub") or "").strip()

        # Phase B: a live session-bound token needs NO password frame.
        try:
            resolved = await resolve_session_subject(ws_claims)
        except HTTPException:
            await websocket.send_json({"type": "error", "payload": {"error": "Session is no longer valid"}})
            await _ws_safe_close(websocket, reason="session_revoked")
            return

        if resolved is not None:
            ws_sid = str(ws_claims.get("sid"))
            _exp = ws_claims.get("exp")
            ws_exp = float(_exp) if isinstance(_exp, (int, float)) else None
        else:
            # Legacy frame: {token, password}, password re-verified.
            if legacy_auth_is_rejected():
                await websocket.send_json({"type": "error", "payload": {"error": "Legacy authentication is no longer accepted. Log in again."}})
                await _ws_safe_close(websocket, reason="legacy_auth_rejected")
                return
            note_legacy_auth("websocket")
            ws_password = str(auth_msg.get("payload", {}).get("password") or "").strip()
            if not ws_password:
                await websocket.send_json({"type": "error", "payload": {"error": "Password missing"}})
                await _ws_safe_close(websocket, reason="invalid_password")
                return
            try:
                ws_reverified = await reverify_password(ws_subject, ws_password)
            except HTTPException:
                # reverify_password() raises 503 when the DB-backed auth path
                # is blocked and break-glass is not explicitly armed — that
                # is a platform outage, not a wrong password. Close with a
                # reason that _reasonIndicatesAuthFailure() (websocket.js)
                # will NOT classify as an auth failure.
                await websocket.send_json({"type": "error", "payload": {"error": "Authentication service is temporarily unavailable"}})
                await _ws_safe_close(websocket, reason="service_unavailable")
                return
            if not ws_reverified:
                await websocket.send_json({"type": "error", "payload": {"error": "Invalid password"}})
                await _ws_safe_close(websocket, reason="invalid_password")
                return

    _dashboard_ws_clients[websocket] = set()

    async def _session_still_valid() -> tuple[bool, str]:
        """(ok, reason). Cheap re-check for a session-bound connection."""
        if ws_exp is not None and time.time() >= ws_exp:
            return False, "token_expired"
        if ws_sid is None:
            return True, ""
        try:
            from .routers.auth import resolve_session_subject as _rss
            ok = await _rss({"sid": ws_sid, "sub": "x", "role": "operator"})
            return (ok is not None), ("" if ok is not None else "session_revoked")
        except HTTPException:
            return False, "session_revoked"
        except Exception:
            return True, ""  # transient DB error \u2014 don't drop the operator

    try:
        await websocket.send_json({
            "type": "connected",
            "payload": {"status": "ok", "service": APP_NAME, "timestamp": utc_now()},
        })

        while True:
            try:
                message = await asyncio.wait_for(
                    _receive_ws_message(websocket),
                    timeout=float(_ws_session_recheck_seconds()),
                )
            except asyncio.TimeoutError:
                ok, why = await _session_still_valid()
                if not ok:
                    await websocket.send_json({"type": "error", "payload": {"error": why}})
                    await _ws_safe_close(websocket, reason=why)
                    return
                continue
            except ValueError as exc:
                await websocket.send_json({"type": "error", "payload": {"error": str(exc)}})
                continue

            ok, why = await _session_still_valid()
            if not ok:
                await websocket.send_json({"type": "error", "payload": {"error": why}})
                await _ws_safe_close(websocket, reason=why)
                return

            event_type = message.get("type")
            payload    = message.get("payload")
            if not isinstance(payload, dict):
                payload = {}

            if event_type == "ping":
                await websocket.send_json({"type": "pong", "payload": {"timestamp": utc_now()}})
                continue

            if event_type == "subscribe":
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
                if channel == "governance" and _orchestrator is not None:
                    await websocket.send_json({
                        "type": "governance_pending_snapshot",
                        "payload": {"pending": _orchestrator.list_pending_reviews()},
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

            safe_type = repr(str(event_type or "")[:64])
            await websocket.send_json({
                "type": "error",
                "payload": {"error": f"Unsupported event: {safe_type}"},
            })

    except WebSocketDisconnect:
        return
    finally:
        _dashboard_ws_clients.pop(websocket, None)

# =============================================================================
# Internal event broadcast endpoint
# Used by FenrirHunter and other internal services to push events to the
# dashboard WebSocket clients without connecting as a WS client themselves.
# =============================================================================
internal_router = APIRouter(prefix="/internal", tags=["internal"])

@internal_router.post("/events/broadcast")
async def internal_broadcast_event(
    body: dict[str, Any], request: Request
) -> dict[str, Any]:
    """
    Broadcast a structured event to connected WebSocket dashboard clients.
    Called by FenrirHunter when it has a finding to report.

    Authenticated with the dedicated S43_FENRIR_API_TOKEN service token
    (see _require_fenrir_service_token) rather than operator JWT/password \u2014
    this is a machine-to-machine call, not a dashboard operator action.

    Body:
      event_type: str  \u2014 WebSocket event type (e.g. "fenrir_finding")
      channel:    str  \u2014 optional channel filter (e.g. "security")
      data:       dict \u2014 event payload forwarded to dashboard clients
    """
    _require_fenrir_service_token(request)

    event_type = str(body.get("event_type") or "event")[:64]
    channel    = str(body.get("channel") or "") or None
    data       = body.get("data") or {}

    if not isinstance(data, dict):
        raise HTTPException(status_code=422, detail="data must be an object")

    await _broadcast_dashboard_event(event_type, data, channel=channel)

    return {
        "ok":         True,
        "event_type": event_type,
        "channel":    channel,
        "clients":    len(_dashboard_ws_clients),
        "timestamp":  utc_now(),
    }

# =============================================================================
# Local proxy test ingestion endpoint
# Accepts local proxy traffic summaries and broadcasts them to dashboard clients.
# =============================================================================

proxy_events_router = APIRouter(prefix="/events", tags=["events"])


@proxy_events_router.post("/proxy")
async def ingest_proxy_event(
    body: dict[str, Any],
    request: Request,
) -> dict[str, Any]:
    """
    Ingest a local proxy traffic event and broadcast it to dashboard clients.

    This is intentionally minimal:
    - accepts JSON from a local proxy script
    - normalizes the event
    - broadcasts it to WebSocket clients subscribed to the "proxy" channel
    """
    await _require_operator(request)

    event = {
        "type": "proxy_event",
        "source": str(body.get("source") or "local_proxy")[:64],
        "method": body.get("method"),
        "url": body.get("url"),
        "host": body.get("host"),
        "path": body.get("path"),
        "status_code": body.get("status_code"),
        "request_size": body.get("request_size", 0),
        "response_size": body.get("response_size", 0),
        "user_agent": body.get("user_agent", ""),
        "client_host": request.client.host if request.client else None,
        "timestamp": utc_now(),
        "raw": body,
    }

    await _broadcast_dashboard_event(
        "proxy_event",
        event,
        channel="proxy",
    )

    return {
        "ok": True,
        "event_type": "proxy_event",
        "channel": "proxy",
        "clients": len(_dashboard_ws_clients),
        "event": event,
        "timestamp": utc_now(),
    }
# =============================================================================
# Watchtower bridge
# =============================================================================
watchtower_router = APIRouter(prefix="/watchtower", tags=["watchtower"])

@watchtower_router.get("/health")
def api_watchtower_health() -> dict[str, Any]:
    # Anonymous route: report only whether the Watchtower bridge is
    # reachable (Pass 1, F-03). watchtower_health_check() also returns the
    # internal Watchtower URL and its raw response body — those stay
    # internal, not on an unauthenticated endpoint.
    return {"bridge": "api_to_watchtower", "reachable": watchtower_health_check()["reachable"]}

@watchtower_router.get("/status")
async def api_watchtower_status(request: Request) -> dict[str, Any]:
    await _require_operator(request)
    result = _watchtower_request("GET", "/watchtower/status")
    return {"bridge": "api_to_watchtower", "watchtower_url": WATCHTOWER_URL,
            "reachable": "error" not in result, "watchtower": result, "timestamp": utc_now()}


@watchtower_router.get("/ready")
def api_watchtower_ready() -> dict[str, Any]:
    # Anonymous route (Pass 1, F-03): the upstream /watchtower/ready body
    # (stale-module names, dependency names, recovery counters) and the
    # internal Watchtower URL are not exposed here. Callers that need that
    # detail use the operator-gated /watchtower/status.
    result = _watchtower_request("GET", "/watchtower/ready")
    return {"bridge": "api_to_watchtower", "reachable": "error" not in result}

@watchtower_router.post("/register")
async def api_register_watchtower(request: Request) -> dict[str, Any]:
    await _require_operator(request)
    return register_api_with_watchtower()

@watchtower_router.post("/heartbeat")
async def api_heartbeat_watchtower(request: Request) -> dict[str, Any]:
    await _require_operator(request)
    return send_api_heartbeat()

@watchtower_router.get("/modules")
async def api_watchtower_modules(request: Request) -> dict[str, Any]:
    # Pass 1 (F-01): this bridge route leaked the full Watchtower module
    # registry anonymously — its sibling api_watchtower_status already
    # required an operator; this one was missing the call.
    await _require_operator(request)
    result = _watchtower_request("GET", "/watchtower/modules")
    return {"bridge": "api_to_watchtower", "reachable": "error" not in result,
            "watchtower": result, "timestamp": utc_now()}

@watchtower_router.get("/check")
async def watchtower_check(request: Request) -> dict[str, Any]:
    # Pass 1 (F-02): anonymous callers could read aggregated
    # health/ready/status plus the local registration snapshot here.
    await _require_operator(request)
    health_result = watchtower_health_check()
    ready_result  = _watchtower_request("GET", "/watchtower/ready")
    status_result = _watchtower_request("GET", "/watchtower/status")
    with _watchtower_lock:
        wt_snapshot = dict(_watchtower_last_status)
    return {
        "service":        "watchtower_bridge",
        "watchtower_url": WATCHTOWER_URL,
        "checks": {
            "health":         "ok" if health_result["reachable"] else "failed",
            "ready":          "ok" if "error" not in ready_result else "failed",
            "status":         "ok" if "error" not in status_result else "failed",
            "api_registered": wt_snapshot.get("registered", False),
        },
        "responses": {
            "health": health_result,
            "ready":  ready_result,
            "status": status_result,
        },
        "timestamp": utc_now(),
    }

@watchtower_router.post("/events")
async def watchtower_ingest_event(
    body: dict[str, Any], request: Request
) -> dict[str, Any]:
    """
    Ingest a structured event from an internal service (FenrirHunter) and
    forward it to the Watchtower core for analysis. Also broadcasts it to
    dashboard clients subscribed to the "watchtower" channel.

    Pass 1 (F-06): this route's only caller is FenrirHunter
    (core/detection/feniri_hunter.py), which sends
    `Authorization: Bearer <S43_FENRIR_API_TOKEN>` and never an operator
    JWT + X-S43-Password. It previously called `_require_operator`, so every
    real Fenrir report was silently rejected with 401 before the token was
    inspected — the identical bug already fixed on the sibling route
    /internal/events/broadcast. It also forwarded to `/watchtower/events` on
    the Watchtower core, which has no such route (404). Both are fixed here:
    the dedicated service-token check, and a forward to the real ingestion
    route `/watchtower/analyze` (the API attaches S43_WATCHTOWER_SERVICE_TOKEN
    to that call itself).
    """
    _require_fenrir_service_token(request)
    result = await asyncio.to_thread(
        _watchtower_request, "POST", "/watchtower/analyze", {"event": body}
    )
    await _broadcast_dashboard_event(
        "watchtower_event",
        {"event": body, "watchtower_response": result, "timestamp": utc_now()},
        channel="watchtower",
    )
    return {"ok": True, "forwarded": result, "timestamp": utc_now()}

# =============================================================================
# Core / rules / config / dependencies / system routers
# =============================================================================
core_router = APIRouter(prefix="/core", tags=["core"])

@core_router.get("/status")
async def core_status() -> dict[str, Any]:
    await asyncio.to_thread(report_dependency_to_watchtower, "sentinel-43-core", "online",
                            {"source": "api-core-status-route"})
    await _broadcast_dashboard_event(
        "dependency_state",
        {"name": "sentinel-43-core", "status": "online", "timestamp": utc_now()},
        channel="dependencies",
    )
    return {"service": "s43_core", "status": "online", "state": "ACTIVE",
            "watchtower_reported": True, "timestamp": utc_now()}

@core_router.get("/health")
def core_health() -> dict[str, Any]:
    report_dependency_to_watchtower("sentinel-43-core-health", "online",
                                    {"source": "api-core-health-route"})
    return {"service": "s43_core", "status": "ok", "watchtower_reported": True, "timestamp": utc_now()}

@core_router.post("/heartbeat")
async def core_heartbeat() -> dict[str, Any]:
    result = await asyncio.to_thread(
        report_dependency_to_watchtower, "sentinel-43-core", "online",
        {"heartbeat_source": "api", "uptime_seconds": uptime_seconds(), "timestamp": utc_now()},
    )
    await _broadcast_dashboard_event(
        "dependency_state",
        {"name": "sentinel-43-core", "status": "online", "timestamp": utc_now()},
        channel="dependencies",
    )
    return {"service": "s43_core", "heartbeat": "sent", "watchtower_response": result,
            "timestamp": utc_now()}

rules_router = APIRouter(prefix="/rules", tags=["rules"])

@rules_router.get("/status")
def rules_status() -> dict[str, Any]:
    return {"service": "rules", "status": "loaded", "active": True, "timestamp": utc_now()}

@rules_router.get("/")
def rules_root() -> dict[str, Any]:
    return {"service": "rules", "message": "Rules registry endpoint active", "timestamp": utc_now()}

config_router = APIRouter(prefix="/config", tags=["config"])

@config_router.get("/status")
def config_status() -> dict[str, Any]:
    return {"service": "config", "status": "loaded", "environment": SENTINEL_ENV,
            "timestamp": utc_now()}

@config_router.get("/")
def config_root() -> dict[str, Any]:
    return {"service": "config", "environment": SENTINEL_ENV, "timestamp": utc_now()}

dependencies_router = APIRouter(prefix="/dependencies", tags=["dependencies"])

@dependencies_router.get("/status")
def dependencies_status() -> dict[str, Any]:
    wt = watchtower_health_check()
    return {
        "service": "dependencies",
        "checks": {
            "api":        "ok",
            "core":       "ok",
            "watchtower": "ok" if wt["reachable"] else "failed",
            "redis":      "unknown",
            "postgres":   "unknown",
        },
        "watchtower_url": WATCHTOWER_URL,
        "timestamp": utc_now(),
    }

@dependencies_router.post("/report/{name}/{state}")
async def report_dependency(name: str, state: str, request: Request) -> dict[str, Any]:
    await _require_operator(request)

    result = report_dependency_to_watchtower(
        name, state, {"source": "api-dependency-report-route"}
    )
    return {"dependency": name, "state": state, "watchtower_response": result,
            "timestamp": utc_now()}

system_router = APIRouter(prefix="/system", tags=["system"])

@system_router.get("/status")
async def system_status(request: Request) -> dict[str, Any]:
    await _require_operator(request)

    wt = _watchtower_request("GET", "/watchtower/status")
    return {
        "system":         "sentinel-43",
        "status":         "online",
        "version":        APP_VERSION,
        "uptime_seconds": uptime_seconds(),
        "components": {
            "api":                "online",
            "core":               "online",
            "watchtower":         "online" if "error" not in wt else "unreachable",
            "rules":              "loaded",
            "config":             "loaded",
            "monitoring_manager": "active" if _monitoring_manager else "disabled",
            "sparta":             "active" if _sparta_instance else "disabled",
            "fenrir":             "active" if _fenrir_instance else "disabled",
            "governance":         "active" if _orchestrator else "disabled",
            "redis":              "unknown",
            "postgres":           "unknown",
        },
        "watchtower": wt,
        "timestamp":  utc_now(),
    }

@system_router.get("/routes")
async def system_routes(request: Request) -> dict[str, Any]:
    await _require_operator(request)

    route_list = [
        {
            "path":    getattr(r, "path", None),
            "name":    getattr(r, "name", None),
            "methods": sorted(getattr(r, "methods", None) or []),
        }
        for r in app.routes if getattr(r, "path", None)
    ]
    return {"service": APP_NAME, "route_count": len(route_list),
            "routes": route_list, "timestamp": utc_now()}

@system_router.get("/intercom/status")
async def intercom_status(request: Request) -> dict[str, Any]:
    await _require_operator(request)

    wt_health  = watchtower_health_check()
    wt_modules = _watchtower_request("GET", "/watchtower/modules")
    return {
        "service":        "sentinel-43-intercom",
        "api":            "online",
        "watchtower":     "online" if wt_health["reachable"] else "unreachable",
        "watchtower_url": WATCHTOWER_URL,
        "modules":        wt_modules,
        "timestamp":      utc_now(),
    }

# =============================================================================
# Fenrir router
# =============================================================================
fenrir_router = APIRouter(prefix="/fenrir", tags=["fenrir"])

def _fenrir_snapshot() -> dict[str, Any]:
    if _fenrir_instance is None:
        return {
            "enabled":   _env_any_bool(
                ("S43_FENRIR_ENABLED", "SENTINEL_FENRIR_ENABLED", "FENRIR_ENABLED")
            ),
            "status":    "disabled",
            "timestamp": utc_now(),
        }
    try:
        snap = _fenrir_instance.snapshot()
        snap["enabled"] = True
        return snap
    except Exception as exc:
        logger.warning("Fenrir snapshot error: %s", exc)
        return {
            "enabled":   True,
            "status":    "unknown",
            "node_id":   getattr(
                getattr(_fenrir_instance, "config", None), "node_id", "unknown"
            ),
            "error":     str(exc),
            "timestamp": utc_now(),
        }

@fenrir_router.get("/status")
async def fenrir_status(request: Request) -> dict[str, Any]:
    await _require_operator(request)
    return _fenrir_snapshot()

@fenrir_router.get("/health")
async def fenrir_health(request: Request) -> dict[str, Any]:
    await _require_operator(request)
    snap = _fenrir_snapshot()
    return {"service": "fenrir", **snap}

@fenrir_router.get("/metrics")
async def fenrir_metrics(request: Request) -> dict[str, Any]:
    await _require_operator(request)
    snap = _fenrir_snapshot()
    return {
        "service":       "fenrir",
        "enabled":       snap.get("enabled", False),
        "status":        snap.get("status", "disabled"),
        "metrics":       snap.get("metrics", {}),
        "anomaly_layer": snap.get("anomaly_layer", {}),
        "timestamp":     utc_now(),
    }

# =============================================================================
# Top-level health / ready
# =============================================================================
@app.get("/health")
def health() -> dict[str, str]:
    # LIVENESS. Deliberately does not touch the database or any dependency:
    # a DB outage or a schema mismatch must not make Kubernetes kill every
    # API pod. "Is this process serving HTTP?" — nothing more.
    return {
        "status":      "ok",
        "service":     APP_NAME,
        "version":     APP_VERSION,
        "environment": SENTINEL_ENV,
    }

@app.get("/ready")
async def ready() -> Any:
    # READINESS. "Should this pod receive traffic right now?" In a non-local
    # environment this refuses (503) when the database it is pointed at is not
    # at the Alembic revision this code expects — behind (migration Job not
    # done), ahead (an old replica after a newer deploy migrated), or a
    # pre-Alembic database that was never adopted. The API never runs the
    # migration itself (MIGRATION_ARCHITECTURE_PASS5AM.md §25); it only checks.
    # Local envs and a no-DATABASE_URL deployment are never gated.
    from ..auth.schema_version import schema_report

    report = await schema_report()
    if report.serving_blocked:
        return JSONResponse(
            status_code=503,
            content={
                "status":       "not_ready",
                "service":      APP_NAME,
                "reason":       "schema_version",
                "schema_state": report.state.value,
                "detail":       report.detail,
            },
        )
    return {"status": "ready", "service": APP_NAME}

# =============================================================================
# Status / version / metrics
# =============================================================================
@root_router.get("/status")
def status() -> dict[str, Any]:
    with _watchtower_lock:
        wt_local = dict(_watchtower_last_status)
    return {
        "service":                APP_NAME,
        "version":                APP_VERSION,
        "status":                 "online",
        "environment":            SENTINEL_ENV,
        "uptime_seconds":         uptime_seconds(),
        "watchtower_url":         WATCHTOWER_URL,
        "watchtower_local_state": wt_local,
        "timestamp":              utc_now(),
    }

@root_router.get("/version")
def version() -> dict[str, Any]:
    return {"service": APP_NAME, "version": APP_VERSION, "timestamp": utc_now()}

@root_router.get("/metrics")
def metrics() -> dict[str, Any]:
    # legacy_auth_request_total — Phase D observability for the X-S43-Password
    # / old-style-token retirement. Per route + `_all`. Credential-free.
    try:
        from .routers.auth import legacy_auth_request_total
        legacy_auth = legacy_auth_request_total()
    except Exception:
        legacy_auth = {}
    return {
        "service":                      APP_NAME,
        "uptime_seconds":               uptime_seconds(),
        "status":                       "online",
        "watchtower_heartbeat_seconds": WATCHTOWER_HEARTBEAT_SECONDS,
        "legacy_auth_request_total":    legacy_auth,
        "timestamp":                    utc_now(),
    }

# =============================================================================
# API compat prefix router
# =============================================================================
api_router = APIRouter(prefix="/api", tags=["api-compat"])

@api_router.get("/ready")
async def compat_api_ready() -> Any:
    return await ready()

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
async def compat_api_watchtower_status(request: Request) -> dict[str, Any]:
    return await api_watchtower_status(request)


@api_router.get("/watchtower/health")
def compat_api_watchtower_health() -> dict[str, Any]:
    return api_watchtower_health()

@api_router.get("/watchtower/ready")
def compat_api_watchtower_ready() -> dict[str, Any]:
    return api_watchtower_ready()

# =============================================================================
# Register all routers
# =============================================================================
app.include_router(root_router)
app.include_router(auth_router)             # /auth/login, /auth/verify
app.include_router(users_router)            # /users (admin-only account management)
app.include_router(bootstrap_router)        # /bootstrap/status, /bootstrap/admin
app.include_router(remote_gateway_router)
app.include_router(watchgate_router)        # /health, /v1/assess, /v1/actions
app.include_router(internal_router)         # /internal/events/broadcast
app.include_router(proxy_events_router)     # /events/proxy
app.include_router(watchtower_router)       # /watchtower/events now included
app.include_router(core_router)
app.include_router(rules_router)
app.include_router(config_router)
app.include_router(dependencies_router)
app.include_router(system_router)
app.include_router(fenrir_router)
app.include_router(api_router)
app.include_router(audit_router)

# =============================================================================
# Health-check access-log noise suppression
#
# Docker's healthcheck (core/api/Dockerfile), Watchtower, and the dashboard
# all poll these unauthenticated liveness/readiness endpoints every few
# seconds, and uvicorn's own access logger (never configured by this app --
# see core/logging/setup.py and core/logging_init.py, neither of which is
# imported here) logs every single one at INFO level. This does not change
# any health check, its cadence, its status code, or what Watchtower sees --
# it only quiets the repeated successful (2xx) access-log lines for exactly
# these paths. Failures and the first success after a failure still print.
# See core/logging/health_check_filter.py for the mechanism.
#
# Deliberately excludes /fenrir/health and /remote-gateway/health: both
# require operator authentication (_require_operator/_authenticate), so
# they're not routine anonymous polling targets and aren't the source of
# this noise.
# =============================================================================
_HEALTH_CHECK_LOG_PATHS: frozenset[str] = frozenset({
    "/health",
    "/ready",
    "/watchtower/health",
    "/watchtower/ready",
    "/core/health",
    "/audit/health",
    "/api/ready",
    "/api/watchtower/health",
    "/api/watchtower/ready",
})
install_health_check_access_filter(_HEALTH_CHECK_LOG_PATHS)

# =============================================================================
# Error handler
# =============================================================================
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={
            "error":     "route_not_found",
            "path":      str(request.url.path),
            "message":   "Requested route is not registered in Sentinel-43 API.",
            "timestamp": utc_now(),
        },
    )
