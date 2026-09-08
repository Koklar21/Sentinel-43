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
# Sentinel-43(TM)
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
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

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
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..bootstrap import bootstrap_expectations
from ..logging.health_check_filter import install_health_check_access_filter
from ..monitoring.watchtower_client import (
    WATCHTOWER_URL,
    watchtower_request as _canonical_watchtower_request,
)
from ..security.jwt_constants import APPROVED_JWT_ALGORITHMS
from .routers.audit import router as audit_router
from .routers.auth import router as auth_router
from .routers.bootstrap import router as bootstrap_router
from .routers.remote_gateway import router as remote_gateway_router
from .routers.routers import router as watchgate_router
from .routers.users import router as users_router

logger = logging.getLogger(__name__)

# =============================================================================
# Environment helpers
# =============================================================================

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def _env_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise RuntimeError(
        f"{name} must be one of "
        f"{sorted(_TRUE_VALUES | _FALSE_VALUES)}; got {raw!r}"
    )


def _env_any_bool(names: tuple[str, ...], default: bool = False) -> bool:
    for name in names:
        if os.getenv(name) is not None:
            return _env_bool(name, default)
    return default


def _env_int(
    name: str,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    raw = os.getenv(name)
    if raw is None:
        value = default
    else:
        try:
            value = int(raw.strip())
        except ValueError as exc:
            raise RuntimeError(f"{name} must be an integer; got {raw!r}") from exc

    if minimum is not None and value < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}; got {value}")
    if maximum is not None and value > maximum:
        raise RuntimeError(f"{name} must be <= {maximum}; got {value}")
    return value


def _env_frozenset(name: str, default: str = "") -> frozenset[str]:
    raw = os.getenv(name, default)
    return frozenset(item.strip() for item in raw.split(",") if item.strip())


# =============================================================================
# Configuration
# =============================================================================

APP_NAME = "sentinel-43-api"
APP_VERSION = _env_str("SENTINEL_VERSION", "0.1.0")
SENTINEL_ENV = _env_str("SENTINEL_ENV", "production").lower()

LOCAL_TEST_ENVIRONMENTS = frozenset({"development", "dev", "local", "test"})
IS_LOCAL_ENV = SENTINEL_ENV in LOCAL_TEST_ENVIRONMENTS

WATCHTOWER_HEARTBEAT_SECONDS = _env_int(
    "S43_WATCHTOWER_HEARTBEAT_SECONDS",
    15,
    minimum=5,
    maximum=3600,
)

MAX_WS_CLIENTS = _env_int(
    "S43_MAX_WS_CLIENTS",
    50,
    minimum=1,
    maximum=10_000,
)

MAX_WS_FRAME_BYTES = _env_int(
    "S43_MAX_WS_FRAME_BYTES",
    64 * 1024,
    minimum=1024,
    maximum=1024 * 1024,
)

WS_SESSION_RECHECK_SECONDS = _env_int(
    "S43_WS_SESSION_RECHECK_SECONDS",
    60,
    minimum=5,
    maximum=300,
)

WS_OUTBOUND_QUEUE_SIZE = _env_int(
    "S43_WS_OUTBOUND_QUEUE_SIZE",
    128,
    minimum=8,
    maximum=4096,
)

WS_SEND_TIMEOUT_SECONDS = _env_int(
    "S43_WS_SEND_TIMEOUT_SECONDS",
    5,
    minimum=1,
    maximum=30,
)

WS_REQUIRE_AUTH = _env_bool("S43_WS_REQUIRE_AUTH", True)
TEST_INJECTION_ENABLED = _env_bool("S43_ENABLE_TEST_INJECTION", False)
ALLOW_DEV_OPERATOR_FALLBACK = _env_bool(
    "S43_ALLOW_DEV_OPERATOR_FALLBACK",
    False,
)

JWT_SECRET = _env_str("S43_JWT_SECRET")
JWT_ALGORITHM = _env_str("S43_JWT_ALGORITHM", "HS256")
_APPROVED_ALGORITHMS = APPROVED_JWT_ALGORITHMS

_ALLOWED_ORIGINS: frozenset[str] = _env_frozenset(
    "S43_ALLOWED_ORIGINS",
    "http://127.0.0.1:5500,http://localhost:5500,"
    "http://127.0.0.1:8000,http://localhost:8000",
)

_TRUSTED_HOSTS = [
    item.strip()
    for item in _env_str("S43_TRUSTED_HOSTS").split(",")
    if item.strip()
]

MAX_DASHBOARD_ACTIONS = _env_int(
    "S43_MAX_DASHBOARD_ACTIONS",
    500,
    minimum=10,
    maximum=100_000,
)

ACTION_ID_RE = re.compile(r"^[A-Z0-9_-]{1,64}$")
EVENT_TYPE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
CHANNEL_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
LOOPBACK_HTTP_ORIGIN_RE = re.compile(
    r"^http://(localhost|127\.0\.0\.1)(:\d+)?$"
)

START_TIME = time.time()

# This composition root still has an in-process action cache and in-process
# WebSocket connections. Until those are moved to durable/shared infrastructure,
# Sentinel-43 must remain single-process unless an explicit operator override is
# supplied for a controlled test.
WEB_CONCURRENCY = _env_int("WEB_CONCURRENCY", 1, minimum=1, maximum=128)
ALLOW_PROCESS_LOCAL_STATE = _env_bool(
    "S43_ALLOW_PROCESS_LOCAL_STATE_WITH_MULTIPLE_WORKERS",
    False,
)


# =============================================================================
# Validation models
# =============================================================================

class DecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=10, max_length=500)
    decision_id: str | None = Field(default=None, max_length=64)

    @field_validator("reason")
    @classmethod
    def clean_reason(cls, value: str) -> str:
        return value.strip()

    @field_validator("decision_id")
    @classmethod
    def clean_decision_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None


class InternalBroadcastBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: str = Field(default="event", min_length=1, max_length=64)
    channel: str | None = Field(default=None, max_length=64)
    data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_type")
    @classmethod
    def valid_event_type(cls, value: str) -> str:
        cleaned = value.strip()
        if not EVENT_TYPE_RE.fullmatch(cleaned):
            raise ValueError("event_type contains unsupported characters")
        return cleaned

    @field_validator("channel")
    @classmethod
    def valid_channel(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        if not CHANNEL_RE.fullmatch(cleaned):
            raise ValueError("channel contains unsupported characters")
        return cleaned


class ProxyEventBody(BaseModel):
    model_config = ConfigDict(extra="allow")

    source: str = Field(default="local_proxy", max_length=64)
    method: str | None = Field(default=None, max_length=16)
    url: str | None = Field(default=None, max_length=2048)
    host: str | None = Field(default=None, max_length=255)
    path: str | None = Field(default=None, max_length=2048)
    status_code: int | None = Field(default=None, ge=100, le=599)
    request_size: int = Field(default=0, ge=0, le=1_000_000_000)
    response_size: int = Field(default=0, ge=0, le=1_000_000_000)
    user_agent: str = Field(default="", max_length=1024)


# =============================================================================
# Runtime state
# =============================================================================

@dataclass(slots=True)
class WebSocketClient:
    websocket: WebSocket
    channels: set[str] = field(default_factory=set)
    outbound: asyncio.Queue[dict[str, Any] | None] = field(
        default_factory=lambda: asyncio.Queue(maxsize=WS_OUTBOUND_QUEUE_SIZE)
    )
    writer_task: asyncio.Task[None] | None = None
    sid: str | None = None
    subject: str | None = None
    role: str | None = None
    exp: float | None = None


@dataclass(slots=True)
class RuntimeState:
    action_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    action_store: dict[str, dict[str, Any]] = field(default_factory=dict)
    action_insert_count: int = 0

    ws_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    ws_capacity: asyncio.Semaphore = field(
        default_factory=lambda: asyncio.Semaphore(MAX_WS_CLIENTS)
    )
    ws_clients: dict[WebSocket, WebSocketClient] = field(default_factory=dict)

    watchtower_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    watchtower_last_status: dict[str, Any] = field(
        default_factory=lambda: {
            "reachable": False,
            "registered": False,
            "last_register_ts": None,
            "last_heartbeat_ts": None,
            "last_error": None,
        }
    )

    stop_heartbeat_event: asyncio.Event | None = None
    heartbeat_task: asyncio.Task[None] | None = None

    monitoring_manager: Any | None = None
    audit_store: Any | None = None
    orchestrator: Any | None = None
    sparta_instance: Any | None = None
    sparta_task: asyncio.Task[Any] | None = None
    fenrir_instance: Any | None = None


runtime = RuntimeState()


# =============================================================================
# Utility helpers
# =============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def uptime_seconds() -> float:
    return round(time.time() - START_TIME, 3)


def _is_local_environment() -> bool:
    return IS_LOCAL_ENV


def _validate_action_id(action_id: str) -> str:
    if not isinstance(action_id, str):
        raise HTTPException(status_code=422, detail="action_id must be a string")
    cleaned = action_id.strip().upper()
    if not ACTION_ID_RE.fullmatch(cleaned):
        raise HTTPException(status_code=422, detail="action_id has an invalid format")
    return cleaned


def _redact_proxy_url(value: str | None) -> str | None:
    if not value:
        return value
    # Keep scheme/host/path but remove query and fragment, where tokens and
    # credentials most commonly leak.
    without_fragment = value.split("#", 1)[0]
    return without_fragment.split("?", 1)[0]


# =============================================================================
# Security configuration validation
# =============================================================================

def _validate_security_config() -> None:
    if JWT_ALGORITHM not in _APPROVED_ALGORITHMS:
        raise RuntimeError(
            f"S43_JWT_ALGORITHM={JWT_ALGORITHM!r} is not approved; "
            f"allowed={sorted(_APPROVED_ALGORITHMS)}"
        )

    if WS_REQUIRE_AUTH and not JWT_SECRET:
        raise RuntimeError(
            "S43_WS_REQUIRE_AUTH=true but S43_JWT_SECRET is not configured"
        )

    if WEB_CONCURRENCY > 1 and not ALLOW_PROCESS_LOCAL_STATE:
        raise RuntimeError(
            "Sentinel-43 currently uses process-local authoritative action "
            "state and process-local WebSocket connections. WEB_CONCURRENCY "
            f"is {WEB_CONCURRENCY}. Refusing multi-worker startup until shared "
            "state/pub-sub exists. For controlled testing only, set "
            "S43_ALLOW_PROCESS_LOCAL_STATE_WITH_MULTIPLE_WORKERS=true."
        )

    if not IS_LOCAL_ENV:
        if not JWT_SECRET:
            raise RuntimeError(
                "Production Sentinel-43 API requires S43_JWT_SECRET"
            )
        if not WS_REQUIRE_AUTH:
            raise RuntimeError(
                "Production Sentinel-43 API requires S43_WS_REQUIRE_AUTH=true"
            )
        if ALLOW_DEV_OPERATOR_FALLBACK:
            raise RuntimeError(
                "S43_ALLOW_DEV_OPERATOR_FALLBACK must be false outside "
                "development/local/test environments"
            )

        if not _TRUSTED_HOSTS and not _env_bool(
            "S43_TRUST_PROXY_HOST_VALIDATION",
            False,
        ):
            raise RuntimeError(
                "Non-local Sentinel-43 API requires S43_TRUSTED_HOSTS, or an "
                "explicit S43_TRUST_PROXY_HOST_VALIDATION=true assertion when "
                "a trusted upstream proxy validates Host."
            )

        if not _env_bool("S43_ALLOW_INSECURE_ORIGINS", False):
            insecure = sorted(
                origin
                for origin in _ALLOWED_ORIGINS
                if origin.startswith("http://")
                and not LOOPBACK_HTTP_ORIGIN_RE.fullmatch(origin)
            )
            if insecure:
                raise RuntimeError(
                    "Non-local Sentinel-43 API requires HTTPS browser origins; "
                    f"found plaintext origins: {insecure}"
                )

        operator_hash = os.getenv("S43_OPERATOR_PASSWORD_HASH", "").strip()
        if operator_hash:
            from .routers.auth import _valid_argon2_hash

            if not _valid_argon2_hash(operator_hash):
                raise RuntimeError(
                    "S43_OPERATOR_PASSWORD_HASH is not a well-formed Argon2id "
                    "hash. Legacy SHA-256 break-glass hashes are not accepted "
                    "outside local/dev/test."
                )

        # The app cannot cryptographically prove the external edge terminated
        # TLS from CORS settings alone. Require an explicit deployment assertion
        # for public/non-local operation.
        if not _env_bool("S43_TLS_TERMINATED_AT_TRUSTED_EDGE", False):
            raise RuntimeError(
                "Non-local Sentinel-43 API requires "
                "S43_TLS_TERMINATED_AT_TRUSTED_EDGE=true. This confirms the "
                "deployment terminates HTTPS/WSS before traffic reaches the API."
            )


def _bootstrap_settings() -> dict[str, Any]:
    """Snapshot the startup security inputs core.bootstrap validates.

    core.bootstrap.validate_bootstrap_expectations() is deliberately env-free
    and validates an already-loaded settings mapping. This composition root
    owns the environment reads.
    """
    return {
        "env": SENTINEL_ENV,
        "jwt_secret": JWT_SECRET,
        "jwt_algorithm": JWT_ALGORITHM,
        "jwt_issuer": _env_str("S43_JWT_ISSUER", "sentinel-43"),
        "jwt_audience": _env_str("S43_JWT_AUDIENCE", "sentinel-43-dashboard"),
        "auth_pepper": _env_str("S43_AUTH_PEPPER"),
        "ws_require_auth": WS_REQUIRE_AUTH,
        "enable_test_injection": TEST_INJECTION_ENABLED,
    }


# =============================================================================
# Authentication helpers
# =============================================================================

async def _get_operator(
    request: Request,
    *,
    allow_local_fallback: bool = False,
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

            claims = verify_jwt_token(token)
            subject = str(claims.get("sub") or "").strip()
            if not subject:
                raise HTTPException(
                    status_code=401,
                    detail="Token subject is missing",
                )

            resolved = await resolve_session_subject(claims)
            if resolved is not None:
                return resolved[0]

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

    if (
        allow_local_fallback
        and IS_LOCAL_ENV
        and ALLOW_DEV_OPERATOR_FALLBACK
    ):
        client_host = request.client.host if request.client else ""
        if client_host not in {"127.0.0.1", "::1", "localhost"}:
            raise HTTPException(
                status_code=401,
                detail="Development operator fallback is loopback-only",
            )
        return "dev-operator"

    raise HTTPException(status_code=401, detail="Authentication required")


async def _require_operator(request: Request) -> str:
    return await _get_operator(request, allow_local_fallback=False)


def _require_fenrir_service_token(request: Request) -> None:
    expected = _env_str("S43_FENRIR_API_TOKEN")
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Internal service authentication is not configured",
        )

    auth = request.headers.get("Authorization", "").strip()
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")

    token = auth[7:].strip()
    if not token or not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Invalid service token")


# =============================================================================
# Action service
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


async def _store_action(action: dict[str, Any]) -> dict[str, Any]:
    safe = copy.deepcopy(action)
    safe["id"] = _validate_action_id(str(safe.get("id") or ""))

    async with runtime.action_lock:
        if safe["id"] in runtime.action_store:
            raise HTTPException(
                status_code=409,
                detail="action already exists",
            )

        runtime.action_store[safe["id"]] = safe
        runtime.action_insert_count += 1

        if len(runtime.action_store) > MAX_DASHBOARD_ACTIONS:
            oldest = sorted(
                runtime.action_store.items(),
                key=lambda item: str(item[1].get("created_at") or ""),
            )[: len(runtime.action_store) - MAX_DASHBOARD_ACTIONS]
            for action_id, _ in oldest:
                del runtime.action_store[action_id]

        return copy.deepcopy(safe)


async def _list_actions(limit: int = 250) -> list[dict[str, Any]]:
    safe_limit = max(1, min(limit, 500))
    async with runtime.action_lock:
        actions = [
            copy.deepcopy(action)
            for action in runtime.action_store.values()
        ]
    return sorted(
        actions,
        key=lambda item: str(item.get("created_at") or ""),
        reverse=True,
    )[:safe_limit]


async def _action_insert_count() -> int:
    async with runtime.action_lock:
        return runtime.action_insert_count


async def _get_action(action_id: str) -> dict[str, Any]:
    cleaned_id = _validate_action_id(action_id)
    async with runtime.action_lock:
        action = runtime.action_store.get(cleaned_id)
        if action is None:
            raise HTTPException(status_code=404, detail="action not found")
        return copy.deepcopy(action)


async def _commit_action_status(
    action_id: str,
    *,
    allowed_statuses: set[str],
    new_status: str,
    reason: str,
    operator: str,
) -> dict[str, Any]:
    cleaned_id = _validate_action_id(action_id)

    async with runtime.action_lock:
        action = runtime.action_store.get(cleaned_id)
        if action is None:
            raise HTTPException(status_code=404, detail="action not found")

        current_status = str(action.get("status") or "")
        if current_status not in allowed_statuses:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"action status is {current_status}; expected one of "
                    f"{sorted(allowed_statuses)}"
                ),
            )

        action["status"] = new_status
        action["decision_reason"] = reason
        action["operator"] = operator
        action["decision_at"] = utc_now()
        return copy.deepcopy(action)


async def _resolve_governance_and_commit_action(
    *,
    action_id: str,
    decision_id: str | None,
    approved: bool,
    allowed_statuses: set[str],
    new_status: str,
    reason: str,
    operator: str,
) -> dict[str, Any]:
    # Snapshot and validate the action first, but do not mutate it until
    # governance resolution succeeds.
    action = await _get_action(action_id)

    if str(action.get("status") or "") not in allowed_statuses:
        raise HTTPException(
            status_code=409,
            detail=(
                f"action status is {action.get('status')}; expected one of "
                f"{sorted(allowed_statuses)}"
            ),
        )

    resolved_decision_id = (
        (decision_id or "").strip()
        or str(action.get("payload", {}).get("decision_id") or "").strip()
        or None
    )

    if runtime.orchestrator is not None:
        if not resolved_decision_id:
            raise HTTPException(
                status_code=409,
                detail="governance decision_id is required while governance is enabled",
            )
        try:
            await asyncio.to_thread(
                runtime.orchestrator.resolve_human_decision,
                resolved_decision_id,
                approved=approved,
                operator_id=operator,
                reason=reason,
            )
        except KeyError as exc:
            raise HTTPException(
                status_code=409,
                detail="governance decision is not pending or does not exist",
            ) from exc
        except Exception as exc:
            logger.exception(
                "Governance resolution failed for decision_id=%s",
                resolved_decision_id,
            )
            raise HTTPException(
                status_code=503,
                detail="Governance decision service is unavailable",
            ) from exc

    # Commit dashboard state only after governance accepts the decision.
    return await _commit_action_status(
        action_id,
        allowed_statuses=allowed_statuses,
        new_status=new_status,
        reason=reason,
        operator=operator,
    )


# =============================================================================
# WebSocket manager
# =============================================================================

async def _ws_safe_close(
    websocket: WebSocket,
    code: int = 1008,
    reason: str = "",
) -> None:
    try:
        await websocket.close(code=code, reason=reason)
    except RuntimeError:
        pass
    except TypeError:
        try:
            await websocket.close(code=code)
        except RuntimeError:
            pass


async def _ws_writer(client: WebSocketClient) -> None:
    try:
        while True:
            frame = await client.outbound.get()
            if frame is None:
                return
            await asyncio.wait_for(
                client.websocket.send_json(frame),
                timeout=float(WS_SEND_TIMEOUT_SECONDS),
            )
    except (asyncio.TimeoutError, WebSocketDisconnect, RuntimeError):
        return
    except Exception:
        logger.debug("WebSocket writer failed", exc_info=True)
    finally:
        await _remove_ws_client(client.websocket)


async def _remove_ws_client(websocket: WebSocket) -> None:
    # Connection-capacity ownership belongs to dashboard_websocket().
    # Removing a client from the broadcast registry must not release the
    # semaphore, otherwise writer failure + handler cleanup can double-release.
    async with runtime.ws_lock:
        runtime.ws_clients.pop(websocket, None)


async def _queue_ws_frame(
    client: WebSocketClient,
    frame: dict[str, Any],
) -> bool:
    try:
        client.outbound.put_nowait(frame)
        return True
    except asyncio.QueueFull:
        logger.warning("Dropping slow WebSocket client: outbound queue full")
        await _ws_safe_close(
            client.websocket,
            code=1011,
            reason="backpressure",
        )
        await _remove_ws_client(client.websocket)
        return False


async def _broadcast_dashboard_event(
    event_type: str,
    payload: dict[str, Any],
    *,
    channel: str | None = None,
) -> None:
    frame = {"type": event_type, "payload": payload}

    async with runtime.ws_lock:
        clients = list(runtime.ws_clients.values())

    for client in clients:
        if channel is not None and channel not in client.channels:
            continue
        await _queue_ws_frame(client, frame)


async def _receive_ws_message(websocket: WebSocket) -> dict[str, Any]:
    raw = await websocket.receive_text()

    if len(raw.encode("utf-8")) > MAX_WS_FRAME_BYTES:
        raise ValueError(
            f"WebSocket frame exceeds {MAX_WS_FRAME_BYTES}-byte limit"
        )

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON in WebSocket frame: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValueError("WebSocket message must be a JSON object")

    return parsed


async def _session_still_valid(
    client: WebSocketClient,
) -> tuple[bool, str]:
    if client.exp is not None and time.time() >= client.exp:
        return False, "token_expired"

    if client.sid is None:
        # Legacy connections are bounded by the JWT expiry check above.
        return True, ""

    if not client.subject:
        return False, "session_invalid"

    try:
        from .routers.auth import resolve_session_subject

        claims: dict[str, Any] = {
            "sid": client.sid,
            "sub": client.subject,
            "role": client.role or "operator",
        }
        if client.exp is not None:
            claims["exp"] = client.exp

        resolved = await resolve_session_subject(claims)
        if resolved is None:
            return False, "session_revoked"
        return True, ""
    except HTTPException:
        return False, "session_revoked"
    except Exception:
        logger.warning(
            "WebSocket session revalidation failed closed for sid=%s",
            client.sid,
            exc_info=True,
        )
        return False, "auth_service_unavailable"


# =============================================================================
# Watchtower helpers
# =============================================================================

def _watchtower_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _canonical_watchtower_request(method, path, payload)


async def _set_watchtower_status(**updates: Any) -> None:
    async with runtime.watchtower_lock:
        runtime.watchtower_last_status.update(updates)


async def watchtower_health_check() -> dict[str, Any]:
    result = await asyncio.to_thread(
        _watchtower_request,
        "GET",
        "/watchtower/health",
    )
    reachable = "error" not in result
    await _set_watchtower_status(
        reachable=reachable,
        last_error=None if reachable else result,
    )
    return {
        "reachable": reachable,
        "url": WATCHTOWER_URL,
        "response": result,
    }


async def register_api_with_watchtower() -> dict[str, Any]:
    capabilities = [
        "health",
        "ready",
        "status",
        "routes",
        "metrics",
        "core_bridge",
        "watchtower_bridge",
        "remote_gateway",
        "remote_operations",
    ]

    if runtime.monitoring_manager is not None:
        capabilities.append("monitoring_manager")
    if runtime.sparta_instance is not None:
        capabilities.append("sparta_integrity_watchdog")
    if _env_bool("S43_JORM_ENABLED", False):
        capabilities.append("jormungandr_audit")
    if runtime.fenrir_instance is not None:
        capabilities.append("fenrir_hunter")

    try:
        from core.middleware import SentinelFirewall  # noqa: F401
        capabilities.append("sentinel_firewall")
    except ImportError:
        pass

    payload = {
        "module_id": APP_NAME,
        "module_type": "api",
        "version": APP_VERSION,
        "endpoint": _env_str(
            "S43_API_PUBLIC_URL",
            "http://s43-api:8000",
        ),
        "capabilities": capabilities,
        "metadata": {
            "environment": SENTINEL_ENV,
            "started_ts": START_TIME,
            "timestamp": utc_now(),
        },
    }

    result = await asyncio.to_thread(
        _watchtower_request,
        "POST",
        "/watchtower/modules/register",
        payload,
    )
    registered = "error" not in result

    await _set_watchtower_status(
        reachable=registered,
        registered=registered,
        last_register_ts=utc_now() if registered else None,
        last_error=None if registered else result,
    )

    return {
        "registered": registered,
        "watchtower_url": WATCHTOWER_URL,
        "response": result,
    }


async def send_api_heartbeat(status: str = "online") -> dict[str, Any]:
    payload = {
        "module_id": APP_NAME,
        "status": status,
        "metrics": {
            "uptime_seconds": uptime_seconds(),
            "timestamp": utc_now(),
        },
        "message": f"Sentinel-43 API heartbeat: {status}",
    }

    result = await asyncio.to_thread(
        _watchtower_request,
        "POST",
        "/watchtower/modules/heartbeat",
        payload,
    )
    ok = "error" not in result

    updates: dict[str, Any] = {
        "reachable": ok,
        "last_error": None if ok else result,
    }
    if ok:
        updates["last_heartbeat_ts"] = utc_now()

    await _set_watchtower_status(**updates)

    return {
        "heartbeat_sent": ok,
        "watchtower_url": WATCHTOWER_URL,
        "response": result,
    }


async def report_dependency_to_watchtower(
    name: str,
    status: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return await asyncio.to_thread(
        _watchtower_request,
        "POST",
        "/watchtower/dependencies/report",
        {
            "name": name,
            "status": status,
            "details": details or {},
        },
    )


async def _async_heartbeat_loop() -> None:
    stop_event = runtime.stop_heartbeat_event
    if stop_event is None:
        return

    previous_reachable: bool | None = None

    while not stop_event.is_set():
        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=float(WATCHTOWER_HEARTBEAT_SECONDS),
            )
            return
        except asyncio.TimeoutError:
            pass

        try:
            result = await send_api_heartbeat()
            reachable = bool(result.get("heartbeat_sent"))

            if previous_reachable is None or reachable != previous_reachable:
                previous_reachable = reachable
                await _broadcast_dashboard_event(
                    "watchtower_state",
                    {
                        "reachable": reachable,
                        "timestamp": utc_now(),
                    },
                    channel="watchtower",
                )

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
        except Exception:
            logger.warning("Heartbeat loop error", exc_info=True)


# =============================================================================
# Subsystem lifecycle
# =============================================================================

async def _start_monitoring_manager() -> None:
    try:
        from core.monitoring import (
            MonitoringManager,
            WatchtowerConfig,
            set_monitoring_manager,
        )

        manager = MonitoringManager(
            WatchtowerConfig.default_sentinel_octagon("sentinel43-api")
        )
        await asyncio.to_thread(manager.start)
        set_monitoring_manager(manager)
        runtime.monitoring_manager = manager
        logger.info("MonitoringManager started and wired")
    except Exception:
        if _env_bool("S43_MONITORING_REQUIRED", False):
            raise
        logger.error("MonitoringManager unavailable", exc_info=True)


async def _start_sparta() -> None:
    if not _env_bool("S43_SPARTA_ENABLED", False):
        return

    try:
        from core.monitoring import IntegrityConfig, SpartaCore

        watched_files: dict[str, str] = {}
        for key, value in os.environ.items():
            if key.startswith("S43_SPARTA_HASH_"):
                file_key = (
                    key[len("S43_SPARTA_HASH_") :]
                    .lower()
                    .replace("_", "/")
                )
                watched_files[file_key] = value

        if not watched_files:
            raise RuntimeError(
                "S43_SPARTA_ENABLED=true but no S43_SPARTA_HASH_* values exist"
            )

        config = IntegrityConfig.from_env(watched_files)
        runtime.sparta_instance = SpartaCore(
            config,
            monitoring_manager=runtime.monitoring_manager,
        )
        runtime.sparta_task = asyncio.create_task(
            runtime.sparta_instance.run(),
            name="sentinel43-sparta-watchdog",
        )
        logger.info(
            "SpartaCore watchdog started for %d files",
            len(watched_files),
        )
    except Exception:
        if _env_bool("S43_SPARTA_REQUIRED", False):
            raise
        logger.error("SpartaCore failed to start", exc_info=True)


async def _start_fenrir() -> None:
    enabled = _env_any_bool(
        (
            "S43_FENRIR_ENABLED",
            "SENTINEL_FENRIR_ENABLED",
            "FENRIR_ENABLED",
        ),
        False,
    )
    if not enabled:
        return

    try:
        from core.detection.feniri_hunter import FenrirHunter

        runtime.fenrir_instance = FenrirHunter()
        await runtime.fenrir_instance.start()
        logger.info("FenrirHunter started")
    except Exception:
        runtime.fenrir_instance = None
        if _env_bool("S43_FENRIR_REQUIRED", False):
            raise
        logger.error("FenrirHunter failed to start", exc_info=True)


async def _start_audit_store() -> None:
    """Construct and initialize the authoritative HMAC-chained audit store.

    The audit store is a hard dependency of governance: SystemOrchestrator
    records every human decision through it. It is also the canonical local
    audit ledger for the rest of the API. S43_AUDIT_HMAC_KEY keys the HMAC
    chain; when it is absent the store cannot be built. That is fatal outside
    development/local/test and whenever governance is enabled.
    """
    from pathlib import Path

    from core.audit import AuditConfig, AuditStore

    signing_key = _env_str("S43_AUDIT_HMAC_KEY")
    required = _env_bool("S43_GOVERNANCE_ENABLED", False) or not IS_LOCAL_ENV

    if not signing_key:
        if required:
            raise RuntimeError(
                "S43_AUDIT_HMAC_KEY is required: the authoritative audit "
                "store cannot be keyed. It is mandatory outside "
                "development/local/test and whenever S43_GOVERNANCE_ENABLED=true."
            )
        logger.warning(
            "S43_AUDIT_HMAC_KEY is not set; authoritative audit store is "
            "disabled (development/local/test only)."
        )
        return

    sqlite_path = Path(
        _env_str("S43_AUDIT_SQLITE_PATH", "sentinel43_state/audit.sqlite3")
    )
    jsonl_raw = _env_str("S43_AUDIT_JSONL_PATH", "logs/audit.jsonl")

    try:
        store = AuditStore(
            AuditConfig(
                sqlite_path=sqlite_path,
                signing_key=signing_key,
                jsonl_path=Path(jsonl_raw) if jsonl_raw else None,
            )
        )
        # initialize() creates the schema and runs full-chain integrity
        # verification, raising on any tamper/inconsistency.
        await asyncio.to_thread(store.initialize)
    except Exception as exc:
        raise RuntimeError(
            f"Authoritative audit store failed to initialize: {exc}"
        ) from exc

    runtime.audit_store = store
    logger.info(
        "Authoritative audit store initialized (%s)",
        sqlite_path,
    )


async def _start_governance() -> None:
    if not _env_bool("S43_GOVERNANCE_ENABLED", False):
        return

    if runtime.audit_store is None:
        raise RuntimeError(
            "Governance requires an initialized authoritative audit store. "
            "Refusing to start SystemOrchestrator without one."
        )

    try:
        from core.governance import build_orchestrator_from_settings

        default_mode = _env_str(
            "S43_GOVERNANCE_DEFAULT_MODE",
            "SHADOW",
        ).upper()

        allowed_modes = _env_frozenset(
            "S43_GOVERNANCE_ALLOWED_MODES",
            "SHADOW,REVIEW",
        )
        if default_mode not in allowed_modes:
            raise RuntimeError(
                f"Unsupported governance mode {default_mode!r}; "
                f"allowed={sorted(allowed_modes)}"
            )

        class Settings:
            env = SENTINEL_ENV
            strict_mode = _env_bool("S43_GOVERNANCE_STRICT", True)
            data_dir = _env_str(
                "S43_DATA_DIR",
                "/var/sentinel43/data",
            )
            audit_signing_key = _env_str(
                "S43_GOVERNANCE_SIGNING_KEY",
            )
            audit_jsonl_path = _env_str(
                "S43_GOVERNANCE_JSONL_PATH",
            )
            default_mode = default_mode
            hash_device_ids = _env_bool(
                "S43_GOVERNANCE_HASH_DEVICE_IDS",
                False,
            )
            velocity_window_seconds = _env_int(
                "S43_VELOCITY_WINDOW_SECONDS",
                60,
                minimum=1,
                maximum=3600,
            )
            velocity_limit = _env_int(
                "S43_VELOCITY_LIMIT",
                10,
                minimum=1,
                maximum=100_000,
            )
            velocity_gc_interval_seconds = _env_int(
                "S43_VELOCITY_GC_INTERVAL",
                300,
                minimum=5,
                maximum=86_400,
            )
            velocity_max_entries_per_user = _env_int(
                "S43_VELOCITY_MAX_ENTRIES",
                1000,
                minimum=1,
                maximum=1_000_000,
            )

        runtime.orchestrator = build_orchestrator_from_settings(
            Settings(),
            monitoring_manager=runtime.monitoring_manager,
        )
        logger.info(
            "SystemOrchestrator started (mode=%s)",
            default_mode,
        )
    except Exception:
        runtime.orchestrator = None
        if _env_bool("S43_GOVERNANCE_REQUIRED", True):
            raise
        logger.error("SystemOrchestrator failed to start", exc_info=True)


async def _register_remote_dispatch_handlers() -> None:
    try:
        from .routers.remote_gateway import (
            RemoteEventActivationRequest,
            RemoteEventType,
            register_dispatch_handler,
        )

        async def approve_handler(
            body: RemoteEventActivationRequest,
        ) -> str:
            action_id = str(
                body.payload.get("action_id") or ""
            ).strip()
            decision_id = str(
                body.payload.get("decision_id") or ""
            ).strip()

            if not action_id:
                raise HTTPException(
                    status_code=422,
                    detail="remote approval requires payload.action_id",
                )

            action = await _resolve_governance_and_commit_action(
                action_id=action_id,
                decision_id=decision_id or None,
                approved=True,
                allowed_statuses={"STAGED"},
                new_status="APPROVED",
                reason=body.reason,
                operator=body.operator_id,
            )
            await _broadcast_dashboard_event(
                "action_status_changed",
                {"action": action},
            )
            return (
                f"Action {action_id} approved via remote gateway "
                f"by {body.operator_id}."
            )

        async def veto_handler(
            body: RemoteEventActivationRequest,
        ) -> str:
            action_id = str(
                body.payload.get("action_id") or ""
            ).strip()
            decision_id = str(
                body.payload.get("decision_id") or ""
            ).strip()

            if not action_id:
                raise HTTPException(
                    status_code=422,
                    detail="remote veto requires payload.action_id",
                )

            action = await _resolve_governance_and_commit_action(
                action_id=action_id,
                decision_id=decision_id or None,
                approved=False,
                allowed_statuses={"PENDING", "STAGED"},
                new_status="VETOED",
                reason=body.reason,
                operator=body.operator_id,
            )
            await _broadcast_dashboard_event(
                "action_status_changed",
                {"action": action},
            )
            return (
                f"Action {action_id} vetoed via remote gateway "
                f"by {body.operator_id}."
            )

        register_dispatch_handler(
            RemoteEventType.APPROVE_DECISION,
            approve_handler,
        )
        register_dispatch_handler(
            RemoteEventType.VETO_DECISION,
            veto_handler,
        )
        logger.info("Remote gateway APPROVE/VETO handlers registered")
    except Exception:
        if _env_bool("S43_REMOTE_GATEWAY_REQUIRED", False):
            raise
        logger.error(
            "Remote gateway dispatch handler registration failed",
            exc_info=True,
        )


async def _shutdown_runtime() -> None:
    if runtime.stop_heartbeat_event is not None:
        runtime.stop_heartbeat_event.set()

    if runtime.heartbeat_task is not None:
        try:
            await asyncio.wait_for(runtime.heartbeat_task, timeout=5.0)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            runtime.heartbeat_task.cancel()

    # Best effort "stopping" heartbeat before monitoring transport goes away.
    try:
        await send_api_heartbeat("stopping")
    except Exception:
        logger.warning("Final Watchtower heartbeat failed", exc_info=True)

    if runtime.fenrir_instance is not None:
        try:
            await asyncio.wait_for(
                runtime.fenrir_instance.shutdown(),
                timeout=5.0,
            )
        except Exception:
            logger.warning("FenrirHunter shutdown error", exc_info=True)

    if runtime.sparta_instance is not None:
        try:
            runtime.sparta_instance.stop()
        except Exception:
            logger.warning("SpartaCore stop error", exc_info=True)

    if runtime.sparta_task is not None:
        try:
            await asyncio.wait_for(runtime.sparta_task, timeout=5.0)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            runtime.sparta_task.cancel()

    if runtime.monitoring_manager is not None:
        try:
            await asyncio.to_thread(runtime.monitoring_manager.stop)
        except Exception:
            logger.warning(
                "MonitoringManager stop error",
                exc_info=True,
            )

    async with runtime.ws_lock:
        clients = list(runtime.ws_clients.values())

    for client in clients:
        await _queue_ws_frame(
            client,
            {
                "type": "server_shutdown",
                "payload": {"timestamp": utc_now()},
            },
        )
        await _ws_safe_close(
            client.websocket,
            code=1012,
            reason="server_shutdown",
        )


# =============================================================================
# Lifespan
# =============================================================================

@asynccontextmanager
async def lifespan(api: FastAPI):
    _validate_security_config()
    bootstrap_expectations(_bootstrap_settings())

    try:
        await _start_monitoring_manager()
        await _start_sparta()
        await _start_fenrir()
        await _start_audit_store()
        await _start_governance()
        await _register_remote_dispatch_handlers()

        # Registration failures are observable, but do not necessarily mean
        # the API itself cannot serve. Deployments that require Watchtower can
        # make this fatal with S43_WATCHTOWER_REQUIRED=true.
        registration = await register_api_with_watchtower()
        heartbeat = await send_api_heartbeat()

        if _env_bool("S43_WATCHTOWER_REQUIRED", False):
            if not registration.get("registered"):
                raise RuntimeError("Watchtower registration failed")
            if not heartbeat.get("heartbeat_sent"):
                raise RuntimeError("Initial Watchtower heartbeat failed")

        await report_dependency_to_watchtower(
            "sentinel-43-api",
            "online",
            {
                "version": APP_VERSION,
                "environment": SENTINEL_ENV,
            },
        )

        runtime.stop_heartbeat_event = asyncio.Event()
        runtime.heartbeat_task = asyncio.create_task(
            _async_heartbeat_loop(),
            name="sentinel43-api-heartbeat",
        )

        api.state.runtime = runtime
        yield

    finally:
        await _shutdown_runtime()


# =============================================================================
# Application
# =============================================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(_ALLOWED_ORIGINS),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-S43-Password",
        "X-Request-ID",
    ],
)

try:
    from core.middleware import FirewallConfig, SentinelFirewall

    class RuntimeMonitoringProxy:
        def __getattr__(self, name: str) -> Any:
            manager = runtime.monitoring_manager
            if manager is None:
                raise RuntimeError("MonitoringManager is not initialized")
            return getattr(manager, name)

    app.add_middleware(
        SentinelFirewall,
        config=FirewallConfig.from_env(),
        monitoring_manager=RuntimeMonitoringProxy(),
    )
except Exception as exc:
    if IS_LOCAL_ENV:
        logger.error(
            "SentinelFirewall registration failed in local/test environment",
            exc_info=True,
        )
    else:
        raise RuntimeError(
            "SentinelFirewall is required outside local/test environments"
        ) from exc

from .middleware.security_headers import (  # noqa: E402
    SecurityHeadersMiddleware,
    TrustedHostGuard,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(TrustedHostGuard)


# =============================================================================
# Optional Sparta node API
# =============================================================================

if _env_bool("S43_SPARTA_ENABLED", False):
    try:
        from core.monitoring import create_node_router

        class RuntimeSpartaProxy:
            def __getattr__(self, name: str) -> Any:
                if runtime.sparta_instance is None:
                    raise RuntimeError("SpartaCore is not initialized")
                return getattr(runtime.sparta_instance, name)

        app.include_router(create_node_router(RuntimeSpartaProxy()))
    except Exception:
        if _env_bool("S43_SPARTA_REQUIRED", False):
            raise
        logger.warning(
            "SpartaCore node router not registered",
            exc_info=True,
        )


# =============================================================================
# Static dashboard
# =============================================================================

DASHBOARD_DIR = _env_str("S43_DASHBOARD_DIR", "dashboard")
DASHBOARD_ASSETS_DIR = os.path.join(DASHBOARD_DIR, "assets")
DASHBOARD_HTML = os.path.join(
    DASHBOARD_DIR,
    "sentinel_43_dashboard.html",
)

if os.path.isdir(DASHBOARD_ASSETS_DIR):
    app.mount(
        "/assets",
        StaticFiles(directory=DASHBOARD_ASSETS_DIR),
        name="dashboard-assets",
    )


@app.get("/dashboard", include_in_schema=False)
def serve_dashboard() -> FileResponse:
    if not os.path.isfile(DASHBOARD_HTML):
        raise HTTPException(status_code=404, detail="dashboard not installed")
    return FileResponse(DASHBOARD_HTML)


@app.get("/dashboard.html", include_in_schema=False)
def serve_dashboard_html() -> FileResponse:
    return serve_dashboard()


# =============================================================================
# Canonical health/readiness
# =============================================================================

@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": APP_NAME,
        "version": APP_VERSION,
    }


@app.get("/ready")
async def ready() -> Any:
    from ..auth.schema_version import schema_report

    report = await schema_report()
    if report.serving_blocked:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "service": APP_NAME,
                "reason": "schema_version",
                "schema_state": report.state.value,
                "detail": report.detail,
            },
        )

    if _env_bool("S43_WATCHTOWER_REQUIRED", False):
        async with runtime.watchtower_lock:
            reachable = bool(
                runtime.watchtower_last_status.get("reachable")
            )
        if not reachable:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "not_ready",
                    "service": APP_NAME,
                    "reason": "watchtower_unreachable",
                },
            )

    return {"status": "ready", "service": APP_NAME}


# =============================================================================
# Root/operator router
# =============================================================================

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


@root_router.get("/status")
def status() -> dict[str, Any]:
    # Deliberately coarse and anonymous.
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
async def metrics(request: Request) -> dict[str, Any]:
    await _require_operator(request)

    try:
        from .routers.auth import legacy_auth_request_total
        legacy_auth = legacy_auth_request_total()
    except Exception:
        legacy_auth = {}

    return {
        "service": APP_NAME,
        "uptime_seconds": uptime_seconds(),
        "status": "online",
        "watchtower_heartbeat_seconds": WATCHTOWER_HEARTBEAT_SECONDS,
        "legacy_auth_request_total": legacy_auth,
        "in_memory_action_insert_count": await _action_insert_count(),
        "timestamp": utc_now(),
    }


@root_router.get("/actions")
async def dashboard_actions(
    request: Request,
    limit: int = 250,
) -> list[dict[str, Any]]:
    await _require_operator(request)
    return await _list_actions(limit)


@root_router.get("/vault/stats")
async def dashboard_vault_stats(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)
    return {
        "in_memory_action_insert_count": await _action_insert_count(),
        "durable_vault": False,
        "timestamp": utc_now(),
    }


@root_router.post("/actions/test-inject")
async def dashboard_test_inject(
    request: Request,
) -> dict[str, Any]:
    if not IS_LOCAL_ENV or not TEST_INJECTION_ENABLED:
        raise HTTPException(
            status_code=403,
            detail="test injection is disabled",
        )

    await _require_operator(request)

    action = await _store_action(_create_synthetic_action())
    await _broadcast_dashboard_event(
        "action_created",
        {"action": action},
    )
    return {
        "ok": True,
        "action": action,
        "timestamp": utc_now(),
    }


@root_router.post("/actions/{action_id}/approve")
async def dashboard_approve_action(
    action_id: str,
    body: DecisionBody,
    request: Request,
) -> dict[str, Any]:
    operator = await _require_operator(request)

    action = await _resolve_governance_and_commit_action(
        action_id=action_id,
        decision_id=body.decision_id,
        approved=True,
        allowed_statuses={"STAGED"},
        new_status="APPROVED",
        reason=body.reason,
        operator=operator,
    )

    await _broadcast_dashboard_event(
        "action_status_changed",
        {"action": action},
    )
    return {
        "ok": True,
        "action": action,
        "timestamp": utc_now(),
    }


@root_router.post("/actions/{action_id}/veto")
async def dashboard_veto_action(
    action_id: str,
    body: DecisionBody,
    request: Request,
) -> dict[str, Any]:
    operator = await _require_operator(request)

    action = await _resolve_governance_and_commit_action(
        action_id=action_id,
        decision_id=body.decision_id,
        approved=False,
        allowed_statuses={"PENDING", "STAGED"},
        new_status="VETOED",
        reason=body.reason,
        operator=operator,
    )

    await _broadcast_dashboard_event(
        "action_status_changed",
        {"action": action},
    )
    return {
        "ok": True,
        "action": action,
        "timestamp": utc_now(),
    }


@root_router.get("/governance/pending")
async def governance_pending_reviews(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)

    if runtime.orchestrator is None:
        return {
            "enabled": False,
            "pending": [],
            "timestamp": utc_now(),
        }

    try:
        pending = await asyncio.to_thread(
            runtime.orchestrator.list_pending_reviews
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Governance service unavailable",
        ) from exc

    return {
        "enabled": True,
        "pending": pending,
        "timestamp": utc_now(),
    }


# =============================================================================
# WebSocket endpoint
# =============================================================================

@app.websocket("/ws")
async def dashboard_websocket(websocket: WebSocket) -> None:
    origin = websocket.headers.get("origin", "")

    if (
        _ALLOWED_ORIGINS
        and origin
        and origin not in _ALLOWED_ORIGINS
    ):
        await _ws_safe_close(
            websocket,
            reason="origin_rejected",
        )
        return

    acquired = False
    try:
        try:
            await asyncio.wait_for(
                runtime.ws_capacity.acquire(),
                timeout=0.05,
            )
            acquired = True
        except asyncio.TimeoutError:
            await websocket.accept()
            await websocket.send_json(
                {
                    "type": "error",
                    "payload": {
                        "error": "Server is at maximum dashboard capacity"
                    },
                }
            )
            await _ws_safe_close(
                websocket,
                reason="capacity",
            )
            return

        await websocket.accept()

        client = WebSocketClient(websocket=websocket)

        if WS_REQUIRE_AUTH:
            await websocket.send_json(
                {
                    "type": "auth_required",
                    "payload": {
                        "message": (
                            'Send {"type":"auth","payload":{"token":"<bearer>"}} '
                            "to continue"
                        )
                    },
                }
            )

            try:
                auth_msg = await asyncio.wait_for(
                    _receive_ws_message(websocket),
                    timeout=15.0,
                )
            except WebSocketDisconnect:
                return
            except (asyncio.TimeoutError, ValueError):
                await _ws_safe_close(
                    websocket,
                    reason="auth_timeout",
                )
                return

            if auth_msg.get("type") != "auth":
                await websocket.send_json(
                    {
                        "type": "error",
                        "payload": {
                            "error": "First message must be an auth frame"
                        },
                    }
                )
                await _ws_safe_close(
                    websocket,
                    reason="invalid_auth_frame",
                )
                return

            payload = auth_msg.get("payload")
            if not isinstance(payload, dict):
                payload = {}

            token = str(payload.get("token") or "").strip()
            if not token:
                await websocket.send_json(
                    {
                        "type": "error",
                        "payload": {"error": "Token missing"},
                    }
                )
                await _ws_safe_close(
                    websocket,
                    reason="invalid_token",
                )
                return

            from .routers.auth import (
                legacy_auth_is_rejected,
                note_legacy_auth,
                resolve_session_subject,
                reverify_password,
                verify_jwt_token,
            )

            try:
                claims = verify_jwt_token(token)
            except HTTPException as exc:
                await websocket.send_json(
                    {
                        "type": "error",
                        "payload": {"error": str(exc.detail)},
                    }
                )
                await _ws_safe_close(
                    websocket,
                    reason="invalid_token",
                )
                return

            subject = str(claims.get("sub") or "").strip()
            if not subject:
                await _ws_safe_close(
                    websocket,
                    reason="invalid_token",
                )
                return

            client.subject = subject
            client.role = str(
                claims.get("role") or "operator"
            ).strip()

            exp = claims.get("exp")
            if isinstance(exp, (int, float)):
                client.exp = float(exp)

            try:
                resolved = await resolve_session_subject(claims)
            except HTTPException:
                await websocket.send_json(
                    {
                        "type": "error",
                        "payload": {
                            "error": "Session is no longer valid"
                        },
                    }
                )
                await _ws_safe_close(
                    websocket,
                    reason="session_revoked",
                )
                return
            except Exception:
                await websocket.send_json(
                    {
                        "type": "error",
                        "payload": {
                            "error": "Authentication service unavailable"
                        },
                    }
                )
                await _ws_safe_close(
                    websocket,
                    code=1011,
                    reason="auth_service_unavailable",
                )
                return

            if resolved is not None:
                sid = str(claims.get("sid") or "").strip()
                if not sid:
                    await _ws_safe_close(
                        websocket,
                        reason="session_invalid",
                    )
                    return
                client.sid = sid
            else:
                if legacy_auth_is_rejected():
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": {
                                "error": (
                                    "Legacy authentication is no longer "
                                    "accepted. Log in again."
                                )
                            },
                        }
                    )
                    await _ws_safe_close(
                        websocket,
                        reason="legacy_auth_rejected",
                    )
                    return

                note_legacy_auth("websocket")
                password = str(
                    payload.get("password") or ""
                ).strip()
                if not password:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": {"error": "Password missing"},
                        }
                    )
                    await _ws_safe_close(
                        websocket,
                        reason="invalid_password",
                    )
                    return

                try:
                    reverified = await reverify_password(
                        subject,
                        password,
                    )
                except HTTPException:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": {
                                "error": (
                                    "Authentication service is temporarily "
                                    "unavailable"
                                )
                            },
                        }
                    )
                    await _ws_safe_close(
                        websocket,
                        code=1011,
                        reason="auth_service_unavailable",
                    )
                    return

                if not reverified:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": {"error": "Invalid password"},
                        }
                    )
                    await _ws_safe_close(
                        websocket,
                        reason="invalid_password",
                    )
                    return

        async with runtime.ws_lock:
            runtime.ws_clients[websocket] = client

        client.writer_task = asyncio.create_task(
            _ws_writer(client),
            name=f"sentinel43-ws-writer-{id(websocket)}",
        )

        await _queue_ws_frame(
            client,
            {
                "type": "connected",
                "payload": {
                    "status": "ok",
                    "service": APP_NAME,
                    "timestamp": utc_now(),
                },
            },
        )

        while True:
            try:
                message = await asyncio.wait_for(
                    _receive_ws_message(websocket),
                    timeout=float(WS_SESSION_RECHECK_SECONDS),
                )
            except asyncio.TimeoutError:
                ok, reason = await _session_still_valid(client)
                if not ok:
                    await _queue_ws_frame(
                        client,
                        {
                            "type": "error",
                            "payload": {"error": reason},
                        },
                    )
                    await _ws_safe_close(
                        websocket,
                        code=1011
                        if reason == "auth_service_unavailable"
                        else 1008,
                        reason=reason,
                    )
                    return
                continue
            except ValueError as exc:
                await _queue_ws_frame(
                    client,
                    {
                        "type": "error",
                        "payload": {"error": str(exc)},
                    },
                )
                continue

            ok, reason = await _session_still_valid(client)
            if not ok:
                await _queue_ws_frame(
                    client,
                    {
                        "type": "error",
                        "payload": {"error": reason},
                    },
                )
                await _ws_safe_close(
                    websocket,
                    code=1011
                    if reason == "auth_service_unavailable"
                    else 1008,
                    reason=reason,
                )
                return

            event_type = str(
                message.get("type") or ""
            ).strip()
            payload = message.get("payload")
            if not isinstance(payload, dict):
                payload = {}

            if event_type == "ping":
                await _queue_ws_frame(
                    client,
                    {
                        "type": "pong",
                        "payload": {"timestamp": utc_now()},
                    },
                )
                continue

            if event_type == "subscribe":
                channel = str(
                    payload.get("channel") or ""
                ).strip()

                if not CHANNEL_RE.fullmatch(channel):
                    await _queue_ws_frame(
                        client,
                        {
                            "type": "error",
                            "payload": {"error": "Invalid channel"},
                        },
                    )
                    continue

                client.channels.add(channel)
                await _queue_ws_frame(
                    client,
                    {
                        "type": "subscribed",
                        "payload": {
                            "channel": channel,
                            "timestamp": utc_now(),
                        },
                    },
                )

                if channel == "actions":
                    await _queue_ws_frame(
                        client,
                        {
                            "type": "actions_snapshot",
                            "payload": {
                                "actions": await _list_actions()
                            },
                        },
                    )

                if channel == "governance" and runtime.orchestrator is not None:
                    try:
                        pending = await asyncio.to_thread(
                            runtime.orchestrator.list_pending_reviews
                        )
                    except Exception:
                        pending = []
                    await _queue_ws_frame(
                        client,
                        {
                            "type": "governance_pending_snapshot",
                            "payload": {"pending": pending},
                        },
                    )
                continue

            if event_type == "unsubscribe":
                channel = str(
                    payload.get("channel") or ""
                ).strip()
                client.channels.discard(channel)
                await _queue_ws_frame(
                    client,
                    {
                        "type": "unsubscribed",
                        "payload": {
                            "channel": channel,
                            "timestamp": utc_now(),
                        },
                    },
                )
                continue

            safe_type = repr(event_type[:64])
            await _queue_ws_frame(
                client,
                {
                    "type": "error",
                    "payload": {
                        "error": f"Unsupported event: {safe_type}"
                    },
                },
            )

    except WebSocketDisconnect:
        return
    finally:
        if acquired:
            existing: WebSocketClient | None
            async with runtime.ws_lock:
                existing = runtime.ws_clients.pop(websocket, None)

            if existing is None:
                runtime.ws_capacity.release()
            else:
                if existing.writer_task is not None:
                    existing.writer_task.cancel()
                runtime.ws_capacity.release()


# =============================================================================
# Internal service event router
# =============================================================================

internal_router = APIRouter(
    prefix="/internal",
    tags=["internal"],
)


@internal_router.post("/events/broadcast")
async def internal_broadcast_event(
    body: InternalBroadcastBody,
    request: Request,
) -> dict[str, Any]:
    _require_fenrir_service_token(request)

    # Fenrir token is restricted to its own namespace.
    if not body.event_type.startswith("fenrir."):
        raise HTTPException(
            status_code=403,
            detail="Fenrir service token may only emit fenrir.* events",
        )

    await _broadcast_dashboard_event(
        body.event_type,
        body.data,
        channel=body.channel,
    )

    async with runtime.ws_lock:
        client_count = len(runtime.ws_clients)

    return {
        "ok": True,
        "event_type": body.event_type,
        "channel": body.channel,
        "clients": client_count,
        "timestamp": utc_now(),
    }


# =============================================================================
# Proxy event router
# =============================================================================

proxy_events_router = APIRouter(
    prefix="/events",
    tags=["events"],
)


@proxy_events_router.post("/proxy")
async def ingest_proxy_event(
    body: ProxyEventBody,
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)

    event = {
        "type": "proxy_event",
        "source": body.source.strip()[:64],
        "method": body.method,
        "url": _redact_proxy_url(body.url),
        "host": body.host,
        "path": _redact_proxy_url(body.path),
        "status_code": body.status_code,
        "request_size": body.request_size,
        "response_size": body.response_size,
        "user_agent": body.user_agent,
        "client_host": (
            request.client.host
            if request.client
            else None
        ),
        "timestamp": utc_now(),
    }

    await _broadcast_dashboard_event(
        "proxy_event",
        event,
        channel="proxy",
    )

    async with runtime.ws_lock:
        client_count = len(runtime.ws_clients)

    return {
        "ok": True,
        "event_type": "proxy_event",
        "channel": "proxy",
        "clients": client_count,
        "event": event,
        "timestamp": utc_now(),
    }


# =============================================================================
# Watchtower router
# =============================================================================

watchtower_router = APIRouter(
    prefix="/watchtower",
    tags=["watchtower"],
)


@watchtower_router.get("/health")
async def api_watchtower_health() -> dict[str, Any]:
    result = await watchtower_health_check()
    return {
        "bridge": "api_to_watchtower",
        "reachable": result["reachable"],
    }


@watchtower_router.get("/ready")
async def api_watchtower_ready() -> dict[str, Any]:
    result = await asyncio.to_thread(
        _watchtower_request,
        "GET",
        "/watchtower/ready",
    )
    return {
        "bridge": "api_to_watchtower",
        "reachable": "error" not in result,
    }


@watchtower_router.get("/status")
async def api_watchtower_status(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)
    result = await asyncio.to_thread(
        _watchtower_request,
        "GET",
        "/watchtower/status",
    )
    return {
        "bridge": "api_to_watchtower",
        "reachable": "error" not in result,
        "watchtower": result,
        "timestamp": utc_now(),
    }


@watchtower_router.post("/register")
async def api_register_watchtower(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)
    return await register_api_with_watchtower()


@watchtower_router.post("/heartbeat")
async def api_heartbeat_watchtower(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)
    return await send_api_heartbeat()


@watchtower_router.get("/modules")
async def api_watchtower_modules(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)
    result = await asyncio.to_thread(
        _watchtower_request,
        "GET",
        "/watchtower/modules",
    )
    return {
        "bridge": "api_to_watchtower",
        "reachable": "error" not in result,
        "watchtower": result,
        "timestamp": utc_now(),
    }


@watchtower_router.get("/check")
async def watchtower_check(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)

    health_result = await watchtower_health_check()
    ready_result = await asyncio.to_thread(
        _watchtower_request,
        "GET",
        "/watchtower/ready",
    )
    status_result = await asyncio.to_thread(
        _watchtower_request,
        "GET",
        "/watchtower/status",
    )

    async with runtime.watchtower_lock:
        snapshot = copy.deepcopy(runtime.watchtower_last_status)

    return {
        "service": "watchtower_bridge",
        "checks": {
            "health": (
                "ok"
                if health_result["reachable"]
                else "failed"
            ),
            "ready": (
                "ok"
                if "error" not in ready_result
                else "failed"
            ),
            "status": (
                "ok"
                if "error" not in status_result
                else "failed"
            ),
            "api_registered": bool(
                snapshot.get("registered")
            ),
        },
        "responses": {
            "health": health_result,
            "ready": ready_result,
            "status": status_result,
        },
        "timestamp": utc_now(),
    }


@watchtower_router.post("/events")
async def watchtower_ingest_event(
    body: dict[str, Any],
    request: Request,
) -> dict[str, Any]:
    _require_fenrir_service_token(request)

    result = await asyncio.to_thread(
        _watchtower_request,
        "POST",
        "/watchtower/analyze",
        {"event": body},
    )

    await _broadcast_dashboard_event(
        "watchtower_event",
        {
            "event": body,
            "watchtower_response": result,
            "timestamp": utc_now(),
        },
        channel="watchtower",
    )

    return {
        "ok": True,
        "forwarded": result,
        "timestamp": utc_now(),
    }


# =============================================================================
# Core router
# =============================================================================

core_router = APIRouter(
    prefix="/core",
    tags=["core"],
)


@core_router.get("/status")
async def core_status(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)
    return {
        "service": "s43_core",
        "status": "online",
        "state": "RUNNING",
        "timestamp": utc_now(),
    }


@core_router.get("/health")
def core_health() -> dict[str, Any]:
    # Coarse and side-effect free.
    return {
        "service": "s43_core",
        "status": "ok",
        "timestamp": utc_now(),
    }


@core_router.post("/heartbeat")
async def core_heartbeat(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)

    result = await report_dependency_to_watchtower(
        "sentinel-43-core",
        "online",
        {
            "heartbeat_source": "api",
            "uptime_seconds": uptime_seconds(),
            "timestamp": utc_now(),
        },
    )

    await _broadcast_dashboard_event(
        "dependency_state",
        {
            "name": "sentinel-43-core",
            "status": "online",
            "timestamp": utc_now(),
        },
        channel="dependencies",
    )

    return {
        "service": "s43_core",
        "heartbeat": "sent" if "error" not in result else "failed",
        "watchtower_response": result,
        "timestamp": utc_now(),
    }


# =============================================================================
# Rules/config/dependencies/system routers
# =============================================================================

rules_router = APIRouter(
    prefix="/rules",
    tags=["rules"],
)


@rules_router.get("/status")
async def rules_status(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)
    return {
        "service": "rules",
        "status": "loaded",
        "active": True,
        "timestamp": utc_now(),
    }


@rules_router.get("/")
async def rules_root(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)
    return {
        "service": "rules",
        "message": "Rules registry endpoint active",
        "timestamp": utc_now(),
    }


config_router = APIRouter(
    prefix="/config",
    tags=["config"],
)


@config_router.get("/status")
async def config_status(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)
    return {
        "service": "config",
        "status": "loaded",
        "environment": SENTINEL_ENV,
        "timestamp": utc_now(),
    }


@config_router.get("/")
async def config_root(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)
    return {
        "service": "config",
        "environment": SENTINEL_ENV,
        "timestamp": utc_now(),
    }


dependencies_router = APIRouter(
    prefix="/dependencies",
    tags=["dependencies"],
)


@dependencies_router.get("/status")
async def dependencies_status(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)
    wt = await watchtower_health_check()

    return {
        "service": "dependencies",
        "checks": {
            "api": "ok",
            "core": "ok",
            "watchtower": (
                "ok"
                if wt["reachable"]
                else "failed"
            ),
            "redis": "unknown",
            "postgres": "unknown",
        },
        "timestamp": utc_now(),
    }


@dependencies_router.post("/report/{name}/{state}")
async def report_dependency(
    name: str,
    state: str,
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)

    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", name):
        raise HTTPException(
            status_code=422,
            detail="invalid dependency name",
        )
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", state):
        raise HTTPException(
            status_code=422,
            detail="invalid dependency state",
        )

    result = await report_dependency_to_watchtower(
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


system_router = APIRouter(
    prefix="/system",
    tags=["system"],
)


@system_router.get("/status")
async def system_status(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)

    wt = await asyncio.to_thread(
        _watchtower_request,
        "GET",
        "/watchtower/status",
    )

    return {
        "system": "sentinel-43",
        "status": "online",
        "version": APP_VERSION,
        "uptime_seconds": uptime_seconds(),
        "components": {
            "api": "online",
            "core": "online",
            "watchtower": (
                "online"
                if "error" not in wt
                else "unreachable"
            ),
            "rules": "loaded",
            "config": "loaded",
            "monitoring_manager": (
                "active"
                if runtime.monitoring_manager
                else "disabled"
            ),
            "sparta": (
                "active"
                if runtime.sparta_instance
                else "disabled"
            ),
            "fenrir": (
                "active"
                if runtime.fenrir_instance
                else "disabled"
            ),
            "governance": (
                "active"
                if runtime.orchestrator
                else "disabled"
            ),
            "redis": "unknown",
            "postgres": "unknown",
        },
        "watchtower": wt,
        "timestamp": utc_now(),
    }


@system_router.get("/routes")
async def system_routes(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)

    route_list = [
        {
            "path": getattr(route, "path", None),
            "name": getattr(route, "name", None),
            "methods": sorted(
                getattr(route, "methods", None) or []
            ),
        }
        for route in app.routes
        if getattr(route, "path", None)
    ]

    return {
        "service": APP_NAME,
        "route_count": len(route_list),
        "routes": route_list,
        "timestamp": utc_now(),
    }


@system_router.get("/intercom/status")
async def intercom_status(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)

    wt_health = await watchtower_health_check()
    wt_modules = await asyncio.to_thread(
        _watchtower_request,
        "GET",
        "/watchtower/modules",
    )

    return {
        "service": "sentinel-43-intercom",
        "api": "online",
        "watchtower": (
            "online"
            if wt_health["reachable"]
            else "unreachable"
        ),
        "modules": wt_modules,
        "timestamp": utc_now(),
    }


# =============================================================================
# Fenrir router
# =============================================================================

fenrir_router = APIRouter(
    prefix="/fenrir",
    tags=["fenrir"],
)


async def _fenrir_snapshot() -> dict[str, Any]:
    instance = runtime.fenrir_instance

    if instance is None:
        return {
            "enabled": _env_any_bool(
                (
                    "S43_FENRIR_ENABLED",
                    "SENTINEL_FENRIR_ENABLED",
                    "FENRIR_ENABLED",
                ),
                False,
            ),
            "status": "disabled",
            "timestamp": utc_now(),
        }

    try:
        snapshot = await asyncio.to_thread(instance.snapshot)
        snapshot["enabled"] = True
        return snapshot
    except Exception:
        logger.warning("Fenrir snapshot error", exc_info=True)
        return {
            "enabled": True,
            "status": "unknown",
            "node_id": getattr(
                getattr(instance, "config", None),
                "node_id",
                "unknown",
            ),
            "timestamp": utc_now(),
        }


@fenrir_router.get("/status")
async def fenrir_status(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)
    return await _fenrir_snapshot()


@fenrir_router.get("/health")
async def fenrir_health(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)
    return {
        "service": "fenrir",
        **(await _fenrir_snapshot()),
    }


@fenrir_router.get("/metrics")
async def fenrir_metrics(
    request: Request,
) -> dict[str, Any]:
    await _require_operator(request)
    snapshot = await _fenrir_snapshot()
    return {
        "service": "fenrir",
        "enabled": snapshot.get("enabled", False),
        "status": snapshot.get("status", "disabled"),
        "metrics": snapshot.get("metrics", {}),
        "anomaly_layer": snapshot.get("anomaly_layer", {}),
        "timestamp": utc_now(),
    }


# =============================================================================
# API compatibility router
# =============================================================================

api_router = APIRouter(
    prefix="/api",
    tags=["api-compat"],
)


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
async def compat_api_config(
    request: Request,
) -> dict[str, Any]:
    return await config_root(request)


@api_router.get("/rules")
async def compat_api_rules(
    request: Request,
) -> dict[str, Any]:
    return await rules_root(request)


@api_router.get("/watchtower/status")
async def compat_api_watchtower_status(
    request: Request,
) -> dict[str, Any]:
    return await api_watchtower_status(request)


@api_router.get("/watchtower/health")
async def compat_api_watchtower_health() -> dict[str, Any]:
    return await api_watchtower_health()


@api_router.get("/watchtower/ready")
async def compat_api_watchtower_ready() -> dict[str, Any]:
    return await api_watchtower_ready()


# =============================================================================
# Router registration
# =============================================================================

app.include_router(root_router)
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(bootstrap_router)
app.include_router(remote_gateway_router)

# IMPORTANT:
# watchgate_router previously advertised another top-level /health route.
# Keep it only if the router no longer registers GET /health. We explicitly
# fail at import time below if a duplicate canonical health route exists.
app.include_router(watchgate_router)

app.include_router(internal_router)
app.include_router(proxy_events_router)
app.include_router(watchtower_router)
app.include_router(core_router)
app.include_router(rules_router)
app.include_router(config_router)
app.include_router(dependencies_router)
app.include_router(system_router)
app.include_router(fenrir_router)
app.include_router(api_router)
app.include_router(audit_router)


def _assert_no_duplicate_routes() -> None:
    seen: dict[tuple[str, str], str] = {}

    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None) or set()
        name = getattr(route, "name", "<unnamed>")

        if not path:
            continue

        for method in methods:
            key = (method.upper(), path)
            previous = seen.get(key)
            if previous is not None:
                raise RuntimeError(
                    "Duplicate route registration detected: "
                    f"{method.upper()} {path} is registered as both "
                    f"{previous!r} and {name!r}"
                )
            seen[key] = str(name)


_assert_no_duplicate_routes()


# =============================================================================
# Health-check access-log filtering
# =============================================================================

_HEALTH_CHECK_LOG_PATHS = frozenset(
    {
        "/health",
        "/ready",
        "/watchtower/health",
        "/watchtower/ready",
        "/core/health",
        "/audit/health",
        "/api/ready",
        "/api/watchtower/health",
        "/api/watchtower/ready",
    }
)

install_health_check_access_filter(_HEALTH_CHECK_LOG_PATHS)


# =============================================================================
# Error handlers
# =============================================================================

@app.exception_handler(404)
async def not_found_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={
            "error": "route_not_found",
            "path": str(request.url.path),
            "message": (
                "Requested route is not registered in Sentinel-43 API."
            ),
            "timestamp": utc_now(),
        },
    )
