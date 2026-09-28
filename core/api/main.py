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
import functools
import json
import logging
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections.abc import Mapping
from typing import Any, Final
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
from ..lifecycle import (
    Reason as SubsystemReason,
    SubsystemRegistry,
    SubsystemState,
    missing_settings,
)
from ..logging.health_check_filter import install_health_check_access_filter
from ..reliability import (
    DeadLetterStore,
    EventReliabilityManager,
    FailureStage,
    IdempotencyLedger,
    RetryPolicy,
    sanitize_reason,
)
from ..monitoring.watchtower_client import (
    configure as _configure_watchtower_client,
    watchtower_request as _canonical_watchtower_request,
)
from ..security.jwt_constants import APPROVED_JWT_ALGORITHMS
from ..monitoring.event_types import EVENT_SCHEMA_VERSION, would_loop
from core.governance.orchestrator import (
    LEGACY_REVIEW_ACTION,
    operations_for_row,
    recommendation_for_row,
    staging_record_matches_row,
)
from ..security_context import (
    IdentityType,
    get_security_context,
    identity_of,
    new_id as new_event_id,
    set_identity as _set_identity,
)
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
    # An env var set to an empty/whitespace string (Compose's `${VAR:-}`
    # pass-through idiom) is treated as unset.
    if not normalized:
        return default
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
        raw = os.getenv(name)
        if raw is not None and raw.strip():
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
    if raw is None or not raw.strip():
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


def _env_float(
    name: str,
    default: float,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        value = default
    else:
        try:
            value = float(raw.strip())
        except ValueError as exc:
            raise RuntimeError(f"{name} must be a number; got {raw!r}") from exc

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
# SENTINEL_ENV is canonical here; S43_ENV is the alias Fenrir/Sparta/Watchtower
# read. Accept either so a deployment that only sets one cannot leave this
# process silently defaulting to "production".
SENTINEL_ENV = (
    _env_str("SENTINEL_ENV") or _env_str("S43_ENV", "production")
).lower()

LOCAL_TEST_ENVIRONMENTS = frozenset({"development", "dev", "local", "test"})
IS_LOCAL_ENV = SENTINEL_ENV in LOCAL_TEST_ENVIRONMENTS

WATCHTOWER_HEARTBEAT_SECONDS = _env_int(
    "S43_WATCHTOWER_HEARTBEAT_SECONDS",
    15,
    minimum=5,
    maximum=3600,
)

# Watchtower connection settings are owned here (the composition root) and
# injected into the canonical client via configure() during lifespan startup.
WATCHTOWER_URL = _env_str(
    "S43_WATCHTOWER_URL", "http://s43-core:9100"
).rstrip("/")
WATCHTOWER_TIMEOUT = _env_float(
    "S43_WATCHTOWER_TIMEOUT",
    2.0,
    minimum=0.1,
    maximum=300.0,
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
    # Top-level Sentinel-43 orchestration authority.  The orchestrator field
    # below is a temporary compatibility alias to sentinel43.orchestrator;
    # it must never hold an independently-created instance.
    sentinel43: Any | None = None
    orchestrator: Any | None = None
    heart: Any | None = None
    sparta_instance: Any | None = None
    sparta_task: asyncio.Task[Any] | None = None
    fenrir_instance: Any | None = None

    #: Event delivery reliability (idempotency, bounded retry, dead-letter).
    reliability: Any | None = None

    #: Lifecycle state of every optional/required subsystem. Populated during
    #: lifespan startup and read by /health, /ready and /system/status.
    subsystems: SubsystemRegistry = field(
        default_factory=SubsystemRegistry
    )


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

    # The Heart reports evidence; the governance orchestrator is the only
    # authority that may stage or resolve a recommendation from it. Enabling
    # one without the other is a configuration error, not a degraded mode, so
    # it is refused here -- explicitly, in every environment, and whatever
    # S43_HEART_REQUIRED says. Governance is NOT auto-enabled behind the
    # operator: turning on an authority is their decision to make.
    if _env_bool("S43_HEART_ENABLED", False) and not _env_bool(
        "S43_GOVERNANCE_ENABLED", False
    ):
        raise RuntimeError(
            "S43_HEART_ENABLED=true requires S43_GOVERNANCE_ENABLED=true: the "
            "Heart has no decision authority of its own and cannot stage or "
            "resolve a recommendation without the governance orchestrator. "
            "Set S43_GOVERNANCE_ENABLED=true, or set S43_HEART_ENABLED=false."
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

        # Per-request password authentication is never accepted here:
        # S43_REJECT_LEGACY_AUTH must be explicitly true, and unset, blank,
        # malformed or false refuses startup. There is no override.
        from .routers.auth import validate_legacy_auth_config

        validate_legacy_auth_config()

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
                    "outside local/dev/test. The break-glass login it belongs "
                    "to is unavailable here anyway: remove the value, or fix it."
                )

        # The env-operator break-glass login is local/dev/test only
        # (routers/auth.py::_env_operator_allowed). Say so when it is
        # configured here, instead of letting it look usable.
        if operator_hash or (
            os.getenv("S43_BREAK_GLASS_ARMED", "").strip().lower() in _TRUE_VALUES
        ):
            logger.warning(
                "Break-glass env-operator login is configured "
                "(S43_OPERATOR_PASSWORD_HASH / S43_BREAK_GLASS_ARMED) but is "
                "unavailable outside development/local/test: every login with "
                "it is refused in environment %r.",
                SENTINEL_ENV,
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
    operator = await _get_operator(request, allow_local_fallback=False)
    _set_identity(request, IdentityType.OPERATOR, operator)
    return operator


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

    # Record WHICH identity authenticated. Never records the token itself.
    _set_identity(request, IdentityType.SERVICE_FENRIR, "fenrir-hunter")


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
    incident_id: str | None = None,
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
        if incident_id:
            # The durable incident this approval opened, so the reviewer can
            # find the record their decision created.
            payload = action.get("payload")
            if isinstance(payload, dict):
                payload["incident_id"] = incident_id
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
    principal: Any | None = None,
) -> dict[str, Any]:
    """Resolve one action through whichever governance backend originated
    it, then commit the shared, canonical action-store status.

    There is exactly one staged-action source of truth for the dashboard's
    /actions surface: a HEART_RECOMMENDATION (Heart-originated, see
    core/governance/heart.py -- deliberately distinct from the pre-existing
    generic "THREAT_ACTION" default used by _create_synthetic_action() and
    the dashboard, which still goes through SystemOrchestrator below like
    any other action) resolves through ThreatGovernor against its durable
    SentinelCoreStore row; every other action resolves through
    SystemOrchestrator against its in-memory pending review, exactly as
    before. Either way, the in-memory action_store entry is committed only
    after the owning governance backend accepts the decision -- never
    independently, and never twice.
    """
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

    if str(action.get("action_type") or "") == "HEART_RECOMMENDATION":
        # Resolved through the top-level Sentinel-43 runtime authority --
        # not by the Heart, which holds no decision authority of its own.
        authority = runtime.sentinel43
        if authority is None or not authority.recommendation_store_attached:
            raise HTTPException(
                status_code=409,
                detail="The Heart is not enabled",
            )
        from core.governance import UnauthorizedDecision

        try:
            resolution = await asyncio.to_thread(
                functools.partial(
                    authority.resolve_recommendation,
                    action_id,
                    approved=approved,
                    operator_id=operator,
                    reason=reason,
                    principal=principal,
                )
            )
            incident_id = str(resolution.get("incident_id") or "") or None
        except KeyError as exc:
            raise HTTPException(
                status_code=404,
                detail="Heart action does not exist",
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(
                status_code=409,
                detail=str(exc),
            ) from exc
        except UnauthorizedDecision as exc:
            raise HTTPException(
                status_code=403,
                detail="operator is not authorized to resolve this action",
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail=str(exc),
            ) from exc
        except Exception as exc:
            logger.exception(
                "Heart decision resolution failed for action_id=%s", action_id
            )
            raise HTTPException(
                status_code=503,
                detail="Heart decision service is unavailable",
            ) from exc

    else:
        incident_id = None
        resolved_decision_id = (
            (decision_id or "").strip()
            or str(action.get("payload", {}).get("decision_id") or "").strip()
            or None
        )

        # Fail closed, exactly as the HEART_RECOMMENDATION branch above.
        # Previously this whole block was SKIPPED when no orchestrator was
        # configured, and the decision was committed to the in-memory
        # store with no governance and no durable audit -- the default
        # path, since S43_GOVERNANCE_ENABLED defaults false.
        if runtime.sentinel43 is None:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Governance is not enabled; this action cannot be "
                    "resolved"
                ),
            )

        # The transaction adapter trusts whatever operator_id it is handed,
        # so an authenticated HUMAN is proven here, from the server-recorded
        # identity -- the same rule the recommendation path enforces inside
        # the orchestrator. A service credential (e.g. a remote-gateway role
        # token with a self-asserted operator_id) cannot decide.
        denial: str | None = None
        if principal is None:
            denial = "NO_AUTHENTICATION_CONTEXT"
        elif principal.subject.strip() != operator.strip():
            denial = "OPERATOR_ID_DOES_NOT_MATCH_AUTHENTICATED_SUBJECT"
        elif not _heart_operator_authenticator(principal):
            denial = "UNAUTHORIZED_DECISION_ATTEMPT"
        if denial is not None:
            try:
                await asyncio.to_thread(
                    functools.partial(
                        runtime.sentinel43.record_denied_decision,
                        resolved_decision_id or "",
                        operator_id=operator,
                        reason_code=denial,
                        identity_type=(
                            principal.identity_type if principal else "none"
                        ),
                    )
                )
            except Exception as exc:
                logger.exception("Failed to audit a refused governance decision")
                raise HTTPException(
                    status_code=503,
                    detail="Governance decision service is unavailable",
                ) from exc
            raise HTTPException(
                status_code=403,
                detail="an authenticated human operator is required to resolve this action",
            )

        if not resolved_decision_id:
            raise HTTPException(
                status_code=409,
                detail="governance decision_id is required while governance is enabled",
            )
        try:
            await asyncio.to_thread(
                runtime.sentinel43.resolve_human_decision,
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
        incident_id=incident_id,
    )


# =============================================================================
# WebSocket manager
# =============================================================================

# Close contract when the authentication/session BACKEND is unavailable (a
# platform outage, not a bad credential):
#   - reason contains none of auth|token|password|credential|session|login,
#     which the dashboard (websocket.js _reasonIndicatesAuthFailure) treats as
#     a client authentication failure;
#   - code is 1011 (server error), NOT 1008 (policy violation): the dashboard
#     reconnects with backoff after 1011 but never after 1008, so a transient
#     outage must not permanently disconnect the client.
# Every use fails closed: the connection is closed, never authenticated.
WS_REASON_AUTH_BACKEND_UNAVAILABLE = "service_unavailable"
WS_CLOSE_AUTH_BACKEND_UNAVAILABLE = 1011


def _ws_close_code_for_reason(reason: str) -> int:
    if reason == WS_REASON_AUTH_BACKEND_UNAVAILABLE:
        return WS_CLOSE_AUTH_BACKEND_UNAVAILABLE
    return 1008


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


async def _ws_send_error_then_close(
    websocket: WebSocket,
    *,
    error: str,
    code: int = 1008,
    reason: str = "",
) -> None:
    """Deliver a terminal error frame, then close -- in that guaranteed order.

    The regular outbound path (``_queue_ws_frame`` -> the client's writer
    task) is fire-and-forget: it enqueues and returns immediately, with no
    guarantee the frame was actually written before the caller's next
    ``await``. That is fine for ordinary broadcast traffic, but wrong for a
    frame telling the client WHY it is about to be disconnected -- queuing
    that frame and then immediately closing races the writer task, and the
    close can reach the client first, silently dropping the explanation.
    (A real network usually hides this by adding enough latency for the
    writer to run first; it reproduces reliably against an in-process
    TestClient with no such delay.)

    Sent directly, bypassing the queue, and awaited before the close call
    returns -- so the reason is guaranteed delivered whenever the transport
    accepts it at all. Best-effort: if the send itself fails, the socket is
    already going away regardless, and the close's own `reason` string still
    carries the same information at the protocol level.
    """
    try:
        await asyncio.wait_for(
            websocket.send_json({"type": "error", "payload": {"error": error}}),
            timeout=float(WS_SEND_TIMEOUT_SECONDS),
        )
    except Exception:
        pass
    await _ws_safe_close(websocket, code=code, reason=reason)


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
        # Bounded per-client queue: a dashboard that stops reading is
        # disconnected rather than allowed to stall event processing for
        # everyone else. The eviction is counted so it is observable.
        if runtime.reliability is not None:
            runtime.reliability.metrics.increment("ws_slow_client_disconnect")
            runtime.reliability.metrics.increment("queue_overflow")
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
    except HTTPException as exc:
        # resolve_session_subject raises 503 when the session SERVICE is
        # unavailable (an outage) and 401 for a genuinely invalid session.
        if exc.status_code == 503:
            return False, WS_REASON_AUTH_BACKEND_UNAVAILABLE
        return False, "session_revoked"
    except Exception:
        logger.warning(
            "WebSocket session revalidation failed closed for sid=%s",
            client.sid,
            exc_info=True,
        )
        return False, WS_REASON_AUTH_BACKEND_UNAVAILABLE


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

                # Startup reports this dependency once (see lifespan). Without
                # a periodic refresh here, Watchtower's own dependency_stale_
                # seconds (60s default) elapses during perfectly ordinary
                # operation and /watchtower/ready reports not_ready forever
                # after, even though /watchtower/health, the module heartbeat
                # above, and everything else stays healthy. Re-report on the
                # same cadence as the module heartbeat so the two stay
                # consistent.
                await report_dependency_to_watchtower(
                    "sentinel-43-api",
                    "online",
                    {
                        "version": APP_VERSION,
                        "environment": SENTINEL_ENV,
                    },
                )
        except Exception:
            logger.warning("Heartbeat loop error", exc_info=True)


# =============================================================================
# Subsystem lifecycle
# =============================================================================

# Subsystem names used in the lifecycle registry and on the status surface.
SUBSYS_MONITORING = "monitoring_manager"
SUBSYS_WATCHTOWER = "watchtower"
SUBSYS_SPARTA = "sparta"
SUBSYS_FENRIR = "fenrir"
SUBSYS_AUDIT = "audit_store"
SUBSYS_GOVERNANCE = "governance"
SUBSYS_HEART = "heart"
SUBSYS_RELIABILITY = "reliability"


def _declare_subsystems() -> None:
    """Register every subsystem before startup so none is silently absent."""
    runtime.subsystems.reset()
    runtime.subsystems.declare(
        SUBSYS_MONITORING, required=_env_bool("S43_MONITORING_REQUIRED", False)
    )
    runtime.subsystems.declare(
        SUBSYS_WATCHTOWER, required=_env_bool("S43_WATCHTOWER_REQUIRED", False)
    )
    runtime.subsystems.declare(
        SUBSYS_SPARTA, required=_env_bool("S43_SPARTA_REQUIRED", False)
    )
    runtime.subsystems.declare(
        SUBSYS_FENRIR, required=_env_bool("S43_FENRIR_REQUIRED", False)
    )
    runtime.subsystems.declare(
        SUBSYS_AUDIT, required=_env_bool("S43_GOVERNANCE_ENABLED", False)
        or not IS_LOCAL_ENV
    )
    runtime.subsystems.declare(
        SUBSYS_GOVERNANCE, required=_env_bool("S43_GOVERNANCE_REQUIRED", True)
        and _env_bool("S43_GOVERNANCE_ENABLED", False)
    )
    runtime.subsystems.declare(
        # Mirrors SUBSYS_GOVERNANCE's pattern exactly: required defaults to
        # True once enabled, so a beta profile that turns the Heart on gets
        # a fail-closed /ready by default, not a silently-optional one.
        SUBSYS_HEART, required=_env_bool("S43_HEART_REQUIRED", True)
        and _env_bool("S43_HEART_ENABLED", False)
    )
    runtime.subsystems.declare(SUBSYS_RELIABILITY, required=False)


def _refuse_unconfigured(
    name: str,
    missing: tuple[str, ...],
    *,
    required_flag: str,
    reason: SubsystemReason,
) -> bool:
    """Record an enabled-but-unconfigured subsystem and decide whether to fail.

    Returns True when startup of that subsystem must be skipped. Raises when
    the deployment marked it required. The names of the unset settings are
    reported; their values are never read, logged, or returned.
    """
    runtime.subsystems.mark_unconfigured(name, missing, reason=reason)
    logger.error(
        "%s is enabled but not configured: configured=false reason=%s "
        "missing=%s (values are never logged)",
        name,
        reason.value,
        ",".join(missing),
    )
    if _env_bool(required_flag, False):
        raise RuntimeError(
            f"{name} is enabled and required but not configured; "
            f"reason={reason.value} missing={','.join(missing)}"
        )
    return True


def _validate_watchtower_config() -> None:
    """Validate the Watchtower client settings the API depends on."""
    missing = missing_settings(
        {
            "S43_WATCHTOWER_URL": WATCHTOWER_URL,
            "S43_WATCHTOWER_SERVICE_TOKEN": _env_str(
                "S43_WATCHTOWER_SERVICE_TOKEN"
            ),
        }
    )
    if missing:
        _refuse_unconfigured(
            SUBSYS_WATCHTOWER,
            missing,
            required_flag="S43_WATCHTOWER_REQUIRED",
            reason=SubsystemReason.MISSING_TOKEN,
        )
        return

    # Reachability is proven later by registration/heartbeat; configuration
    # is correct, so the subsystem is at least startable.
    runtime.subsystems.mark_starting(SUBSYS_WATCHTOWER)


async def _start_monitoring_manager() -> None:
    runtime.subsystems.mark_starting(SUBSYS_MONITORING)
    try:
        from core.monitoring import (
            MonitoringManager,
            WatchtowerConfig,
            WatchtowerNode,
            WatchtowerNodeScanner,
            set_monitoring_manager,
        )

        node = WatchtowerNode(
            WatchtowerConfig.default_sentinel_octagon(
                _env_str("S43_WATCHTOWER_NODE_ID", "sentinel43-api")
            )
        )

        manager = MonitoringManager(WatchtowerNodeScanner(node))
        await asyncio.to_thread(manager.start)
        set_monitoring_manager(manager)
        runtime.monitoring_manager = manager
        runtime.subsystems.mark_active(
            SUBSYS_MONITORING, "Scanning via the embedded Watchtower node."
        )
        logger.info("MonitoringManager started and wired")
    except Exception as exc:
        runtime.subsystems.mark_failed(
            SUBSYS_MONITORING, f"Failed to start: {type(exc).__name__}"
        )
        if _env_bool("S43_MONITORING_REQUIRED", False):
            raise
        logger.error("MonitoringManager unavailable", exc_info=True)


async def _start_sparta() -> None:
    if not _env_bool("S43_SPARTA_ENABLED", False):
        runtime.subsystems.mark_disabled(SUBSYS_SPARTA)
        return

    watched_files: dict[str, str] = {}
    for key, value in os.environ.items():
        if key.startswith("S43_SPARTA_HASH_"):
            file_key = (
                key[len("S43_SPARTA_HASH_") :]
                .lower()
                .replace("_", "/")
            )
            watched_files[file_key] = value

    # Validate before constructing anything: an enabled Sparta with no node
    # token serves 503 on every /node route, and one with no digests cannot
    # watch anything. Both are refused here with an explicit reason instead
    # of surfacing later as a half-started subsystem.
    required: dict[str, str | None] = {
        "S43_SPARTA_NODE_TOKEN": _env_str("S43_SPARTA_NODE_TOKEN"),
    }
    if not IS_LOCAL_ENV:
        required["S43_SPARTA_TOKEN_SECRET"] = _env_str(
            "S43_SPARTA_TOKEN_SECRET"
        )

    missing = missing_settings(required)
    if missing:
        _refuse_unconfigured(
            SUBSYS_SPARTA,
            missing,
            required_flag="S43_SPARTA_REQUIRED",
            reason=SubsystemReason.MISSING_TOKEN,
        )
        return

    if not watched_files:
        _refuse_unconfigured(
            SUBSYS_SPARTA,
            ("S43_SPARTA_HASH_*",),
            required_flag="S43_SPARTA_REQUIRED",
            reason=SubsystemReason.MISSING_CONFIG,
        )
        return

    runtime.subsystems.mark_starting(SUBSYS_SPARTA)
    try:
        from core.monitoring import build_sparta_core

        # build_sparta_core() is the canonical Sparta factory: it owns the
        # IntegrityConfig.from_env() read and the SpartaCore construction.
        # Duplicating that here was a second composition path for the same
        # object.
        runtime.sparta_instance = build_sparta_core(
            watched_files,
            monitoring_manager=runtime.monitoring_manager,
        )
        runtime.sparta_task = asyncio.create_task(
            runtime.sparta_instance.run(),
            name="sentinel43-sparta-watchdog",
        )
        runtime.subsystems.mark_active(
            SUBSYS_SPARTA,
            f"Watching {len(watched_files)} file(s).",
        )
        logger.info(
            "SpartaCore watchdog started for %d files",
            len(watched_files),
        )
    except Exception as exc:
        runtime.sparta_instance = None
        runtime.subsystems.mark_failed(
            SUBSYS_SPARTA, f"Failed to start: {type(exc).__name__}"
        )
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
        runtime.subsystems.mark_disabled(SUBSYS_FENRIR)
        return

    # Validate before starting. A FenrirHunter with no service token, or with
    # nowhere to report, still reaches HUNTING and then silently discards
    # every finding -- exactly the half-alive startup this check exists to
    # prevent. The token's value is never inspected beyond emptiness.
    missing = missing_settings(
        {"S43_FENRIR_API_TOKEN": _env_str("S43_FENRIR_API_TOKEN")}
    )
    if missing:
        _refuse_unconfigured(
            SUBSYS_FENRIR,
            missing,
            required_flag="S43_FENRIR_REQUIRED",
            reason=SubsystemReason.MISSING_TOKEN,
        )
        return

    if not (
        _env_str("S43_FENRIR_WATCHTOWER_URL")
        or _env_str("S43_FENRIR_BROADCAST_URL")
    ):
        _refuse_unconfigured(
            SUBSYS_FENRIR,
            ("S43_FENRIR_WATCHTOWER_URL", "S43_FENRIR_BROADCAST_URL"),
            required_flag="S43_FENRIR_REQUIRED",
            reason=SubsystemReason.MISSING_CONFIG,
        )
        return

    runtime.subsystems.mark_starting(SUBSYS_FENRIR)
    try:
        from core.detection.feniri_hunter import FenrirHunter

        runtime.fenrir_instance = FenrirHunter()
        await runtime.fenrir_instance.start()
        # Feed allowlisted originating events into the SAME detector instance
        # Fenrir evaluates (no second detector, queue or bus).
        attach = getattr(
            runtime.monitoring_manager, "attach_threat_ingestor", None
        )
        if callable(attach):
            attach(
                runtime.fenrir_instance.detector,
                producers={
                    "firewall": (
                        os.getenv(
                            "S43_FIREWALL_MONITORING_SOURCE",
                            "sentinel-firewall",
                        ).strip()
                        or "sentinel-firewall"
                    )
                },
            )
        runtime.subsystems.mark_active(
            SUBSYS_FENRIR, "Hunting and reporting through the API bridge."
        )
        logger.info("FenrirHunter started")
    except Exception as exc:
        runtime.fenrir_instance = None
        runtime.subsystems.mark_failed(
            SUBSYS_FENRIR, f"Failed to start: {type(exc).__name__}"
        )
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

    from core.audit import AuditConfig, AuditStore, set_audit_store

    signing_key = _env_str("S43_AUDIT_HMAC_KEY")
    required = _env_bool("S43_GOVERNANCE_ENABLED", False) or not IS_LOCAL_ENV

    if not signing_key:
        if required:
            raise RuntimeError(
                "S43_AUDIT_HMAC_KEY is required: the authoritative audit "
                "store cannot be keyed. It is mandatory outside "
                "development/local/test and whenever S43_GOVERNANCE_ENABLED=true."
            )
        # Intentionally selecting the unconfigured local path: clear both
        # the runtime handle and the canonical cross-package registry, not
        # just leave them at their initial None. Within one long-lived
        # process (the test suite booting the app's lifespan repeatedly),
        # a *previous* lifespan may have registered a real store; without
        # this, a later, deliberately-unconfigured run would silently
        # inherit and keep using it.
        runtime.audit_store = None
        set_audit_store(None)
        runtime.subsystems.mark_unconfigured(
            SUBSYS_AUDIT,
            ("S43_AUDIT_HMAC_KEY",),
            reason=SubsystemReason.MISSING_TOKEN,
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
    # Also register in the canonical cross-package registry, mirroring
    # set_monitoring_manager(), so late callers (e.g. the Remote Gateway)
    # can reach the authoritative store without importing core.api back.
    set_audit_store(store)
    runtime.subsystems.mark_active(
        SUBSYS_AUDIT, "HMAC-chained audit store initialized and verified."
    )
    logger.info(
        "Authoritative audit store initialized (%s)",
        sqlite_path,
    )


async def _start_governance() -> None:
    if not _env_bool("S43_GOVERNANCE_ENABLED", False):
        runtime.subsystems.mark_disabled(SUBSYS_GOVERNANCE)
        return

    if runtime.audit_store is None:
        raise RuntimeError(
            "Governance requires an initialized authoritative audit store. "
            "Refusing to start Sentinel-43 runtime authority without one."
        )

    try:
        from core.governance import build_runtime_authority_from_settings

        # Mode validation (SHADOW | HUMAN_GATED, never ACTIVE) is enforced in
        # core.governance.composition. The composition root only reads the
        # environment and passes concrete values down.
        resolved_default_mode = _env_str(
            "S43_GOVERNANCE_DEFAULT_MODE",
            _env_str("S43_DEFAULT_MODE", "HUMAN_GATED"),
        ).upper()

        class Settings:
            environment = SENTINEL_ENV
            default_mode = resolved_default_mode
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
            velocity_max_tracked_users = _env_int(
                "S43_VELOCITY_MAX_ENTRIES",
                1000,
                minimum=1,
                maximum=1_000_000,
            )

        runtime.sentinel43 = build_runtime_authority_from_settings(
            Settings(),
            audit_store=runtime.audit_store,
            monitoring_manager=runtime.monitoring_manager,
        )
        # Transitional compatibility aliases only. Sentinel43RuntimeAuthority
        # owns both instances; the API does not create a second orchestrator
        # or a second monitoring manager.
        runtime.orchestrator = runtime.sentinel43.orchestrator
        runtime.monitoring_manager = runtime.sentinel43.monitoring_manager
        runtime.subsystems.mark_active(
            SUBSYS_GOVERNANCE,
            f"Human-gated orchestrator active (mode={resolved_default_mode}).",
        )
        logger.info(
            "Sentinel43RuntimeAuthority started (mode=%s)",
            resolved_default_mode,
        )
    except Exception as exc:
        runtime.sentinel43 = None
        runtime.orchestrator = None
        runtime.subsystems.mark_failed(
            SUBSYS_GOVERNANCE, f"Failed to start: {type(exc).__name__}"
        )
        if _env_bool("S43_GOVERNANCE_REQUIRED", True):
            raise
        logger.error("Sentinel43RuntimeAuthority failed to start", exc_info=True)


def _heart_operator_authenticator(principal: Any) -> bool:
    """Kernel-level authorization for a Heart approve/veto.

    Decides from the identity the request pipeline RECORDED when it
    verified the credential -- not from the operator string the caller
    sent, which on the v1 routes is request-body data. First production
    consumer of ``IdentityType.is_human``, which until now was only
    ever written and never read.
    """
    if not principal.is_human:
        return False
    if principal.identity_type != IdentityType.OPERATOR.value:
        return False

    subject = principal.subject.strip()
    if not subject or subject == IdentityType.ANONYMOUS.value:
        return False

    # Belt and braces: the trusted context above is the real control, but a
    # token minted with a service NAME as its subject must not be recorded as
    # a human decision either.
    return not any(
        identity.is_service and subject == identity.value
        for identity in IdentityType
    )


def _decision_principal(request: Request, operator: str) -> Any:
    """Build the Heart's principal from the SERVER-side identity.

    ``identity_of`` reads the security context the authentication
    dependency attached to this request; nothing here is caller data.
    """
    from core.governance import DecisionPrincipal

    identity = identity_of(request)
    return DecisionPrincipal(
        subject=operator,
        identity_type=identity.value,
        is_human=identity.is_human,
    )


def _report_heart_health(healthy: bool, detail: str) -> None:
    """Given to ThreatGovernor so it can report its own health truthfully.

    Reuses the exact SubsystemRegistry every other subsystem already
    reports through -- no second health framework. A transient failure
    that later succeeds again flips this back to ACTIVE on its own (see
    core/governance/heart.py's on_health_change calls), the same way
    Watchtower's own reachability flag self-heals.
    """
    if healthy:
        runtime.subsystems.mark_active(SUBSYS_HEART, detail)
    else:
        runtime.subsystems.mark_failed(SUBSYS_HEART, detail)


class _HeartActionSink:
    """Mirrors a Heart-staged recommendation into the existing canonical
    action store -- there is deliberately no separate Heart-only queue
    (see core/governance/heart.py's module docstring).

    ThreatGovernor.observe() runs in a worker thread (FenrirHunter offloads
    it via run_in_executor); this bridges back onto the event loop that
    owns runtime.action_store's asyncio.Lock, the same way any other
    cross-thread call into asyncio-owned state must.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def stage(self, record: dict[str, Any]) -> None:
        async def _do() -> None:
            action = await _store_action(record)
            await _broadcast_dashboard_event(
                "action_created",
                {"action": action},
            )

        future = asyncio.run_coroutine_threadsafe(_do(), self._loop)
        future.result(timeout=10.0)


_HEART_RECOVERY_PAGE = 1000
# Rejected decision attempts are audited against the same correlation id,
# so this window must stay well clear of a legitimate action's history.
_HEART_AUDIT_LOOKUP_LIMIT = 500
_HEART_LEGACY_AUDIT_LIMIT = 1000
_HEART_TERMINAL_DECISIONS = frozenset({"APPROVED", "VETOED", "EXECUTED", "EXPIRED"})


class HeartRecoveryError(RuntimeError):
    """Recovery could not establish a trustworthy view of pending actions.

    Raised (not swallowed) so _start_heart marks the Heart FAILED, which
    blocks /ready through the required-subsystem mechanism while liveness
    stays truthful.
    """


def _heart_row_problem(
    row: Mapping[str, Any], audited: list[dict[str, Any]]
) -> str | None:
    """Why a parsed pending row must NOT be exposed for a human decision.

    The persisted row alone is never trusted: the HMAC-verified ledger must
    hold exactly one STAGED record whose security-relevant contents match,
    and no later terminal decision.
    """
    action_id = str(row["action_id"])
    staged = [
        rec
        for rec in audited
        if rec.get("decision") == "STAGED"
        and rec.get("decision_id") == action_id
    ]
    if len(staged) != 1:
        return "no_unique_staged_audit_record"
    rec = staged[0]
    if any(
        other.get("decision") in _HEART_TERMINAL_DECISIONS
        for other in audited
    ):
        return "terminal_decision_already_audited"
    if f"{rec.get('identity')}|{rec.get('source_ip')}" != row["target_value"]:
        return "audit_target_mismatch"
    # The durable row must propose exactly the operations the authenticated
    # staging record bound. A record from before operations were recorded can
    # only back a row that also predates them.
    if not staging_record_matches_row(rec, row):
        return "audit_operation_mismatch"
    if rec.get("threat_kind") != row["kind"]:
        return "audit_kind_mismatch"
    if rec.get("severity") != row["severity"]:
        return "audit_severity_mismatch"
    if rec.get("source_kind") != row["source_kind"]:
        return "audit_source_kind_mismatch"
    try:
        if abs(float(rec.get("score")) - float(row["score"])) > 1e-6:
            return "audit_score_mismatch"
    except (TypeError, ValueError):
        return "audit_score_mismatch"
    return None


def _legacy_heart_audit_index(audit_store: Any) -> dict[str, list[dict[str, Any]]]:
    """Heart records that carry no ``component``, grouped by decision_id.

    Bounded: if the legacy ledger is larger than one read, recovery cannot
    prove it saw every relevant record, so it refuses rather than guess.
    """
    limit = _HEART_LEGACY_AUDIT_LIMIT
    records = audit_store.get_records_without_component(limit=limit)
    if len(records) >= limit:
        raise HeartRecoveryError(
            f"{len(records)}+ legacy audit records without a component; "
            "recovery cannot enumerate them all"
        )
    index: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if record.get("subsystem") != "heart":
            continue
        decision_id = str(record.get("decision_id") or "")
        if decision_id:
            index.setdefault(decision_id, []).append(record)
    return index


async def _rehydrate_heart_pending() -> int:
    """Reload durably staged, still-PENDING Heart rows into the canonical
    action store after a restart, so they stay visible in /actions and can
    still be approved or vetoed (the store is in-memory; the row is not).

    Fail-closed contract:
      * more pending rows than one page, or more than the canonical store can
        hold without evicting, blocks readiness (HeartRecoveryError);
      * a malformed row blocks readiness rather than being skipped;
      * a row without a matching authenticated STAGED audit record is
        quarantined (moved to a terminal state, never re-exposed) and no audit
        record is ever fabricated for it;
      * only a verified-equivalent duplicate already in the store is skipped;
        any other error propagates.
    """
    authority = runtime.sentinel43
    if authority is None or not authority.recommendation_store_attached:
        return 0

    rows = await asyncio.to_thread(
        authority.list_pending_recommendations, _HEART_RECOVERY_PAGE
    )
    if len(rows) >= _HEART_RECOVERY_PAGE:
        raise HeartRecoveryError(
            f"{len(rows)}+ pending Heart rows; recovery cannot enumerate "
            "them all -- resolve or expire pending rows before restart"
        )
    if not rows:
        return 0

    audit_store = authority.audit_store
    verification = await asyncio.to_thread(audit_store.verify_integrity)
    if not getattr(verification, "valid", False):
        raise HeartRecoveryError(
            "audit ledger failed integrity verification during Heart recovery"
        )

    legacy_index: dict[str, list[dict[str, Any]]] | None = None
    verified: list[dict[str, Any]] = []
    quarantine: list[tuple[str, str]] = []
    malformed: list[str] = []

    for row in rows:
        try:
            action_id = _validate_action_id(str(row["action_id"]))
            created_ms = int(row["created_at_ms"])
            target = str(row["target_value"])
            identity, sep, source_ip = target.rpartition("|")
            if not sep or not identity or not source_ip:
                raise ValueError("target_value is not identity|source_ip")
            created = datetime.fromtimestamp(
                created_ms / 1000, tz=timezone.utc
            ).isoformat()
            float(row["score"])
            kind = str(row["kind"])
            severity = str(row["severity"])
            source_kind = str(row["source_kind"])
            reason = str(row["reason"])
        except Exception:
            malformed.append(str(row.get("action_id", "?"))[:64])
            continue

        audited = await asyncio.to_thread(
            audit_store.get_records,
            component="heart",
            correlation_id=action_id,
            limit=_HEART_AUDIT_LOOKUP_LIMIT,
        )
        if not audited:
            # Records written before the component/correlation_id lookup keys
            # existed can only be found by content. A legitimately audited
            # decision must not be expired just because it predates them.
            if legacy_index is None:
                legacy_index = await asyncio.to_thread(
                    _legacy_heart_audit_index, audit_store
                )
            audited = legacy_index.get(action_id, [])
        problem = (
            "audit_history_too_long"
            if len(audited) >= _HEART_AUDIT_LOOKUP_LIMIT
            else _heart_row_problem(row, audited)
        )
        if problem is not None:
            quarantine.append((action_id, problem))
            continue

        verified.append(
            {
                "id": action_id,
                "action_type": "HEART_RECOMMENDATION",
                "status": "STAGED",
                "created_at": created,
                "decision_reason": "",
                "operator": "",
                "payload": {
                    "source": "heart",
                    "identity": identity,
                    "source_ip": source_ip,
                    "ip": source_ip,
                    "threat_kind": kind,
                    "severity": severity,
                    "source_kind": source_kind,
                    "score": float(row["score"]),
                    "reason": reason,
                    "operations": operations_for_row(row),
                    "actions": list(row.get("actions") or ()),
                    # The account an account-scoped operation would act on,
                    # so a reviewer sees it before approving one.
                    "principal": str(row.get("principal_id") or ""),
                    "recommendation": recommendation_for_row(row),
                    "approval": recommendation_for_row(row)["approval"],
                    "legacy": str(row["primary_action"]) == LEGACY_REVIEW_ACTION,
                    "rehydrated": True,
                },
            }
        )

    if malformed:
        raise HeartRecoveryError(
            f"{len(malformed)} malformed pending Heart row(s): "
            + ", ".join(malformed[:20])
        )

    async with runtime.action_lock:
        existing_ids = set(runtime.action_store)
    new_records = [r for r in verified if r["id"] not in existing_ids]
    if len(existing_ids) + len(new_records) > MAX_DASHBOARD_ACTIONS:
        raise HeartRecoveryError(
            "restoring pending Heart actions would exceed the canonical "
            f"action store limit ({MAX_DASHBOARD_ACTIONS}) and evict live "
            "actions"
        )

    for action_id, problem in quarantine:
        await asyncio.to_thread(
            authority.expire_unverifiable_recommendation,
            action_id,
            problem=problem,
        )
        logger.error(
            "Heart recovery quarantined %s (%s); it is not actionable",
            action_id,
            problem,
        )

    restored = 0
    for record in verified:
        try:
            await _store_action(record)
            restored += 1
        except HTTPException as exc:
            if exc.status_code != 409:
                raise
            async with runtime.action_lock:
                current = runtime.action_store.get(record["id"]) or {}
            cur_payload = current.get("payload") or {}
            new_payload = record["payload"]
            if not (
                current.get("action_type") == record["action_type"]
                and all(
                    cur_payload.get(k) == new_payload[k]
                    for k in ("identity", "source_ip", "threat_kind")
                )
            ):
                raise HeartRecoveryError(
                    f"action {record['id']} already exists with different "
                    "contents"
                ) from exc
    return restored


async def _start_heart() -> None:
    """Build the "Heart" -- human-governed staging for threat assessments.

    Reconnects Fenrir/detection-layer findings to the same human-governed
    pattern SystemOrchestrator already applies to transactions: dedupe,
    corroboration, authoritative audit, and staging for an explicit human
    decision. Disabled by default (S43_HEART_ENABLED) so enabling it is an
    explicit operator choice, not a silent behavior change from upgrading.

    Unlike _start_governance(), a required-but-failed Heart never raises
    here: it is marked FAILED and left there, which already makes /ready
    report 503 through the exact required-subsystem mechanism every other
    subsystem uses (core/lifecycle.py's blocks_readiness). Raising would
    crash the whole process -- taking detection, Watchtower, the dashboard,
    and auth down with it -- when only Heart-governed staging actually
    needs to stop.
    """
    if not _env_bool("S43_HEART_ENABLED", False):
        runtime.subsystems.mark_disabled(SUBSYS_HEART)
        return

    if runtime.sentinel43 is None:
        runtime.subsystems.mark_failed(
            SUBSYS_HEART,
            "Requires the Sentinel-43 runtime authority (S43_GOVERNANCE_ENABLED=true): "
            "the Heart has no decision authority of its own.",
        )
        logger.error(
            "The Heart is enabled but the Sentinel-43 runtime authority is not "
            "running; refusing to start the Heart without its authority."
        )
        return

    if runtime.audit_store is None:
        runtime.subsystems.mark_failed(
            SUBSYS_HEART,
            "Requires an initialized authoritative audit store.",
        )
        logger.error(
            "The Heart is enabled but the authoritative audit store is "
            "not initialized; refusing to start ThreatGovernor."
        )
        return

    try:
        from pathlib import Path

        from core.governance import build_heart_from_settings
        from core.sentinel43_core_db import (
            ActionStatus,
            CoreStoreConfig,
            SentinelCoreStore,
        )

        resolved_default_mode = _env_str(
            "S43_HEART_DEFAULT_MODE",
            _env_str("S43_DEFAULT_MODE", "HUMAN_GATED"),
        ).upper()

        class Settings:
            default_mode = resolved_default_mode
            velocity_window_seconds = _env_int(
                "S43_HEART_VELOCITY_WINDOW_SECONDS", 60, minimum=1, maximum=3600
            )
            velocity_limit = _env_int(
                "S43_HEART_VELOCITY_LIMIT", 30, minimum=1, maximum=100_000
            )
            dedupe_ttl_seconds = _env_int(
                "S43_HEART_DEDUPE_TTL_SECONDS", 300, minimum=1, maximum=86_400
            )
            corroboration_window_seconds = _env_int(
                "S43_HEART_CORROBORATION_WINDOW_SECONDS",
                300,
                minimum=1,
                maximum=86_400,
            )
            corroboration_min_signals_for_high = _env_int(
                "S43_HEART_CORROBORATION_MIN_SIGNALS", 2, minimum=2, maximum=100
            )
            # Must stay below _HEART_RECOVERY_PAGE so a restart can always
            # enumerate what staging was allowed to create.
            max_pending_actions = _env_int(
                "S43_HEART_MAX_PENDING_ACTIONS",
                500,
                minimum=1,
                maximum=_HEART_RECOVERY_PAGE - 1,
            )

        core_store = SentinelCoreStore(
            CoreStoreConfig(
                db_path=Path(
                    _env_str(
                        "S43_HEART_SQLITE_PATH",
                        "sentinel43_state/heart.sqlite3",
                    )
                )
            )
        )
        await asyncio.to_thread(core_store.initialize)

        runtime.heart = build_heart_from_settings(
            Settings(),
            audit_store=runtime.audit_store,
            core_store=core_store,
            monitoring_manager=runtime.monitoring_manager,
            authority=runtime.sentinel43,
            action_sink=_HeartActionSink(asyncio.get_running_loop()),
            on_health_change=_report_heart_health,
            operator_authenticator=_heart_operator_authenticator,
        )

        # Recovery finishes BEFORE Fenrir may stage live, otherwise a row
        # inserted but not yet audited would be read as unaudited and
        # quarantined while it is being legitimately staged.
        restored = await _rehydrate_heart_pending()
        if restored:
            logger.info(
                "Heart: restored %d pending recommendation(s) after restart",
                restored,
            )

        if runtime.fenrir_instance is not None:
            runtime.fenrir_instance.heart = runtime.heart

        # A store that is ALREADY at or over the ceiling keeps working and
        # keeps observing, but cannot stage. The new limit stops that state
        # getting worse; it does not repair it, so say so rather than
        # reporting an unqualified "active".
        backlog = await asyncio.to_thread(
            runtime.sentinel43.count_pending_recommendations
        )
        ceiling = runtime.heart.config.max_pending_actions
        if backlog >= ceiling:
            detail = (
                f"Human-gated threat staging SUSPENDED (mode="
                f"{resolved_default_mode}): {backlog} pending recommendations "
                f"at the ceiling of {ceiling}. Observation continues; resolve "
                f"pending decisions to resume staging."
            )
            logger.error(
                "Heart started with a pending backlog of %d at the ceiling of "
                "%d -- staging is suspended until decisions are resolved",
                backlog,
                ceiling,
            )
        else:
            detail = (
                f"Human-gated threat staging active "
                f"(mode={resolved_default_mode}, pending={backlog}/{ceiling})."
            )
        runtime.subsystems.mark_active(SUBSYS_HEART, detail)
        logger.info("Heart (ThreatGovernor) started (mode=%s)", resolved_default_mode)
    except Exception as exc:
        runtime.heart = None
        if runtime.fenrir_instance is not None:
            runtime.fenrir_instance.heart = None
        # A Heart that failed to start must not leave its decisions reachable
        # through the orchestrator either.
        if runtime.sentinel43 is not None:
            runtime.sentinel43.detach_recommendation_store()
        runtime.subsystems.mark_failed(
            SUBSYS_HEART, f"Failed to start: {type(exc).__name__}"
        )
        logger.error("Heart failed to start", exc_info=True)


async def _start_reliability() -> None:
    """Build the event delivery reliability layer.

    Optional by design: if it cannot be built the API still serves and the
    event path behaves exactly as it did before, just without idempotency,
    bounded retry or dead-lettering. It is reported DEGRADED rather than
    silently absent.

    The audit sink is the authoritative store, so delivery-state transitions
    land in the same ledger as everything else -- no second pseudo-audit log.
    """
    runtime.subsystems.mark_starting(SUBSYS_RELIABILITY)
    try:
        from pathlib import Path as _Path

        store = DeadLetterStore(
            sqlite_path=_Path(
                _env_str(
                    "S43_DEAD_LETTER_PATH",
                    "sentinel43_state/dead_letter.sqlite3",
                )
            ),
            max_rows=_env_int(
                "S43_DEAD_LETTER_MAX_ROWS", 10_000,
                minimum=1, maximum=1_000_000,
            ),
        )
        await asyncio.to_thread(store.initialize)

        audit_store = runtime.audit_store

        def _audit_sink(payload: dict[str, Any]) -> None:
            if audit_store is None:
                return
            audit_store.append(payload)

        runtime.reliability = EventReliabilityManager(
            dead_letter_store=store,
            idempotency=IdempotencyLedger(
                max_entries=_env_int(
                    "S43_IDEMPOTENCY_MAX_ENTRIES", 10_000,
                    minimum=1, maximum=1_000_000,
                ),
                ttl_seconds=_env_float(
                    "S43_IDEMPOTENCY_TTL_SECONDS", 900.0,
                    minimum=1.0, maximum=86_400.0,
                ),
            ),
            retry_policy=RetryPolicy(
                max_attempts=_env_int(
                    "S43_DELIVERY_MAX_ATTEMPTS", 3, minimum=1, maximum=10
                ),
                base_delay_seconds=_env_float(
                    "S43_DELIVERY_BASE_DELAY", 0.2,
                    minimum=0.001, maximum=60.0,
                ),
                max_delay_seconds=_env_float(
                    "S43_DELIVERY_MAX_DELAY", 5.0,
                    minimum=0.001, maximum=300.0,
                ),
                total_deadline_seconds=_env_float(
                    "S43_DELIVERY_DEADLINE", 10.0,
                    minimum=0.01, maximum=300.0,
                ),
            ),
            audit_sink=_audit_sink if audit_store is not None else None,
        )
        runtime.subsystems.mark_active(
            SUBSYS_RELIABILITY,
            "Idempotency, bounded retry and dead-lettering active.",
        )
        logger.info("Event reliability layer active")
    except Exception as exc:
        runtime.reliability = None
        runtime.subsystems.mark_failed(
            SUBSYS_RELIABILITY, f"Failed to start: {type(exc).__name__}"
        )
        logger.error("Event reliability layer unavailable", exc_info=True)


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
        finally:
            runtime.fenrir_instance = None
            runtime.subsystems.mark_stopped(SUBSYS_FENRIR)

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
        finally:
            runtime.sparta_task = None

    # close() after the watchdog task has drained: stop() asks the loop to
    # exit, close() releases the instance's resources. Both are part of the
    # SpartaCore shutdown contract (see setup_signal_handlers).
    if runtime.sparta_instance is not None:
        try:
            runtime.sparta_instance.close()
        except Exception:
            logger.warning("SpartaCore close error", exc_info=True)
        finally:
            runtime.sparta_instance = None
            runtime.subsystems.mark_stopped(SUBSYS_SPARTA)

    if runtime.reliability is not None:
        runtime.reliability = None
        runtime.subsystems.mark_stopped(SUBSYS_RELIABILITY)

    if runtime.sentinel43 is None and runtime.monitoring_manager is not None:
        try:
            await asyncio.to_thread(runtime.monitoring_manager.stop)
        except Exception:
            logger.warning(
                "MonitoringManager stop error",
                exc_info=True,
            )
        finally:
            runtime.monitoring_manager = None
            runtime.subsystems.mark_stopped(SUBSYS_MONITORING)
            # Deregister from the canonical registry too, so late callers
            # (remote gateway, firewall) see "no manager" rather than a
            # stopped one that would raise on analyze_event().
            try:
                from core.monitoring import set_monitoring_manager

                set_monitoring_manager(None)
            except Exception:
                logger.debug(
                    "MonitoringManager deregistration failed",
                    exc_info=True,
                )

    # Sentinel-43 owns the governance/owner-engine lifecycle. Shut that
    # authority down while the authoritative audit store is still available,
    # then clear the temporary subordinate compatibility alias.
    if runtime.sentinel43 is not None:
        try:
            await asyncio.to_thread(runtime.sentinel43.shutdown)
        except Exception:
            logger.warning(
                "Sentinel43RuntimeAuthority shutdown error",
                exc_info=True,
            )
        finally:
            runtime.sentinel43 = None
            runtime.orchestrator = None
            runtime.monitoring_manager = None
            if runtime.subsystems.get(SUBSYS_MONITORING) is not None:
                runtime.subsystems.mark_stopped(SUBSYS_MONITORING)
            if runtime.subsystems.get(SUBSYS_GOVERNANCE) is not None:
                runtime.subsystems.mark_stopped(SUBSYS_GOVERNANCE)

    # The Heart owns no unmanaged resource of its own (SentinelCoreStore
    # connects per-call, like AuditStore's own connection discipline), but
    # a stale reference must not survive shutdown -- a repeated lifespan in
    # the same process (tests booting the app repeatedly) must never
    # inherit a previous run's Heart, and a lingering runtime.heart while
    # audit_store is about to close below would let a late caller stage an
    # action whose audit append is guaranteed to fail. FenrirHunter's own
    # shutdown, above, already stopped its scan loop (the only caller of
    # .heart) before clearing runtime.fenrir_instance, so there is no
    # remaining reference to that instance's .heart attribute to clear here.
    runtime.heart = None
    if runtime.subsystems.get(SUBSYS_HEART) is not None:
        runtime.subsystems.mark_stopped(SUBSYS_HEART)

    # Close, then deregister, the audit store the same way, so late callers
    # (e.g. the Remote Gateway) see "no store" rather than a closed/stale
    # one, and so a subsequent lifespan in the same process (tests booting
    # the app repeatedly) never inherits a previous run's registration. A
    # lingering reference elsewhere sees an honest CLOSED health state
    # rather than a stale HEALTHY one.
    if runtime.audit_store is not None:
        try:
            runtime.audit_store.close()
        except Exception:
            logger.debug(
                "AuditStore close failed",
                exc_info=True,
            )
    runtime.audit_store = None
    try:
        from core.audit import set_audit_store

        set_audit_store(None)
    except Exception:
        logger.debug(
            "AuditStore deregistration failed",
            exc_info=True,
        )

    async with runtime.ws_lock:
        clients = list(runtime.ws_clients.values())

    for client in clients:
        try:
            await asyncio.wait_for(
                client.websocket.send_json(
                    {
                        "type": "server_shutdown",
                        "payload": {"timestamp": utc_now()},
                    }
                ),
                timeout=float(WS_SEND_TIMEOUT_SECONDS),
            )
        except Exception:
            pass
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

    # Inject the Watchtower connection settings into the canonical client
    # before any subsystem can call it.
    _configure_watchtower_client(
        base_url=WATCHTOWER_URL,
        timeout_seconds=WATCHTOWER_TIMEOUT,
    )

    # Declare every subsystem, then validate configuration, before starting
    # anything. An enabled-but-unconfigured subsystem is refused with an
    # explicit reason rather than started half-alive.
    _declare_subsystems()
    _validate_watchtower_config()

    try:
        await _start_monitoring_manager()
        await _start_sparta()
        await _start_fenrir()
        await _start_audit_store()
        await _start_reliability()
        await _start_governance()
        await _start_heart()

        # Registration failures are observable, but do not necessarily mean
        # the API itself cannot serve. Deployments that require Watchtower can
        # make this fatal with S43_WATCHTOWER_REQUIRED=true.
        registration = await register_api_with_watchtower()
        heartbeat = await send_api_heartbeat()

        # Configuration was validated before startup; this is the first
        # evidence of actual reachability, so the Watchtower subsystem's
        # state is settled here.
        if runtime.subsystems.get(SUBSYS_WATCHTOWER) is not None:
            if registration.get("registered") and heartbeat.get(
                "heartbeat_sent"
            ):
                runtime.subsystems.mark_active(
                    SUBSYS_WATCHTOWER, "Registered and sending heartbeats."
                )
            else:
                runtime.subsystems.mark_failed(
                    SUBSYS_WATCHTOWER,
                    "Configured but unreachable at startup.",
                    reason=SubsystemReason.DEPENDENCY_UNREACHABLE,
                )

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

# Interactive API documentation (/docs, /redoc) and the raw schema
# (/openapi.json) are a local/dev convenience only. FastAPI enables all
# three unconditionally unless told otherwise; passing None for each
# disables the route entirely (a real 404, not merely hidden UI with the
# JSON schema still served) rather than relying solely on an ingress
# annotation the application itself has no way to verify is in effect.
_DOCS_ENABLED = IS_LOCAL_ENV

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if _DOCS_ENABLED else None,
    redoc_url="/redoc" if _DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _DOCS_ENABLED else None,
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

    # Readiness reflects whether this service can do its job. A REQUIRED
    # subsystem that is not ACTIVE blocks readiness; an optional one that is
    # disabled is entirely fine, and an optional one that is faulted leaves
    # the API ready but degraded rather than killing it.
    report = runtime.subsystems.readiness()

    if not report.ready:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "service": APP_NAME,
                "reason": "subsystem_unavailable",
                "blocking": list(report.blocking),
                "subsystems": {
                    item.name: {
                        "state": item.state.value,
                        "configured": item.configured,
                        "reason": item.reason.value,
                    }
                    for item in report.subsystems
                },
            },
        )

    body: dict[str, Any] = {"status": "ready", "service": APP_NAME}
    if report.degraded:
        body["degraded"] = list(report.degraded)
    return body


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
        "event_reliability": (
            runtime.reliability.status()
            if runtime.reliability is not None
            else {"state": "unavailable"}
        ),
        "timestamp": utc_now(),
    }


@root_router.get("/actions")
async def dashboard_actions(
    request: Request,
    limit: int = 250,
) -> list[dict[str, Any]]:
    await _require_operator(request)
    return await _list_actions(limit)


@root_router.get("/incidents")
async def dashboard_incidents(
    request: Request,
    limit: int = 200,
) -> dict[str, Any]:
    """Incident records opened by approved recommendations.

    These are internal follow-up records in this system's own durable store.
    Opening one is the only effect an approval produces, and it produces no
    effect outside Sentinel-43.
    """
    await _require_operator(request)

    authority = runtime.sentinel43
    if authority is None or not authority.recommendation_store_attached:
        raise HTTPException(
            status_code=409,
            detail="The governance orchestration store is not attached",
        )

    if not 1 <= int(limit) <= 1000:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 1000")

    # Through the authority's read accessor, never the store object itself.
    incidents = await asyncio.to_thread(
        functools.partial(authority.list_incidents, limit=int(limit))
    )
    return {
        "incidents": [dict(incident) for incident in incidents],
        "timestamp": utc_now(),
    }


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
        principal=_decision_principal(request, operator),
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
        principal=_decision_principal(request, operator),
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

    if runtime.sentinel43 is None:
        return {
            "enabled": False,
            "pending": [],
            "timestamp": utc_now(),
        }

    try:
        pending = await asyncio.to_thread(
            runtime.sentinel43.list_pending_reviews
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


# Heart-originated recommendations are not exposed through a second,
# Heart-only API surface: they are staged and resolved through the exact
# same /actions, /actions/{id}/approve, and /actions/{id}/veto routes above,
# distinguished only by action_type == "HEART_RECOMMENDATION" (deliberately
# distinct from the pre-existing generic "THREAT_ACTION" default used by
# _create_synthetic_action() and the dashboard, which is unrelated)
# (see _resolve_governance_and_commit_action and
# core/governance/heart.py's ActionSink). There is one canonical
# staged-action source of truth for the dashboard.


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
            except HTTPException as exc:
                if exc.status_code == 503:
                    # Session service unavailable: an outage, not a revoked
                    # session. Fail closed with the outage contract.
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
                        code=WS_CLOSE_AUTH_BACKEND_UNAVAILABLE,
                        reason=WS_REASON_AUTH_BACKEND_UNAVAILABLE,
                    )
                    return
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
                    code=WS_CLOSE_AUTH_BACKEND_UNAVAILABLE,
                    reason=WS_REASON_AUTH_BACKEND_UNAVAILABLE,
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
                        code=WS_CLOSE_AUTH_BACKEND_UNAVAILABLE,
                        reason=WS_REASON_AUTH_BACKEND_UNAVAILABLE,
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
                    # Sent directly and awaited, not queued -- see
                    # _ws_send_error_then_close's docstring for why the
                    # queue races the close it precedes.
                    await _ws_send_error_then_close(
                        websocket,
                        error=reason,
                        code=_ws_close_code_for_reason(reason),
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
                await _ws_send_error_then_close(
                    websocket,
                    error=reason,
                    code=_ws_close_code_for_reason(reason),
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

                if channel == "governance" and runtime.sentinel43 is not None:
                    try:
                        pending = await asyncio.to_thread(
                            runtime.sentinel43.list_pending_reviews
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

    # Distribution only -- deliberately NOT a second monitoring ingestion
    # path. Fenrir's real producer (FenrirHunter.process_finding) posts
    # every finding to BOTH this route and /watchtower/events concurrently,
    # and a raw finding carries no event_id of its own, so each route used
    # to assign it a DIFFERENT one and MonitoringManager analyzed the same
    # finding twice under two identities -- doubling alert counts and
    # corrupting temporal/frequency scoring. /watchtower/events is the
    # canonical analysis path (it also owns the reliability/idempotency
    # pipeline and the real Watchtower delivery); this route still builds
    # the canonical envelope for identity/correlation and still guards
    # against a circular Watchtower-derived event, but must not
    # independently trigger a second analysis of the same finding.
    envelope = _delivery_envelope(
        {
            "event_type": body.event_type,
            "source": "FenrirHunter",
            **(body.data if isinstance(body.data, dict) else {}),
        },
        request,
    )
    _reject_analysis_loop(envelope)

    await _broadcast_dashboard_event(
        body.event_type,
        {
            **body.data,
            "event_id": envelope["event_id"],
            "correlation_id": envelope["correlation_id"],
        },
        channel=body.channel,
    )

    async with runtime.ws_lock:
        client_count = len(runtime.ws_clients)

    return {
        "ok": True,
        "event_id": envelope["event_id"],
        "correlation_id": envelope["correlation_id"],
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


#: Finding-content fields MonitoringManager needs to actually analyze and
#: score a detection, not just know one happened. Allowlist only, matching
#: core/reliability.py's sanitize_for_record principle: a producer field
#: reaches monitoring only if it is named here, so a new or hostile field
#: cannot ride along unexamined. Never secrets, credentials, or raw auth
#: material -- none of that is ever part of a request JSON body to begin
#: with (the service token lives in the Authorization header, which this
#: never touches).
_MAX_FINDING_INDICATORS: Final[int] = 50
_MAX_FINDING_INDICATOR_LEN: Final[int] = 256


def _sanitize_finding_fields(body: Mapping[str, Any]) -> dict[str, Any]:
    """Project a producer body down to the finding content that may reach
    MonitoringManager, bounded and type-checked field by field."""
    extra: dict[str, Any] = {}

    severity = body.get("severity")
    if isinstance(severity, str) and severity.strip():
        extra["severity"] = severity.strip()[:64]

    threat_kind = body.get("threat_kind")
    if isinstance(threat_kind, str) and threat_kind.strip():
        extra["threat_kind"] = threat_kind.strip()[:128]

    source_ip = body.get("source_ip")
    if isinstance(source_ip, str) and source_ip.strip():
        extra["source_ip"] = source_ip.strip()[:64]

    indicators = body.get("indicators")
    if isinstance(indicators, (list, tuple)):
        cleaned = tuple(
            str(item).strip()[:_MAX_FINDING_INDICATOR_LEN]
            for item in list(indicators)[:_MAX_FINDING_INDICATORS]
            if str(item).strip()
        )
        if cleaned:
            extra["indicators"] = cleaned

    confidence = body.get("confidence")
    if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
        extra["confidence"] = max(0.0, min(1.0, float(confidence)))

    return extra


async def _notify_monitoring(
    envelope: Mapping[str, Any],
    *,
    kind: str,
    extra: Mapping[str, Any] | None = None,
) -> bool:
    """Publish one accepted event into the canonical monitoring path.

    Every other producer (firewall, Sparta, remote gateway, governance)
    already reaches MonitoringManager. Fenrir -- the primary detection nerve
    -- did not: its findings went to Watchtower and the dashboard and were
    never analyzed by the manager.

    The producer's own ``event_type`` (e.g. "fenrir.finding") is carried as a
    field while ``kind`` stays a canonical typed kind, because normalize_event
    rejects an unknown kind outright. Best-effort by design -- monitoring is
    observational and must not fail an accepted ingest -- but counted rather
    than silently swallowed, so a broken monitoring path is visible.
    """
    manager = runtime.monitoring_manager
    if manager is None:
        return False

    event: dict[str, Any] = {
        "kind": kind,
        "event_id": envelope.get("event_id", ""),
        "correlation_id": envelope.get("correlation_id", ""),
        "parent_event_id": envelope.get("parent_event_id", ""),
        "event_type": envelope.get("event_type", ""),
        "source": envelope.get("source", ""),
        "source_identity": envelope.get("source_identity", ""),
        "created_at": envelope.get("created_at", ""),
        "schema_version": envelope.get("schema_version", ""),
    }
    if extra:
        event.update(dict(extra))

    try:
        await asyncio.to_thread(manager.analyze_event, event)
        return True
    except Exception:
        if runtime.reliability is not None:
            runtime.reliability.metrics.increment("events_rejected")
        logger.warning(
            "Monitoring analysis failed for event_id=%s",
            envelope.get("event_id"),
            exc_info=True,
        )
        return False


def _reject_analysis_loop(envelope: Mapping[str, Any]) -> None:
    """Refuse to re-submit an analyzer's own derived output to itself.

    Watchtower finding -> monitoring -> Watchtower -> ... is unbounded. An
    event carrying parent_event_id AND naming Watchtower as its own source is
    a derived assessment, not a new signal, so forwarding it for analysis
    again would close the cycle.
    """
    if would_loop(envelope, analyzer_source="Watchtower"):
        raise HTTPException(
            status_code=409,
            detail=(
                "Refusing to re-analyze a Watchtower-derived finding; "
                "this would create a circular event path."
            ),
        )


def _delivery_envelope(
    body: Mapping[str, Any],
    request: Request,
) -> dict[str, Any]:
    """Build the reliability envelope for an inbound event.

    Non-destructive on purpose: this ingress forwards arbitrary producer
    bodies to Watchtower, which does its own scanning, so the envelope is
    derived alongside the body rather than by rejecting anything that is not
    a known typed event kind.

    A producer-supplied event_id is preserved -- that is what makes a
    transport retry recognisable as the same logical event. The
    correlation_id comes from the request's SecurityContext so the event ties
    back to everything else that happened on that request.
    """
    context = get_security_context(request)

    event_id = str(
        body.get("event_id") or body.get("id") or ""
    ).strip() or new_event_id()

    correlation_id = (
        str(body.get("correlation_id") or "").strip()
        or (context.correlation_id if context is not None else "")
        # Never empty: an event with no wider correlation still traces as a
        # singleton under its own id, which is far more useful downstream
        # than a blank field.
        or event_id
    )

    return {
        "event_id": event_id,
        "correlation_id": correlation_id,
        # Causal linkage, if the producer declared one.
        "parent_event_id": str(body.get("parent_event_id") or "").strip(),
        "event_type": str(
            body.get("event_type") or body.get("kind") or "event"
        ),
        "kind": str(body.get("kind") or ""),
        "schema_version": str(
            body.get("schema_version") or EVENT_SCHEMA_VERSION
        ),
        "source": str(body.get("source") or "fenrir"),
        "source_identity": (
            context.identity_type.value
            if context is not None
            else IdentityType.SERVICE_FENRIR.value
        ),
        "created_at": str(body.get("created_at") or utc_now()),
        "ingested_at": utc_now(),
    }


@watchtower_router.post("/events")
async def watchtower_ingest_event(
    body: dict[str, Any],
    request: Request,
) -> dict[str, Any]:
    _require_fenrir_service_token(request)

    envelope = _delivery_envelope(body, request)
    _reject_analysis_loop(envelope)
    forwarded = {**body, **{
        "event_id": envelope["event_id"],
        "correlation_id": envelope["correlation_id"],
    }}

    def _deliver() -> Any:
        return _watchtower_request(
            "POST",
            "/watchtower/analyze",
            {"event": forwarded},
        )

    reliability = runtime.reliability

    if reliability is None:
        # Reliability layer unavailable: behave exactly as before, but still
        # refuse to call a failed delivery a success.
        result = await asyncio.to_thread(_deliver)
        delivered = isinstance(result, dict) and "error" not in result
        delivery = {
            "state": "DELIVERED" if delivered else "FAILED_TERMINAL",
            "event_id": envelope["event_id"],
            "correlation_id": envelope["correlation_id"],
            "attempts": 1,
        }
    else:
        # "payload" carries the exact body Watchtower is sent (``forwarded``,
        # already computed above for ``_deliver``) so that, if this event is
        # ever dead-lettered, an operator replay can faithfully redeliver it
        # rather than reconstruct a payload-less approximation from
        # sanitized metadata alone. It is stored behind a separate,
        # protected path -- see core/reliability.py's REPLAY FIDELITY note
        # -- never through the sanitized dashboard-visible projection.
        outcome = await asyncio.to_thread(
            reliability.deliver,
            {**envelope, "payload": forwarded},
            _deliver,
            stage=FailureStage.WATCHTOWER_DELIVERY,
        )
        delivered = outcome.handled
        result = outcome.response
        delivery = outcome.to_dict()

    # The canonical monitoring path -- the ONLY one for a Fenrir finding
    # (see internal_broadcast_event's comment on why the other route must
    # not also call this). Findings previously reached Watchtower and the
    # dashboard but never MonitoringManager at all; carrying only the
    # envelope reached MonitoringManager but not the finding CONTENT
    # (severity, threat_kind, source_ip, indicators, confidence), which is
    # what analysis/scoring actually needs to do anything with the event.
    await _notify_monitoring(
        envelope,
        kind="security",
        extra={
            "delivery_state": delivery.get("state", ""),
            **_sanitize_finding_fields(body),
        },
    )

    # Distribution carries the same identity the event was accepted under.
    await _broadcast_dashboard_event(
        "watchtower_event",
        {
            "event": forwarded,
            "event_id": envelope["event_id"],
            "correlation_id": envelope["correlation_id"],
            "watchtower_response": result,
            "delivery": delivery,
            "timestamp": utc_now(),
        },
        channel="watchtower",
    )

    if not delivered:
        # A failed delivery is never reported as ok:true. This route used to
        # return success unconditionally, so a Watchtower outage looked
        # identical to a clean ingest.
        return JSONResponse(
            status_code=503,
            content={
                "ok": False,
                "delivery": delivery,
                "forwarded": result,
                "timestamp": utc_now(),
            },
        )

    return {
        "ok": True,
        "delivery": delivery,
        "forwarded": result,
        "timestamp": utc_now(),
    }


# =============================================================================
# Event reliability operator router
#
# Authenticated HUMAN operator surface. Service tokens do not reach these
# routes: _require_operator is the human/session verifier, and a Fenrir,
# Sparta or Watchtower service credential cannot satisfy it. Replay is an
# explicit operator act -- there is no automatic or scheduled replay anywhere
# in this module.
# =============================================================================

reliability_router = APIRouter(
    prefix="/reliability",
    tags=["reliability"],
)

#: Replay outcomes that were refused before, or without confirmation after,
#: a delivery attempt. Each is a state conflict, not a not-found or a
#: validation error, so each maps to 409 -- matching the convention already
#: used for a refused analysis loop (see ``_reject_analysis_loop``).
_REPLAY_CONFLICT_DETAIL: Final[dict[str, str]] = {
    "already_replayed": (
        "This event was already successfully replayed; it will not be "
        "redelivered again through this route."
    ),
    "replay_in_progress": (
        "A replay attempt for this event is already in progress, or an "
        "earlier attempt's outcome could not be confirmed. It requires "
        "operator reconciliation before another attempt can be made."
    ),
    "replay_unavailable": (
        "This event has no faithfully replayable body persisted -- a "
        "legacy record, or one whose payload exceeded the size bound at "
        "record time. Replay is refused rather than redelivering a "
        "payload-less approximation of the original event."
    ),
    "reconciliation_required": (
        "A delivery attempt was made but its result could not be "
        "persisted, so whether it succeeded is unknown. It requires "
        "manual reconciliation before another replay attempt can be made."
    ),
}


def _require_reliability() -> Any:
    manager = runtime.reliability
    if manager is None:
        raise HTTPException(
            status_code=503,
            detail="Event reliability layer is not available.",
        )
    return manager


@reliability_router.get("/status")
async def reliability_status(request: Request) -> dict[str, Any]:
    await _require_operator(request)
    return _require_reliability().status()


@reliability_router.get("/failed-events")
async def reliability_failed_events(
    request: Request,
    limit: int = 50,
    replay_status: str | None = None,
) -> dict[str, Any]:
    """Sanitized metadata for dead-lettered events.

    Records contain provenance and failure classification only -- never a
    payload, token or credential (see reliability.sanitize_for_record).
    """
    await _require_operator(request)
    manager = _require_reliability()

    store = manager.dead_letter_store
    if store is None:
        raise HTTPException(
            status_code=503,
            detail="No dead-letter store is configured.",
        )

    records = await asyncio.to_thread(
        store.list_records,
        limit=max(1, min(int(limit), 500)),
        replay_status=replay_status,
    )
    return {
        "count": len(records),
        "counts": await asyncio.to_thread(store.counts),
        "events": [record.to_dict() for record in records],
        "timestamp": utc_now(),
    }


@reliability_router.post("/replay/{event_id}")
async def reliability_replay(
    event_id: str,
    request: Request,
) -> dict[str, Any]:
    """Replay ONE dead-lettered event, on explicit operator instruction.

    Bounded by construction: one request produces at most one delivery
    attempt. There is no replay-all, and a failed replay returns to the
    dead-letter state rather than being recycled. Replay re-delivers an
    event; it never executes a remediation or approves an action.
    """
    operator = await _require_operator(request)
    manager = _require_reliability()

    safe_id = str(event_id).strip()
    if not safe_id or len(safe_id) > 200:
        raise HTTPException(status_code=422, detail="Invalid event_id.")

    def _redeliver(envelope: Mapping[str, Any]) -> Any:
        return _watchtower_request(
            "POST",
            "/watchtower/analyze",
            {"event": dict(envelope)},
        )

    outcome = await asyncio.to_thread(
        manager.replay,
        safe_id,
        _redeliver,
        operator=operator,
    )

    if outcome.reason == "unknown_event_id":
        raise HTTPException(
            status_code=404,
            detail="No dead-lettered event with that id.",
        )

    conflict_detail = _REPLAY_CONFLICT_DETAIL.get(outcome.reason)
    if conflict_detail is not None:
        raise HTTPException(status_code=409, detail=conflict_detail)

    if not outcome.delivered:
        # A real delivery attempt was made and Watchtower rejected it or
        # could not be reached (state DEAD_LETTERED, outcome.reason is
        # classify_delivery_result's bounded reason token). This must never
        # be a 200: the dashboard's ApiClient derives "ok" purely from HTTP
        # status, so a 200 body with "ok": false here would report success
        # to the UI for a replay that did not happen.
        raise HTTPException(
            status_code=503,
            detail=(
                "Watchtower did not accept the replay; the event remains "
                f"dead-lettered ({sanitize_reason(outcome.reason)})."
            ),
        )

    return {
        "ok": True,
        "replay": outcome.to_dict(),
        "operator": operator,
        "timestamp": utc_now(),
    }


# =============================================================================
# Operator findings router
# =============================================================================
#
# Baseline verification found that Fenrir/Sparta findings successfully reach
# MonitoringManager (which correctly scores and, for SpartaCore, actually
# changes the embedded WatchtowerNode's own state) but had no authenticated
# operator-facing retrieval surface -- only raw container logs. This router
# is a VIEW into the canonical state MonitoringManager/WatchtowerNode already
# maintain (WatchtowerNode.recent_events, a bounded deque sized by existing
# config), not a new findings database, event bus, or monitoring subsystem.

operator_router = APIRouter(
    prefix="/operator",
    tags=["operator"],
)

#: Named fields a finding entry may surface to an operator. Allowlist only,
#: matching the same principle as _sanitize_finding_fields: a field reaches
#: the operator only if it is named here, so an unexamined producer field
#: (or a raw internal object) can never ride through. Never a service token,
#: credential, Authorization header, or unrestricted producer blob.
_FINDING_ALLOWED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        # Identity / provenance (BaseEvent)
        "id",
        "event_id",
        "kind",
        "event_type",
        "schema_version",
        "source",
        "source_identity",
        "correlation_id",
        "parent_event_id",
        "created_at",
        "ingested_at",
        "received_ts",
        "created_ts",
        # Security/finding content (SecurityEvent)
        "severity",
        "threat_kind",
        "source_ip",
        "indicators",
        "confidence",
        "secrets_exposed",
        "privilege_escalation",
        "unsigned_artifact",
        "debug_mode_enabled",
        # Integrity content (LogEvent / SpartaCore)
        "integrity_status",
        # Alert-wrapper content (WatchtowerNode.scan_event's own findings)
        "source_event_id",
        "alerts",
        "coordinator_decision",
        # Dropped-event-wrapper content
        "accepted",
        "dropped_reason",
        "node_state",
    }
)


def _finding_subsystem(entry: Mapping[str, Any]) -> str:
    """Best-effort human-facing subsystem label for one finding entry."""
    identity = str(entry.get("source_identity") or "").strip()
    if identity.startswith("service:"):
        return identity[len("service:") :]
    if identity:
        return identity
    return str(entry.get("source") or "unknown").strip() or "unknown"


def _sanitize_finding_entry(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Project one raw recent_events entry down to the operator-safe view."""
    entry = {
        key: raw[key]
        for key in _FINDING_ALLOWED_FIELDS
        if key in raw
    }
    entry["subsystem"] = _finding_subsystem(raw)
    return entry


def _finding_timestamp(entry: Mapping[str, Any]) -> float:
    """Best-effort epoch timestamp for filtering/ordering, never raises."""
    created_at = entry.get("created_at")
    if isinstance(created_at, str) and created_at:
        try:
            return datetime.fromisoformat(
                created_at.replace("Z", "+00:00")
            ).timestamp()
        except ValueError:
            pass

    for key in ("created_ts", "received_ts"):
        value = entry.get(key)
        if isinstance(value, (int, float)):
            return float(value)

    return 0.0


def _parse_since(since: str) -> float:
    since = since.strip()
    try:
        return float(since)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(since.replace("Z", "+00:00")).timestamp()
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="since must be an epoch-seconds number or an ISO-8601 timestamp",
        ) from None


@operator_router.get("/findings")
async def operator_findings(
    request: Request,
    limit: int = 50,
    source: str | None = None,
    severity: str | None = None,
    event_type: str | None = None,
    subsystem: str | None = None,
    since: str | None = None,
) -> dict[str, Any]:
    """Bounded, authenticated, sanitized view of recent MonitoringManager
    findings -- Fenrir detections, SpartaCore integrity events/alerts, and
    anything else routed through analyze_event(). Human operators only.

    This is read access to existing canonical state; it does not stage,
    approve, or execute anything, so it carries no governance/audit action
    of its own -- the same convention already used by the other read-only
    status/listing routes (/reliability/status, /reliability/failed-events).
    """
    await _require_operator(request)

    manager = runtime.monitoring_manager
    if manager is None:
        raise HTTPException(
            status_code=503,
            detail="MonitoringManager is not available.",
        )

    bounded_limit = max(1, min(int(limit), 500))

    try:
        snapshot = manager.recent_events(bounded_limit)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None

    since_ts = _parse_since(since) if since else None

    findings: list[dict[str, Any]] = []
    for raw in snapshot.get("events", []):
        if not isinstance(raw, Mapping):
            continue

        sanitized = _sanitize_finding_entry(raw)

        if source is not None and sanitized.get("source") != source:
            continue
        if severity is not None and sanitized.get("severity") != severity:
            continue
        if event_type is not None and sanitized.get("event_type") != event_type:
            continue
        if subsystem is not None and sanitized.get("subsystem") != subsystem:
            continue
        if since_ts is not None and _finding_timestamp(sanitized) < since_ts:
            continue

        findings.append(sanitized)

    return {
        "count": len(findings),
        "limit": bounded_limit,
        "findings": findings,
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

    authority_snapshot = (
        runtime.sentinel43.authority_snapshot()
        if runtime.sentinel43 is not None
        else {
            "authority": "Sentinel43RuntimeAuthority",
            "state": "unavailable",
            "external_execution_supported": False,
        }
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
            # Real lifecycle state, not a present/absent guess: an enabled
            # subsystem that was refused for missing configuration reports
            # UNAVAILABLE here, where it previously read "disabled".
            **{
                item.name: item.state.value
                for item in runtime.subsystems.snapshot()
            },
            "redis": "unknown",
            "postgres": "unknown",
        },
        "subsystems": runtime.subsystems.to_dict(),
        "readiness": runtime.subsystems.readiness().to_dict(),
        "watchtower": wt,
        "sentinel43_authority": authority_snapshot,
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
app.include_router(reliability_router)
app.include_router(operator_router)
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
