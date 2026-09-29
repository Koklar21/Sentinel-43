# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
#
# See LICENSE.md and COMMERCIAL_LICENSE.md at the repository root.
# =============================================================================

"""Sentinel-43 API dependency wiring.

This module resolves application dependencies from validated configuration,
keeps authentication delegation centralized, and treats Watchtower telemetry
as best-effort observability rather than part of dependency correctness.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from importlib import import_module
from typing import Any, Callable, Final, Protocol, TypeVar, cast

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.deps import get_db_session
from ...monitoring.watchtower_client import watchtower_report
from .config import (
    DEFAULT_ENGINE_FACTORY,
    DEFAULT_STORE_FACTORY,
    ApiConfig,
    load_config,
)

logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

ENV_DEV_ENGINE_ENABLED: Final[str] = "S43_ENABLE_DEV_ENGINE"
ENV_DEV_STORE_ENABLED: Final[str] = "S43_ENABLE_DEV_STORE"

DEPS_MODULE_ID: Final[str] = "sentinel43-api-deps"

_TRUE_VALUES: Final[frozenset[str]] = frozenset(
    {"1", "true", "yes", "on", "enabled"}
)

_FALSE_VALUES: Final[frozenset[str]] = frozenset(
    {"0", "false", "no", "off", "disabled"}
)

_FACTORY_SPEC_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$"
)

_ENGINE_REQUIRED_METHODS: Final[tuple[str, ...]] = (
    "handle_assessment",
    "approve_action",
    "veto_action",
)

_STORE_REQUIRED_METHODS: Final[tuple[str, ...]] = (
    "get_status",
    "list_actions",
)


# =============================================================================
# Protocols
# =============================================================================

class EngineProtocol(Protocol):
    def handle_assessment(self, mode: str, assessment: Any) -> Any: ...
    def approve_action(
        self,
        action_id: str,
        operator_id: str,
        *,
        reason: str = "",
    ) -> bool: ...
    def veto_action(
        self,
        action_id: str,
        operator_id: str,
        *,
        reason: str,
    ) -> bool: ...


class StoreProtocol(Protocol):
    def get_status(self, action_id: str) -> Any: ...
    def list_actions(
        self,
        *,
        status: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> Any: ...


T = TypeVar("T")


# =============================================================================
# Errors
# =============================================================================

class DependencyResolutionError(RuntimeError):
    """Raised when a configured Sentinel-43 dependency cannot be resolved."""


# =============================================================================
# Utility helpers
# =============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env_bool(
    name: str,
    *,
    default: bool,
    strict: bool,
) -> bool:
    raw = os.getenv(name)

    if raw is None:
        return default

    value = raw.strip().lower()

    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False

    if strict:
        raise DependencyResolutionError(
            f"{name} must be a boolean value; got {raw!r}"
        )

    logger.warning(
        "Invalid boolean for %s=%r; using default %s",
        name,
        raw,
        default,
    )
    return default


# =============================================================================
# Watchtower telemetry
# =============================================================================

def _report_dependency_event(
    *,
    status: str,
    event: str,
    config: ApiConfig,
    details: dict[str, Any] | None = None,
) -> None:
    module_id = os.getenv("S43_DEPS_MODULE_ID", DEPS_MODULE_ID).strip() or DEPS_MODULE_ID
    timestamp = utc_now()

    payload = {
        "event": {
            "kind": "dependency",
            "source": module_id,
            "status": status,
            "dependency_status": status,
            "details": {
                "event": event,
                "timestamp": timestamp,
                "environment": config.environment,
                **(details or {}),
            },
        }
    }

    watchtower_report(
        "POST",
        "/watchtower/analyze",
        payload,
    )


@lru_cache(maxsize=1)
def register_dependencies_with_watchtower() -> None:
    """Register this module once per process.

    Registration is explicit and cached. Dependency resolution does not
    repeatedly re-register the module on every request or every error.
    """
    config = load_config()
    module_id = os.getenv("S43_DEPS_MODULE_ID", DEPS_MODULE_ID).strip() or DEPS_MODULE_ID

    payload = {
        "module_id": module_id,
        "module_type": "api-dependencies",
        "version": config.version,
        "endpoint": None,
        "capabilities": [
            "engine_factory_resolution",
            "store_factory_resolution",
            "dependency_interface_validation",
            "dev_engine_stub",
            "dev_store_stub",
        ],
        "metadata": {
            "timestamp": utc_now(),
            "environment": config.environment,
        },
    }

    watchtower_report(
        "POST",
        "/watchtower/modules/register",
        payload,
    )


# =============================================================================
# Authentication dependencies
# =============================================================================

async def _authenticate_request(
    request: Request,
    *,
    legacy_metric_route: str,
) -> tuple[str, dict[str, Any]]:
    """Authenticate an operator/admin request using the canonical auth module."""
    auth = request.headers.get("Authorization", "").strip()

    if not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    token = auth[7:].strip()
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    from ..routers.auth import (
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
            detail="Invalid token",
        )

    resolved = await resolve_session_subject(claims)
    if resolved is not None:
        return resolved[0], claims

    if legacy_auth_is_rejected():
        raise HTTPException(
            status_code=401,
            detail="Legacy authentication is no longer accepted. Log in again.",
        )

    note_legacy_auth(legacy_metric_route)

    password = request.headers.get(PASSWORD_HEADER_NAME, "")
    if not password:
        raise HTTPException(
            status_code=401,
            detail="Password required",
        )

    if not await reverify_password(subject, password):
        raise HTTPException(
            status_code=401,
            detail="Invalid password",
        )

    return subject, claims


async def require_operator(request: Request) -> str:
    """Require a valid Sentinel-43 operator/admin authentication context."""
    subject, _claims = await _authenticate_request(
        request,
        legacy_metric_route="/v1",
    )
    return subject


async def require_admin(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
) -> str:
    """Require a live, active admin account from the DB-backed user store."""
    from ...auth.users import get_user_by_username

    subject, _claims = await _authenticate_request(
        request,
        legacy_metric_route="/users",
    )

    try:
        user = await get_user_by_username(session, subject)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="User account store is unavailable.",
        ) from exc

    if user is None:
        raise HTTPException(
            status_code=403,
            detail="Admin role required",
        )

    if not bool(getattr(user, "is_active", False)):
        raise HTTPException(
            status_code=403,
            detail="Admin role required",
        )

    if str(getattr(user, "role", "")).lower() != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin role required",
        )

    return subject


# =============================================================================
# Factory resolution
# =============================================================================

def _validate_factory_spec(spec: str) -> str:
    cleaned = spec.strip()

    if not _FACTORY_SPEC_RE.fullmatch(cleaned):
        raise DependencyResolutionError(
            f"Invalid factory spec {spec!r}; expected 'module.path:callable'"
        )

    return cleaned


def _parse_factory(spec: str) -> tuple[str, str]:
    cleaned = _validate_factory_spec(spec)
    module_name, callable_name = cleaned.split(":", 1)
    return module_name, callable_name


def _load_callable(spec: str) -> Callable[[], Any]:
    module_name, callable_name = _parse_factory(spec)

    try:
        module = import_module(module_name)
    except Exception as exc:
        raise DependencyResolutionError(
            f"Failed to import dependency module {module_name!r} "
            f"for factory {spec!r}"
        ) from exc

    candidate = getattr(module, callable_name, None)

    if candidate is None or not callable(candidate):
        raise DependencyResolutionError(
            f"Factory {spec!r} did not resolve to a callable"
        )

    return cast(Callable[[], Any], candidate)


@lru_cache(maxsize=64)
def _cached_factory(spec: str) -> Callable[[], Any]:
    return _load_callable(spec)


def clear_factory_caches() -> None:
    """Clear only factory-resolution caches.

    This is intended for tests or controlled configuration reloads.
    """
    _cached_factory.cache_clear()
    register_dependencies_with_watchtower.cache_clear()


def _require_methods(
    obj: T,
    methods: tuple[str, ...],
    *,
    kind: str,
    factory_spec: str,
) -> T:
    missing = [
        method
        for method in methods
        if not callable(getattr(obj, method, None))
    ]

    if missing:
        raise DependencyResolutionError(
            f"{kind} factory {factory_spec!r} returned "
            f"{type(obj).__name__} missing callable methods: "
            f"{', '.join(missing)}"
        )

    return obj


def _ensure_dev_factory_allowed(
    *,
    config: ApiConfig,
    kind: str,
    spec: str,
    default_spec: str,
    flag_name: str,
) -> None:
    if spec != default_spec:
        return

    enabled = _env_bool(
        flag_name,
        default=False,
        strict=not config.is_local,
    )

    if not config.is_local:
        raise DependencyResolutionError(
            f"{kind} development factory {spec!r} is forbidden outside "
            "development/test"
        )

    if not enabled:
        raise DependencyResolutionError(
            f"{kind} is using development factory {spec!r}, but "
            f"{flag_name}=true is not set"
        )


def _resolve_dependency(
    *,
    config: ApiConfig,
    kind: str,
    spec: str,
    required_methods: tuple[str, ...],
    default_spec: str,
    dev_flag: str,
) -> Any:
    cleaned_spec = _validate_factory_spec(spec)

    _ensure_dev_factory_allowed(
        config=config,
        kind=kind,
        spec=cleaned_spec,
        default_spec=default_spec,
        flag_name=dev_flag,
    )

    try:
        factory = _cached_factory(cleaned_spec)
        obj = factory()

        if obj is None:
            raise DependencyResolutionError(
                f"{kind} factory {cleaned_spec!r} returned None"
            )

        obj = _require_methods(
            obj,
            required_methods,
            kind=kind,
            factory_spec=cleaned_spec,
        )

        _report_dependency_event(
            status="online",
            event=f"{kind.lower()}_resolved",
            config=config,
            details={
                "factory_spec": cleaned_spec,
                "returned_type": type(obj).__name__,
            },
        )
        return obj

    except Exception as exc:
        _report_dependency_event(
            status="failed",
            event=f"{kind.lower()}_resolution_failed",
            config=config,
            details={
                "factory_spec": cleaned_spec,
                "exception_type": type(exc).__name__,
            },
        )

        if isinstance(exc, DependencyResolutionError):
            raise

        raise DependencyResolutionError(
            f"Failed to resolve {kind.lower()} dependency "
            f"from {cleaned_spec!r}"
        ) from exc


# =============================================================================
# Dev stubs
# =============================================================================

class DevEngine:
    """Non-enforcing development engine stub."""

    def handle_assessment(
        self,
        mode: str,
        assessment: Any,
    ) -> dict[str, Any]:
        return {
            "assessment_id": "dev-000",
            "severity": 0,
            "confidence": 0,
            "summary": f"dev_engine(mode={mode})",
            "tags": ["dev"],
        }

    def approve_action(
        self,
        action_id: str,
        operator_id: str,
        *,
        reason: str = "",
    ) -> bool:
        # Dev stub acknowledges the request only. It does not execute an
        # external action.
        return True

    def veto_action(
        self,
        action_id: str,
        operator_id: str,
        *,
        reason: str,
    ) -> bool:
        return True


@dataclass(slots=True)
class DevStore:
    actions: dict[str, dict[str, Any]] = field(default_factory=dict)

    def get_status(self, action_id: str) -> Any:
        return self.actions.get(
            action_id,
            {
                "action_id": action_id,
                "decision": "unknown",
            },
        )

    def list_actions(
        self,
        *,
        status: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        safe_limit = max(1, min(int(limit), 500))
        items = list(self.actions.values())

        if status:
            items = [
                item
                for item in items
                if item.get("decision") == status
                or item.get("status") == status
            ]

        return {
            "items": items[:safe_limit],
            "next_cursor": None,
        }


def dev_engine_factory() -> EngineProtocol:
    config = load_config()

    if not config.is_local:
        raise DependencyResolutionError(
            "DevEngine is forbidden outside development/test"
        )

    if not _env_bool(
        ENV_DEV_ENGINE_ENABLED,
        default=False,
        strict=False,
    ):
        raise DependencyResolutionError(
            f"DevEngine is disabled; set {ENV_DEV_ENGINE_ENABLED}=true "
            "for local development only"
        )

    return DevEngine()


def dev_store_factory() -> StoreProtocol:
    config = load_config()

    if not config.is_local:
        raise DependencyResolutionError(
            "DevStore is forbidden outside development/test"
        )

    if not _env_bool(
        ENV_DEV_STORE_ENABLED,
        default=False,
        strict=False,
    ):
        raise DependencyResolutionError(
            f"DevStore is disabled; set {ENV_DEV_STORE_ENABLED}=true "
            "for local development only"
        )

    # Return a fresh store per dependency resolution. Tests and local requests
    # no longer share mutable global state by accident.
    return DevStore()


# =============================================================================
# Public dependency providers
# =============================================================================

def get_audit_health_status(request: Request) -> str:
    """Return the audit store's bounded last-known health value.

    The router receives only the health value, never the mutable audit store.
    Missing runtime/store state is reported explicitly rather than treated as
    healthy.
    """
    runtime = getattr(request.app.state, "runtime", None)
    store = getattr(runtime, "audit_store", None)
    if store is None:
        return "unavailable"

    health = getattr(store, "last_known_health", None)
    value = getattr(health, "value", health)
    normalized = str(value or "").strip().lower()
    return normalized or "unknown"


def get_runtime_authority(request: Request) -> Any:
    """Return the one live Sentinel-43 runtime authority for API mutations."""
    runtime = getattr(request.app.state, "runtime", None)
    authority = getattr(runtime, "sentinel43", None)
    if authority is None:
        raise HTTPException(
            status_code=503,
            detail="Sentinel-43 runtime authority is unavailable.",
        )
    return authority


def get_optional_runtime_authority(request: Request) -> Any | None:
    """Return the live authority when present, without creating a fallback."""
    runtime = getattr(request.app.state, "runtime", None)
    return getattr(runtime, "sentinel43", None)


def get_engine() -> EngineProtocol:
    """Resolve and validate the configured engine dependency."""
    config = load_config()
    register_dependencies_with_watchtower()

    obj = _resolve_dependency(
        config=config,
        kind="Engine",
        spec=config.engine_factory,
        required_methods=_ENGINE_REQUIRED_METHODS,
        default_spec=DEFAULT_ENGINE_FACTORY,
        dev_flag=ENV_DEV_ENGINE_ENABLED,
    )

    return cast(EngineProtocol, obj)


def get_store() -> StoreProtocol:
    """Resolve and validate the configured store dependency."""
    config = load_config()
    register_dependencies_with_watchtower()

    obj = _resolve_dependency(
        config=config,
        kind="Store",
        spec=config.store_factory,
        required_methods=_STORE_REQUIRED_METHODS,
        default_spec=DEFAULT_STORE_FACTORY,
        dev_flag=ENV_DEV_STORE_ENABLED,
    )

    return cast(StoreProtocol, obj)


def deps_status() -> dict[str, Any]:
    """Return non-sensitive dependency wiring diagnostics."""
    config = load_config()

    return {
        "module_id": (
            os.getenv("S43_DEPS_MODULE_ID", DEPS_MODULE_ID).strip()
            or DEPS_MODULE_ID
        ),
        "version": config.version,
        "engine_factory": config.engine_factory,
        "store_factory": config.store_factory,
        "factory_cache": _cached_factory.cache_info()._asdict(),
        "environment": config.environment,
        "timestamp": utc_now(),
    }


__all__ = [
    "DependencyResolutionError",
    "DevEngine",
    "DevStore",
    "EngineProtocol",
    "StoreProtocol",
    "clear_factory_caches",
    "deps_status",
    "dev_engine_factory",
    "dev_store_factory",
    "get_audit_health_status",
    "get_engine",
    "get_optional_runtime_authority",
    "get_runtime_authority",
    "get_store",
    "register_dependencies_with_watchtower",
    "require_admin",
    "require_operator",
]
