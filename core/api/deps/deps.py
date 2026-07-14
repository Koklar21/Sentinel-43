# =============================================================================
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

"""Sentinel-43 API layer: dependency wiring."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

import jwt as pyjwt
from fastapi import HTTPException, Request
from ...security.jwt_constants import APPROVED_JWT_ALGORITHMS
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from importlib import import_module
from typing import Any, Callable, Optional


# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------

ENV_ENGINE_FACTORY = "SENTINEL_ENGINE_FACTORY"
ENV_STORE_FACTORY = "SENTINEL_STORE_FACTORY"

DEFAULT_ENGINE_FACTORY = "core.api.deps:dev_engine_factory"
DEFAULT_STORE_FACTORY = "core.api.deps:dev_store_factory"

DEPS_MODULE_ID = os.getenv("S43_DEPS_MODULE_ID", "sentinel43-api-deps")
DEPS_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")
WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/")
WATCHTOWER_TIMEOUT = float(os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0"))

ENV_DEV_ENGINE_ENABLED = "S43_ENABLE_DEV_ENGINE"
ENV_DEV_STORE_ENABLED = "S43_ENABLE_DEV_STORE"

JWT_SECRET = os.getenv("S43_JWT_SECRET", "").strip()
JWT_ALGORITHM = os.getenv("S43_JWT_ALGORITHM", "HS256").strip()
JWT_ISSUER = os.getenv("S43_JWT_ISSUER", "sentinel-43").strip()
JWT_AUDIENCE = os.getenv("S43_JWT_AUDIENCE", "sentinel-43-dashboard").strip()

_APPROVED_ALGORITHMS = APPROVED_JWT_ALGORITHMS
_APPROVED_ROLES = frozenset({"operator", "admin"})


# -----------------------------------------------------------------------------
# Watchtower intercom
# -----------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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

            parsed = json.loads(body)
            if isinstance(parsed, dict):
                parsed.setdefault("status_code", response.status)
                return parsed

            return {"status_code": response.status, "body": parsed}

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


def _register_deps_with_watchtower() -> None:
    payload = {
        "module_id": DEPS_MODULE_ID,
        "module_type": "api-dependencies",
        "version": DEPS_VERSION,
        "endpoint": None,
        "capabilities": [
            "engine_factory_resolution",
            "store_factory_resolution",
            "dependency_interface_validation",
            "dev_engine_stub",
            "dev_store_stub",
        ],
        "metadata": {"timestamp": utc_now()},
    }

    _watchtower_request("POST", "/watchtower/modules/register", payload)


def _report_deps_status(
    status: str,
    event: str,
    details: dict[str, Any] | None = None,
) -> None:
    _register_deps_with_watchtower()

    payload = {
        "name": DEPS_MODULE_ID,
        "status": status,
        "version": DEPS_VERSION,
        "details": {
            "event": event,
            "timestamp": utc_now(),
            **(details or {}),
        },
    }

    _watchtower_request("POST", "/watchtower/dependencies/report", payload)


def _report_deps_event(
    status: str,
    event: str,
    details: dict[str, Any] | None = None,
) -> None:
    payload = {
        "event": {
            "kind": "dependency",
            "source": DEPS_MODULE_ID,
            "status": status,
            "dependency_status": status,
            "details": {
                "event": event,
                "timestamp": utc_now(),
                **(details or {}),
            },
        }
    }

    _watchtower_request("POST", "/watchtower/analyze", payload)



# -----------------------------------------------------------------------------
# Auth dependency
# -----------------------------------------------------------------------------

_TRUE_VALUES = {"1", "true", "yes", "on", "enabled"}
_FALSE_VALUES = {"0", "false", "no", "off", "disabled"}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default

    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False

    return default


def _verify_operator_jwt(token: str) -> dict[str, Any]:
    if JWT_ALGORITHM not in _APPROVED_ALGORITHMS:
        raise HTTPException(status_code=503, detail="JWT algorithm is not approved")

    if not JWT_SECRET:
        raise HTTPException(status_code=503, detail="JWT validation not configured")

    try:
        return pyjwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except pyjwt.InvalidIssuerError:
        raise HTTPException(status_code=401, detail="Invalid token issuer")
    except pyjwt.InvalidAudienceError:
        raise HTTPException(status_code=401, detail="Invalid token audience")
    except pyjwt.MissingRequiredClaimError as exc:
        raise HTTPException(status_code=401, detail=f"Missing required claim: {exc}")
    except pyjwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def require_operator(request: Request) -> str:
    auth = request.headers.get("Authorization", "").strip()

    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")

    token = auth[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")

    claims = _verify_operator_jwt(token)

    roles: set[str] = set()

    role_claim = claims.get("role")
    if role_claim:
        roles.add(str(role_claim).strip())

    scope_claim = claims.get("scope")
    if isinstance(scope_claim, str):
        roles.update(part.strip() for part in scope_claim.split() if part.strip())
    elif isinstance(scope_claim, (list, tuple, set)):
        roles.update(str(part).strip() for part in scope_claim if str(part).strip())

    if not roles.intersection(_APPROVED_ROLES):
        raise HTTPException(status_code=403, detail="Operator role required")

    subject = str(claims.get("sub") or "").strip()
    subject = subject if subject else f"bearer:{token[:16]}"

    # A valid JWT is no longer sufficient on its own — every protected
    # request must also re-supply the operator's password.
    from ..routers.auth import PASSWORD_HEADER_NAME, reverify_password

    password = request.headers.get(PASSWORD_HEADER_NAME, "")
    if not password:
        raise HTTPException(status_code=401, detail="Password required")
    if not await reverify_password(subject, password):
        raise HTTPException(status_code=401, detail="Invalid password")

    return subject


def _ensure_dev_factory_allowed(
    *,
    kind: str,
    spec: str,
    default_spec: str,
    flag_name: str,
) -> None:
    if spec != default_spec:
        return

    if _env_bool(flag_name, False):
        return

    _report_deps_status(
        status="failed",
        event="dev_dependency_disabled",
        details={
            "kind": kind,
            "factory_spec": spec,
            "enable_with": flag_name,
        },
    )

    raise HTTPException(
        status_code=503,
        detail={
            "error": f"S43_{kind.upper()}_DEV_FACTORY_DISABLED",
            "message": (
                f"{kind} is using the development factory, but {flag_name}=true "
                "is not set."
            ),
            "factory_spec": spec,
            "enable_with": flag_name,
        },
    )


# -----------------------------------------------------------------------------
# Expected interfaces
# -----------------------------------------------------------------------------

_ENGINE_REQUIRED_METHODS = (
    "handle_assessment",
    "approve_action",
    "veto_action",
)

_STORE_REQUIRED_METHODS = (
    "get_status",
    "list_actions",
)


def _require_methods(obj: Any, methods: tuple[str, ...], *, kind: str, factory_spec: str) -> Any:
    missing = [m for m in methods if not hasattr(obj, m)]

    if missing:
        _report_deps_status(
            status="failed",
            event="dependency_interface_validation_failed",
            details={
                "kind": kind,
                "factory_spec": factory_spec,
                "returned_type": type(obj).__name__,
                "missing_methods": missing,
            },
        )

        raise ValueError(
            f"{kind} factory '{factory_spec}' returned {type(obj).__name__} "
            f"missing methods: {', '.join(missing)}"
        )

    _report_deps_event(
        status="online",
        event="dependency_interface_validated",
        details={
            "kind": kind,
            "factory_spec": factory_spec,
            "returned_type": type(obj).__name__,
        },
    )

    return obj


# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

def _parse_factory(spec: str) -> tuple[str, str]:
    if ":" not in spec:
        _report_deps_status(
            status="failed",
            event="invalid_factory_spec",
            details={"factory_spec": spec},
        )
        raise ValueError(f"Invalid factory spec '{spec}'. Expected 'module.path:callable'.")

    mod, fn = spec.split(":", 1)
    mod = mod.strip()
    fn = fn.strip()

    if not mod or not fn:
        _report_deps_status(
            status="failed",
            event="invalid_factory_spec",
            details={"factory_spec": spec},
        )
        raise ValueError(f"Invalid factory spec '{spec}'. Expected 'module.path:callable'.")

    return mod, fn


def _load_callable(spec: str) -> Callable[[], Any]:
    mod_name, fn_name = _parse_factory(spec)

    try:
        mod = import_module(mod_name)
    except Exception as exc:
        _report_deps_status(
            status="failed",
            event="factory_module_import_failed",
            details={
                "factory_spec": spec,
                "module": mod_name,
                "error": str(exc),
                "exception_type": type(exc).__name__,
            },
        )
        raise

    fn = getattr(mod, fn_name, None)

    if fn is None or not callable(fn):
        _report_deps_status(
            status="failed",
            event="factory_callable_resolution_failed",
            details={
                "factory_spec": spec,
                "module": mod_name,
                "callable": fn_name,
            },
        )
        raise ValueError(f"Factory '{spec}' did not resolve to a callable.")

    _report_deps_event(
        status="online",
        event="factory_callable_resolved",
        details={
            "factory_spec": spec,
            "module": mod_name,
            "callable": fn_name,
        },
    )

    return fn  # type: ignore[return-value]


@lru_cache(maxsize=64)
def _cached_factory(spec: str) -> Callable[[], Any]:
    return _load_callable(spec)


def clear_factory_caches() -> None:
    _cached_factory.cache_clear()

    _report_deps_status(
        status="degraded",
        event="factory_cache_cleared",
        details={},
    )


# -----------------------------------------------------------------------------
# Dev stubs
# -----------------------------------------------------------------------------

class DevEngine:
    def handle_assessment(self, mode: str, assessment: Any) -> Any:
        return {
            "assessment_id": "dev-000",
            "severity": 0,
            "confidence": 0,
            "summary": f"dev_engine(mode={mode})",
            "tags": ["dev"],
        }

    def approve_action(self, action_id: str, operator_id: str, *, reason: str = "") -> bool:
        return True

    def veto_action(self, action_id: str, operator_id: str, *, reason: str) -> bool:
        return True


@dataclass
class DevStore:
    actions: dict[str, dict[str, Any]] = field(default_factory=dict)

    def get_status(self, action_id: str) -> Any:
        return self.actions.get(action_id, {"action_id": action_id, "decision": "unknown"})

    def list_actions(
        self,
        *,
        status: Optional[str] = None,
        limit: int = 50,
        cursor: Optional[str] = None,
    ) -> Any:
        items = list(self.actions.values())

        if status:
            items = [
                x for x in items
                if x.get("decision") == status or x.get("status") == status
            ]

        return {
            "items": items[:limit],
            "next_cursor": None,
        }


_DEV_STORE_SINGLETON = DevStore()


def reset_dev_store_state() -> None:
    _DEV_STORE_SINGLETON.actions.clear()

    _report_deps_status(
        status="degraded",
        event="dev_store_reset",
        details={},
    )


def dev_engine_factory() -> Any:
    if not _env_bool(ENV_DEV_ENGINE_ENABLED, False):
        _report_deps_status(
            status="failed",
            event="dev_engine_factory_disabled",
            details={
                "factory": "dev_engine_factory",
                "enable_with": ENV_DEV_ENGINE_ENABLED,
            },
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error": "S43_ENGINE_DEV_FACTORY_DISABLED",
                "message": (
                    "DevEngine is disabled. Set S43_ENABLE_DEV_ENGINE=true "
                    "only for local development, or configure SENTINEL_ENGINE_FACTORY."
                ),
                "enable_with": ENV_DEV_ENGINE_ENABLED,
            },
        )

    _report_deps_event(
        status="online",
        event="dev_engine_created",
        details={"factory": "dev_engine_factory"},
    )
    return DevEngine()


def dev_store_factory() -> Any:
    if not _env_bool(ENV_DEV_STORE_ENABLED, False):
        _report_deps_status(
            status="failed",
            event="dev_store_factory_disabled",
            details={
                "factory": "dev_store_factory",
                "enable_with": ENV_DEV_STORE_ENABLED,
            },
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error": "S43_STORE_DEV_FACTORY_DISABLED",
                "message": (
                    "DevStore is disabled. Set S43_ENABLE_DEV_STORE=true "
                    "only for local development, or configure SENTINEL_STORE_FACTORY."
                ),
                "enable_with": ENV_DEV_STORE_ENABLED,
            },
        )

    _report_deps_event(
        status="online",
        event="dev_store_returned",
        details={"factory": "dev_store_factory", "singleton": True},
    )
    return _DEV_STORE_SINGLETON


# -----------------------------------------------------------------------------
# Public dependencies
# -----------------------------------------------------------------------------

def get_engine() -> Any:
    spec = os.getenv(ENV_ENGINE_FACTORY, DEFAULT_ENGINE_FACTORY)

    _ensure_dev_factory_allowed(
        kind="engine",
        spec=spec,
        default_spec=DEFAULT_ENGINE_FACTORY,
        flag_name=ENV_DEV_ENGINE_ENABLED,
    )

    try:
        factory = _cached_factory(spec)
        obj = factory()
        return _require_methods(
            obj,
            _ENGINE_REQUIRED_METHODS,
            kind="Engine",
            factory_spec=spec,
        )

    except Exception as exc:
        _report_deps_status(
            status="failed",
            event="get_engine_failed",
            details={
                "factory_spec": spec,
                "error": str(exc),
                "exception_type": type(exc).__name__,
            },
        )
        raise


def get_store() -> Any:
    spec = os.getenv(ENV_STORE_FACTORY, DEFAULT_STORE_FACTORY)

    _ensure_dev_factory_allowed(
        kind="store",
        spec=spec,
        default_spec=DEFAULT_STORE_FACTORY,
        flag_name=ENV_DEV_STORE_ENABLED,
    )

    try:
        factory = _cached_factory(spec)
        obj = factory()
        return _require_methods(
            obj,
            _STORE_REQUIRED_METHODS,
            kind="Store",
            factory_spec=spec,
        )

    except Exception as exc:
        _report_deps_status(
            status="failed",
            event="get_store_failed",
            details={
                "factory_spec": spec,
                "error": str(exc),
                "exception_type": type(exc).__name__,
            },
        )
        raise


def deps_status() -> dict[str, Any]:
    return {
        "module_id": DEPS_MODULE_ID,
        "version": DEPS_VERSION,
        "engine_factory": os.getenv(ENV_ENGINE_FACTORY, DEFAULT_ENGINE_FACTORY),
        "store_factory": os.getenv(ENV_STORE_FACTORY, DEFAULT_STORE_FACTORY),
        "watchtower_url": WATCHTOWER_URL,
        "factory_cache": _cached_factory.cache_info()._asdict(),
        "timestamp": utc_now(),
    }


__all__ = [
    "get_engine",
    "get_store",
    "require_operator",
    "deps_status",
    "clear_factory_caches",
    "reset_dev_store_state",
    "DevEngine",
    "DevStore",
    "dev_engine_factory",
    "dev_store_factory",
]
