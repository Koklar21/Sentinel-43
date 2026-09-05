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

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from importlib import import_module
from typing import Any, Callable, Optional

from ...monitoring.watchtower_client import WATCHTOWER_URL, watchtower_request


# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------

ENV_ENGINE_FACTORY = "SENTINEL_ENGINE_FACTORY"
ENV_STORE_FACTORY = "SENTINEL_STORE_FACTORY"

DEFAULT_ENGINE_FACTORY = "core.api.deps:dev_engine_factory"
DEFAULT_STORE_FACTORY = "core.api.deps:dev_store_factory"

DEPS_MODULE_ID = os.getenv("S43_DEPS_MODULE_ID", "sentinel43-api-deps")
DEPS_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")


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
    # DEFECT_INVENTORY.md D-16: this used to build the request without the
    # internal service token, so every call here 401'd against Watchtower
    # and the module-registration / dependency-report callers below silently
    # believed it had succeeded. Delegates to the canonical client, which
    # attaches Authorization and never swallows a failure without logging it.
    return watchtower_request(method, path, payload)


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
    _report_deps_event(
        status="online",
        event="dev_engine_created",
        details={"factory": "dev_engine_factory"},
    )
    return DevEngine()


def dev_store_factory() -> Any:
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
    "deps_status",
    "clear_factory_caches",
    "reset_dev_store_state",
    "DevEngine",
    "DevStore",
    "dev_engine_factory",
    "dev_store_factory",
]

from .deps import require_admin, require_operator

# -----------------------------------------------------------------------------
# Batch 2 canonical dependency exports
# -----------------------------------------------------------------------------
# Keep package-level imports aligned with core.api.deps.deps so routers using:
#   from core.api.deps import get_engine, get_store, require_operator
# receive the guarded implementations.

from .deps import (
    DevEngine,
    DevStore,
    clear_factory_caches,
    deps_status,
    dev_engine_factory,
    dev_store_factory,
    get_engine,
    get_store,
    require_admin,
    require_operator,
    reset_dev_store_state,
)

