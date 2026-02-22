# =============================================================================
# Copyright (c) 2026 Justin [LastName or Entity]
#
# Sentinel is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
#
# See LICENSE.md and COMMERCIAL_LICENSE.md at the repository root.
# =============================================================================

"""Sentinel-43 API layer: dependency wiring.

File: api/deps.py

This module produces FastAPI dependencies:
- Engine instance
- Store instance

Design goals:
- Clear wiring via env-configured factories.
- Cached factory resolution (no import_module per request).
- Fast failure when factories return objects missing required methods.
- Dev stubs available so the API can run before core is wired.

Factory configuration:
  SENTINEL_ENGINE_FACTORY="module.path:create_engine"
  SENTINEL_STORE_FACTORY="module.path:create_store"

Each factory must be a **zero-arg** callable returning the engine/store object.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from importlib import import_module
from typing import Any, Callable, Optional

import os


# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------

ENV_ENGINE_FACTORY = "SENTINEL_ENGINE_FACTORY"
ENV_STORE_FACTORY = "SENTINEL_STORE_FACTORY"

DEFAULT_ENGINE_FACTORY = "api.deps:dev_engine_factory"
DEFAULT_STORE_FACTORY = "api.deps:dev_store_factory"


# -----------------------------------------------------------------------------
# Expected interfaces (runtime checks)
# -----------------------------------------------------------------------------

_ENGINE_REQUIRED_METHODS = (
    "handle_assessment",
    "approve_action",
    "veto_action",
)

_STORE_REQUIRED_METHODS = (
    "get_status",
    # list_actions is used by the /v1/actions endpoint; treat it as required.
    "list_actions",
)


def _require_methods(obj: Any, methods: tuple[str, ...], *, kind: str, factory_spec: str) -> Any:
    missing = [m for m in methods if not hasattr(obj, m)]
    if missing:
        raise ValueError(
            f"{kind} factory '{factory_spec}' returned {type(obj).__name__} missing methods: {', '.join(missing)}"
        )
    return obj


# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------


def _parse_factory(spec: str) -> tuple[str, str]:
    """Parse 'module.path:callable' spec."""
    if ":" not in spec:
        raise ValueError(f"Invalid factory spec '{spec}'. Expected 'module.path:callable'.")
    mod, fn = spec.split(":", 1)
    mod = mod.strip()
    fn = fn.strip()
    if not mod or not fn:
        raise ValueError(f"Invalid factory spec '{spec}'. Expected 'module.path:callable'.")
    return mod, fn


def _load_callable(spec: str) -> Callable[[], Any]:
    """Resolve a factory spec to a callable."""
    mod_name, fn_name = _parse_factory(spec)
    mod = import_module(mod_name)
    fn = getattr(mod, fn_name, None)
    if fn is None or not callable(fn):
        raise ValueError(f"Factory '{spec}' did not resolve to a callable.")
    return fn  # type: ignore[return-value]


@lru_cache(maxsize=64)
def _cached_factory(spec: str) -> Callable[[], Any]:
    """Cache factory resolution so we don't do imports/lookups per request."""
    return _load_callable(spec)


def clear_factory_caches() -> None:
    """Clear cached factory lookups.

    Useful in tests or if you intentionally change env vars at runtime.
    """
    _cached_factory.cache_clear()


# -----------------------------------------------------------------------------
# Dev stubs (safe defaults)
# -----------------------------------------------------------------------------


class DevEngine:
    """A boring dev engine so routes can run before core is wired."""

    def handle_assessment(self, mode: str, assessment: Any) -> Any:
        # Keep output schema compatible with _as_assessment_out in routes.
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
    """A dev store that keeps action status in memory."""

    actions: dict[str, dict[str, Any]] = field(default_factory=dict)

    def get_status(self, action_id: str) -> Any:
        return self.actions.get(action_id, {"action_id": action_id, "decision": "unknown"})

    def list_actions(self, *, status: Optional[str] = None, limit: int = 50, cursor: Optional[str] = None) -> Any:
        # cursor is ignored for dev.
        items = list(self.actions.values())
        if status:
            items = [x for x in items if (x.get("decision") == status or x.get("status") == status)]
        return {"items": items[:limit], "next_cursor": None}


# Shared dev store backing, explicitly named.
# If you prefer request-scoped stores, set SENTINEL_STORE_FACTORY to a factory
# that constructs a new store each call.
_DEV_STORE_SINGLETON = DevStore()


def reset_dev_store_state() -> None:
    """Clear the shared dev store (useful for tests)."""
    _DEV_STORE_SINGLETON.actions.clear()


def dev_engine_factory() -> Any:
    return DevEngine()


def dev_store_factory() -> Any:
    return _DEV_STORE_SINGLETON


# -----------------------------------------------------------------------------
# Public dependencies
# -----------------------------------------------------------------------------


def get_engine() -> Any:
    """FastAPI dependency: returns an engine instance.

    Uses SENTINEL_ENGINE_FACTORY or falls back to api.deps:dev_engine_factory.
    """
    spec = os.getenv(ENV_ENGINE_FACTORY, DEFAULT_ENGINE_FACTORY)
    factory = _cached_factory(spec)
    obj = factory()
    return _require_methods(obj, _ENGINE_REQUIRED_METHODS, kind="Engine", factory_spec=spec)


def get_store() -> Any:
    """FastAPI dependency: returns a store instance.

    Uses SENTINEL_STORE_FACTORY or falls back to api.deps:dev_store_factory.
    """
    spec = os.getenv(ENV_STORE_FACTORY, DEFAULT_STORE_FACTORY)
    factory = _cached_factory(spec)
    obj = factory()
    return _require_methods(obj, _STORE_REQUIRED_METHODS, kind="Store", factory_spec=spec)


# -----------------------------------------------------------------------------
# Minimal tests
# -----------------------------------------------------------------------------


def _run_self_tests() -> None:  # pragma: no cover
    import unittest

    class BadEngine:
        pass

    class BadStore:
        def get_status(self, action_id: str) -> Any:
            return {}

    def bad_engine_factory() -> Any:
        return BadEngine()

    def bad_store_factory() -> Any:
        return BadStore()

    class DepsTests(unittest.TestCase):
        def setUp(self) -> None:
            reset_dev_store_state()
            clear_factory_caches()

        def test_parse_factory(self):
            self.assertEqual(_parse_factory("x.y:z"), ("x.y", "z"))

        def test_parse_factory_bad(self):
            with self.assertRaises(ValueError):
                _parse_factory("nope")

        def test_dev_factories_work(self):
            e = dev_engine_factory()
            s = dev_store_factory()
            self.assertTrue(hasattr(e, "handle_assessment"))
            self.assertTrue(hasattr(s, "get_status"))
            self.assertTrue(hasattr(s, "list_actions"))

        def test_cached_factory(self):
            # Use this module's name so the test works whether imported as api.deps
            # or executed as __main__.
            spec = f"{__name__}:dev_engine_factory"
            f1 = _cached_factory(spec)
            f2 = _cached_factory(spec)
            self.assertIs(f1, f2)

        def test_engine_interface_validation(self):
            # Wire a bad factory via env and confirm we fail with a clear error.
            os.environ[ENV_ENGINE_FACTORY] = f"{__name__}:bad_engine_factory"
            # Make sure our module has the symbol (it does, local function above).
            with self.assertRaises(ValueError) as ctx:
                get_engine()
            self.assertIn("missing methods", str(ctx.exception))

        def test_store_interface_validation(self):
            os.environ[ENV_STORE_FACTORY] = f"{__name__}:bad_store_factory"
            with self.assertRaises(ValueError) as ctx:
                get_store()
            self.assertIn("missing methods", str(ctx.exception))

        def test_reset_dev_store_state(self):
            s = dev_store_factory()
            s.actions["x"] = {"action_id": "x", "decision": "approved"}
            reset_dev_store_state()
            self.assertEqual(s.actions, {})

    unittest.main(argv=["deps.py"], exit=False)


if __name__ == "__main__":  # pragma: no cover
    _run_self_tests()
