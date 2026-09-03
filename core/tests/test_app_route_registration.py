# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_app_route_registration.py
#
# Integration pass (next-PR) Phase B regression guard.
#
# The beta branch and main independently added the account-management users
# router. Merging the two produced a duplicate `from .routers.users import
# router as users_router` AND a duplicate `app.include_router(users_router)`
# in core/api/main.py -- the exact "duplicate method/path registration
# introduced by a merge" class of defect. These tests fail if any APIRouter
# is wired into the app more than once, and pin the account router's
# admin gate and the auth endpoints so a future merge can't silently drop
# them.
# =============================================================================

from __future__ import annotations

import os

# core.api.main freezes several values as module constants at import time.
os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_JWT_SECRET", "test-secret-route-registration-0000")
os.environ.setdefault("S43_JWT_ALGORITHM", "HS256")

import core.api.main as main_module  # noqa: E402
from core.api.deps import require_admin  # noqa: E402
from core.api.routers.users import router as users_router  # noqa: E402


def _included_routers(app):
    """Every APIRouter object wired into `app` via include_router, in order.

    FastAPI >=0.14x represents an included router lazily as an
    `_IncludedRouter` route carrying `original_router`; older versions flatten
    the routes. Handle both.
    """
    found = []
    for route in app.routes:
        original = getattr(route, "original_router", None)
        if original is not None:
            found.append(original)
    return found


def test_no_apirouter_is_included_more_than_once():
    included = _included_routers(main_module.app)
    if not included:
        # Flattening FastAPI build -- fall back to (method, path) duplicate
        # detection over concrete routes.
        seen: dict[tuple, int] = {}
        for route in main_module.app.routes:
            path = getattr(route, "path", None)
            methods = getattr(route, "methods", None) or {"WS"}
            if path is None:
                continue
            for method in methods:
                seen[(method, path)] = seen.get((method, path), 0) + 1
        dupes = {k: v for k, v in seen.items() if v > 1}
        assert not dupes, f"duplicate (method, path) registrations: {dupes}"
        return

    counts: dict[int, int] = {}
    for router in included:
        counts[id(router)] = counts.get(id(router), 0) + 1
    duplicated = [rid for rid, n in counts.items() if n > 1]
    if duplicated:
        offenders = []
        for router in included:
            if id(router) in duplicated:
                paths = sorted({getattr(r, "path", "?") for r in router.routes})
                offenders.append(paths)
        raise AssertionError(
            f"{len(duplicated)} APIRouter(s) included more than once: {offenders}"
        )


def test_users_router_is_wired_and_admin_gated():
    included = _included_routers(main_module.app)
    if included:
        assert any(r is users_router for r in included), (
            "users_router is not wired into the app (account management "
            "endpoints would 404)"
        )

    # Router-level dependency: require_admin gates every /users route.
    dep_calls = [
        getattr(d, "dependency", None) for d in (users_router.dependencies or [])
    ]
    assert require_admin in dep_calls, (
        "users_router lost its router-level Depends(require_admin) gate"
    )

    paths = {r.path for r in users_router.routes}
    assert {"/users", "/users/{user_id}", "/users/{user_id}/password"} <= paths


def test_auth_endpoints_present():
    schema = main_module.app.openapi()
    paths = set(schema.get("paths", {}))
    for expected in ("/auth/login", "/auth/refresh", "/auth/logout"):
        assert expected in paths, f"{expected} missing from the OpenAPI schema"
