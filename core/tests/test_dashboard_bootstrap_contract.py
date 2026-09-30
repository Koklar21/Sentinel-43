# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Dashboard first-run onboarding architectural contract.

These are deliberately narrow source-boundary guards. Backend bootstrap
semantics are tested with the bootstrap/auth suites; this file prevents the
dashboard from drifting back to a login-only UI or bypassing the governed
first-admin route.
"""

import ast
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
AUTH_JS = REPO_ROOT / "dashboard" / "assets" / "js" / "auth.js"
BOOTSTRAP_ROUTER = REPO_ROOT / "core" / "api" / "routers" / "bootstrap.py"


def test_dashboard_discovers_first_run_before_showing_login():
    source = AUTH_JS.read_text(encoding="utf-8")

    assert 'BOOTSTRAP_STATUS_ENDPOINT  = "/bootstrap/status"' in source
    assert "initialized = await fetchBootstrapStatus()" in source
    assert "if (!initialized.initialized)" in source
    assert "showBootstrapOverlay" in source


def test_dashboard_uses_the_canonical_bootstrap_and_login_paths():
    source = AUTH_JS.read_text(encoding="utf-8")

    assert 'BOOTSTRAP_ADMIN_ENDPOINT   = "/bootstrap/admin"' in source
    assert "await bootstrapFirstAdmin(username, password, email, claimToken)" in source
    # Account creation establishes identity; normal session creation still
    # happens through the existing login endpoint immediately afterward.
    assert "const result = await attemptLogin(username, password)" in source


def test_dashboard_fails_closed_when_bootstrap_state_is_unknown():
    source = AUTH_JS.read_text(encoding="utf-8")

    assert "Unable to determine Sentinel-43 initialization state." in source
    assert 'showOverlay(err.message || "Unable to determine initialization state.", true)' in source


def test_bootstrap_admin_route_remains_under_runtime_authority():
    source = BOOTSTRAP_ROUTER.read_text(encoding="utf-8")

    assert "get_runtime_authority" in source
    assert "authority.identity.bootstrap_first_admin" in source

    tree = ast.parse(source)
    calls = {
        node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, (ast.Attribute, ast.Name))
    }
    assert "bootstrap_first_admin" in calls
    assert "create_first_admin" not in calls
