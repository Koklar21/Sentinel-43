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
# =============================================================================
#
# core/tests/test_v1_legacy_disposition.py
#
# Post-merge baseline remediation, Section D.
#
# Baseline verification found every route under /v1/* (core/api/routers/
# routers.py) returning an unconditional 500 in any standard deployment,
# because they depended on a generic Engine/Store abstraction
# (core.api.deps.get_engine/get_store) that was never wired to a real
# backend anywhere in the tree -- SENTINEL_ENGINE_FACTORY/
# SENTINEL_STORE_FACTORY are declared nowhere, and no production
# implementation of either protocol exists.
#
# This file proves the actual disposition, with NEITHER S43_ENABLE_DEV_STORE
# NOR S43_ENABLE_DEV_ENGINE set -- the exact condition that 500'd before:
#
#   REPLACE (GET /v1/actions, POST /v1/actions/{id}/approve|veto):
#       wired directly to the same canonical in-memory action ledger and
#       human-gated governance-commit path the modern, working /actions
#       family already uses. A real staged action can be listed, approved,
#       and vetoed through /v1 with no dev-only environment variables set,
#       and the ledger v1 sees is the SAME ledger /actions sees.
#
#   DEPRECATE (POST /v1/assess):
#       an explicit, stable 501 Not Implemented -- never a crash, and
#       unaffected by S43_ENABLE_DEV_ENGINE (there is no Engine dependency
#       left on this route at all, so arming the old escape hatch changes
#       nothing).
# =============================================================================

from __future__ import annotations

import os

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_ENV", "test")
os.environ.setdefault("S43_JWT_SECRET", "test-secret-for-v1-disposition-tests")
os.environ.setdefault("S43_JWT_ALGORITHM", "HS256")
os.environ.setdefault("S43_JWT_ISSUER", "sentinel-43-v1-disposition-test")
os.environ.setdefault("S43_JWT_AUDIENCE", "sentinel-43-dashboard-v1-disposition-test")

import jwt  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import core.api.main as main_module  # noqa: E402
import core.api.routers.auth as auth_module  # noqa: E402
from core.api.main import app  # noqa: E402

JWT_SECRET = os.environ["S43_JWT_SECRET"]
JWT_ISSUER = os.environ["S43_JWT_ISSUER"]
JWT_AUDIENCE = os.environ["S43_JWT_AUDIENCE"]
PASSWORD = "v1-disposition-test-password"


def _token(role: str = "operator") -> str:
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": "v1-disposition-operator",
            "role": role,
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()) - 5,
            "exp": int(now.timestamp()) + 3600,
        },
        JWT_SECRET,
        algorithm="HS256",
    )


def _headers(role: str = "operator") -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_token(role)}",
        "X-S43-Password": PASSWORD,
    }


@pytest.fixture(autouse=True)
def _no_dev_escape_hatches(monkeypatch):
    """The exact condition that used to 500: neither escape hatch armed."""
    monkeypatch.setenv("SENTINEL_ENV", "test")
    monkeypatch.setenv("S43_JWT_SECRET", JWT_SECRET)
    monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("S43_JWT_ISSUER", JWT_ISSUER)
    monkeypatch.setenv("S43_JWT_AUDIENCE", JWT_AUDIENCE)
    monkeypatch.delenv("S43_ENABLE_DEV_STORE", raising=False)
    monkeypatch.delenv("S43_ENABLE_DEV_ENGINE", raising=False)

    async def _fake_reverify_password(username: str, password: str) -> bool:
        return bool(username) and password == PASSWORD

    monkeypatch.setattr(auth_module, "reverify_password", _fake_reverify_password)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def staged_action():
    """A real staged action in the SAME ledger GET /actions reads."""
    import asyncio

    action = asyncio.run(main_module._store_action(main_module._create_synthetic_action()))
    yield action


# ---------------------------------------------------------------------------
# DEPRECATE: /v1/assess
# ---------------------------------------------------------------------------

def test_v1_assess_is_a_stable_501_never_a_crash(client):
    response = client.post("/v1/assess", json={}, headers=_headers())
    assert response.status_code == 501
    assert response.json()["detail"]["error"]["code"] == "S43_V1_ASSESS_DEPRECATED"


def test_v1_assess_501_is_unaffected_by_the_old_dev_engine_escape_hatch(client, monkeypatch):
    monkeypatch.setenv("S43_ENABLE_DEV_ENGINE", "true")
    response = client.post("/v1/assess", json={}, headers=_headers())
    assert response.status_code == 501


# ---------------------------------------------------------------------------
# REPLACE: GET /v1/actions
# ---------------------------------------------------------------------------

def test_v1_actions_no_longer_500s_with_no_dev_store_configured(client):
    response = client.get("/v1/actions", headers=_headers())
    assert response.status_code == 200, response.text


def test_v1_actions_sees_the_same_ledger_as_the_modern_actions_route(client, staged_action):
    v1_response = client.get("/v1/actions", headers=_headers())
    modern_response = client.get("/actions", headers=_headers())

    assert v1_response.status_code == 200
    assert modern_response.status_code == 200

    v1_ids = {item["action_id"] for item in v1_response.json()["items"]}
    modern_ids = {item["id"] for item in modern_response.json()}
    assert staged_action["id"] in v1_ids
    assert staged_action["id"] in modern_ids


def test_v1_actions_maps_staged_to_pending_decision(client, staged_action):
    response = client.get("/v1/actions", headers=_headers())
    item = next(i for i in response.json()["items"] if i["action_id"] == staged_action["id"])
    assert item["decision"] == "pending"


# ---------------------------------------------------------------------------
# REPLACE: POST /v1/actions/{id}/approve and /veto
# ---------------------------------------------------------------------------

def test_v1_approve_commits_through_the_real_governance_path(client, staged_action):
    response = client.post(
        f"/v1/actions/{staged_action['id']}/approve",
        json={"operator_id": "v1-disposition-operator", "reason": "approved via v1 disposition test"},
        headers=_headers(),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["result"] is True
    assert body["action"]["decision"] == "approved"

    # The modern route sees the exact same committed state.
    modern = client.get("/actions", headers=_headers())
    committed = next(a for a in modern.json() if a["id"] == staged_action["id"])
    assert committed["status"] == "APPROVED"


def test_v1_veto_commits_through_the_real_governance_path(client, staged_action):
    response = client.post(
        f"/v1/actions/{staged_action['id']}/veto",
        json={"operator_id": "v1-disposition-operator", "reason": "vetoed via v1 disposition test"},
        headers=_headers(),
    )
    assert response.status_code == 200, response.text
    assert response.json()["action"]["decision"] == "vetoed"


def test_v1_approve_rejects_an_action_id_mismatch_without_touching_the_ledger(client, staged_action):
    response = client.post(
        f"/v1/actions/{staged_action['id']}/approve",
        json={
            "action_id": "a-completely-different-id",
            "operator_id": "v1-disposition-operator",
            "reason": "should never commit",
        },
        headers=_headers(),
    )
    assert response.status_code == 400

    modern = client.get("/actions", headers=_headers())
    committed = next(a for a in modern.json() if a["id"] == staged_action["id"])
    assert committed["status"] == "STAGED"


def test_v1_approve_of_an_unknown_action_is_404_not_500(client):
    response = client.post(
        "/v1/actions/ACT-DOES-NOT-EXIST/approve",
        json={"operator_id": "v1-disposition-operator", "reason": "no such action to approve"},
        headers=_headers(),
    )
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Auth / governance invariants are unchanged by the rewiring
# ---------------------------------------------------------------------------

def test_v1_actions_still_requires_operator_auth(client):
    response = client.get("/v1/actions")
    assert response.status_code == 401


def test_v1_approve_still_requires_operator_auth(client, staged_action):
    response = client.post(
        f"/v1/actions/{staged_action['id']}/approve",
        json={"operator_id": "nobody", "reason": "no auth supplied at all"},
    )
    assert response.status_code == 401
