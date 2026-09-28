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

def test_v1_approve_is_refused_when_no_governance_backend_is_configured(
    client, staged_action
):
    """Missing required orchestration rejects the decision.

    This is the DEFAULT configuration (S43_GOVERNANCE_ENABLED is false), and
    it previously committed the approval with no governance evaluation and no
    durable audit of the decision.
    """
    assert main_module.runtime.orchestrator is None

    response = client.post(
        f"/v1/actions/{staged_action['id']}/approve",
        json={"operator_id": "v1-disposition-operator", "reason": "approved via v1 disposition test"},
        headers=_headers(),
    )
    assert response.status_code == 409, response.text
    assert "governance is not enabled" in response.text.lower()

    # The action is untouched -- not approved, still awaiting a decision.
    modern = client.get("/actions", headers=_headers())
    committed = next(a for a in modern.json() if a["id"] == staged_action["id"])
    assert committed["status"] == "STAGED"
    assert committed["operator"] == ""
    assert committed["decision_reason"] == ""


def test_v1_veto_is_refused_when_no_governance_backend_is_configured(
    client, staged_action
):
    assert main_module.runtime.orchestrator is None

    response = client.post(
        f"/v1/actions/{staged_action['id']}/veto",
        json={"operator_id": "v1-disposition-operator", "reason": "vetoed via v1 disposition test"},
        headers=_headers(),
    )
    assert response.status_code == 409, response.text

    modern = client.get("/actions", headers=_headers())
    committed = next(a for a in modern.json() if a["id"] == staged_action["id"])
    assert committed["status"] == "STAGED"


def test_the_modern_route_is_refused_on_the_same_terms(client, staged_action):
    """Proof that this is not a v1-only control: the modern route shares the
    one choke point and refuses identically, so there is no alternate route."""
    assert main_module.runtime.orchestrator is None

    response = client.post(
        f"/actions/{staged_action['id']}/approve",
        json={"reason": "approved via the modern route"},
        headers=_headers(),
    )
    assert response.status_code == 409, response.text

    modern = client.get("/actions", headers=_headers())
    committed = next(a for a in modern.json() if a["id"] == staged_action["id"])
    assert committed["status"] == "STAGED"


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


# ---------------------------------------------------------------------------
# Legitimate success through the REAL orchestration path
# ---------------------------------------------------------------------------
@pytest.fixture
def governed_action(monkeypatch):
    """A staged action backed by a genuine SystemOrchestrator pending review.

    Produced by the orchestrator's own producer (process_transaction), so the
    decision_id the route resolves is one governance actually issued.
    """
    import asyncio
    import tempfile
    from datetime import datetime, timezone as _tz
    from pathlib import Path

    from core.audit import AuditConfig, AuditStore
    from core.governance import build_orchestrator_from_settings
    from core.governance.orchestrator import CallerContext, DecisionStatus

    directory = Path(tempfile.mkdtemp(prefix="s43-v1-governed-"))
    audit = AuditStore(
        AuditConfig(sqlite_path=directory / "audit.sqlite3", signing_key="k" * 48)
    )
    audit.initialize()

    class Settings:
        default_mode = "HUMAN_GATED"
        velocity_window_seconds = 60.0
        velocity_limit = 10_000
        velocity_gc_interval_seconds = 300.0
        velocity_max_tracked_users = 10_000

    orchestrator = build_orchestrator_from_settings(Settings(), audit_store=audit)

    caller = CallerContext(
        caller_id="v1-governed-admin",
        caller_roles=frozenset({"admin"}),
        authenticated_at=datetime.now(_tz.utc),
    )
    decision = orchestrator.process_transaction(
        caller=caller,
        user_id="governed-user",
        amount_str="25.00",
        metadata={"source": "v1-disposition-test"},
        mode="HUMAN_GATED",
        risk_score="75",
    )
    assert decision.status is DecisionStatus.REVIEW, decision
    assert decision.decision_id

    action = main_module._create_synthetic_action()
    action["payload"]["decision_id"] = decision.decision_id
    stored = asyncio.run(main_module._store_action(action))

    monkeypatch.setattr(main_module.runtime, "orchestrator", orchestrator)
    yield stored, orchestrator, audit, decision.decision_id


def test_v1_approve_commits_through_the_real_governance_path(client, governed_action):
    """Now literally true: the decision_id was issued by the orchestrator and
    is resolved by it before the action store is touched."""
    action, orchestrator, audit, decision_id = governed_action

    response = client.post(
        f"/v1/actions/{action['id']}/approve",
        json={"operator_id": "ignored-by-design", "reason": "approved via v1 disposition test"},
        headers=_headers(),
    )
    assert response.status_code == 200, response.text
    assert response.json()["action"]["decision"] == "approved"

    modern = client.get("/actions", headers=_headers())
    committed = next(a for a in modern.json() if a["id"] == action["id"])
    assert committed["status"] == "APPROVED"

    # The decision really was consumed by governance, not merely committed.
    assert decision_id not in {
        review["decision_id"] for review in orchestrator.list_pending_reviews()
    }


def test_v1_veto_commits_through_the_real_governance_path(client, governed_action):
    action, orchestrator, audit, decision_id = governed_action

    response = client.post(
        f"/v1/actions/{action['id']}/veto",
        json={"operator_id": "ignored-by-design", "reason": "vetoed via v1 disposition test"},
        headers=_headers(),
    )
    assert response.status_code == 200, response.text
    assert response.json()["action"]["decision"] == "vetoed"


def test_v1_records_the_authenticated_subject_not_the_request_body(
    client, governed_action
):
    """The caller-supplied operator_id must not become the recorded decider."""
    action, orchestrator, audit, decision_id = governed_action

    response = client.post(
        f"/v1/actions/{action['id']}/approve",
        json={"operator_id": "somebody-else-entirely", "reason": "approved via v1 disposition test"},
        headers=_headers(),
    )
    assert response.status_code == 200, response.text

    modern = client.get("/actions", headers=_headers())
    committed = next(a for a in modern.json() if a["id"] == action["id"])
    assert committed["operator"] == "v1-disposition-operator"
    assert committed["operator"] != "somebody-else-entirely"


def test_a_second_decision_on_a_resolved_action_is_refused(client, governed_action):
    """Duplicate decisions fail safely rather than resolving twice."""
    action, orchestrator, audit, decision_id = governed_action

    first = client.post(
        f"/v1/actions/{action['id']}/approve",
        json={"operator_id": "ignored-by-design", "reason": "approved via v1 disposition test"},
        headers=_headers(),
    )
    assert first.status_code == 200, first.text

    second = client.post(
        f"/v1/actions/{action['id']}/approve",
        json={"operator_id": "ignored-by-design", "reason": "approved a second time"},
        headers=_headers(),
    )
    assert second.status_code == 409, second.text

    third = client.post(
        f"/v1/actions/{action['id']}/veto",
        json={"operator_id": "ignored-by-design", "reason": "flipping the decision"},
        headers=_headers(),
    )
    assert third.status_code == 409, third.text


def test_unauthenticated_and_service_callers_cannot_resolve(client, governed_action):
    """Unauthorized humans and service identities are rejected at the door."""
    action, orchestrator, audit, decision_id = governed_action

    unauthenticated = client.post(
        f"/v1/actions/{action['id']}/approve",
        json={"operator_id": "ignored-by-design", "reason": "no credential presented"},
    )
    assert unauthenticated.status_code in (401, 403), unauthenticated.text

    bad_token = {"Authorization": "Bearer not-a-real-token", "X-S43-Password": PASSWORD}
    forged = client.post(
        f"/v1/actions/{action['id']}/approve",
        json={"operator_id": "ignored-by-design", "reason": "forged credential"},
        headers=bad_token,
    )
    assert forged.status_code in (401, 403), forged.text

    modern = client.get("/actions", headers=_headers())
    committed = next(a for a in modern.json() if a["id"] == action["id"])
    assert committed["status"] == "STAGED"


# ---------------------------------------------------------------------------
# No alternate route: service-token Remote Gateway is not a human surface
# ---------------------------------------------------------------------------
def test_the_remote_gateway_has_no_approve_or_veto_capability():
    from core.api.routers import remote_gateway
    from core.api.routers.remote_gateway import RemoteEventType

    values = {event.value for event in RemoteEventType}
    assert "approve_decision" not in values
    assert "veto_decision" not in values

    # Human decisions are not merely unregistered; no dispatch registry entry
    # can name a capability that the gateway's public event vocabulary lacks.
    registered = {event.value for event in remote_gateway._dispatch_registry}
    assert "approve_decision" not in registered
    assert "veto_decision" not in registered
