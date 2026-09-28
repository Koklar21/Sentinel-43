# =============================================================================
# Sentinel-43 -- Heart restart-recovery regressions
#
# Permanent coverage (PR #292) for _rehydrate_heart_pending / _start_heart:
# pending Heart rows are exposed for a human decision only when the
# authenticated audit ledger backs them; everything else is quarantined or
# blocks readiness. Approve/veto go through the real authenticated routes.
#
# Real audit store, real core store, real ThreatGovernor, real FastAPI app in
# disposable temp storage. No network, no skips.
# =============================================================================
from __future__ import annotations

import os
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import jwt
import pytest

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_ENV", "test")
os.environ.setdefault("S43_JWT_SECRET", "test-secret-for-heart-recovery-tests")
os.environ.setdefault("S43_JWT_ALGORITHM", "HS256")

from fastapi.testclient import TestClient  # noqa: E402

import core.api.main as main_module  # noqa: E402
import core.api.routers.auth as auth_module  # noqa: E402
from core.audit import AuditConfig, AuditStore  # noqa: E402
from core.detection.sentinel_threat_types import (  # noqa: E402
    ThreatAssessment,
    ThreatKind,
    ThreatSeverity,
    ThreatSourceKind,
)
from core.governance import (  # noqa: E402
    DecisionPrincipal,
    UnauthorizedDecision,
    build_heart_from_settings,
    build_runtime_authority_from_settings,
)
from core.security_context import IdentityType  # noqa: E402
from core.sentinel43_core_db import (  # noqa: E402
    ActionStatus,
    CoreStoreConfig,
    IncidentStatus,
    PendingAction,
    SentinelCoreStore,
)

JWT_SECRET = "test-secret-for-heart-recovery-tests"
JWT_ISSUER = "sentinel-43-test"
JWT_AUDIENCE = "sentinel-43-dashboard-test"
PASSWORD = "heart-recovery-test-password"


async def _fake_reverify_password(username: str, password: str) -> bool:
    return bool(username) and password == PASSWORD


@pytest.fixture(autouse=True)
def _auth_env(monkeypatch):
    monkeypatch.setenv("S43_JWT_SECRET", JWT_SECRET)
    monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("S43_JWT_ISSUER", JWT_ISSUER)
    monkeypatch.setenv("S43_JWT_AUDIENCE", JWT_AUDIENCE)
    monkeypatch.setenv("S43_REJECT_LEGACY_AUTH", "false")
    monkeypatch.setattr(auth_module, "reverify_password", _fake_reverify_password)
    runtime = main_module.runtime
    monkeypatch.setattr(runtime, "action_store", {})
    monkeypatch.setattr(runtime, "heart", None)
    monkeypatch.setattr(runtime, "audit_store", None)
    monkeypatch.setattr(runtime, "fenrir_instance", None)
    monkeypatch.setattr(runtime, "orchestrator", None)
    monkeypatch.setattr(runtime, "sentinel43", None)
    yield
    # Never leave a failed Heart behind for tests that share the process.
    runtime.subsystems.mark_disabled(main_module.SUBSYS_HEART)


@pytest.fixture(scope="module")
def client():
    with TestClient(main_module.app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _stack():
    directory = Path(tempfile.mkdtemp(prefix="s43-heart-recovery-"))
    audit = AuditStore(
        AuditConfig(sqlite_path=directory / "audit.sqlite3", signing_key="k" * 48)
    )
    audit.initialize()
    core = SentinelCoreStore(CoreStoreConfig(db_path=directory / "heart.sqlite3"))
    core.initialize()

    class Settings:
        default_mode = "HUMAN_GATED"
        velocity_window_seconds = 60
        velocity_limit = 100_000
        dedupe_ttl_seconds = 300
        corroboration_window_seconds = 300
        corroboration_min_signals_for_high = 2

    heart = build_heart_from_settings(
        Settings(),
        audit_store=audit,
        core_store=core,
        authority=_authority(audit),
        operator_authenticator=main_module._heart_operator_authenticator,
    )
    return directory, audit, core, heart


def _authority(audit, mode: str = "HUMAN_GATED"):
    """The Sentinel-43 runtime authority every Heart decision goes through."""

    class GovernanceSettings:
        default_mode = mode

    return build_runtime_authority_from_settings(
        GovernanceSettings(),
        audit_store=audit,
    )


#: The actions the engine's OWN policy produces for the assessment _stage
#: submits -- no plan is patched anywhere in this helper.
APPROVABLE_PLAN = ["RATE_LIMIT", "REQUIRE_HUMAN_REVIEW"]


def _stage(heart, ip: str, *, severity=ThreatSeverity.HIGH, score: float = 50.0):
    """Stage a recommendation the REAL engine plans, approvable as a whole.

    Severity HIGH below the engine's high_threshold (65), from a source that
    is not automation-likely, for a threat kind that is neither a credential
    attack nor a generic intrusion: the engine's own _build_mid_high then
    plans RATE_LIMIT + REQUIRE_HUMAN_REVIEW -- throttling, which the policy
    vocabulary states exactly, plus the review this staging already is.

    Planning, staging, dedupe, approval and veto all run the engine's code.
    """
    decision = heart.observe(
        ThreatAssessment(
            identity="anonymous",
            source_ip=ip,
            threat_kind=ThreatKind.DATA_EXFILTRATION,
            severity=severity,
            source_kind=ThreatSourceKind.MIXED_OR_UNKNOWN,
            score=score,
            indicators={"evidence_seq": 1, "evidence_sources": ["firewall", "sparta"]},
            supporting_tags=["t"],
            window_size=5,
        )
    )
    assert decision.status == "STAGED" and decision.action_id, decision
    return decision.action_id


def _stage_planned(heart, ip: str, actions: list[str]):
    """Stage a recommendation whose plan is fixed to ``actions``.

    Only for action combinations the engine's current policy cannot produce
    on its own (see test_reachable_engine_plans). The directive is built from
    the engine's own ResponseDirective/ResponseAction types, and staging,
    approval and veto still run through the engine's code.
    """
    engine = heart._authority._engine
    module = engine.module
    original = engine.plan

    def fixed_plan(assessment):
        plan = original(assessment)
        base = plan["directive"]
        directive = module.ResponseDirective(
            identity=base.identity,
            source_ip=base.source_ip,
            primary_action=module.ResponseAction[actions[0]],
            additional_actions=[module.ResponseAction[name] for name in actions[1:]],
            reason=base.reason,
            expires_at=base.expires_at,
            threat_kind=base.threat_kind,
            threat_severity=base.threat_severity,
            source_kind=base.source_kind,
            score=base.score,
        )
        return {
            "directive": directive,
            "actions": list(actions),
            "summary": {
                **plan["summary"],
                "primary_action": actions[0],
                "actions": list(actions),
            },
        }

    engine.plan = fixed_plan
    try:
        decision = heart.observe(
            ThreatAssessment(
                identity="anonymous",
                source_ip=ip,
                threat_kind=ThreatKind.DATA_EXFILTRATION,
                severity=ThreatSeverity.CRITICAL,
                source_kind=ThreatSourceKind.MIXED_OR_UNKNOWN,
                score=90.0,
                indicators={"evidence_seq": 1, "evidence_sources": ["firewall", "sparta"]},
                supporting_tags=["t"],
                window_size=5,
            )
        )
    finally:
        del engine.plan
    assert decision.status == "STAGED" and decision.action_id, decision
    return decision.action_id


def _raw_row(core, action_id: str, *, target="anonymous|198.51.100.1", kind="x") -> None:
    core.insert_pending(
        PendingAction(
            action_id=action_id,
            created_at_ms=int(time.time() * 1000),
            status=ActionStatus.PENDING,
            target_type="identity_source_ip",
            target_value=target,
            primary_action="human_review",
            actions=("review",),
            severity="HIGH",
            kind=kind,
            source_kind="MIXED_OR_UNKNOWN",
            score=80.0,
            reason="r",
            system_id="heart",
        )
    )


def _sql_at(core, action_id: str, created_at_ms: int) -> None:
    """Move one recorded action's timestamp, to test a window boundary."""
    connection = sqlite3.connect(core._config.db_path)
    try:
        connection.execute(
            "UPDATE pending_actions SET created_at_ms=? WHERE action_id=?",
            (created_at_ms, action_id),
        )
        connection.commit()
    finally:
        connection.close()


def _sql(directory: Path, statement: str, params: tuple = ()) -> None:
    connection = sqlite3.connect(directory / "heart.sqlite3")
    try:
        connection.execute(statement, params)
        connection.commit()
    finally:
        connection.close()


def _headers(subject: str = "heart-op") -> dict[str, str]:
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": subject,
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()) - 5,
            "exp": int(now.timestamp()) + 3600,
            "role": "operator",
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}", "X-S43-Password": PASSWORD}


def _principal(
    subject: str = "heart-op",
    identity: IdentityType = IdentityType.OPERATOR,
) -> DecisionPrincipal:
    """The trusted context the request pipeline would have recorded."""
    return DecisionPrincipal(
        subject=subject,
        identity_type=identity.value,
        is_human=identity.is_human,
    )


def _recover(client) -> int:
    return client.portal.call(main_module._rehydrate_heart_pending)


def _use(heart) -> None:
    main_module.runtime.heart = heart
    main_module.runtime.sentinel43 = heart._authority
    main_module.runtime.orchestrator = heart._authority.orchestrator
    main_module.runtime.action_store.clear()


def _start_production_governance(client, monkeypatch, audit) -> None:
    """Run the real _start_governance, as the app lifespan does."""
    monkeypatch.setenv("S43_GOVERNANCE_ENABLED", "true")
    main_module.runtime.audit_store = audit
    client.portal.call(main_module._start_governance)
    assert main_module.runtime.orchestrator is not None


# ---------------------------------------------------------------------------
# Valid recovery, then authenticated human decisions
# ---------------------------------------------------------------------------
def test_valid_staged_rows_are_recovered_and_visible(client):
    _, _, _, heart = _stack()
    action_id = _stage(heart, "203.0.113.9")
    _use(heart)

    assert _recover(client) == 1
    action = main_module.runtime.action_store[action_id]
    assert action["action_type"] == "HEART_RECOMMENDATION"
    assert action["status"] == "STAGED"
    assert action["payload"]["source_ip"] == "203.0.113.9"
    assert action["payload"]["rehydrated"] is True

    listed = client.get("/actions", headers=_headers())
    assert listed.status_code == 200
    assert action_id in listed.text


def test_approve_after_recovery_requires_authentication_and_audits(client):
    _, audit, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.9")
    _use(heart)
    assert _recover(client) == 1

    unauthenticated = client.post(f"/actions/{action_id}/approve", json={"reason": "reviewed by operator"})
    assert unauthenticated.status_code in (401, 403)
    assert core.get_status(action_id) == ActionStatus.PENDING

    response = client.post(f"/actions/{action_id}/approve", headers=_headers(), json={"reason": "reviewed by operator"})
    assert response.status_code == 200, response.text
    assert core.get_status(action_id) == ActionStatus.APPROVED
    records = audit.get_records(component="heart", correlation_id=action_id)
    assert [r["decision"] for r in records] == ["STAGED", "APPROVED"]


def test_veto_after_recovery(client):
    _, audit, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.10")
    _use(heart)
    assert _recover(client) == 1

    response = client.post(f"/actions/{action_id}/veto", headers=_headers(), json={"reason": "not a real threat"})
    assert response.status_code == 200, response.text
    assert core.get_status(action_id) == ActionStatus.VETOED
    records = audit.get_records(component="heart", correlation_id=action_id)
    assert [r["decision"] for r in records] == ["STAGED", "VETOED"]


def test_double_resolution_is_rejected_and_terminal_rows_never_return(client):
    _, _, core, heart = _stack()
    approved = _stage(heart, "203.0.113.11")
    vetoed = _stage(heart, "203.0.113.12")
    _use(heart)
    assert _recover(client) == 2

    assert client.post(f"/actions/{approved}/approve", headers=_headers(), json={"reason": "reviewed by operator"}).status_code == 200
    assert client.post(f"/actions/{approved}/approve", headers=_headers(), json={"reason": "second attempt here"}).status_code == 409
    assert client.post(f"/actions/{approved}/veto", headers=_headers(), json={"reason": "flip the decision"}).status_code == 409
    assert client.post(f"/actions/{vetoed}/veto", headers=_headers(), json={"reason": "not a real threat"}).status_code == 200
    with pytest.raises(RuntimeError):
        heart.resolve_human_decision(
            vetoed,
            approved=True,
            operator_id="heart-op",
            reason="try again please",
            principal=_principal(),
        )

    # A second restart must not resurrect terminal actions.
    main_module.runtime.action_store.clear()
    assert _recover(client) == 0
    assert main_module.runtime.action_store == {}


# ---------------------------------------------------------------------------
# Quarantine: unaudited / mismatched / already-decided rows never become actionable
# ---------------------------------------------------------------------------
def test_unaudited_row_is_quarantined_and_cannot_be_decided(client):
    _, audit, core, heart = _stack()
    good = _stage(heart, "203.0.113.20")
    _raw_row(core, "HEART-NOAUDIT0001")  # crash window: inserted, never audited
    _use(heart)

    assert _recover(client) == 1
    assert set(main_module.runtime.action_store) == {good}
    assert core.get_status("HEART-NOAUDIT0001") == ActionStatus.EXPIRED
    assert audit.get_records(component="heart", correlation_id="HEART-NOAUDIT0001") == [], (
        "recovery must never fabricate an audit record"
    )
    with pytest.raises(RuntimeError):
        heart.resolve_human_decision(
            "HEART-NOAUDIT0001",
            approved=True,
            operator_id="heart-op",
            reason="try to approve",
            principal=_principal(),
        )
    assert client.post("/actions/HEART-NOAUDIT0001/approve", headers=_headers(), json={"reason": "reviewed by operator"}).status_code == 404


@pytest.mark.parametrize(
    "column,value",
    [
        ("severity", "CRITICAL"),
        ("source_kind", "HUMAN_LIKELY"),
        ("kind", "different_kind"),
        ("target_value", "anonymous|203.0.113.99"),
        ("score", 1.0),
    ],
)
def test_row_contents_that_disagree_with_the_audit_are_quarantined(client, column, value):
    directory, audit, core, heart = _stack()
    good = _stage(heart, "203.0.113.30")
    tampered = _stage(heart, "203.0.113.31")
    _sql(directory, f"UPDATE pending_actions SET {column}=? WHERE action_id=?", (value, tampered))
    _use(heart)

    assert _recover(client) == 1
    assert set(main_module.runtime.action_store) == {good}
    assert core.get_status(tampered) == ActionStatus.EXPIRED
    assert len(audit.get_records(component="heart", correlation_id=tampered)) == 1


def test_row_with_an_audited_terminal_decision_is_quarantined(client):
    _, audit, core, heart = _stack()
    decided = _stage(heart, "203.0.113.40")
    audit.append(
        {
            "subsystem": "heart",
            "component": "heart",
            "correlation_id": decided,
            "decision_id": decided,
            "decision": "VETOED",
            "reason_code": "HUMAN_VETOED",
        }
    )
    _use(heart)

    assert _recover(client) == 0
    assert core.get_status(decided) == ActionStatus.EXPIRED
    assert main_module.runtime.action_store == {}


# ---------------------------------------------------------------------------
# Fail-closed: malformed rows, overflow, store limit, conflicting duplicates
# ---------------------------------------------------------------------------
def test_malformed_row_blocks_recovery_and_exposes_nothing(client):
    directory, _, core, heart = _stack()
    _stage(heart, "203.0.113.50")
    _raw_row(core, "HEART-BADROW000001")
    _sql(directory, "UPDATE pending_actions SET created_at_ms='garbage' WHERE action_id='HEART-BADROW000001'")
    _use(heart)

    with pytest.raises(main_module.HeartRecoveryError, match="malformed"):
        _recover(client)
    assert main_module.runtime.action_store == {}


def test_malformed_target_blocks_recovery(client):
    directory, _, core, heart = _stack()
    _raw_row(core, "HEART-BADROW000002")
    _sql(directory, "UPDATE pending_actions SET target_value='no-separator' WHERE action_id='HEART-BADROW000002'")
    _use(heart)

    with pytest.raises(main_module.HeartRecoveryError, match="malformed"):
        _recover(client)


def test_more_pending_rows_than_one_page_blocks_recovery(client):
    directory, _, _, heart = _stack()
    now = int(time.time() * 1000)
    rows = [
        (f"HEART-OVF{i:08d}", now, "PENDING", "identity_source_ip", "anonymous|10.0.0.1",
         "human_review", '["review"]', "HIGH", "k", "MIXED_OR_UNKNOWN", 1.0, "r", "heart", None, None, None)
        for i in range(main_module._HEART_RECOVERY_PAGE)
    ]
    connection = sqlite3.connect(directory / "heart.sqlite3")
    try:
        connection.executemany(
            "INSERT INTO pending_actions (action_id,created_at_ms,status,target_type,target_value,"
            "primary_action,actions_json,severity,kind,source_kind,score,reason,system_id,"
            "execute_at_ms,operator_id,operator_reason) VALUES (" + ",".join("?" * 16) + ")",
            rows,
        )
        connection.commit()
    finally:
        connection.close()
    _use(heart)

    with pytest.raises(main_module.HeartRecoveryError, match="cannot enumerate"):
        _recover(client)
    assert main_module.runtime.action_store == {}


def test_recovery_that_would_evict_live_actions_blocks(client, monkeypatch):
    _, _, _, heart = _stack()
    _stage(heart, "203.0.113.60")
    _stage(heart, "203.0.113.61")
    _use(heart)
    monkeypatch.setattr(main_module, "MAX_DASHBOARD_ACTIONS", 1)

    with pytest.raises(main_module.HeartRecoveryError, match="limit"):
        _recover(client)
    assert main_module.runtime.action_store == {}


def test_equivalent_duplicate_is_skipped_but_conflicting_duplicate_fails(client):
    _, _, _, heart = _stack()
    action_id = _stage(heart, "203.0.113.70")
    _use(heart)

    assert _recover(client) == 1
    assert _recover(client) == 0  # verified-equivalent duplicate
    main_module.runtime.action_store[action_id]["payload"]["identity"] = "someone-else"
    with pytest.raises(main_module.HeartRecoveryError, match="different contents"):
        _recover(client)


def test_unexpected_store_errors_propagate(client, monkeypatch):
    _, _, _, heart = _stack()
    _stage(heart, "203.0.113.71")
    _use(heart)

    async def _boom(_record):
        raise RuntimeError("store exploded")

    monkeypatch.setattr(main_module, "_store_action", _boom)
    with pytest.raises(RuntimeError, match="store exploded"):
        _recover(client)


# ---------------------------------------------------------------------------
# Readiness fails closed while liveness stays available
# ---------------------------------------------------------------------------
def test_failed_recovery_blocks_readiness_but_not_liveness(monkeypatch):
    directory, audit, core, heart = _stack()
    _raw_row(core, "HEART-BADROW000003")
    _sql(directory, "UPDATE pending_actions SET target_value='no-separator' WHERE action_id='HEART-BADROW000003'")
    monkeypatch.setenv("S43_HEART_ENABLED", "true")
    monkeypatch.setenv("S43_HEART_REQUIRED", "true")
    # Valid configuration: an enabled Heart always declares its authority
    # (see test_heart_governance_invariant.py), and governance requires the
    # keyed authoritative audit ledger. What fails here is at RUNTIME.
    monkeypatch.setenv("S43_GOVERNANCE_ENABLED", "true")
    monkeypatch.setenv("S43_AUDIT_HMAC_KEY", "a" * 64)
    monkeypatch.setenv("S43_HEART_SQLITE_PATH", str(directory / "heart.sqlite3"))

    with TestClient(main_module.app) as test_client:
        _start_production_governance(test_client, monkeypatch, audit)
        test_client.portal.call(main_module._start_heart)

        assert main_module.runtime.heart is None
        ready = test_client.get("/ready")
        live = test_client.get("/health")
        assert ready.status_code == 503, ready.text
        assert "heart" in ready.text
        assert live.status_code == 200

        # Once the corrupt row is resolved, restarting Heart restores readiness.
        _sql(directory, "UPDATE pending_actions SET status='EXPIRED' WHERE action_id='HEART-BADROW000003'")
        test_client.portal.call(main_module._start_heart)
        assert main_module.runtime.heart is not None
        assert test_client.get("/ready").status_code == 200


# ---------------------------------------------------------------------------
# Recovery / live-ingestion race protection
# ---------------------------------------------------------------------------
def test_heart_attaches_to_authority_only_after_recovery_completes(monkeypatch):
    directory, audit, _, _ = _stack()
    monkeypatch.setenv("S43_HEART_REQUIRED", "true")
    monkeypatch.setenv("S43_AUDIT_HMAC_KEY", "a" * 64)
    monkeypatch.setenv("S43_HEART_SQLITE_PATH", str(directory / "heart.sqlite3"))

    seen_during_recovery: list = []

    async def _recording_recovery() -> int:
        authority = main_module.runtime.sentinel43
        seen_during_recovery.append(
            None if authority is None else authority.heart
        )
        return 0

    monkeypatch.setattr(main_module, "_rehydrate_heart_pending", _recording_recovery)

    with TestClient(main_module.app) as test_client:
        monkeypatch.setenv("S43_HEART_ENABLED", "true")
        _start_production_governance(test_client, monkeypatch, audit)
        test_client.portal.call(main_module._start_heart)

        assert seen_during_recovery == [main_module.runtime.heart]
        assert main_module.runtime.sentinel43 is not None
        assert (
            main_module.runtime.sentinel43.heart
            is main_module.runtime.heart
            is not None
        )


# ---------------------------------------------------------------------------
# Kernel-level authorization (restored historical operator_authenticator)
# ---------------------------------------------------------------------------
def test_kernel_denies_a_service_identity_that_passed_transport_auth(client):
    """A valid operator JWT whose subject is a SERVICE identity is rejected by
    the governance kernel, not merely by the transport layer."""
    _, audit, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.80")
    _use(heart)
    assert _recover(client) == 1

    response = client.post(
        f"/actions/{action_id}/approve",
        headers=_headers("service:watchtower"),
        json={"reason": "service trying to self-approve"},
    )
    assert response.status_code == 403, response.text
    assert core.get_status(action_id) == ActionStatus.PENDING

    records = audit.get_records(component="heart", correlation_id=action_id)
    assert [r["decision"] for r in records] == ["STAGED", "DENIED"]
    assert records[-1]["reason_code"] == "UNAUTHORIZED_DECISION_ATTEMPT"
    assert records[-1]["operator_id"] == "service:watchtower"


@pytest.mark.parametrize(
    "identity",
    [
        "service:sentinel-api",
        "service:watchtower",
        "service:fenrir",
        "service:sparta-node",
        "service:remote-gateway",
        "anonymous",
        "   ",
    ],
)
def test_no_service_or_anonymous_identity_can_resolve(identity):
    _, _, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.81")

    with pytest.raises((UnauthorizedDecision, ValueError)):
        heart.resolve_human_decision(
            action_id,
            approved=True,
            operator_id=identity,
            reason="attempted resolve",
            principal=_principal(subject=identity),
        )
    assert core.get_status(action_id) == ActionStatus.PENDING


def test_a_human_operator_is_still_authorized():
    _, _, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.82")

    heart.resolve_human_decision(
        action_id,
        approved=True,
        operator_id="heart-op",
        reason="legitimate approval",
        principal=_principal(),
    )
    assert core.get_status(action_id) == ActionStatus.APPROVED


def test_kernel_fails_closed_when_no_authenticator_is_injected(tmp_path):
    """The historical default was `lambda _op: False`; an unconfigured kernel
    must authorize nothing rather than trusting its caller."""
    audit = AuditStore(
        AuditConfig(sqlite_path=tmp_path / "audit.sqlite3", signing_key="k" * 48)
    )
    audit.initialize()
    core = SentinelCoreStore(CoreStoreConfig(db_path=tmp_path / "heart.sqlite3"))
    core.initialize()

    class Settings:
        default_mode = "HUMAN_GATED"
        velocity_window_seconds = 60
        velocity_limit = 100_000
        dedupe_ttl_seconds = 300
        corroboration_window_seconds = 300
        corroboration_min_signals_for_high = 2

    heart = build_heart_from_settings(
        Settings(),
        audit_store=audit,
        core_store=core,
        authority=_authority(audit),
    )  # no operator_authenticator
    action_id = _stage(heart, "203.0.113.83")

    with pytest.raises(UnauthorizedDecision):
        heart.resolve_human_decision(
            action_id,
            approved=True,
            operator_id="heart-op",
            reason="should be denied",
            principal=_principal(),
        )
    assert core.get_status(action_id) == ActionStatus.PENDING


def test_denied_attempts_do_not_quarantine_a_legitimate_action(client):
    """A rejected decision is audited against the same correlation id; that
    must not make the row look inconsistent to restart recovery."""
    _, _, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.84")

    for _ in range(12):
        with pytest.raises(UnauthorizedDecision):
            heart.resolve_human_decision(
                action_id,
                approved=True,
                operator_id="service:fenrir",
                reason="repeated denied attempt",
                principal=_principal(subject="service:fenrir"),
            )

    _use(heart)
    assert _recover(client) == 1
    assert action_id in main_module.runtime.action_store
    assert core.get_status(action_id) == ActionStatus.PENDING

    response = client.post(
        f"/actions/{action_id}/approve",
        headers=_headers(),
        json={"reason": "legitimate approval after denials"},
    )
    assert response.status_code == 200, response.text
    assert core.get_status(action_id) == ActionStatus.APPROVED


# ---------------------------------------------------------------------------
# The kernel decides from trusted context, not the caller's operator string
# ---------------------------------------------------------------------------
def test_absent_authentication_context_is_denied():
    """No principal at all must deny, whatever operator_id is supplied."""
    _, audit, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.90")

    with pytest.raises(UnauthorizedDecision):
        heart.resolve_human_decision(
            action_id,
            approved=True,
            operator_id="heart-op",
            reason="no context supplied",
        )
    assert core.get_status(action_id) == ActionStatus.PENDING
    records = audit.get_records(component="heart", correlation_id=action_id)
    assert records[-1]["reason_code"] == "NO_AUTHENTICATION_CONTEXT"


def test_operator_id_must_be_the_authenticated_subject():
    """An authenticated human cannot record the decision under someone else."""
    _, audit, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.91")

    with pytest.raises(UnauthorizedDecision):
        heart.resolve_human_decision(
            action_id,
            approved=True,
            operator_id="someone-else",
            reason="impersonation attempt",
            principal=_principal(subject="heart-op"),
        )
    assert core.get_status(action_id) == ActionStatus.PENDING
    records = audit.get_records(component="heart", correlation_id=action_id)
    assert (
        records[-1]["reason_code"]
        == "OPERATOR_ID_DOES_NOT_MATCH_AUTHENTICATED_SUBJECT"
    )


@pytest.mark.parametrize(
    "identity",
    [
        IdentityType.SERVICE_API,
        IdentityType.SERVICE_WATCHTOWER,
        IdentityType.SERVICE_FENRIR,
        IdentityType.SERVICE_SPARTA_NODE,
        IdentityType.SERVICE_REMOTE_GATEWAY,
        IdentityType.ANONYMOUS,
    ],
)
def test_non_human_authenticated_context_is_denied(identity):
    """Even with a matching subject, a non-human identity cannot decide."""
    _, _, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.92")

    with pytest.raises(UnauthorizedDecision):
        heart.resolve_human_decision(
            action_id,
            approved=True,
            operator_id="svc",
            reason="service attempting a decision",
            principal=DecisionPrincipal(
                subject="svc",
                identity_type=identity.value,
                is_human=identity.is_human,
            ),
        )
    assert core.get_status(action_id) == ActionStatus.PENDING


def test_audit_failure_during_a_decision_fails_safe(monkeypatch):
    """If the decision cannot be audited it must not be reported as made."""
    _, audit, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.93")

    def _explode(_payload):
        raise RuntimeError("ledger unavailable")

    monkeypatch.setattr(heart.audit_store, "append", _explode)

    with pytest.raises(RuntimeError, match="ledger unavailable"):
        heart.resolve_human_decision(
            action_id,
            approved=True,
            operator_id="heart-op",
            reason="audit will fail",
            principal=_principal(),
        )

    # Compensated back to PENDING rather than left in an unaudited terminal
    # state a second attempt would find already resolved.
    assert core.get_status(action_id) == ActionStatus.PENDING


def test_concurrent_decisions_resolve_exactly_once():
    """Two racing approvals: one wins, the other is refused."""
    import threading

    _, _, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.94")

    outcomes: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(6)

    def attempt() -> None:
        barrier.wait()
        try:
            heart.resolve_human_decision(
                action_id,
                approved=True,
                operator_id="heart-op",
                reason="concurrent approval attempt",
                principal=_principal(),
            )
            result = "ok"
        except Exception as exc:  # noqa: BLE001 - recording the outcome
            result = type(exc).__name__
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=attempt) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert outcomes.count("ok") == 1, outcomes
    assert core.get_status(action_id) == ActionStatus.APPROVED


# ---------------------------------------------------------------------------
# Governance through the established policy authority (core.policy_gate),
# exercised through the PRODUCTION composition, not a test-built component.
# ---------------------------------------------------------------------------
def _start_production_heart(client, monkeypatch, directory: Path, audit):
    """Compose Heart first, then bind a real Fenrir to the runtime authority."""
    import core.detection.feniri_hunter as fenrir_module

    monkeypatch.setenv("S43_HEART_ENABLED", "true")
    monkeypatch.setenv("S43_GOVERNANCE_ENABLED", "true")
    monkeypatch.setenv("S43_AUDIT_HMAC_KEY", "a" * 64)
    monkeypatch.setenv("S43_HEART_SQLITE_PATH", str(directory / "heart.sqlite3"))
    _start_production_governance(client, monkeypatch, audit)
    client.portal.call(main_module._start_heart)

    assert main_module.runtime.heart is not None
    assert main_module.runtime.sentinel43 is not None
    assert main_module.runtime.sentinel43.heart is main_module.runtime.heart

    fenrir = fenrir_module.FenrirHunter(
        authority=main_module.runtime.sentinel43
    )
    return fenrir


def _feed_two_trusted_producers(fenrir, ip: str) -> None:
    import uuid as _uuid

    from core.detection.sentinel_threat_detector import EventContext

    for producer in ("firewall", "sparta"):
        for _ in range(40):
            fenrir.detector.ingest(
                EventContext(
                    source_identity="anonymous",
                    source_ip=ip,
                    event_type="firewall_block",
                    success=False,
                    metadata={
                        "trusted_producer": producer,
                        "event_id": str(_uuid.uuid4()),
                    },
                )
            )


def test_production_staging_is_decided_by_the_policy_authority(client, monkeypatch):
    directory, audit, _, _ = _stack()
    fenrir = _start_production_heart(client, monkeypatch, directory, audit)
    _feed_two_trusted_producers(fenrir, "203.0.113.120")

    client.portal.call(fenrir.observe_signals)

    staged = [
        r for r in audit.get_records(component="heart", limit=500)
        if r.get("decision") == "STAGED"
    ]
    assert len(staged) == 1, staged
    # The orchestration engine made this decision, and says so.
    assert staged[0]["engine"]["class"] == "Sentinel43ResponseEngine"
    assert staged[0]["engine"]["path"] == "Sentinel-43/Shadow_mode.py"
    assert staged[0]["engine_plan"]["actions"]
    for policy in staged[0]["policy"]:
        assert policy["status"] == "REQUIRES_HUMAN"
        assert policy["mode"] == "HUMAN_GATED"
        assert policy["human_approved"] is False

    # ...and that staged recommendation is the one the canonical surface shows.
    action_id = staged[0]["decision_id"]
    assert main_module.runtime.action_store[action_id]["action_type"] == (
        "HEART_RECOMMENDATION"
    )


def test_production_recommendation_states_why_it_cannot_be_approved(client, monkeypatch):
    """Through the production composition, the real engine's plan for real
    detector evidence includes operations the policy vocabulary cannot state.
    It is preserved, marked unavailable-for-approval with exact reasons, and
    remains vetoable."""
    directory, audit, _, _ = _stack()
    fenrir = _start_production_heart(client, monkeypatch, directory, audit)
    _feed_two_trusted_producers(fenrir, "203.0.113.121")
    client.portal.call(fenrir.observe_signals)
    staged = next(
        r for r in audit.get_records(component="heart", limit=500)
        if r.get("decision") == "STAGED"
    )
    action_id = staged["decision_id"]
    approval = staged["recommendation"]["approval"]
    assert approval["available"] is False and approval["reasons"]

    shown = main_module.runtime.action_store[action_id]["payload"]["approval"]
    assert shown == approval

    response = client.post(
        f"/actions/{action_id}/approve",
        headers=_headers(),
        json={"reason": "reviewed by operator"},
    )
    assert response.status_code == 409, response.text
    assert "approval is unavailable" in response.text

    veto = client.post(
        f"/actions/{action_id}/veto",
        headers=_headers(),
        json={"reason": "declining the recommendation"},
    )
    assert veto.status_code == 200, veto.text
    vetoed = audit.get_records(component="heart", correlation_id=action_id)[-1]
    assert vetoed["decided_by"] == "Sentinel43ResponseEngine.veto_action"


def test_shadow_observation_is_decided_by_the_policy_authority():
    directory, audit, core, _ = _stack()

    class Settings:
        default_mode = "SHADOW"
        velocity_window_seconds = 60
        velocity_limit = 100_000
        dedupe_ttl_seconds = 300
        corroboration_window_seconds = 300
        corroboration_min_signals_for_high = 2

    heart = build_heart_from_settings(
        Settings(),
        audit_store=audit,
        core_store=core,
        authority=_authority(audit),
        operator_authenticator=main_module._heart_operator_authenticator,
    )
    decision = heart.observe(
        ThreatAssessment(
            identity="anonymous",
            source_ip="203.0.113.122",
            threat_kind=list(ThreatKind)[0],
            severity=ThreatSeverity.HIGH,
            source_kind=ThreatSourceKind.AI_AUTOMATION_LIKELY,
            score=80.0,
            indicators={"evidence_seq": 1, "evidence_sources": ["firewall", "sparta"]},
            supporting_tags=["t"],
            window_size=5,
        )
    )
    assert decision.reason == "POLICY_OBSERVED"
    observed = [
        r for r in audit.get_records(component="heart", limit=500)
        if r.get("reason_code") == "POLICY_OBSERVED"
    ]
    assert observed and observed[-1]["policy"]
    assert all(p["status"] == "OBSERVE" for p in observed[-1]["policy"])
    assert heart.list_pending() == ()


def test_policy_refusal_stops_staging_without_acting(monkeypatch):
    """If the policy authority does not permit the operation, the Heart
    records that and stages nothing -- it never resolves a disagreement by
    acting. PRIVILEGE_ESCALATION is in the REAL rule table's always_deny set,
    so this exercises the real evaluator, not a mock."""
    import core.governance.orchestrator as orchestrator_module
    from core.policy_gate import GovernanceAction, PolicyContext
    from core.policy_gate import evaluate as real_evaluate

    _, audit, core, heart = _stack()

    def refusing_policy(context):
        return real_evaluate(
            PolicyContext(
                action=GovernanceAction.PRIVILEGE_ESCALATION,
                actor_id=context.actor_id,
                tenant_id=context.tenant_id,
                resource=context.resource,
                mode=context.mode,
                human_approved=context.human_approved,
                correlation_id=context.correlation_id,
            )
        )

    monkeypatch.setattr(orchestrator_module, "evaluate", refusing_policy)

    decision = heart.observe(
        ThreatAssessment(
            identity="anonymous",
            source_ip="203.0.113.123",
            threat_kind=list(ThreatKind)[0],
            severity=ThreatSeverity.HIGH,
            source_kind=ThreatSourceKind.AI_AUTOMATION_LIKELY,
            score=80.0,
            indicators={"evidence_seq": 1, "evidence_sources": ["firewall", "sparta"]},
            supporting_tags=["t"],
            window_size=5,
        )
    )
    assert decision.reason == "POLICY_REFUSED"
    assert heart.list_pending() == ()
    refused = [
        r for r in audit.get_records(component="heart", limit=500)
        if r.get("reason_code") == "POLICY_REFUSED"
    ]
    assert refused[-1]["policy"][0]["status"] == "DENY"
    assert refused[-1]["policy"][0]["reasons"] == ["ALWAYS_DENIED"]


def test_policy_refusal_blocks_approval_and_leaves_the_action_pending(
    client, monkeypatch
):
    import core.governance.heart as heart_module
    from core.policy_gate import GovernanceAction

    _, audit, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.124")
    _use(heart)
    assert _recover(client) == 1

    import core.governance.orchestrator as orchestrator_module
    from core.policy_gate import PolicyContext, evaluate as real_evaluate

    def refusing_policy(context):
        # The real evaluator, asked about an operation its rule table
        # always denies: the policy authority now refuses this approval.
        return real_evaluate(
            PolicyContext(
                action=GovernanceAction.PRIVILEGE_ESCALATION,
                actor_id=context.actor_id,
                tenant_id=context.tenant_id,
                resource=context.resource,
                mode=context.mode,
                human_approved=context.human_approved,
                correlation_id=context.correlation_id,
            )
        )

    monkeypatch.setattr(orchestrator_module, "evaluate", refusing_policy)
    response = client.post(
        f"/actions/{action_id}/approve",
        headers=_headers(),
        json={"reason": "reviewed by operator"},
    )
    assert response.status_code == 409, response.text
    assert core.get_status(action_id) == ActionStatus.PENDING
    last = audit.get_records(component="heart", correlation_id=action_id)[-1]
    assert last["decision"] == "DENIED" and last["reason_code"] == "POLICY_REFUSED"

    # A veto declines the operation, so policy does not stand in its way.
    vetoed = client.post(
        f"/actions/{action_id}/veto",
        headers=_headers(),
        json={"reason": "declining under policy refusal"},
    )
    assert vetoed.status_code == 200, vetoed.text
    assert core.get_status(action_id) == ActionStatus.VETOED


# ---------------------------------------------------------------------------
# The orchestrator is the authority; the Heart cannot act on its own
# ---------------------------------------------------------------------------
def _assessment(
    ip: str,
    identity: str = "anonymous",
    source_kind: ThreatSourceKind = ThreatSourceKind.AI_AUTOMATION_LIKELY,
) -> ThreatAssessment:
    return ThreatAssessment(
        identity=identity,
        source_ip=ip,
        threat_kind=list(ThreatKind)[0],
        severity=ThreatSeverity.HIGH,
        source_kind=source_kind,
        score=80.0,
        indicators={"evidence_seq": 1, "evidence_sources": ["firewall", "sparta"]},
        supporting_tags=["t"],
        window_size=5,
    )


def test_heart_source_contains_no_decision_writes():
    """Structural: the only code that inserts or transitions a pending
    decision is the orchestrator. The Heart module has no path to do it."""
    import inspect

    import core.governance.heart as heart_module
    import core.governance.orchestrator as orchestrator_module

    heart_source = inspect.getsource(heart_module)
    for forbidden in ("insert_pending(", "transition_status(", "evaluate("):
        assert forbidden not in heart_source, forbidden

    import core.governance.sentinel43_engine as engine_module

    engine_source = inspect.getsource(engine_module)
    assert "insert_pending(" in engine_source
    assert "transition_status(" in engine_source
    orchestrator_source = inspect.getsource(orchestrator_module)
    assert "engine.stage(" in orchestrator_source
    assert "engine.approve if approved else engine.veto" in orchestrator_source


def test_a_heart_without_an_authority_stages_and_resolves_nothing(tmp_path):
    audit = AuditStore(AuditConfig(sqlite_path=tmp_path / "a.sqlite3", signing_key="k" * 48))
    audit.initialize()
    core = SentinelCoreStore(CoreStoreConfig(db_path=tmp_path / "h.sqlite3"))
    core.initialize()

    class Settings:
        default_mode = "HUMAN_GATED"

    heart = build_heart_from_settings(Settings(), audit_store=audit, core_store=core)

    decision = heart.observe(_assessment("203.0.113.130"))
    assert decision.status == "OBSERVED" and decision.reason == "NO_GOVERNANCE_AUTHORITY"
    assert core.count_actions() == 0

    from core.governance.orchestrator import RecommendationAuthorityUnavailable

    with pytest.raises(RecommendationAuthorityUnavailable):
        heart.resolve_human_decision(
            "HEART-ANYTHING0001",
            approved=True,
            operator_id="heart-op",
            reason="no authority",
            principal=_principal(),
        )


def test_staging_records_the_orchestrator_the_operation_and_its_target():
    _, audit, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.131")

    row = core.get_action(action_id)
    assert list(row["actions"]) == APPROVABLE_PLAN
    assert row["system_id"] == "SENTINEL-43-NEXUS-01"

    staged = audit.get_records(component="heart", correlation_id=action_id)[0]
    assert staged["authority"] == "system_orchestrator"
    assert staged["engine"]["class"] == "Sentinel43ResponseEngine"
    assert staged["operations"] == [
        {
            "action": "rate_limit",
            "target_type": "subject",
            "target": "anonymous|203.0.113.131",
            "engine_action": "RATE_LIMIT",
        }
    ]
    assert staged["unsupported_actions"] == []
    assert staged["recommendation"]["approval"]["available"] is True
    # The policy decision is bound to that operation AND its target.
    assert staged["policy"][0]["action"] == "rate_limit"
    assert staged["policy"][0]["resource"] == "subject:anonymous|203.0.113.131"


def test_approval_is_bound_to_the_staged_operation_and_target(client):
    _, audit, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.132")
    _use(heart)
    assert _recover(client) == 1

    response = client.post(
        f"/actions/{action_id}/approve",
        headers=_headers(),
        json={"reason": "reviewed by operator"},
    )
    assert response.status_code == 200, response.text

    approved = audit.get_records(component="heart", correlation_id=action_id)[-1]
    assert approved["authority"] == "system_orchestrator"
    assert approved["identity_type"] == "operator"
    assert approved["decided_by"] == "Sentinel43ResponseEngine.approve_action"
    assert approved["enforcement"].startswith("not_performed")
    assert response.json()["action"]["status"] == "APPROVED"
    assert approved["operations"][0]["target"] == "anonymous|203.0.113.132"
    assert approved["policy"][0]["resource"] == "subject:anonymous|203.0.113.132"
    assert approved["policy"][0]["human_approved"] is True
    # Nothing was enforced, and no incident was authorized by this plan.
    assert "incident_id" not in approved


def test_a_changed_operation_cannot_be_approved(client):
    """Consent is to what was staged. If the durable row now proposes a
    different operation, approval is refused and nothing changes."""
    directory, audit, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.133")
    _use(heart)
    assert _recover(client) == 1

    _sql(directory, "UPDATE pending_actions SET primary_action='quarantine' WHERE action_id=?", (action_id,))
    response = client.post(
        f"/actions/{action_id}/approve",
        headers=_headers(),
        json={"reason": "reviewed by operator"},
    )
    assert response.status_code == 409, response.text
    assert core.get_status(action_id) == ActionStatus.PENDING
    last = audit.get_records(component="heart", correlation_id=action_id)[-1]
    assert last["reason_code"] == "OPERATION_DOES_NOT_MATCH_STAGING_RECORD"

    # ...and a restart will not re-expose it either.
    main_module.runtime.action_store.clear()
    assert _recover(client) == 0
    assert core.get_status(action_id) == ActionStatus.EXPIRED


def test_an_unsupported_recommendation_is_staged_but_not_approvable(client):
    """For an ordinary-source HIGH intrusion the engine recommends step-up
    auth, rate limiting and an account block. Throttling is authorizable, but
    the two account actions have no account to act on, so the recommendation
    is NOT approvable -- not even for its supported part -- and the operator
    is told which actions block it. It can still be vetoed."""
    _, audit, core, heart = _stack()
    decision = heart.observe(
        _assessment("203.0.113.134", source_kind=ThreatSourceKind.MIXED_OR_UNKNOWN)
    )
    assert decision.status == "STAGED"
    staged = audit.get_records(component="heart", correlation_id=decision.action_id)[0]
    # The supported part was assessed, but it is not on its own approvable.
    assert [o["action"] for o in staged["operations"]] == ["rate_limit"]
    assert set(staged["unsupported_actions"]) == {"STEP_UP_AUTH", "TEMP_BLOCK_IDENTITY"}
    assert staged["recommendation"]["approval"]["available"] is False

    _use(heart)
    assert _recover(client) == 1
    approve = client.post(
        f"/actions/{decision.action_id}/approve",
        headers=_headers(),
        json={"reason": "reviewed by operator"},
    )
    assert approve.status_code == 409, approve.text
    assert core.get_status(decision.action_id) == ActionStatus.PENDING
    last = audit.get_records(component="heart", correlation_id=decision.action_id)[-1]
    assert last["reason_code"] == "APPROVAL_UNAVAILABLE"
    assert set(last["approval"]["blocking_actions"]) == {
        "STEP_UP_AUTH",
        "TEMP_BLOCK_IDENTITY",
    }
    # The limitation is visible through the API the dashboard reads.
    listed = client.get("/actions", headers=_headers())
    shown = next(a for a in listed.json() if a["id"] == decision.action_id)
    assert shown["payload"]["approval"]["available"] is False
    assert any("TEMP_BLOCK_IDENTITY" in r for r in shown["payload"]["approval"]["reasons"])

    veto = client.post(
        f"/actions/{decision.action_id}/veto",
        headers=_headers(),
        json={"reason": "declining an unsupported recommendation"},
    )
    assert veto.status_code == 200, veto.text
    assert core.get_status(decision.action_id) == ActionStatus.VETOED


def test_the_route_resolves_through_the_orchestrator_not_the_heart(client):
    """With the Heart object gone the same authority still decides; with the
    authority's store detached, nothing can be decided at all."""
    _, audit, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.135")
    _use(heart)
    assert _recover(client) == 1

    main_module.runtime.heart = None
    response = client.post(
        f"/actions/{action_id}/approve",
        headers=_headers(),
        json={"reason": "reviewed by operator"},
    )
    assert response.status_code == 200, response.text

    second = _stage(heart, "203.0.113.136")
    main_module.runtime.action_store.clear()
    main_module.runtime.orchestrator = heart._authority
    assert _recover(client) == 1
    heart._authority.detach_recommendation_store()
    refused = client.post(
        f"/actions/{second}/approve",
        headers=_headers(),
        json={"reason": "reviewed by operator"},
    )
    assert refused.status_code == 409, refused.text
    assert core.get_status(second) == ActionStatus.PENDING


def test_an_enabled_heart_without_its_authority_blocks_readiness(monkeypatch):
    directory, audit, _, _ = _stack()
    monkeypatch.setenv("S43_HEART_ENABLED", "true")
    monkeypatch.setenv("S43_HEART_REQUIRED", "true")
    # The configuration is valid -- an enabled Heart declares its authority.
    # What fails is at RUNTIME: governance never comes up, so the Heart meets
    # an absent authority on the real startup path.
    monkeypatch.setenv("S43_GOVERNANCE_ENABLED", "true")
    monkeypatch.setenv("S43_AUDIT_HMAC_KEY", "a" * 64)
    monkeypatch.setenv("S43_HEART_SQLITE_PATH", str(directory / "heart.sqlite3"))

    async def _governance_never_starts() -> None:
        main_module.runtime.orchestrator = None

    monkeypatch.setattr(main_module, "_start_governance", _governance_never_starts)

    with TestClient(main_module.app) as test_client:
        main_module.runtime.audit_store = audit

        assert main_module.runtime.orchestrator is None
        assert main_module.runtime.heart is None
        status = main_module.runtime.subsystems.get(main_module.SUBSYS_HEART)
        assert "governance orchestrator" in status.detail, status.detail
        ready = test_client.get("/ready")
        assert ready.status_code == 503, ready.text
        assert "heart" in ready.text
        assert test_client.get("/health").status_code == 200


# ---------------------------------------------------------------------------
# Legacy recovery: records written before lookup fields / operations existed
# ---------------------------------------------------------------------------
def _legacy_staged(audit, action_id: str, *, with_component: bool) -> None:
    record = {
        "subsystem": "heart",
        "identity": "anonymous",
        "source_ip": "198.51.100.1",
        "threat_kind": "x",
        "severity": "HIGH",
        "source_kind": "MIXED_OR_UNKNOWN",
        "score": 80.0,
        "supporting_tags": [],
        "indicators": {},
        "decision": "STAGED",
        "reason_code": "STAGED_FOR_HUMAN_REVIEW",
        "decision_id": action_id,
    }
    if with_component:
        record["component"] = "heart"
        record["correlation_id"] = action_id
    audit.append(record)


@pytest.mark.parametrize("with_component", [False, True], ids=["pre-lookup-fields", "pre-operation"])
def test_legitimately_audited_legacy_rows_are_recovered_not_expired(client, with_component):
    _, audit, core, heart = _stack()
    _raw_row(core, "HEART-LEGACY000001")  # primary_action "human_review"
    _legacy_staged(audit, "HEART-LEGACY000001", with_component=with_component)
    _use(heart)

    assert _recover(client) == 1
    assert core.get_status("HEART-LEGACY000001") == ActionStatus.PENDING
    restored = main_module.runtime.action_store["HEART-LEGACY000001"]
    assert restored["payload"]["legacy"] is True
    assert restored["payload"]["operations"] is None


def test_a_legacy_recommendation_cannot_be_approved_but_can_be_vetoed(client):
    """No operation was ever recorded for it, so approving would bind human
    consent to something nobody proposed. It stays decidable by veto."""
    _, audit, core, heart = _stack()
    _raw_row(core, "HEART-LEGACY000002")
    _legacy_staged(audit, "HEART-LEGACY000002", with_component=False)
    _use(heart)
    assert _recover(client) == 1

    approve = client.post(
        "/actions/HEART-LEGACY000002/approve",
        headers=_headers(),
        json={"reason": "reviewed by operator"},
    )
    assert approve.status_code == 409, approve.text
    assert core.get_status("HEART-LEGACY000002") == ActionStatus.PENDING

    veto = client.post(
        "/actions/HEART-LEGACY000002/veto",
        headers=_headers(),
        json={"reason": "declining a legacy recommendation"},
    )
    assert veto.status_code == 200, veto.text
    assert core.get_status("HEART-LEGACY000002") == ActionStatus.VETOED


def test_a_legacy_row_with_a_legacy_terminal_decision_is_not_resurrected(client):
    _, audit, core, heart = _stack()
    _raw_row(core, "HEART-LEGACY000003")
    _legacy_staged(audit, "HEART-LEGACY000003", with_component=False)
    audit.append(
        {
            "subsystem": "heart",
            "decision_id": "HEART-LEGACY000003",
            "decision": "VETOED",
            "reason_code": "HUMAN_VETOED",
        }
    )
    _use(heart)

    assert _recover(client) == 0
    assert core.get_status("HEART-LEGACY000003") == ActionStatus.EXPIRED


def test_a_legacy_row_whose_content_disagrees_is_quarantined(client):
    directory, audit, core, heart = _stack()
    _raw_row(core, "HEART-LEGACY000004")
    _legacy_staged(audit, "HEART-LEGACY000004", with_component=False)
    _sql(directory, "UPDATE pending_actions SET severity='CRITICAL' WHERE action_id='HEART-LEGACY000004'")
    _use(heart)

    assert _recover(client) == 0
    assert core.get_status("HEART-LEGACY000004") == ActionStatus.EXPIRED


def test_the_remote_gateway_cannot_decide_a_heart_recommendation(client):
    """Same rule on the recommendation path: the real gateway handler carries
    no authenticated human, so the orchestrator refuses and audits it."""
    from fastapi import HTTPException

    from core.api.routers import remote_gateway
    from core.api.routers.remote_gateway import (
        RemoteEventActivationRequest,
        RemoteEventType,
    )

    _, audit, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.140")
    _use(heart)
    assert _recover(client) == 1

    handler = remote_gateway._dispatch_registry[RemoteEventType.APPROVE_DECISION]
    with pytest.raises(HTTPException) as refused:
        client.portal.call(
            handler,
            RemoteEventActivationRequest(
                operator_id="remote-admin",
                target_id="sentinel43-api",
                event_type=RemoteEventType.APPROVE_DECISION,
                reason="remote decision attempt via the gateway",
                correlation_id="gw-correlation-0002",
                dry_run=False,
                payload={"action_id": action_id, "decision_id": action_id},
            ),
        )
    assert refused.value.status_code == 403
    assert core.get_status(action_id) == ActionStatus.PENDING
    last = audit.get_records(component="heart", correlation_id=action_id)[-1]
    assert last["decision"] == "DENIED"
    assert last["reason_code"] == "NO_AUTHENTICATION_CONTEXT"


# ---------------------------------------------------------------------------
# The owner-designated engine is the running decider, and it is contained
# ---------------------------------------------------------------------------
def test_the_running_engine_is_the_unmodified_owner_file():
    from core.governance.sentinel43_engine import (
        EXPECTED_ENGINE_SHA256,
        engine_digest,
        engine_source_path,
    )

    _, _, _, heart = _stack()
    identity = heart._authority.engine_identity
    on_disk = engine_digest(engine_source_path().read_bytes())
    assert identity["sha256"] == on_disk
    # ...and the file on disk is the one that was reviewed, whatever line
    # endings this checkout materialised it with.
    assert identity["sha256"] == EXPECTED_ENGINE_SHA256
    assert identity["class"] == "Sentinel43ResponseEngine"


def test_the_engine_has_no_live_executor_and_refuses_execution():
    import threading
    import time

    from core.governance.sentinel43_engine import CoreStoreActionStore

    _, _, core, heart = _stack()
    time.sleep(0.2)
    assert not [t for t in threading.enumerate() if "executor" in t.name]

    store = CoreStoreActionStore(core)
    assert store.fetch_due_pending(now_ms=0, limit=10) == []
    assert store.mark_pending_executing("HEART-ANY") is False
    assert store.expire_overdue(now_ms=10**15) == 0
    with pytest.raises(RuntimeError):
        store.finalize_execution("HEART-ANY", ok=True)


def test_active_mode_is_refused_by_the_engine_adapter():
    _, _, _, heart = _stack()
    engine = heart._authority._engine
    plan = engine.plan(_assessment("203.0.113.150"))
    with pytest.raises(RuntimeError, match="no autonomous execution"):
        engine.stage(
            plan["directive"],
            mode_value="ACTIVE",
            subject_key="anonymous|203.0.113.150",
            kind="GENERIC_INTRUSION",
            severity="HIGH",
            source_kind="AI_AUTOMATION_LIKELY",
            score=80.0,
        )


def test_the_engine_authenticator_refuses_outside_a_governed_decision():
    """Calling the engine's own approve_action directly -- bypassing the
    orchestrator -- gets nothing: its authenticator is bound to a principal
    that only the orchestrator supplies."""
    _, _, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.151")
    raw_engine = heart._authority._engine._engine

    assert raw_engine.approve_action(action_id, "heart-op", "direct call") is False
    assert raw_engine.veto_action(action_id, "heart-op", "direct call") is False
    assert core.get_status(action_id) == ActionStatus.PENDING


def test_distinct_anonymous_sources_are_not_collapsed_by_the_engine():
    """All firewall evidence is identity "anonymous"; the engine must still
    treat each source as its own principal."""
    _, _, core, heart = _stack()
    first = _stage(heart, "203.0.113.160")
    second = _stage(heart, "203.0.113.161")
    assert first != second
    assert core.count_actions(status=ActionStatus.PENDING) == 2


def test_each_containment_layer_refuses_active_on_its_own():
    """Two independent layers refuse ACTIVE: the adapter's mode check, and the
    store, which will not accept an auto-executing (PENDING-with-timer) row."""
    from types import SimpleNamespace

    from core.governance.sentinel43_engine import CoreStoreActionStore

    _, _, core, heart = _stack()
    with pytest.raises(RuntimeError, match="no autonomous execution"):
        heart._authority._engine._mode("ACTIVE")

    store = CoreStoreActionStore(core)
    with pytest.raises(RuntimeError, match="no autonomous execution"):
        store.insert_pending_action(SimpleNamespace(status="PENDING"))


# ---------------------------------------------------------------------------
# Operational honesty: what each engine action means and whether it is approvable
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "severity,source_kind,kind,score,approvable,blocking",
    [
        # Throttling alone, and throttling plus the review this staging is:
        # both are approvable, because the policy vocabulary states them.
        ("MEDIUM", "MIXED_OR_UNKNOWN", "PAYLOAD_ABUSE", 50.0, True, set()),
        ("HIGH", "MIXED_OR_UNKNOWN", "DATA_EXFILTRATION", 50.0, True, set()),
        # A credential attack adds step-up authentication, which needs an
        # account this subject does not name.
        (
            "HIGH",
            "MIXED_OR_UNKNOWN",
            "CREDENTIAL_ATTACK",
            50.0,
            False,
            {"STEP_UP_AUTH"},
        ),
        # Above the engine's temporary-block threshold an account block is
        # added; automation-likely adds the IP block, which IS approvable.
        (
            "HIGH",
            "AI_AUTOMATION_LIKELY",
            "RATE_ANOMALY",
            80.0,
            False,
            {"TEMP_BLOCK_IDENTITY"},
        ),
        # Critical plans quarantine the session and block the account.
        (
            "CRITICAL",
            "MIXED_OR_UNKNOWN",
            "GENERIC_INTRUSION",
            90.0,
            False,
            {"QUARANTINE_SESSION", "HARD_BLOCK_IDENTITY"},
        ),
    ],
)
def test_reachable_engine_plans(
    severity, source_kind, kind, score, approvable, blocking
):
    """What the engine's OWN policy plans for real findings, and exactly which
    of those plans a human can approve under the policy vocabulary.

    The plans that cannot be approved are blocked only by actions that name an
    account or a session: the subject a finding carries is an identity type
    and an address, so there is no account for them to act on. Nothing is
    relabelled to make them approvable.
    """
    from core.governance.sentinel43_engine import assess_actions

    _, _, _, heart = _stack()
    plan = heart._authority._engine.plan(
        ThreatAssessment(
            identity="anonymous",
            source_ip="203.0.113.170",
            threat_kind=ThreatKind[kind],
            severity=ThreatSeverity[severity],
            source_kind=ThreatSourceKind[source_kind],
            score=score,
        )
    )
    assessed = assess_actions(plan["actions"], subject_key="anonymous|203.0.113.170")
    assert assessed["approval"]["available"] is approvable, plan["actions"]
    assert set(assessed["approval"]["blocking_actions"]) == blocking, plan["actions"]
    assert len(assessed["approval"]["reasons"]) == len(
        assessed["approval"]["blocking_actions"]
    )
    # No engine action is ever recorded as a network block unless it IS one.
    for item in assessed["items"]:
        if item["policy_action"] == "network_block":
            assert item["engine_action"] in ("TEMP_BLOCK_IP", "HARD_BLOCK_IP")


def test_each_engine_action_keeps_its_own_meaning():
    """Throttling, step-up authentication and account blocks each map to the
    policy operation that states THEIR meaning -- never to a network block,
    and never to each other."""
    from core.governance.sentinel43_engine import ACTION_CATALOG

    assert {
        name: entry[2]
        for name, entry in ACTION_CATALOG.items()
        if entry[2] is not None
    } == {
        "TEMP_BLOCK_IP": "network_block",
        "HARD_BLOCK_IP": "network_block",
        "QUARANTINE_SESSION": "quarantine",
        "STEP_UP_AUTH": "step_up_auth",
        "RATE_LIMIT": "rate_limit",
        "TEMP_BLOCK_IDENTITY": "account_block_temporary",
        "HARD_BLOCK_IDENTITY": "account_block_extended",
        "OPEN_INCIDENT": "incident_open",
    }


@pytest.mark.parametrize(
    "action", ["STEP_UP_AUTH", "TEMP_BLOCK_IDENTITY", "HARD_BLOCK_IDENTITY", "QUARANTINE_SESSION"]
)
@pytest.mark.parametrize("identity", ["anonymous", "operator", "service:watchtower"])
def test_account_actions_have_no_account_to_act_on(action, identity):
    """The subject is an identity TYPE and an address. No account is invented
    for these, and no address operation is substituted for one -- for an
    anonymous source or any other."""
    from core.governance.sentinel43_engine import assess_actions

    assessed = assess_actions([action], subject_key=f"{identity}|203.0.113.172")
    item = assessed["items"][0]
    assert item["status"] == "NO_VALID_TARGET"
    assert item["target"] is None
    assert assessed["operations"] == []
    assert assessed["approval"]["available"] is False
    assert "account" in item["reason"]


def test_a_mixed_recommendation_is_not_partially_approved():
    """Supported and unsupported together: approval is unavailable for the
    whole recommendation -- never a quiet approval of the supported part."""
    from core.governance.sentinel43_engine import assess_actions

    assessed = assess_actions(
        ["RATE_LIMIT", "TEMP_BLOCK_IP", "TEMP_BLOCK_IDENTITY", "REQUIRE_HUMAN_REVIEW"],
        subject_key="anonymous|203.0.113.173",
    )
    # Throttling and the IP block ARE expressible...
    assert [o["action"] for o in assessed["operations"]] == ["rate_limit", "network_block"]
    assert assessed["approval"]["available"] is False  # ...but not on their own
    assert assessed["approval"]["blocking_actions"] == ["TEMP_BLOCK_IDENTITY"]


# ---------------------------------------------------------------------------
# Security review findings (bounded to the authority boundary and adapters)
# ---------------------------------------------------------------------------
def test_engine_store_cannot_transition_outside_a_governed_decision():
    from core.governance.sentinel43_engine import CoreStoreActionStore

    _, _, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.180")
    store = CoreStoreActionStore(core)
    with pytest.raises(PermissionError):
        store.update_action_status(
            action_id,
            "APPROVED",
            operator_id="anyone",
            operator_reason="direct store call",
            expected_status="STAGED",
        )
    assert core.get_status(action_id) == ActionStatus.PENDING


def test_decision_authority_does_not_leak_to_a_concurrent_direct_call():
    """While one governed approval is in progress in another thread, a direct
    engine call in this thread still sees no authority."""
    import threading

    _, _, core, heart = _stack()
    first = _stage(heart, "203.0.113.181")
    second = _stage(heart, "203.0.113.182")
    raw_engine = heart._authority._engine._engine

    inside = threading.Event()
    release = threading.Event()
    original = core.transition_status

    def slow_transition(action_id, **kwargs):
        if action_id == first:
            inside.set()
            release.wait(5)
        return original(action_id, **kwargs)

    core.transition_status = slow_transition
    worker = threading.Thread(
        target=lambda: heart.resolve_human_decision(
            first,
            approved=True,
            operator_id="heart-op",
            reason="governed approval in progress",
            principal=_principal(),
        )
    )
    worker.start()
    assert inside.wait(5)
    try:
        assert raw_engine.approve_action(second, "heart-op", "direct call") is False
    finally:
        release.set()
        worker.join(5)
        del core.transition_status

    assert core.get_status(first) == ActionStatus.APPROVED
    assert core.get_status(second) == ActionStatus.PENDING


def test_a_swapped_engine_action_is_detected(client):
    """Temporary and hard blocks are the same policy action on the same
    target; the binding still distinguishes them."""
    import json as _json

    directory, audit, core, heart = _stack()
    action_id = _stage(heart, "203.0.113.183")
    _use(heart)
    assert _recover(client) == 1
    _sql(
        directory,
        "UPDATE pending_actions SET primary_action='HARD_BLOCK_IP', actions_json=? WHERE action_id=?",
        (_json.dumps(["HARD_BLOCK_IP", "REQUIRE_HUMAN_REVIEW"]), action_id),
    )
    response = client.post(
        f"/actions/{action_id}/approve", headers=_headers(), json={"reason": "reviewed by operator"}
    )
    assert response.status_code == 409, response.text
    assert core.get_status(action_id) == ActionStatus.PENDING


def test_an_unreviewed_engine_file_is_refused(tmp_path):
    from core.governance.sentinel43_engine import (
        EngineUnavailable,
        engine_source_path,
        load_engine_module,
    )

    (tmp_path / "Sentinel-43").mkdir()
    altered = engine_source_path().read_bytes() + b"\n# altered\n"
    (tmp_path / "Sentinel-43" / "Shadow_mode.py").write_bytes(altered)
    with pytest.raises(EngineUnavailable, match="sha256"):
        load_engine_module(root=tmp_path)


def test_a_malformed_subject_never_reaches_the_engine():
    _, audit, core, heart = _stack()
    authority = heart._authority
    from core.governance.orchestrator import GovernanceMode, ThreatRecommendation

    outcome = authority.stage_recommendation(
        ThreatRecommendation(
            subject_key="anonymous|203.0.113.184",
            assessment=ThreatAssessment(
                identity="anonymous|203.0.113.9",  # forged separator
                source_ip="203.0.113.184",
                threat_kind=list(ThreatKind)[0],
                severity=ThreatSeverity.HIGH,
                source_kind=ThreatSourceKind.AI_AUTOMATION_LIKELY,
                score=80.0,
            ),
            evidence={"subsystem": "heart"},
            requested_mode=GovernanceMode.HUMAN_GATED,
            created_at=time.time(),
        )
    )
    assert outcome.reason == "INVALID_SUBJECT"
    assert core.count_actions() == 0


def test_restored_actions_carry_their_approval_state(client):
    _, _, _, heart = _stack()
    action_id = _stage(heart, "203.0.113.185")
    _use(heart)
    assert _recover(client) == 1
    payload = main_module.runtime.action_store[action_id]["payload"]
    assert payload["approval"]["available"] is True
    assert [
        i["engine_action"] for i in payload["recommendation"]["items"]
    ] == APPROVABLE_PLAN


# ---------------------------------------------------------------------------
# Incident records: the one effect an approval produces, and it is internal
# ---------------------------------------------------------------------------
def test_approving_an_incident_recommendation_opens_a_durable_record(client):
    """A recommendation whose plan includes OPEN_INCIDENT opens a durable
    incident record in this system's own store when a human approves it --
    not an audit line, a record that can be read back."""
    _, audit, core, heart = _stack()
    action_id = _stage_planned(heart, "203.0.113.190", ["RATE_LIMIT", "OPEN_INCIDENT"])
    _use(heart)
    assert _recover(client) == 1

    assert core.count_incidents() == 0
    response = client.post(
        f"/actions/{action_id}/approve",
        headers=_headers(),
        json={"reason": "opening an incident for follow-up"},
    )
    assert response.status_code == 200, response.text

    incident_id = core.incident_id_for_action(action_id)
    incident = core.get_incident(incident_id)
    assert incident is not None
    assert incident["status"] == "OPEN"
    assert incident["action_id"] == action_id
    assert incident["subject_value"] == "anonymous|203.0.113.190"
    assert tuple(incident["engine_actions"]) == ("RATE_LIMIT", "OPEN_INCIDENT")
    assert incident["opened_by"] == "heart-op"

    # The decision record names the incident it opened.
    approved = audit.get_records(component="heart", correlation_id=action_id)[-1]
    assert approved["incident_id"] == incident_id
    # ...and so does the action the dashboard reads.
    assert response.json()["action"]["payload"]["incident_id"] == incident_id

    listed = client.get("/incidents", headers=_headers())
    assert listed.status_code == 200, listed.text
    assert [i["incident_id"] for i in listed.json()["incidents"]] == [incident_id]


def test_a_vetoed_incident_recommendation_opens_nothing(client):
    _, _, core, heart = _stack()
    action_id = _stage_planned(heart, "203.0.113.191", ["RATE_LIMIT", "OPEN_INCIDENT"])
    _use(heart)
    assert _recover(client) == 1

    response = client.post(
        f"/actions/{action_id}/veto",
        headers=_headers(),
        json={"reason": "not an incident"},
    )
    assert response.status_code == 200, response.text
    assert core.count_incidents() == 0


def test_an_unauditable_incident_decision_is_reverted_and_the_incident_retracted():
    """If the decision cannot be recorded, the approval is reverted -- and the
    incident it opened is retracted rather than left standing."""
    _, audit, core, heart = _stack()
    action_id = _stage_planned(heart, "203.0.113.192", ["RATE_LIMIT", "OPEN_INCIDENT"])
    authority = heart._authority

    original = authority._append_audit

    def fail_on_decision(record):
        if record.get("decision") in ("APPROVED", "VETOED"):
            raise RuntimeError("audit ledger unavailable")
        return original(record)

    authority._append_audit = fail_on_decision
    try:
        with pytest.raises(RuntimeError, match="audit ledger unavailable"):
            authority.resolve_recommendation(
                action_id,
                approved=True,
                operator_id="heart-op",
                reason="reviewed",
                principal=_principal(),
            )
    finally:
        authority._append_audit = original

    assert core.get_status(action_id) == ActionStatus.PENDING
    incident = core.get_incident(core.incident_id_for_action(action_id))
    assert incident is not None and incident["status"] == "RETRACTED"
    assert incident["retracted_reason"] == "reverted_unaudited_decision"
    assert core.count_incidents(status=IncidentStatus.OPEN) == 0


def test_opening_the_same_incident_twice_keeps_one_record():
    _, _, core, _heart = _stack()
    first = core.open_incident(
        action_id="a-1",
        severity="CRITICAL",
        kind="GENERIC_INTRUSION",
        subject_type="identity_source_ip",
        subject_value="anonymous|203.0.113.193",
        summary="s",
        engine_actions=("OPEN_INCIDENT",),
        opened_by="heart-op",
    )
    second = core.open_incident(
        action_id="a-1",
        severity="CRITICAL",
        kind="GENERIC_INTRUSION",
        subject_type="identity_source_ip",
        subject_value="anonymous|203.0.113.193",
        summary="s",
        engine_actions=("OPEN_INCIDENT",),
        opened_by="heart-op",
    )
    assert first == second
    assert core.count_incidents() == 1


def test_no_incident_is_opened_without_a_human_decision():
    """Staging alone opens nothing: the incident is an authorized response,
    not a side effect of observing a threat."""
    _, _, core, heart = _stack()
    _stage_planned(heart, "203.0.113.194", ["RATE_LIMIT", "OPEN_INCIDENT"])
    assert core.count_incidents() == 0


def test_a_real_critical_plan_is_approvable_only_when_the_evidence_names_an_account():
    """The engine's own CRITICAL plan quarantines a session and blocks an
    account. Those act on the account the request pipeline authenticated: with
    one, the whole plan is approvable; without one, it is not, and nothing is
    substituted to make it so."""
    from core.governance.sentinel43_engine import assess_actions

    _, _, _, heart = _stack()
    plan = heart._authority._engine.plan(
        ThreatAssessment(
            identity="operator",
            source_ip="203.0.113.195",
            threat_kind=ThreatKind.GENERIC_INTRUSION,
            severity=ThreatSeverity.CRITICAL,
            source_kind=ThreatSourceKind.MIXED_OR_UNKNOWN,
            score=90.0,
        )
    )
    assert "OPEN_INCIDENT" in plan["actions"]

    without = assess_actions(plan["actions"], subject_key="operator|203.0.113.195")
    assert without["approval"]["available"] is False
    assert set(without["approval"]["blocking_actions"]) == {
        "QUARANTINE_SESSION",
        "HARD_BLOCK_IDENTITY",
    }

    with_account = assess_actions(
        plan["actions"],
        subject_key="operator|203.0.113.195",
        principal="user-7f3a",
    )
    assert with_account["approval"]["available"] is True
    assert with_account["approval"]["blocking_actions"] == []
    by_action = {o["engine_action"]: o for o in with_account["operations"]}
    # Each operation acts on what it names, and the account ones on the account.
    assert by_action["HARD_BLOCK_IDENTITY"] == {
        "action": "account_block_extended",
        "target_type": "account",
        "target": "user-7f3a",
        "engine_action": "HARD_BLOCK_IDENTITY",
    }
    assert by_action["QUARANTINE_SESSION"]["target"] == "user-7f3a"
    assert by_action["HARD_BLOCK_IP"]["target"] == "203.0.113.195"


def test_an_anonymous_source_never_gains_an_account(client):
    """Decision 2, enforced at the boundary: even if an account were recorded
    against an anonymous subject, no account action becomes approvable."""
    from core.governance.sentinel43_engine import assess_actions

    assessed = assess_actions(
        ["HARD_BLOCK_IDENTITY"],
        subject_key="anonymous|203.0.113.197",
        principal="user-7f3a",
    )
    assert assessed["items"][0]["status"] == "NO_VALID_TARGET"
    assert assessed["items"][0]["target"] is None
    assert assessed["operations"] == []


def test_a_window_with_two_accounts_names_neither():
    """The account is the target of a real response, so ambiguity is refused
    rather than resolved by picking one."""
    from core.governance.sentinel43_engine import principal_of_assessment

    def _assess(principals):
        return SimpleNamespace(indicators={"subject_principals": principals})

    assert principal_of_assessment(_assess(["user-a"])) == "user-a"
    assert principal_of_assessment(_assess(["user-a", "user-b"])) == ""
    assert principal_of_assessment(_assess([])) == ""
    assert principal_of_assessment(SimpleNamespace(indicators={})) == ""
    # Never free-form text: an unprintable or oversized value names nothing.
    assert principal_of_assessment(_assess(["a\nb"])) == ""
    assert principal_of_assessment(_assess(["u" * 500])) == ""


def test_new_policy_operations_require_an_authenticated_human():
    """Each new operation is human-required in HUMAN_GATED and observe-only in
    SHADOW -- approval is never implicit."""
    from core.policy_gate import (
        STATUS_OBSERVE,
        STATUS_REQUIRES_HUMAN,
        STATUS_ALLOW,
        PolicyContext,
        evaluate,
    )

    for action in (
        "rate_limit",
        "step_up_auth",
        "account_block_temporary",
        "account_block_extended",
        "incident_open",
    ):
        def _ctx(mode, approved):
            return PolicyContext(
                action=action,
                actor_id="heart-op",
                tenant_id="default",
                resource="subject:anonymous|203.0.113.196",
                mode=mode,
                human_approved=approved,
            )

        assert evaluate(_ctx("SHADOW", False)).status == STATUS_OBSERVE
        assert evaluate(_ctx("HUMAN_GATED", False)).status == STATUS_REQUIRES_HUMAN
        assert evaluate(_ctx("HUMAN_GATED", True)).status == STATUS_ALLOW


def test_a_forged_single_operation_row_cannot_shortcut_the_assessment(client):
    """The policy vocabulary now contains operations that share a name with
    engine actions (rate_limit, step_up_auth, ...). A row that claims the
    pre-engine single-operation shape must still not be able to present an
    engine action as one approvable operation, skipping the rest of the plan."""
    from core.governance.orchestrator import recommendation_for_row

    directory, _, core, heart = _stack()
    action_id = _stage_planned(
        heart, "203.0.113.196", ["RATE_LIMIT", "TEMP_BLOCK_IDENTITY"]
    )
    _sql(
        directory,
        "UPDATE pending_actions SET system_id='heart' WHERE action_id=?",
        (action_id,),
    )
    row = core.get_action(action_id)
    assessed = recommendation_for_row(row)
    # Still assessed as the engine plan it is: the account block blocks it.
    assert assessed["approval"]["available"] is False
    assert assessed["approval"]["blocking_actions"] == ["TEMP_BLOCK_IDENTITY"]

    _use(heart)
    assert _recover(client) == 1
    approve = client.post(
        f"/actions/{action_id}/approve",
        headers=_headers(),
        json={"reason": "reviewed by operator"},
    )
    assert approve.status_code == 409, approve.text
    assert core.get_status(action_id) == ActionStatus.PENDING


# ---------------------------------------------------------------------------
# The production path for an account-scoped response, end to end
# ---------------------------------------------------------------------------
def _stage_critical(heart, ip: str, principal: str = "user-7f3a"):
    """Stage the engine's own CRITICAL plan for an authenticated subject.

    No plan is patched: the engine's _build_critical produces
    QUARANTINE_SESSION + HARD_BLOCK_IDENTITY + HARD_BLOCK_IP + OPEN_INCIDENT +
    REQUIRE_HUMAN_REVIEW, and the account those act on is the one the request
    pipeline authenticated, carried in the evidence.
    """
    decision = heart.observe(
        ThreatAssessment(
            identity=IdentityType.OPERATOR.value,
            source_ip=ip,
            threat_kind=ThreatKind.GENERIC_INTRUSION,
            severity=ThreatSeverity.CRITICAL,
            source_kind=ThreatSourceKind.MIXED_OR_UNKNOWN,
            score=90.0,
            indicators={
                "evidence_seq": 1,
                "evidence_sources": ["firewall", "sparta"],
                "subject_principals": [principal],
            },
            supporting_tags=["t"],
            window_size=5,
        )
    )
    assert decision.status == "STAGED" and decision.action_id, decision
    return decision.action_id


def test_a_real_critical_recommendation_is_approved_end_to_end(client):
    """The owner's engine plans it, the orchestration authority stages and
    resolves it, an authenticated human approves it, and the account-scoped
    operations are recorded against the account -- not an address."""
    _, audit, core, heart = _stack()
    action_id = _stage_critical(heart, "203.0.113.200")

    row = core.get_action(action_id)
    assert list(row["actions"]) == [
        "QUARANTINE_SESSION",
        "HARD_BLOCK_IDENTITY",
        "HARD_BLOCK_IP",
        "OPEN_INCIDENT",
        "REQUIRE_HUMAN_REVIEW",
    ]
    assert row["principal_id"] == "user-7f3a"

    _use(heart)
    assert _recover(client) == 1
    restored = main_module.runtime.action_store[action_id]["payload"]
    assert restored["approval"]["available"] is True
    assert restored["principal"] == "user-7f3a"

    response = client.post(
        f"/actions/{action_id}/approve",
        headers=_headers(),
        json={"reason": "confirmed account compromise"},
    )
    assert response.status_code == 200, response.text
    assert core.get_status(action_id) == ActionStatus.APPROVED

    approved = audit.get_records(component="heart", correlation_id=action_id)[-1]
    assert approved["decided_by"] == "Sentinel43ResponseEngine.approve_action"
    assert approved["identity_type"] == "operator"
    by_action = {o["engine_action"]: o for o in approved["operations"]}
    assert by_action["HARD_BLOCK_IDENTITY"]["action"] == "account_block_extended"
    assert by_action["HARD_BLOCK_IDENTITY"]["target"] == "user-7f3a"
    assert by_action["QUARANTINE_SESSION"]["action"] == "quarantine"
    assert by_action["HARD_BLOCK_IP"]["target"] == "203.0.113.200"
    # Every authorized operation was policy-checked as itself.
    assert {p["action"] for p in approved["policy"]} == {
        "quarantine",
        "account_block_extended",
        "network_block",
        "incident_open",
    }
    # ...and the plan's incident was opened, durably.
    incident = core.get_incident(approved["incident_id"])
    assert incident["status"] == "OPEN"
    assert incident["subject_value"] == "operator|203.0.113.200"
    # Still nothing was enforced.
    assert approved["enforcement"].startswith("not_performed")


def test_the_account_an_approval_acts_on_cannot_be_changed_after_review(client):
    """Consent is to the account that was reviewed. A row whose principal has
    since changed cannot be approved on the staging record."""
    directory, audit, core, heart = _stack()
    action_id = _stage_critical(heart, "203.0.113.201")
    _use(heart)
    assert _recover(client) == 1

    _sql(
        directory,
        "UPDATE pending_actions SET principal_id='someone-else' WHERE action_id=?",
        (action_id,),
    )
    response = client.post(
        f"/actions/{action_id}/approve",
        headers=_headers(),
        json={"reason": "reviewed by operator"},
    )
    assert response.status_code == 409, response.text
    assert core.get_status(action_id) == ActionStatus.PENDING
    last = audit.get_records(component="heart", correlation_id=action_id)[-1]
    assert last["reason_code"] == "OPERATION_DOES_NOT_MATCH_STAGING_RECORD"
    assert core.count_incidents() == 0


def test_a_critical_recommendation_without_an_account_is_veto_only(client):
    """The same real plan, from a source the pipeline never authenticated:
    staged, honestly unapprovable, and vetoable."""
    _, audit, core, heart = _stack()
    decision = heart.observe(
        ThreatAssessment(
            identity="anonymous",
            source_ip="203.0.113.202",
            threat_kind=ThreatKind.GENERIC_INTRUSION,
            severity=ThreatSeverity.CRITICAL,
            source_kind=ThreatSourceKind.MIXED_OR_UNKNOWN,
            score=90.0,
            indicators={"evidence_seq": 1, "evidence_sources": ["firewall", "sparta"]},
            supporting_tags=["t"],
            window_size=5,
        )
    )
    assert decision.status == "STAGED"
    _use(heart)
    assert _recover(client) == 1

    approve = client.post(
        f"/actions/{decision.action_id}/approve",
        headers=_headers(),
        json={"reason": "reviewed by operator"},
    )
    assert approve.status_code == 409
    assert core.count_incidents() == 0
    veto = client.post(
        f"/actions/{decision.action_id}/veto",
        headers=_headers(),
        json={"reason": "no account to act on"},
    )
    assert veto.status_code == 200, veto.text
    assert core.get_status(decision.action_id) == ActionStatus.VETOED


# ---------------------------------------------------------------------------
# Original oversight controls, in the production orchestration path
# ---------------------------------------------------------------------------
def _seed_action_for_target(core, action_id: str, target: str, created_at_ms: int) -> None:
    """An action already recorded against ``target`` -- what the budget counts."""
    core.insert_pending(
        PendingAction(
            action_id=action_id,
            created_at_ms=created_at_ms,
            status=ActionStatus.VETOED,
            target_type="identity_source_ip",
            target_value=target,
            primary_action="RATE_LIMIT",
            actions=("RATE_LIMIT",),
            severity="HIGH",
            kind="DATA_EXFILTRATION",
            source_kind="MIXED_OR_UNKNOWN",
            score=50.0,
            reason="earlier action for this target",
            system_id="SENTINEL-43-NEXUS-01",
        )
    )


def test_the_action_budget_holds_a_repeatedly_targeted_subject(monkeypatch):
    """The original oversight budget: once enough actions have been recorded
    against ONE target inside the window, a further recommendation for it is
    observed, not staged. Other subjects are unaffected."""
    _, audit, core, heart = _stack()
    monkeypatch.setattr(heart._authority, "_budget_max_per_target", 2)
    now_ms = int(time.time() * 1000)
    _seed_action_for_target(core, "seed-1", "anonymous|203.0.113.210", now_ms)
    _seed_action_for_target(core, "seed-2", "anonymous|203.0.113.210", now_ms)

    held = heart.observe(
        ThreatAssessment(
            identity="anonymous",
            source_ip="203.0.113.210",
            threat_kind=ThreatKind.DATA_EXFILTRATION,
            severity=ThreatSeverity.HIGH,
            source_kind=ThreatSourceKind.MIXED_OR_UNKNOWN,
            score=52.0,
            indicators={"evidence_seq": 1, "evidence_sources": ["firewall", "sparta"]},
            supporting_tags=["t"],
            window_size=5,
        )
    )
    assert held.status == "OBSERVED"
    assert held.reason == "BUDGET_EXCEEDED"
    assert core.count_actions() == 2  # nothing new was staged

    record = audit.get_records(component="heart", limit=200)[-1]
    assert record["reason_code"] == "BUDGET_EXCEEDED"
    assert record["budget_target"] == "anonymous|203.0.113.210"
    assert record["budget_limit"] == 2

    # A different subject is not affected by another subject's budget.
    other = _stage(heart, "203.0.113.211")
    assert core.get_status(other) == ActionStatus.PENDING


def test_the_budget_counts_only_actions_inside_its_window(monkeypatch):
    """An action older than the window no longer holds the target."""
    _, _, core, heart = _stack()
    monkeypatch.setattr(heart._authority, "_budget_max_per_target", 1)
    monkeypatch.setattr(heart._authority, "_budget_window_seconds", 300)
    _seed_action_for_target(
        core,
        "seed-old",
        "anonymous|203.0.113.212",
        int((time.time() - 600) * 1000),
    )

    staged = _stage(heart, "203.0.113.212")
    assert core.get_status(staged) == ActionStatus.PENDING


def test_the_engine_events_reach_the_one_audit_ledger():
    """The engine's own account of what it did is durable, in the same ledger
    as the governed decision -- not a second store, and not only a log line."""
    _, audit, _, heart = _stack()
    action_id = _stage(heart, "203.0.113.213")

    engine_records = [
        r
        for r in audit.get_records(component="sentinel43_engine", limit=200)
        if r.get("decision") == "ENGINE_EVENT"
    ]
    assert engine_records, "the engine's own events were not audited"
    staged_events = [
        r
        for r in engine_records
        if r["reason_code"] == "Action staged"
        and r["engine_context"].get("action_id") == action_id
    ]
    assert len(staged_events) == 1
    assert staged_events[0]["engine_module"] == "OVERSIGHT"
    assert staged_events[0]["component"] == "sentinel43_engine"

    # The engine's refusal of an unauthenticated approval is recorded too.
    with pytest.raises(UnauthorizedDecision):
        heart._authority.resolve_recommendation(
            action_id,
            approved=True,
            operator_id="not-the-operator",
            reason="x",
            principal=_principal(
                subject="someone-else", identity=IdentityType.SERVICE_API
            ),
        )


def test_an_unauditable_engine_event_does_not_change_the_decision():
    """Audit continuity is best-effort for the engine's own log lines: a sink
    failure must not stop the engine deciding, because the decision records
    that DO fail closed are written by the orchestrator."""
    _, _, core, heart = _stack()
    store = heart._authority._engine.store

    def explode(_record):
        raise RuntimeError("ledger unavailable")

    store._audit_sink = explode
    action_id = _stage(heart, "203.0.113.214")
    assert core.get_status(action_id) == ActionStatus.PENDING
