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
)
from core.security_context import IdentityType  # noqa: E402
from core.sentinel43_core_db import (  # noqa: E402
    ActionStatus,
    CoreStoreConfig,
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
        operator_authenticator=main_module._heart_operator_authenticator,
    )
    return directory, audit, core, heart


def _stage(heart, ip: str):
    """Stage one real, audited pending action via two independent producers."""
    decision = heart.observe(
        ThreatAssessment(
            identity="anonymous",
            source_ip=ip,
            threat_kind=list(ThreatKind)[0],
            severity=ThreatSeverity.HIGH,
            source_kind=ThreatSourceKind.MIXED_OR_UNKNOWN,
            score=80.0,
            indicators={"evidence_seq": 1, "evidence_sources": ["firewall", "sparta"]},
            supporting_tags=["t"],
            window_size=5,
        )
    )
    assert decision.status == "STAGED" and decision.action_id
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
    main_module.runtime.action_store.clear()


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
    monkeypatch.setenv("S43_HEART_SQLITE_PATH", str(directory / "heart.sqlite3"))

    with TestClient(main_module.app) as test_client:
        main_module.runtime.audit_store = audit
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
def test_fenrir_is_wired_to_heart_only_after_recovery_completes(monkeypatch):
    directory, audit, _, _ = _stack()
    monkeypatch.setenv("S43_HEART_ENABLED", "true")
    monkeypatch.setenv("S43_HEART_REQUIRED", "true")
    monkeypatch.setenv("S43_HEART_SQLITE_PATH", str(directory / "heart.sqlite3"))

    fenrir = SimpleNamespace(heart=None)
    seen_during_recovery: list = []

    async def _recording_recovery() -> int:
        seen_during_recovery.append(fenrir.heart)
        return 0

    monkeypatch.setattr(main_module, "_rehydrate_heart_pending", _recording_recovery)

    with TestClient(main_module.app) as test_client:
        main_module.runtime.audit_store = audit
        main_module.runtime.fenrir_instance = fenrir
        fenrir.heart = None
        test_client.portal.call(main_module._start_heart)

        assert seen_during_recovery == [None], "Fenrir must not stage live while recovery reads pending rows"
        assert fenrir.heart is main_module.runtime.heart is not None


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
        Settings(), audit_store=audit, core_store=core
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
