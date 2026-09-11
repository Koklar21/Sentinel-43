# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_pr275_corrections.py
#
# Regression coverage for the five merge-blocking defects found reviewing
# PR #275. Each defect was silent in its own way -- the system reported a
# plausible outcome while doing the wrong thing.
#
#   1. SHADOW/OBSERVE was routed through the generic non-allowed path and
#      became BLOCKED/POLICY_DENY, so observational mode blocked everything.
#   2. SpartaCore emitted integrity_status="compromised" while WatchtowerNode
#      matched "tampered", a value nothing emits -- a real integrity
#      compromise raised no alert.
#   3. normalize_event() generated a fallback id BEFORE consulting the
#      producer-supplied event_id, silently replacing a valid producer
#      identity with a fresh UUID.
#   4. Sparta compared credentials with secrets.compare_digest(str, str),
#      which raises TypeError on non-ASCII input -- a client could turn an
#      intended 401 into a 500.
#   5. docker-compose hard-requires S43_AUDIT_HMAC_KEY, but the canonical
#      secret generator never produced it.
#
# NOTE: test_policy_gate_smoke.py already covers the policy-gate layer, which
# was correct. The defect was in the ORCHESTRATOR consuming that decision, so
# these tests exercise SystemOrchestrator end to end.
# =============================================================================

from __future__ import annotations

import hashlib
import pathlib
import tempfile
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from core.audit.store import AuditConfig, AuditStore
from core.governance.orchestrator import (
    CallerContext,
    DecisionStatus,
    GovernanceMode,
    ReasonCode,
    SystemOrchestrator,
)
from core.guards.velocity import VelocityConfig, VelocityGuard
from core.monitoring import (
    MonitoringManager,
    WatchtowerConfig,
    WatchtowerNode,
    WatchtowerNodeScanner,
)
from core.monitoring.event_types import (
    INTEGRITY_STATUS_COMPROMISED,
    INTEGRITY_STATUS_OK,
    KNOWN_INTEGRITY_STATUSES,
    normalize_event,
)
from core.monitoring.sparta_core import (
    IntegrityConfig,
    SpartaCore,
    _require_node_token,
    _sign_token,
    _verify_token,
)
from core.policy_gate import PolicyContext, evaluate

NODE_TOKEN = "spn-" + "k" * 40
TOKEN_SECRET = "sps-" + "m" * 40


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _orchestrator(mode: GovernanceMode) -> SystemOrchestrator:
    root = pathlib.Path(tempfile.mkdtemp())
    store = AuditStore(
        AuditConfig(
            sqlite_path=root / "audit.sqlite3",
            signing_key="zq" * 32,
            jsonl_path=None,
        )
    )
    store.initialize()
    return SystemOrchestrator(
        audit_store=store,
        velocity_guard=VelocityGuard(
            VelocityConfig(window_seconds=60.0, limit=100)
        ),
        environment="test",
        default_mode=mode,
        hash_device_ids=False,
        monitoring_manager=None,
    )


def _caller(caller_id: str, *roles: str) -> CallerContext:
    return CallerContext(
        caller_id=caller_id,
        caller_roles=frozenset(roles or ("user",)),
        authenticated_at=datetime.now(timezone.utc),
    )


def _manager() -> MonitoringManager:
    node = WatchtowerNode(
        WatchtowerConfig.default_sentinel_octagon("test-node")
    )
    manager = MonitoringManager(WatchtowerNodeScanner(node))
    manager.start()
    return manager


def _sparta_config(**overrides) -> IntegrityConfig:
    base = {
        "watched_files": {},
        "node_signature": "test-node",
        "node_api_token": NODE_TOKEN,
        "token_secret": TOKEN_SECRET,
    }
    base.update(overrides)
    return IntegrityConfig(**base)


# --------------------------------------------------------------------------- #
# 1. SHADOW / OBSERVE must not become POLICY_DENY
# --------------------------------------------------------------------------- #

def test_shadow_known_action_is_observed_not_blocked():
    """A. PolicyDecision.allowed is `status == ALLOW`, so OBSERVE arrived in
    the not-allowed branch and fell through to POLICY_DENY."""
    decision = _orchestrator(GovernanceMode.SHADOW).process_transaction(
        caller=_caller("u1"),
        user_id="u1",
        amount_str="10.00",
        metadata={"tenant_id": "t"},
        risk_score="10",
    )

    assert decision.reason is not ReasonCode.POLICY_DENY
    assert decision.status is not DecisionStatus.BLOCKED
    assert decision.status is DecisionStatus.APPROVED
    assert decision.reason is ReasonCode.POLICY_OBSERVED


def test_observation_is_distinguishable_from_a_real_allow():
    """Observation must not be recorded as CLEARED, or the audit trail cannot
    tell an observed action from a genuinely permitted one."""
    decision = _orchestrator(GovernanceMode.SHADOW).process_transaction(
        caller=_caller("u1"),
        user_id="u1",
        amount_str="10.00",
        metadata={"tenant_id": "t"},
        risk_score="10",
    )
    assert decision.reason is ReasonCode.POLICY_OBSERVED
    assert decision.reason is not ReasonCode.CLEARED


def test_shadow_still_enforces_authorization():
    """B. SHADOW is observational about POLICY, not about who you are."""
    decision = _orchestrator(GovernanceMode.SHADOW).process_transaction(
        caller=_caller("u1"),
        user_id="someone-else",
        amount_str="10.00",
        metadata={"tenant_id": "t"},
        risk_score="10",
    )
    assert decision.status is DecisionStatus.BLOCKED
    assert decision.reason is ReasonCode.AUTHORIZATION_FAILED


def test_human_gated_still_requires_human_approval():
    """C."""
    decision = _orchestrator(GovernanceMode.HUMAN_GATED).process_transaction(
        caller=_caller("admin1", "admin"),
        user_id="victim",
        amount_str="10.00",
        metadata={"tenant_id": "t"},
        risk_score="10",
    )
    assert decision.status is DecisionStatus.REVIEW
    assert decision.reason is ReasonCode.POLICY_REQUIRES_HUMAN
    assert decision.decision_id


@pytest.mark.parametrize("mode", ["SHADOW", "HUMAN_GATED"])
def test_unknown_action_denied_in_every_mode(mode):
    """D. Fail closed, including in SHADOW."""
    decision = evaluate(
        PolicyContext(
            action="not_a_real_action",
            actor_id="a",
            tenant_id="t",
            resource="r",
            mode=mode,
        )
    )
    assert not decision.allowed
    assert decision.status == "UNKNOWN_ACTION"


def test_unknown_mode_denied():
    """E. An unrecognised mode must never be permissive."""
    decision = evaluate(
        PolicyContext(
            action="write",
            actor_id="a",
            tenant_id="t",
            resource="r",
            mode="ACTIVE",
        )
    )
    assert not decision.allowed
    assert decision.status == "UNKNOWN_MODE"


def test_observe_invokes_no_executor():
    """F. Observation must not trigger any external/autonomous action.

    The orchestrator's only monitoring collaborator is an observational sink;
    any call it makes must be analyze_event, never an execute-style method.
    """
    calls: list[str] = []

    class _RecordingSink:
        def analyze_event(self, event, **kwargs):
            calls.append("analyze_event")
            return None

        def __getattr__(self, name):  # pragma: no cover - must never fire
            raise AssertionError(
                f"orchestrator reached for a non-observational method: {name}"
            )

    orchestrator = _orchestrator(GovernanceMode.SHADOW)
    orchestrator._monitoring_manager = _RecordingSink()

    decision = orchestrator.process_transaction(
        caller=_caller("u1"),
        user_id="u1",
        amount_str="10.00",
        metadata={"tenant_id": "t"},
        risk_score="10",
    )

    assert decision.status is DecisionStatus.APPROVED
    assert set(calls) <= {"analyze_event"}


# --------------------------------------------------------------------------- #
# 2. Sparta "compromised" must reach Watchtower as a critical finding
# --------------------------------------------------------------------------- #

def test_producer_and_scanner_share_one_vocabulary():
    assert INTEGRITY_STATUS_COMPROMISED in KNOWN_INTEGRITY_STATUSES
    assert INTEGRITY_STATUS_OK in KNOWN_INTEGRITY_STATUSES
    # "tampered" was the scanner's private vocabulary; nothing emits it.
    assert "tampered" not in KNOWN_INTEGRITY_STATUSES


def test_real_hash_mismatch_raises_a_watchtower_alert(tmp_path):
    """A + B. A genuine integrity compromise must produce the alert."""
    watched = tmp_path / "watched.bin"
    watched.write_bytes(b"original")
    wrong_digest = hashlib.sha256(b"different").hexdigest()

    manager = _manager()
    core = SpartaCore(
        _sparta_config(watched_files={str(watched): wrong_digest}),
        monitoring_manager=manager,
    )
    result = core.check_integrity()
    core.close()

    assert result.ok is False
    assert manager.get_status()["manager"]["alert_count"] > 0


def test_healthy_integrity_raises_no_alert(tmp_path):
    """C."""
    watched = tmp_path / "watched.bin"
    watched.write_bytes(b"original")
    good_digest = hashlib.sha256(b"original").hexdigest()

    manager = _manager()
    core = SpartaCore(
        _sparta_config(watched_files={str(watched): good_digest}),
        monitoring_manager=manager,
    )
    result = core.check_integrity()
    core.close()

    assert result.ok is True
    assert manager.get_status()["manager"]["alert_count"] == 0


@pytest.mark.parametrize("status", ["banana", "TAMPERED", "unknown", "0"])
def test_unrecognised_integrity_status_is_not_read_as_healthy(status):
    """D. Fail safe: an unknown status is not evidence of health."""
    manager = _manager()
    result = manager.analyze_event(
        {
            "kind": "log",
            "integrity_status": status,
            "missing_required_fields": False,
        }
    )
    assert result.alert_count > 0


def test_one_compromise_produces_one_scan():
    """E. No duplicate alert loop."""
    manager = _manager()
    manager.analyze_event(
        {
            "kind": "log",
            "integrity_status": INTEGRITY_STATUS_COMPROMISED,
            "missing_required_fields": False,
        }
    )
    assert manager.get_status()["manager"]["scan_count"] == 1


# --------------------------------------------------------------------------- #
# 3. producer-supplied event_id must be preserved
# --------------------------------------------------------------------------- #

def test_producer_event_id_is_preserved():
    event = normalize_event({"kind": "log", "event_id": "producer-abc"}).event
    assert event.id == "producer-abc"
    assert event.event_id == "producer-abc"


def test_canonical_id_is_preserved():
    assert normalize_event(
        {"kind": "log", "id": "canonical-xyz"}
    ).event.id == "canonical-xyz"


def test_identity_is_generated_when_neither_is_supplied():
    event = normalize_event({"kind": "log"}).event
    assert event.id
    assert len(event.id) >= 32


def test_matching_id_and_event_id_are_accepted():
    assert normalize_event(
        {"kind": "log", "id": "same-1", "event_id": "same-1"}
    ).event.id == "same-1"


def test_conflicting_id_and_event_id_are_rejected():
    """Ambiguous identity must fail rather than silently pick a winner."""
    with pytest.raises(ValueError, match="conflicting event identity"):
        normalize_event({"kind": "log", "id": "a-1", "event_id": "b-2"})


def test_repeated_normalization_does_not_mint_a_second_identity():
    first = normalize_event({"kind": "log", "event_id": "stable-77"}).event
    second = normalize_event(first.to_dict()).event
    third = normalize_event(second.to_dict()).event
    assert first.id == second.id == third.id == "stable-77"


@pytest.mark.parametrize("field", ["event_id", "id"])
def test_blank_identity_is_rejected_not_silently_generated(field):
    """Present-but-blank is malformed input. Generating a fresh identity for
    it would silently accept a producer bug."""
    with pytest.raises(ValueError, match="must not be empty"):
        normalize_event({"kind": "log", field: "   "})


def test_event_identity_is_not_correlation_identity():
    event = normalize_event(
        {"kind": "log", "event_id": "ev-1", "correlation_id": "corr-9"}
    ).event
    assert event.id == "ev-1"
    assert event.correlation_id == "corr-9"


# --------------------------------------------------------------------------- #
# 4. Sparta credential comparison must be byte-safe
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "credential",
    [
        "tökén-accented",
        "日本語トークン",
        "ÿþ",
        "é" * 60,
        "\U0001F511\U0001F512",
    ],
)
def test_non_ascii_credential_is_401_never_500(credential):
    """secrets.compare_digest(str, str) raises TypeError on non-ASCII, which
    would surface as an unhandled 500 instead of an auth rejection."""
    with pytest.raises(HTTPException) as caught:
        _require_node_token(f"Bearer {credential}", _sparta_config())
    assert caught.value.status_code == 401


def test_unconfigured_server_token_is_503():
    with pytest.raises(HTTPException) as caught:
        _require_node_token(
            f"Bearer {NODE_TOKEN}", _sparta_config(node_api_token="")
        )
    assert caught.value.status_code == 503


@pytest.mark.parametrize(
    "header", [None, "", "Bearer ", "Basic abc", "Bearer wrong-value"]
)
def test_missing_or_wrong_credential_is_401(header):
    with pytest.raises(HTTPException) as caught:
        _require_node_token(header, _sparta_config())
    assert caught.value.status_code == 401


def test_correct_credential_is_accepted():
    _require_node_token(f"Bearer {NODE_TOKEN}", _sparta_config())


def test_non_ascii_session_signature_fails_without_raising():
    assert _verify_token(
        "node:9999999999:sïgnätüre", TOKEN_SECRET
    ) is None


def test_valid_session_token_still_verifies():
    token = _sign_token("node-1", TOKEN_SECRET, 3600)
    assert _verify_token(token, TOKEN_SECRET) == "node-1"


# --------------------------------------------------------------------------- #
# 5. S43_AUDIT_HMAC_KEY must be in the canonical setup path
# --------------------------------------------------------------------------- #

def test_secret_generator_includes_the_audit_hmac_key():
    """docker-compose hard-requires it, so the documented generation path has
    to produce it or a correct setup still fails Compose's required check."""
    from core.cli.generate_secrets import _SECRET_SPECS

    assert "S43_AUDIT_HMAC_KEY" in {spec.key for spec in _SECRET_SPECS}


def test_generated_audit_key_satisfies_the_audit_store():
    from core.audit.store import _secret_from_str
    from core.cli.generate_secrets import _SECRET_SPECS

    spec = next(
        s for s in _SECRET_SPECS if s.key == "S43_AUDIT_HMAC_KEY"
    )
    value = spec.generator(spec.min_bytes)
    assert len(_secret_from_str(value)) >= 32


def test_env_example_documents_the_audit_hmac_key():
    root = pathlib.Path(__file__).resolve().parents[2]
    text = (root / ".env.example").read_text(encoding="utf-8")
    assert "S43_AUDIT_HMAC_KEY=" in text
    # Name and placeholder only -- never a real generated secret.
    assert "S43_AUDIT_HMAC_KEY=CHANGE_ME" in text
