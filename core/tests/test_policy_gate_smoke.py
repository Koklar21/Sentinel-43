"""
Smoke tests for Sentinel-43 Policy Gate

These tests are intentionally small and deterministic.
They validate:
- SHADOW never blocks but records shadow_would_status
- HUMAN_GATED requires approval for high-risk actions
- AUTONOMOUS_VETO blocks high-risk actions
- Unknown actions are deny-by-default outside SHADOW
- Decision schema is stable
"""

from __future__ import annotations

import pytest

from core.policy_gate.governance import (
    MODE_AUTONOMOUS_VETO,
    MODE_HUMAN_GATED,
    MODE_SHADOW,
    ACTION_DELETE,
    ACTION_READ,
)
from core.policy_gate.policy_gate import PolicyContext, evaluate


def _assert_schema(dec: dict) -> None:
    # Schema must be stable for audit + API clients.
    expected = {
        "allowed",
        "status",
        "mode",
        "action",
        "reasons",
        "tags",
        "shadow_would_status",
        "evaluated_at",
    }
    assert set(dec.keys()) == expected
    assert isinstance(dec["allowed"], bool)
    assert isinstance(dec["status"], str)
    assert isinstance(dec["mode"], str)
    assert isinstance(dec["action"], str)
    assert isinstance(dec["reasons"], list)
    assert isinstance(dec["tags"], list)
    assert (dec["shadow_would_status"] is None) or isinstance(dec["shadow_would_status"], str)
    assert isinstance(dec["evaluated_at"], str)


def test_shadow_allows_but_records_would_status_for_risky_action():
    ctx = PolicyContext(action=ACTION_DELETE, mode=MODE_SHADOW)
    decision = evaluate(ctx).to_dict()
    _assert_schema(decision)

    assert decision["allowed"] is True
    assert decision["status"] == "ALLOW"
    # Delete requires human approval in non-shadow by default governance
    assert decision["shadow_would_status"] in {"REQUIRES_HUMAN", "DENY"}


def test_human_gated_requires_approval_for_delete():
    ctx = PolicyContext(action=ACTION_DELETE, mode=MODE_HUMAN_GATED)
    decision = evaluate(ctx).to_dict()
    _assert_schema(decision)

    assert decision["allowed"] is False
    assert decision["status"] == "REQUIRES_HUMAN"
    assert decision["shadow_would_status"] is None


def test_autonomous_veto_denies_delete():
    ctx = PolicyContext(action=ACTION_DELETE, mode=MODE_AUTONOMOUS_VETO)
    decision = evaluate(ctx).to_dict()
    _assert_schema(decision)

    assert decision["allowed"] is False
    assert decision["status"] == "DENY"
    assert "autonomous_veto" in decision["tags"]


def test_read_is_allowed_in_all_modes():
    for mode in (MODE_SHADOW, MODE_HUMAN_GATED, MODE_AUTONOMOUS_VETO):
        ctx = PolicyContext(action=ACTION_READ, mode=mode)
        decision = evaluate(ctx).to_dict()
        _assert_schema(decision)

        assert decision["allowed"] is True
        assert decision["status"] == "ALLOW"


def test_unknown_action_denied_by_default_outside_shadow():
    ctx = PolicyContext(action="warp_drive", mode=MODE_HUMAN_GATED)
    decision = evaluate(ctx).to_dict()
    _assert_schema(decision)

    assert decision["allowed"] is False
    assert decision["status"] == "UNKNOWN_ACTION"
    assert "deny_by_default" in decision["tags"]


def test_unknown_action_allowed_in_shadow_but_flagged():
    ctx = PolicyContext(action="warp_drive", mode=MODE_SHADOW)
    decision = evaluate(ctx).to_dict()
    _assert_schema(decision)

    assert decision["allowed"] is True
    assert decision["status"] == "UNKNOWN_ACTION"
    assert decision["shadow_would_status"] == "DENY"
    assert "unknown_action" in decision["tags"]