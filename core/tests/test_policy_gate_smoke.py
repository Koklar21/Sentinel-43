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

"""Smoke tests for the Sentinel-43 Policy Gate.

Reconciled to the canonical enum-based governance model
(``core.policy_gate.governance``): the only modes are SHADOW and HUMAN_GATED.
There is no autonomous / veto mode -- the policy layer never authorises
execution on its own.

These tests pin, deterministically:
  * SHADOW is observe-only: it never returns ALLOW / executable, it returns
    OBSERVE.
  * HUMAN_GATED requires explicit human approval for a human-gated action.
  * An unknown action is denied in EVERY mode (fail-closed), including SHADOW.
  * An unknown mode is denied (fail-closed), never permissive.
  * An always-denied action (privilege escalation) is denied in every mode.
  * The obsolete autonomous-mode constants stay absent.
  * The decision dict schema is stable for audit + API clients.
"""

from __future__ import annotations

import pytest

from core.policy_gate.governance import GovernanceAction, GovernanceMode
from core.policy_gate.policy_gate import PolicyContext, evaluate

_SCHEMA_KEYS = {
    "allowed",
    "executable",
    "status",
    "mode",
    "action",
    "actor_id",
    "tenant_id",
    "resource",
    "human_approved",
    "request_id",
    "correlation_id",
    "reasons",
    "tags",
}


def _ctx(action, mode, *, human_approved: bool = False) -> PolicyContext:
    return PolicyContext(
        action=action,
        actor_id="actor-1",
        tenant_id="tenant-1",
        resource="resource-1",
        mode=mode,
        human_approved=human_approved,
    )


def _assert_schema(dec: dict) -> None:
    # Auditability is a core feature -- do not slim this schema.
    assert set(dec.keys()) == _SCHEMA_KEYS
    assert isinstance(dec["allowed"], bool)
    assert isinstance(dec["executable"], bool)
    assert isinstance(dec["status"], str)
    assert (dec["mode"] is None) or isinstance(dec["mode"], str)
    assert (dec["action"] is None) or isinstance(dec["action"], str)
    assert isinstance(dec["actor_id"], str)
    assert isinstance(dec["tenant_id"], str)
    assert isinstance(dec["resource"], str)
    assert isinstance(dec["human_approved"], bool)
    assert (dec["request_id"] is None) or isinstance(dec["request_id"], str)
    assert (dec["correlation_id"] is None) or isinstance(dec["correlation_id"], str)
    assert isinstance(dec["reasons"], list)
    assert isinstance(dec["tags"], list)


# ---------------------------------------------------------------------------
# No autonomous execution mode exists
# ---------------------------------------------------------------------------

def test_autonomous_modes_and_constants_are_absent():
    assert {m.name for m in GovernanceMode} == {"SHADOW", "HUMAN_GATED"}
    import core.policy_gate.governance as gov

    for removed in (
        "MODE_AUTONOMOUS_VETO",
        "MODE_HUMAN_GATED",
        "MODE_SHADOW",
        "AUTONOMOUS_VETO",
        "ACTION_DELETE",
    ):
        assert not hasattr(gov, removed), f"{removed} must stay removed"


# ---------------------------------------------------------------------------
# SHADOW is observe-only -- never ALLOW, never executable
# ---------------------------------------------------------------------------

def test_shadow_is_observe_only_for_a_human_gated_action():
    dec = evaluate(_ctx(GovernanceAction.DELETE, GovernanceMode.SHADOW)).to_dict()
    _assert_schema(dec)
    assert dec["status"] == "OBSERVE"
    assert dec["allowed"] is False
    assert dec["executable"] is False
    assert "shadow_observe_only" in dec["tags"]


def test_shadow_is_observe_only_for_a_read():
    dec = evaluate(_ctx(GovernanceAction.READ, GovernanceMode.SHADOW)).to_dict()
    _assert_schema(dec)
    assert dec["status"] == "OBSERVE"
    assert dec["allowed"] is False


# ---------------------------------------------------------------------------
# HUMAN_GATED requires explicit human approval
# ---------------------------------------------------------------------------

def test_human_gated_requires_approval_for_delete():
    dec = evaluate(_ctx(GovernanceAction.DELETE, GovernanceMode.HUMAN_GATED)).to_dict()
    _assert_schema(dec)
    assert dec["status"] == "REQUIRES_HUMAN"
    assert dec["allowed"] is False
    assert dec["executable"] is False
    assert "human_required" in dec["tags"]


def test_human_gated_allows_delete_only_with_human_approval():
    dec = evaluate(
        _ctx(GovernanceAction.DELETE, GovernanceMode.HUMAN_GATED, human_approved=True)
    ).to_dict()
    _assert_schema(dec)
    assert dec["status"] == "ALLOW"
    assert dec["allowed"] is True
    assert dec["human_approved"] is True


def test_human_gated_allows_a_plain_read_without_approval():
    dec = evaluate(_ctx(GovernanceAction.READ, GovernanceMode.HUMAN_GATED)).to_dict()
    _assert_schema(dec)
    assert dec["status"] == "ALLOW"
    assert dec["allowed"] is True


# ---------------------------------------------------------------------------
# Fail-closed: unknown action / unknown mode / always-denied
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode", [GovernanceMode.SHADOW, GovernanceMode.HUMAN_GATED])
def test_unknown_action_is_denied_in_every_mode(mode):
    dec = evaluate(_ctx("warp_drive", mode)).to_dict()
    _assert_schema(dec)
    assert dec["status"] == "UNKNOWN_ACTION"
    assert dec["allowed"] is False
    assert dec["executable"] is False
    assert "unknown_action" in dec["tags"]


def test_unknown_mode_is_denied_not_permissive():
    dec = evaluate(_ctx(GovernanceAction.READ, "AUTONOMOUS_VETO")).to_dict()
    _assert_schema(dec)
    assert dec["status"] == "UNKNOWN_MODE"
    assert dec["allowed"] is False
    assert dec["executable"] is False
    assert "unknown_mode" in dec["tags"]


@pytest.mark.parametrize("mode", [GovernanceMode.SHADOW, GovernanceMode.HUMAN_GATED])
def test_privilege_escalation_is_always_denied(mode):
    dec = evaluate(_ctx(GovernanceAction.PRIVILEGE_ESCALATION, mode)).to_dict()
    _assert_schema(dec)
    assert dec["status"] == "DENY"
    assert dec["allowed"] is False
    assert "always_denied" in dec["tags"]
