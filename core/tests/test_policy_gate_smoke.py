# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
#
# Sentinel-43 is distributed under a dual-license model:
#
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
#
# Unauthorized copying, redistribution, relicensing, reverse engineering,
# or commercial exploitation outside the terms of the applicable license
# is strictly prohibited.
#
# By accessing, modifying, distributing, or using this software, you agree
# to comply with the terms of the applicable license.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
#
# Commercial Licensing:
# Contact the copyright holder for commercial licensing terms.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

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
    # Includes full audit trail fields — auditability is a core feature,
    # not a side quest. Do not remove these fields to satisfy a slim schema.
    expected = {
        "allowed",
        "status",
        "mode",
        "action",
        "actor_id",
        "tenant_id",
        "resource",
        "request_id",
        "correlation_id",
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
    assert isinstance(dec["actor_id"], str)
    assert isinstance(dec["tenant_id"], str)
    assert isinstance(dec["resource"], str)
    assert (dec["request_id"] is None) or isinstance(dec["request_id"], str)
    assert (dec["correlation_id"] is None) or isinstance(dec["correlation_id"], str)
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
