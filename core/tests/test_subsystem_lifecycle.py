# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_subsystem_lifecycle.py
#
# Contract coverage for subsystem lifecycle state, startup configuration
# validation, and dependency-based readiness (core/lifecycle.py), plus the
# WatchtowerNode clean-shutdown distinction.
#
# The behaviour under test is "refuse to start half-alive": an enabled but
# unconfigured subsystem must be reported UNAVAILABLE with configured=false
# and a machine-readable reason, and must NOT be constructed -- which is how
# FenrirHunter previously reached HUNTING with no credential and silently
# discarded every finding.
# =============================================================================

from __future__ import annotations

import json

import pytest

from core.lifecycle import (
    Reason,
    SubsystemRegistry,
    SubsystemState,
    SubsystemStatus,
    missing_settings,
)
from core.monitoring.watchtower import (
    WatchtowerConfig,
    WatchtowerNode,
    WatchtowerState,
)


# --------------------------------------------------------------------------- #
# missing_settings: names only, never values
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "value", [None, "", "   ", "\t", "\n"],
)
def test_unset_empty_and_whitespace_count_as_missing(value):
    assert missing_settings({"S43_X": value}) == ("S43_X",)


def test_present_value_is_not_missing():
    assert missing_settings({"S43_X": "something"}) == ()


def test_missing_settings_never_returns_a_value():
    secret = "SUPERSECRET-do-not-leak"
    result = missing_settings({"S43_SET": secret, "S43_UNSET": ""})
    assert result == ("S43_UNSET",)
    assert secret not in json.dumps(result)


def test_declaration_order_is_preserved():
    assert missing_settings(
        {"S43_A": "", "S43_B": "ok", "S43_C": None}
    ) == ("S43_A", "S43_C")


# --------------------------------------------------------------------------- #
# lifecycle states
# --------------------------------------------------------------------------- #

def test_all_lifecycle_states_exist():
    assert {s.value for s in SubsystemState} == {
        "DISABLED", "STARTING", "ACTIVE", "DEGRADED",
        "UNAVAILABLE", "FAILED", "STOPPING", "STOPPED",
    }


def test_unavailable_and_failed_are_distinct():
    """"not configured" and "it broke" are different operator questions."""
    reg = SubsystemRegistry()
    reg.declare("a")
    reg.mark_unconfigured("a", ("S43_X",))
    assert reg.get("a").state is SubsystemState.UNAVAILABLE

    reg.declare("b")
    reg.mark_failed("b", "boom")
    assert reg.get("b").state is SubsystemState.FAILED


@pytest.mark.parametrize(
    "state,faulted",
    [
        (SubsystemState.DISABLED, False),
        (SubsystemState.ACTIVE, False),
        (SubsystemState.STOPPED, False),
        (SubsystemState.STARTING, True),
        (SubsystemState.DEGRADED, True),
        (SubsystemState.UNAVAILABLE, True),
        (SubsystemState.FAILED, True),
        (SubsystemState.STOPPING, True),
    ],
)
def test_disabled_and_stopped_are_not_faults(state, faulted):
    """Disabled-on-purpose and cleanly-stopped are not failures."""
    assert SubsystemStatus(name="x", state=state).faulted is faulted


def test_status_rejects_an_empty_name():
    with pytest.raises(ValueError):
        SubsystemStatus(name="   ")


# --------------------------------------------------------------------------- #
# registry + readiness policy
# --------------------------------------------------------------------------- #

def test_unconfigured_subsystem_reports_reason_and_missing_names():
    reg = SubsystemRegistry()
    reg.declare("fenrir", required=False)
    reg.mark_unconfigured(
        "fenrir", ("S43_FENRIR_API_TOKEN",), reason=Reason.MISSING_TOKEN
    )

    status = reg.get("fenrir")
    assert status.state is SubsystemState.UNAVAILABLE
    assert status.configured is False
    assert status.reason is Reason.MISSING_TOKEN
    assert status.missing == ("S43_FENRIR_API_TOKEN",)


def test_required_subsystem_not_active_blocks_readiness():
    reg = SubsystemRegistry()
    reg.declare("sparta", required=True)
    reg.mark_unconfigured("sparta", ("S43_SPARTA_NODE_TOKEN",))

    report = reg.readiness()
    assert report.ready is False
    assert "sparta" in report.blocking


def test_optional_disabled_subsystem_does_not_affect_readiness():
    reg = SubsystemRegistry()
    reg.declare("fenrir", required=False)
    reg.mark_disabled("fenrir")

    report = reg.readiness()
    assert report.ready is True
    assert report.blocking == ()
    assert report.degraded == ()


def test_optional_faulted_subsystem_is_degraded_but_still_ready():
    reg = SubsystemRegistry()
    reg.declare("fenrir", required=False)
    reg.mark_failed("fenrir", "boom")

    report = reg.readiness()
    assert report.ready is True
    assert report.degraded == ("fenrir",)
    assert reg.get("fenrir").state is SubsystemState.FAILED


def test_stopped_subsystem_is_not_reported_as_degraded():
    reg = SubsystemRegistry()
    reg.declare("sparta", required=False)
    reg.mark_active("sparta")
    reg.mark_stopped("sparta")

    report = reg.readiness()
    assert report.ready is True
    assert report.degraded == ()


def test_registry_snapshots_are_immutable_records():
    reg = SubsystemRegistry()
    reg.declare("sparta")
    first = reg.get("sparta")
    reg.mark_active("sparta")

    # The earlier snapshot must not have mutated underneath the caller.
    assert first.state is SubsystemState.DISABLED
    assert reg.get("sparta").state is SubsystemState.ACTIVE


def test_status_dict_carries_only_names_and_codes():
    reg = SubsystemRegistry()
    reg.declare("fenrir")
    reg.mark_unconfigured(
        "fenrir", ("S43_FENRIR_API_TOKEN",), reason=Reason.MISSING_TOKEN
    )
    blob = json.dumps(reg.to_dict())

    assert "S43_FENRIR_API_TOKEN" in blob
    assert "missing_token" in blob
    # The record has no field capable of holding a credential value.
    assert set(reg.get("fenrir").to_dict()) == {
        "name", "state", "configured", "required",
        "reason", "detail", "missing", "updated_at",
    }


# --------------------------------------------------------------------------- #
# WatchtowerNode: a clean shutdown is not a fault
# --------------------------------------------------------------------------- #

def _node(node_id: str = "test-node") -> WatchtowerNode:
    return WatchtowerNode(
        WatchtowerConfig.default_sentinel_octagon(node_id)
    )


def test_clean_shutdown_is_stopped_not_failed():
    node = _node()
    node.start()
    node.stop()
    assert node.state is WatchtowerState.STOPPED


def test_stop_is_idempotent():
    node = _node()
    node.start()
    node.stop()
    node.stop()
    assert node.state is WatchtowerState.STOPPED


def test_stop_does_not_mask_a_real_failure():
    """A node that failed and is then stopped must stay FAILED."""
    node = _node()
    node.start()
    node.set_state(WatchtowerState.FAILED)
    node.stop()
    assert node.state is WatchtowerState.FAILED


def test_stopped_node_drops_events():
    assert WatchtowerState.STOPPED in WatchtowerNode._DROP_EVENT_STATES


def test_stopped_node_cannot_be_restarted_in_place():
    node = _node()
    node.start()
    node.stop()
    with pytest.raises(RuntimeError, match="STOPPED"):
        node.start()


def test_stopped_node_is_not_ready():
    node = _node()
    node.start()
    node.stop()
    assert node.readiness()["ready"] is False
    assert node.readiness()["state"] == "STOPPED"
