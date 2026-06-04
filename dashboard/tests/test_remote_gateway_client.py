"""
Sentinel-43 Dashboard Tests
Remote Gateway Client
"""

from __future__ import annotations

from dashboard.services.remote_gateway_client import (
    activate_remote_event,
    get_remote_audit_records,
    get_remote_gateway_health,
    get_remote_gateway_snapshot,
    get_remote_targets,
)


def test_get_remote_gateway_health_returns_dict() -> None:
    result = get_remote_gateway_health()

    assert isinstance(result, dict)


def test_get_remote_targets_returns_dict() -> None:
    result = get_remote_targets()

    assert isinstance(result, dict)


def test_get_remote_audit_records_requires_correlation_id() -> None:
    result = get_remote_audit_records("")

    assert result["ok"] is False
    assert result["error"] is not None


def test_activate_remote_event_returns_dict() -> None:
    result = activate_remote_event(
        operator_id="test-user",
        operator_role="auditor",
        target_id="test-target",
        event_type="request_diagnostic_snapshot",
        reason="Testing remote gateway event.",
        correlation_id="TEST-123456",
        dry_run=True,
    )

    assert isinstance(result, dict)


def test_get_remote_gateway_snapshot_returns_dict() -> None:
    result = get_remote_gateway_snapshot()

    assert isinstance(result, dict)

    assert "health" in result
    assert "targets" in result
