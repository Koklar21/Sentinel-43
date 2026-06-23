"""
Sentinel-43 Dashboard Tests
Audit Client
"""

from __future__ import annotations

from dashboard.services.audit_client import (
    get_audit_record,
    get_audit_records,
    get_audit_snapshot,
    get_audit_status,
)


def test_get_audit_records_returns_dict() -> None:
    result = get_audit_records()
    assert isinstance(result, dict)


def test_get_audit_status_returns_dict() -> None:
    result = get_audit_status()
    assert isinstance(result, dict)


def test_get_audit_record_requires_id() -> None:
    result = get_audit_record("")
    assert result["ok"] is False
    assert result["error"] is not None


def test_get_audit_snapshot_returns_dict() -> None:
    result = get_audit_snapshot()
    assert isinstance(result, dict)
    # Snapshot wraps output in ApiResponse.to_dict() — records and status
    # live inside result["data"], not at the top level.
    data = result.get("data", {})
    assert "records" in data
    assert "status" in data
