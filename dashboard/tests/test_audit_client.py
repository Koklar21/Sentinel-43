"""
dashboard/tests/test_audit_client.py

Tests for Sentinel-43 dashboard audit client.
"""

from __future__ import annotations

from unittest.mock import Mock, patch

from dashboard.services.audit_client import (
    fetch_audit_logs,
    get_audit_records,
    normalize_audit_logs,
)


@patch("dashboard.services.audit_client.api_client")
def test_fetch_audit_logs_calls_api_client(mock_api_client: Mock) -> None:
    mock_api_client.get_audit_logs.return_value = {"records": []}

    result = fetch_audit_logs()

    assert result == {"records": []}
    mock_api_client.get_audit_logs.assert_called_once_with()


def test_normalize_audit_logs_returns_records() -> None:
    response = {"records": [{"id": "a1"}]}

    assert normalize_audit_logs(response) == [{"id": "a1"}]


def test_normalize_audit_logs_returns_logs() -> None:
    response = {"logs": [{"id": "l1"}]}

    assert normalize_audit_logs(response) == [{"id": "l1"}]


def test_normalize_audit_logs_returns_audit_logs() -> None:
    response = {"audit_logs": [{"id": "al1"}]}

    assert normalize_audit_logs(response) == [{"id": "al1"}]


def test_normalize_audit_logs_returns_items() -> None:
    response = {"items": [{"id": "i1"}]}

    assert normalize_audit_logs(response) == [{"id": "i1"}]


def test_normalize_audit_logs_returns_empty_for_empty_response() -> None:
    assert normalize_audit_logs({}) == []


def test_normalize_audit_logs_returns_empty_for_unknown_shape() -> None:
    response = {"status": "ok"}

    assert normalize_audit_logs(response) == []


@patch("dashboard.services.audit_client.fetch_audit_logs")
def test_get_audit_records_returns_empty_on_failed_response(
    mock_fetch_audit_logs: Mock,
) -> None:
    mock_fetch_audit_logs.return_value = {
        "success": False,
        "error": "backend unavailable",
    }

    assert get_audit_records() == []


@patch("dashboard.services.audit_client.fetch_audit_logs")
def test_get_audit_records_fetches_and_normalizes(
    mock_fetch_audit_logs: Mock,
) -> None:
    mock_fetch_audit_logs.return_value = {
        "records": [
            {"id": "audit-1"},
            {"id": "audit-2"},
        ]
    }

    result = get_audit_records()

    assert result == [
        {"id": "audit-1"},
        {"id": "audit-2"},
    ]
