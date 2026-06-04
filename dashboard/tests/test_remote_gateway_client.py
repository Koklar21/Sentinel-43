"""
dashboard/tests/test_remote_gateway_client.py

Tests for Sentinel-43 dashboard Remote Gateway client.
"""

from __future__ import annotations

from unittest.mock import Mock, patch

from dashboard.services.remote_gateway_client import (
    fetch_remote_operations,
    get_remote_gateway_records,
    normalize_remote_operations,
    submit_remote_gateway_event,
)


@patch("dashboard.services.remote_gateway_client.api_client")
def test_fetch_remote_operations_calls_api_client(mock_api_client: Mock) -> None:
    mock_api_client.get_remote_operations.return_value = {"events": []}

    result = fetch_remote_operations()

    assert result == {"events": []}
    mock_api_client.get_remote_operations.assert_called_once_with()


@patch("dashboard.services.remote_gateway_client.api_client")
def test_submit_remote_gateway_event_calls_api_client(mock_api_client: Mock) -> None:
    payload = {"event_type": "PING", "source": "dashboard"}
    mock_api_client.submit_remote_event.return_value = {"success": True}

    result = submit_remote_gateway_event(payload)

    assert result == {"success": True}
    mock_api_client.submit_remote_event.assert_called_once_with(payload)


def test_submit_remote_gateway_event_rejects_empty_payload() -> None:
    result = submit_remote_gateway_event({})

    assert result["success"] is False
    assert "cannot be empty" in result["error"]


def test_normalize_remote_operations_returns_records() -> None:
    response = {"records": [{"id": "r1"}]}

    assert normalize_remote_operations(response) == [{"id": "r1"}]


def test_normalize_remote_operations_returns_events() -> None:
    response = {"events": [{"id": "e1"}]}

    assert normalize_remote_operations(response) == [{"id": "e1"}]


def test_normalize_remote_operations_returns_remote_events() -> None:
    response = {"remote_events": [{"id": "re1"}]}

    assert normalize_remote_operations(response) == [{"id": "re1"}]


def test_normalize_remote_operations_returns_items() -> None:
    response = {"items": [{"id": "i1"}]}

    assert normalize_remote_operations(response) == [{"id": "i1"}]


def test_normalize_remote_operations_returns_empty_for_empty_response() -> None:
    assert normalize_remote_operations({}) == []


def test_normalize_remote_operations_returns_empty_for_unknown_shape() -> None:
    assert normalize_remote_operations({"status": "ok"}) == []


@patch("dashboard.services.remote_gateway_client.fetch_remote_operations")
def test_get_remote_gateway_records_returns_empty_on_failed_response(
    mock_fetch_remote_operations: Mock,
) -> None:
    mock_fetch_remote_operations.return_value = {
        "success": False,
        "error": "remote gateway unavailable",
    }

    assert get_remote_gateway_records() == []


@patch("dashboard.services.remote_gateway_client.fetch_remote_operations")
def test_get_remote_gateway_records_fetches_and_normalizes(
    mock_fetch_remote_operations: Mock,
) -> None:
    mock_fetch_remote_operations.return_value = {
        "events": [
            {"id": "remote-1"},
            {"id": "remote-2"},
        ]
    }

    result = get_remote_gateway_records()

    assert result == [
        {"id": "remote-1"},
        {"id": "remote-2"},
    ]
