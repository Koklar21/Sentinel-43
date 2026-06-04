"""
dashboard/tests/test_api_client.py

Tests for Sentinel-43 dashboard API client.
"""

from __future__ import annotations

from unittest.mock import Mock, patch

import requests

from dashboard.services.api_client import APIClient


def test_api_client_initializes_with_clean_base_url() -> None:
    client = APIClient(base_url="http://localhost:8000/")

    assert client.base_url == "http://localhost:8000"


@patch("dashboard.services.api_client.requests.request")
def test_request_returns_json_response(mock_request: Mock) -> None:
    mock_response = Mock()
    mock_response.content = b'{"status":"ok"}'
    mock_response.json.return_value = {"status": "ok"}
    mock_response.raise_for_status.return_value = None

    mock_request.return_value = mock_response

    client = APIClient(base_url="http://localhost:8000")
    result = client.get_health()

    assert result == {"status": "ok"}
    mock_request.assert_called_once_with(
        method="GET",
        url="http://localhost:8000/health",
        timeout=10,
    )


@patch("dashboard.services.api_client.requests.request")
def test_request_returns_empty_dict_for_empty_response(mock_request: Mock) -> None:
    mock_response = Mock()
    mock_response.content = b""
    mock_response.raise_for_status.return_value = None

    mock_request.return_value = mock_response

    client = APIClient()
    result = client.get_ready()

    assert result == {}


@patch("dashboard.services.api_client.requests.request")
def test_request_handles_request_exception(mock_request: Mock) -> None:
    mock_request.side_effect = requests.RequestException("connection failed")

    client = APIClient(base_url="http://localhost:8000")
    result = client.get_health()

    assert result["success"] is False
    assert "connection failed" in result["error"]


@patch("dashboard.services.api_client.requests.request")
def test_get_root_calls_root_endpoint(mock_request: Mock) -> None:
    mock_response = Mock()
    mock_response.content = b'{"name":"sentinel"}'
    mock_response.json.return_value = {"name": "sentinel"}
    mock_response.raise_for_status.return_value = None

    mock_request.return_value = mock_response

    client = APIClient(base_url="http://localhost:8000")
    result = client.get_root()

    assert result == {"name": "sentinel"}
    assert mock_request.call_args.kwargs["url"] == "http://localhost:8000/"


@patch("dashboard.services.api_client.requests.request")
def test_submit_remote_event_posts_payload(mock_request: Mock) -> None:
    mock_response = Mock()
    mock_response.content = b'{"success":true}'
    mock_response.json.return_value = {"success": True}
    mock_response.raise_for_status.return_value = None

    mock_request.return_value = mock_response

    client = APIClient(base_url="http://localhost:8000")
    payload = {"event": "test"}

    result = client.submit_remote_event(payload)

    assert result == {"success": True}
    mock_request.assert_called_once_with(
        method="POST",
        url="http://localhost:8000/remote-operations",
        timeout=10,
        json=payload,
    )


def test_endpoint_methods_exist() -> None:
    client = APIClient(base_url="http://localhost:8000")

    assert callable(client.get_health)
    assert callable(client.get_ready)
    assert callable(client.get_root)
    assert callable(client.get_watchtower_status)
    assert callable(client.get_remote_operations)
    assert callable(client.submit_remote_event)
    assert callable(client.get_audit_logs)
    assert callable(client.get_node_status)
