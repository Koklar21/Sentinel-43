"""
dashboard/tests/test_health_client.py

Tests for Sentinel-43 health client.
"""

from __future__ import annotations

from unittest.mock import Mock, patch

from dashboard.services.health_client import (
    fetch_health,
    fetch_ready,
    get_health_status,
)


@patch("dashboard.services.health_client.api_client")
def test_fetch_health_calls_api_client(
    mock_api_client: Mock,
) -> None:
    mock_api_client.get_health.return_value = {
        "status": "healthy",
    }

    result = fetch_health()

    assert result == {
        "status": "healthy",
    }

    mock_api_client.get_health.assert_called_once_with()


@patch("dashboard.services.health_client.api_client")
def test_fetch_ready_calls_api_client(
    mock_api_client: Mock,
) -> None:
    mock_api_client.get_ready.return_value = {
        "ready": True,
    }

    result = fetch_ready()

    assert result == {
        "ready": True,
    }

    mock_api_client.get_ready.assert_called_once_with()


@patch("dashboard.services.health_client.fetch_health")
@patch("dashboard.services.health_client.fetch_ready")
def test_get_health_status_combines_results(
    mock_fetch_ready: Mock,
    mock_fetch_health: Mock,
) -> None:
    mock_fetch_health.return_value = {
        "status": "healthy",
    }

    mock_fetch_ready.return_value = {
        "ready": True,
    }

    result = get_health_status()

    assert result["health"]["status"] == "healthy"
    assert result["ready"]["ready"] is True


@patch("dashboard.services.health_client.fetch_health")
@patch("dashboard.services.health_client.fetch_ready")
def test_get_health_status_handles_empty_results(
    mock_fetch_ready: Mock,
    mock_fetch_health: Mock,
) -> None:
    mock_fetch_health.return_value = {}
    mock_fetch_ready.return_value = {}

    result = get_health_status()

    assert result["health"] == {}
    assert result["ready"] == {}
