"""
Sentinel-43 Dashboard Tests
API Client
"""

from __future__ import annotations

from dashboard.services.api_client import (
    ApiClient,
    ApiResponse,
)


def test_api_response_to_dict() -> None:
    response = ApiResponse(
        ok=True,
        status_code=200,
        data={"status": "ok"},
    )

    result = response.to_dict()

    assert result["ok"] is True
    assert result["status_code"] == 200


def test_api_client_build_url() -> None:
    client = ApiClient(
        base_url="http://localhost:8000",
    )

    url = client._build_url("/health")

    assert url == "http://localhost:8000/health"


def test_api_client_build_url_without_slash() -> None:
    client = ApiClient(
        base_url="http://localhost:8000",
    )

    url = client._build_url("health")

    assert url == "http://localhost:8000/health"


def test_api_client_accepts_absolute_url() -> None:
    client = ApiClient()

    url = client._build_url(
        "https://example.com/test",
    )

    assert url == "https://example.com/test"
