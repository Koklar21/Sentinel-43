"""
dashboard/services/remote_gateway_client.py

Remote Gateway service wrapper for Sentinel-43 Dashboard.
"""

from __future__ import annotations

from typing import Any

from dashboard.services.api_client import api_client


def fetch_remote_operations() -> dict[str, Any]:
    """
    Fetch remote operations status/events from the Sentinel-43 API.
    """
    return api_client.get_remote_operations()


def submit_remote_gateway_event(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Submit a remote gateway event to the Sentinel-43 API.
    """
    if not payload:
        return {
            "success": False,
            "error": "Remote gateway payload cannot be empty.",
        }

    return api_client.submit_remote_event(payload)


def normalize_remote_operations(response: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Normalize remote gateway API response into dashboard-ready records.
    """

    if not response:
        return []

    if isinstance(response.get("records"), list):
        return response["records"]

    if isinstance(response.get("events"), list):
        return response["events"]

    if isinstance(response.get("remote_events"), list):
        return response["remote_events"]

    if isinstance(response.get("items"), list):
        return response["items"]

    return []


def get_remote_gateway_records() -> list[dict[str, Any]]:
    """
    Fetch and normalize remote gateway records.
    """

    response = fetch_remote_operations()

    if response.get("success") is False:
        return []

    return normalize_remote_operations(response)
