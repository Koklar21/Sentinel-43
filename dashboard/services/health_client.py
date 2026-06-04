"""
dashboard/services/audit_client.py

Audit-specific service wrapper for Sentinel-43 Dashboard.
"""

from __future__ import annotations

from typing import Any

from dashboard.services.api_client import api_client


def fetch_audit_logs() -> dict[str, Any]:
    """
    Fetch audit log records from the Sentinel-43 API.

    Returns:
        dict[str, Any]: Audit log response payload.
    """
    return api_client.get_audit_logs()


def normalize_audit_logs(response: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Normalize audit API response into a list of audit records.

    Returns:
        list[dict[str, Any]]: Normalized audit log records.
    """

    if not response:
        return []

    if isinstance(response.get("records"), list):
        return response["records"]

    if isinstance(response.get("logs"), list):
        return response["logs"]

    if isinstance(response.get("audit_logs"), list):
        return response["audit_logs"]

    if isinstance(response.get("items"), list):
        return response["items"]

    return []


def get_audit_records() -> list[dict[str, Any]]:
    """
    Fetch and normalize audit records.

    Returns:
        list[dict[str, Any]]: Audit records ready for dashboard display.
    """

    response = fetch_audit_logs()

    if response.get("success") is False:
        return []

    return normalize_audit_logs(response)
