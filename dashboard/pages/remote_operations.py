"""
Sentinel-43 Dashboard Page: Remote Operations.

This page is the dashboard-facing UI logic for authorized remote operations.
It does NOT perform backend authorization directly. It calls the API service layer.
"""

from __future__ import annotations

from typing import Any

from dashboard.services.remote_gateway_client import (
    activate_remote_event,
    get_remote_gateway_health,
    get_remote_targets,
)


PAGE_TITLE = "Remote Operations"


def load_remote_operations_page() -> dict[str, Any]:
    """
    Load initial remote operations page data.

    Used by the dashboard app to render:
      - Gateway health
      - Registered targets
      - Available event types
    """
    gateway_health = get_remote_gateway_health()
    targets = get_remote_targets()

    return {
        "page": PAGE_TITLE,
        "gateway_health": gateway_health,
        "targets": targets,
        "ready": gateway_health.get("enabled", False),
    }


def submit_remote_event(
    *,
    operator_id: str,
    operator_role: str,
    target_id: str,
    event_type: str,
    reason: str,
    correlation_id: str,
    dry_run: bool = True,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Submit a remote event activation request through the service client.

    The backend remote gateway still performs:
      - token validation
      - role validation
      - target validation
      - event validation
      - audit logging
    """
    return activate_remote_event(
        operator_id=operator_id,
        operator_role=operator_role,
        target_id=target_id,
        event_type=event_type,
        reason=reason,
        correlation_id=correlation_id,
        dry_run=dry_run,
        payload=payload or {},
    )


def render_remote_operations_summary() -> dict[str, Any]:
    """
    Lightweight page summary.

    This keeps dashboard/app.py from needing to know endpoint details.
    """
    data = load_remote_operations_page()

    return {
        "title": PAGE_TITLE,
        "gateway_state": data.get("gateway_health", {}).get("state", "unknown"),
        "gateway_enabled": data.get("gateway_health", {}).get("enabled", False),
        "target_count": len(data.get("targets", [])),
        "targets": data.get("targets", []),
    }
