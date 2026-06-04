"""
Sentinel-43 Dashboard Page
Remote Operations
"""

from __future__ import annotations

from typing import Any

from dashboard.services.remote_gateway_client import (
    activate_remote_event,
    get_remote_audit_records,
    get_remote_gateway_health,
    get_remote_gateway_snapshot,
    get_remote_targets,
)


PAGE_ID = "remote_operations"
PAGE_TITLE = "Remote Operations"


def load_remote_operations_page() -> dict[str, Any]:
    """
    Load Remote Operations page data.
    """

    return {
        "page_id": PAGE_ID,
        "page_title": PAGE_TITLE,
        "snapshot": get_remote_gateway_snapshot(),
        "health": get_remote_gateway_health(),
        "targets": get_remote_targets(),
    }


def submit_remote_operation(
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


def get_remote_operation_audit(
    correlation_id: str,
) -> dict[str, Any]:
    return get_remote_audit_records(correlation_id)


def get_remote_operations_summary() -> dict[str, Any]:
    data = load_remote_operations_page()
    snapshot = data.get("snapshot", {})

    return {
        "page": PAGE_TITLE,
        "ok": snapshot.get("ok", False),
        "health_ok": data["health"].get("ok", False),
        "targets_ok": data["targets"].get("ok", False),
    }
