"""
Sentinel-43 Dashboard Service
Remote Gateway Client

Calls the authorized Remote Gateway API endpoints.
"""

from __future__ import annotations

from typing import Any

from dashboard.services.api_client import api_get, api_post


def get_remote_gateway_health() -> dict[str, Any]:
    return api_get("/remote/health")


def get_remote_targets() -> dict[str, Any]:
    return api_get("/remote/targets")


def activate_remote_event(
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
    body = {
        "operator_id": operator_id,
        "operator_role": operator_role,
        "target_id": target_id,
        "event_type": event_type,
        "reason": reason,
        "correlation_id": correlation_id,
        "dry_run": dry_run,
        "payload": payload or {},
    }

    return api_post("/remote/events/activate", body)


def get_remote_audit_records(correlation_id: str) -> dict[str, Any]:
    cleaned = correlation_id.strip()

    if not cleaned:
        return {
            "ok": False,
            "status_code": None,
            "data": None,
            "error": "correlation_id is required",
            "headers": {},
        }

    return api_get(f"/remote/audit/{cleaned}")


def get_remote_gateway_snapshot() -> dict[str, Any]:
    health = get_remote_gateway_health()
    targets = get_remote_targets()

    return {
        "ok": health.get("ok", False) and targets.get("ok", False),
        "health": health,
        "targets": targets,
    }
