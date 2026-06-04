"""
Sentinel-43 Dashboard Service
Audit Client

Provides dashboard access to audit-related API endpoints.
"""

from __future__ import annotations

from typing import Any

from dashboard.services.api_client import api_get


def get_audit_records() -> dict[str, Any]:
    return api_get("/audit")


def get_audit_status() -> dict[str, Any]:
    return api_get("/audit/status")


def get_audit_record(audit_id: str) -> dict[str, Any]:
    cleaned = audit_id.strip()

    if not cleaned:
        return {
            "ok": False,
            "status_code": None,
            "data": None,
            "error": "audit_id is required",
            "headers": {},
        }

    return api_get(f"/audit/{cleaned}")


def get_audit_snapshot() -> dict[str, Any]:
    records = get_audit_records()
    status = get_audit_status()

    return {
        "ok": records.get("ok", False) and status.get("ok", False),
        "records": records,
        "status": status,
    }
