"""
Sentinel-43 Dashboard Page
Audit
"""

from __future__ import annotations

from typing import Any

from dashboard.services.audit_client import (
    get_audit_record,
    get_audit_records,
    get_audit_snapshot,
    get_audit_status,
)


PAGE_ID = "audit"
PAGE_TITLE = "Audit"


def load_audit_page() -> dict[str, Any]:
    """
    Load Audit page data.
    """

    return {
        "page_id": PAGE_ID,
        "page_title": PAGE_TITLE,
        "snapshot": get_audit_snapshot(),
        "records": get_audit_records(),
        "status": get_audit_status(),
    }


def load_audit_record(audit_id: str) -> dict[str, Any]:
    return get_audit_record(audit_id)


def get_audit_summary() -> dict[str, Any]:
    data = load_audit_page()
    snapshot = data.get("snapshot", {})

    return {
        "page": PAGE_TITLE,
        "ok": snapshot.get("ok", False),
        "records_ok": data["records"].get("ok", False),
        "status_ok": data["status"].get("ok", False),
    }
