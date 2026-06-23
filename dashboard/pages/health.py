"""
Sentinel-43 Dashboard Page
Health
"""

from __future__ import annotations

from typing import Any

from dashboard.services.health_client import (
    get_api_health,
    get_api_metrics,
    get_api_ready,
    get_api_status,
    get_health_snapshot,
)


PAGE_ID = "health"
PAGE_TITLE = "System Health"


def load_health_page() -> dict[str, Any]:
    """
    Load health page data.
    """

    return {
        "page_id": PAGE_ID,
        "page_title": PAGE_TITLE,
        "snapshot": get_health_snapshot(),
        "health": get_api_health(),
        "ready": get_api_ready(),
        "status": get_api_status(),
        "metrics": get_api_metrics(),
    }


def get_health_summary() -> dict[str, Any]:
    data = load_health_page()
    snapshot = data.get("snapshot", {})

    return {
        "page": PAGE_TITLE,
        "ok": snapshot.get("ok", False),
        "health_ok": data["health"].get("ok", False),
        "ready_ok": data["ready"].get("ok", False),
        "status_ok": data["status"].get("ok", False),
        "metrics_ok": data["metrics"].get("ok", False),
    }
def build_health_page() -> dict[str, Any]:
    return load_health_page()
