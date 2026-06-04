"""
Sentinel-43 Dashboard Page
Watchtower
"""

from __future__ import annotations

from typing import Any

from dashboard.services.watchtower_client import (
    get_watchtower_alerts,
    get_watchtower_health,
    get_watchtower_metrics,
    get_watchtower_nodes,
    get_watchtower_snapshot,
    get_watchtower_status,
)


PAGE_ID = "watchtower"
PAGE_TITLE = "Watchtower"


def load_watchtower_page() -> dict[str, Any]:
    """
    Load Watchtower page data.
    """

    return {
        "page_id": PAGE_ID,
        "page_title": PAGE_TITLE,
        "snapshot": get_watchtower_snapshot(),
        "health": get_watchtower_health(),
        "status": get_watchtower_status(),
        "nodes": get_watchtower_nodes(),
        "alerts": get_watchtower_alerts(),
        "metrics": get_watchtower_metrics(),
    }


def get_watchtower_summary() -> dict[str, Any]:
    data = load_watchtower_page()
    snapshot = data.get("snapshot", {})

    return {
        "page": PAGE_TITLE,
        "ok": snapshot.get("ok", False),
        "health_ok": data["health"].get("ok", False),
        "status_ok": data["status"].get("ok", False),
        "nodes_ok": data["nodes"].get("ok", False),
        "alerts_ok": data["alerts"].get("ok", False),
        "metrics_ok": data["metrics"].get("ok", False),
    }
