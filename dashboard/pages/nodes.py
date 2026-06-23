"""
Sentinel-43 Dashboard Page
Nodes
"""

from __future__ import annotations

from typing import Any

from dashboard.services.watchtower_client import (
    get_watchtower_nodes,
    get_watchtower_status,
)


PAGE_ID = "nodes"
PAGE_TITLE = "Nodes"


def load_nodes_page() -> dict[str, Any]:
    """
    Load node status page data.
    """

    return {
        "page_id": PAGE_ID,
        "page_title": PAGE_TITLE,
        "nodes": get_watchtower_nodes(),
        "status": get_watchtower_status(),
    }


def get_nodes_summary() -> dict[str, Any]:
    data = load_nodes_page()

    nodes = data.get("nodes", {})
    status = data.get("status", {})

    node_count = 0

    if isinstance(nodes.get("data"), list):
        node_count = len(nodes["data"])

    return {
        "page": PAGE_TITLE,
        "nodes_ok": nodes.get("ok", False),
        "status_ok": status.get("ok", False),
        "node_count": node_count,
    }
def build_nodes_page() -> dict[str, Any]:
    return load_nodes_page()
