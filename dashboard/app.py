"""
Sentinel-43 Dashboard Application
"""

from __future__ import annotations

from typing import Any

from dashboard.layouts.main_layout import main_layout

from dashboard.pages.dashboard import load_dashboard_page
from dashboard.pages.health import load_health_page
from dashboard.pages.watchtower import load_watchtower_page
from dashboard.pages.nodes import load_nodes_page
from dashboard.pages.audit import load_audit_page
from dashboard.pages.remote_operations import (
    load_remote_operations_page,
)
from dashboard.pages.settings import load_settings_page


PAGE_LOADERS = {
    "dashboard": load_dashboard_page,
    "health": load_health_page,
    "watchtower": load_watchtower_page,
    "nodes": load_nodes_page,
    "audit": load_audit_page,
    "remote_operations": load_remote_operations_page,
    "settings": load_settings_page,
}


class DashboardApplication:
    """
    Sentinel-43 Dashboard Controller.
    """

    def get_page(self, page_name: str) -> dict[str, Any]:
        loader = PAGE_LOADERS.get(page_name)

        if loader is None:
            return {
                "error": f"Unknown page: {page_name}",
            }

        page = loader()

        return main_layout.render(
            page_title=page.get("page_title", page_name),
            page_content=page,
        )

    def available_pages(self) -> list[str]:
        return sorted(PAGE_LOADERS.keys())


dashboard_app = DashboardApplication()
