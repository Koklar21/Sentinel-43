"""
Sentinel-43 Dashboard Layout
Sidebar
"""

from __future__ import annotations

from typing import Any


class Sidebar:
    """
    Dashboard navigation sidebar.
    """

    def __init__(self) -> None:
        self.navigation = [
            {
                "id": "dashboard",
                "label": "Dashboard",
                "route": "/dashboard",
            },
            {
                "id": "health",
                "label": "Health",
                "route": "/health",
            },
            {
                "id": "watchtower",
                "label": "Watchtower",
                "route": "/watchtower",
            },
            {
                "id": "nodes",
                "label": "Nodes",
                "route": "/nodes",
            },
            {
                "id": "audit",
                "label": "Audit",
                "route": "/audit",
            },
            {
                "id": "remote_operations",
                "label": "Remote Operations",
                "route": "/remote-operations",
            },
            {
                "id": "settings",
                "label": "Settings",
                "route": "/settings",
            },
        ]

    def render(self) -> dict[str, Any]:
        return {
            "title": "Sentinel-43",
            "navigation": self.navigation,
            "navigation_count": len(self.navigation),
        }


sidebar = Sidebar()
def build_sidebar() -> Sidebar:
    return Sidebar()
