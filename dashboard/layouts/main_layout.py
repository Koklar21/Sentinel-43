"""
Sentinel-43 Dashboard Layout
Main Layout
"""

from __future__ import annotations

from typing import Any

from dashboard.layouts.footer import footer
from dashboard.layouts.sidebar import sidebar
from dashboard.layouts.topbar import topbar


class MainLayout:
    """
    Primary dashboard layout.

    Composes:
    - Topbar
    - Sidebar
    - Page Content
    - Footer
    """

    def render(
        self,
        *,
        page_title: str,
        page_content: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "title": page_title,
            "topbar": topbar.render(page_title=page_title),
            "sidebar": sidebar.render(),
            "content": page_content,
            "footer": footer.render(),
        }


main_layout = MainLayout()
def build_main_layout(
    page_title: str,
    page_content: dict[str, Any],
) -> dict[str, Any]:
    return main_layout.render(
        page_title=page_title,
        page_content=page_content,
    )
