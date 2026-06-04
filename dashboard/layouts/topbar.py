"""
Sentinel-43 Dashboard Layout
Topbar
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class Topbar:
    """
    Dashboard top navigation bar.
    """

    def render(
        self,
        *,
        page_title: str,
    ) -> dict[str, Any]:
        return {
            "page_title": page_title,
            "system_name": "Sentinel-43",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "online",
        }


topbar = Topbar()
