"""
Sentinel-43 Dashboard Page
Settings
"""

from __future__ import annotations

from typing import Any


PAGE_ID = "settings"
PAGE_TITLE = "Settings"


def load_settings_page() -> dict[str, Any]:
    """
    Load dashboard settings page.

    Future expansion:
    - Theme settings
    - Refresh intervals
    - API endpoint configuration
    - Dashboard preferences
    - Notification controls
    """

    return {
        "page_id": PAGE_ID,
        "page_title": PAGE_TITLE,
        "settings": {
            "theme": "dark",
            "auto_refresh": True,
            "refresh_interval_seconds": 15,
            "notifications_enabled": True,
        },
    }


def get_settings_summary() -> dict[str, Any]:
    data = load_settings_page()

    return {
        "page": PAGE_TITLE,
        "settings_loaded": True,
        "settings_count": len(data.get("settings", {})),
    }
