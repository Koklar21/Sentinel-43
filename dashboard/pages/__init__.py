"""
dashboard.pages

Page exports for the Sentinel-43 Dashboard.
"""

from .audit import build_audit_page
from .dashboard import build_dashboard_page
from .health import build_health_page
from .nodes import build_nodes_page
from .remote_operations import build_remote_operations_page
from .settings import build_settings_page
from .watchtower import build_watchtower_page

__all__ = [
    "build_audit_page",
    "build_dashboard_page",
    "build_health_page",
    "build_nodes_page",
    "build_remote_operations_page",
    "build_settings_page",
    "build_watchtower_page",
]
