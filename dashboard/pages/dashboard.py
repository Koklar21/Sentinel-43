"""
dashboard/pages/dashboard.py

Main dashboard page for Sentinel-43.
"""

from __future__ import annotations

from dash import html

from dashboard.components.activity_feed import build_activity_feed
from dashboard.components.alert_panel import build_alert_panel
from dashboard.components.health_panel import build_health_panel
from dashboard.components.status_card import build_status_card


def build_dashboard_page() -> html.Div:
    """
    Build the primary Sentinel-43 dashboard page.

    Returns:
        html.Div: Dashboard page layout.
    """

    return html.Div(
        [
            html.Div(
                [
                    html.H2(
                        "System Overview",
                        className="page-title",
                    ),
                    html.P(
                        "Real-time operational status of Sentinel-43.",
                        className="page-subtitle",
                    ),
                ],
                className="page-header",
            ),

            html.Div(
                [
                    build_status_card(
                        title="API Status",
                        value="ONLINE",
                        status="healthy",
                    ),
                    build_status_card(
                        title="Watchtower",
                        value="ACTIVE",
                        status="healthy",
                    ),
                    build_status_card(
                        title="Remote Gateway",
                        value="CONNECTED",
                        status="healthy",
                    ),
                    build_status_card(
                        title="Alerts",
                        value="0",
                        status="healthy",
                    ),
                ],
                className="dashboard-status-grid",
            ),

            html.Div(
                [
                    build_health_panel(),
                    build_alert_panel(),
                ],
                className="dashboard-panel-grid",
            ),

            html.Div(
                [
                    build_activity_feed(),
                ],
                className="dashboard-activity-section",
            ),
        ],
        className="dashboard-page",
    )
