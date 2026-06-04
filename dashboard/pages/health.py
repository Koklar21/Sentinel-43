"""
dashboard/pages/health.py

System health page for Sentinel-43.
"""

from __future__ import annotations

from dash import html

from dashboard.components.health_panel import build_health_panel
from dashboard.components.status_card import build_status_card


def build_health_page() -> html.Div:
    """
    Build the system health page.

    Returns:
        html.Div: Health page layout.
    """

    return html.Div(
        [
            html.Div(
                [
                    html.H2(
                        "System Health",
                        className="page-title",
                    ),
                    html.P(
                        "Monitor overall platform health and operational readiness.",
                        className="page-subtitle",
                    ),
                ],
                className="page-header",
            ),

            html.Div(
                [
                    build_status_card(
                        title="API",
                        value="ONLINE",
                        status="healthy",
                    ),
                    build_status_card(
                        title="Watchtower",
                        value="ACTIVE",
                        status="healthy",
                    ),
                    build_status_card(
                        title="Database",
                        value="CONNECTED",
                        status="healthy",
                    ),
                    build_status_card(
                        title="Remote Gateway",
                        value="CONNECTED",
                        status="healthy",
                    ),
                ],
                className="health-status-grid",
            ),

            html.Div(
                [
                    build_health_panel(),
                ],
                className="health-panel-section",
            ),
        ],
        className="health-page",
    )
