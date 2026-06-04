"""
dashboard/pages/watchtower.py

Watchtower monitoring page for Sentinel-43.
"""

from __future__ import annotations

from dash import html

from dashboard.components.alert_panel import build_alert_panel
from dashboard.components.status_card import build_status_card


def build_watchtower_page() -> html.Div:
    """
    Build the Watchtower monitoring page.

    Returns:
        html.Div: Watchtower page layout.
    """

    return html.Div(
        [
            html.Div(
                [
                    html.H2(
                        "Watchtower",
                        className="page-title",
                    ),
                    html.P(
                        (
                            "Monitor Sentinel-43 tower health, "
                            "degradation state, and escalation conditions."
                        ),
                        className="page-subtitle",
                    ),
                ],
                className="page-header",
            ),

            html.Div(
                [
                    build_status_card(
                        title="Overall Status",
                        value="ACTIVE",
                        status="healthy",
                    ),
                    build_status_card(
                        title="Tower Count",
                        value="8",
                        status="healthy",
                    ),
                    build_status_card(
                        title="Degraded Towers",
                        value="0",
                        status="healthy",
                    ),
                    build_status_card(
                        title="Active Alerts",
                        value="0",
                        status="healthy",
                    ),
                ],
                className="watchtower-status-grid",
            ),

            html.Div(
                [
                    html.Div(
                        [
                            html.H3(
                                "Tower Overview",
                                className="section-title",
                            ),

                            html.Ul(
                                [
                                    html.Li("API_HEALTH"),
                                    html.Li("EXPECTATION_GUARD"),
                                    html.Li("CONFIG_DRIFT"),
                                    html.Li("LOGGING_AUDIT"),
                                    html.Li("ERROR_RATE"),
                                    html.Li("DEPENDENCY_HEALTH"),
                                    html.Li("RESOURCE_PRESSURE"),
                                    html.Li("SECURITY_BASELINE"),
                                ],
                                className="tower-list",
                            ),
                        ],
                        className="card watchtower-overview",
                    ),

                    build_alert_panel(),
                ],
                className="watchtower-panel-grid",
            ),
        ],
        className="watchtower-page",
    )
