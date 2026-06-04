"""
dashboard/layouts/topbar.py

Top navigation/status bar for Sentinel-43.
"""

from __future__ import annotations

from dash import html


def build_topbar() -> html.Div:
    """
    Build dashboard top status bar.

    Returns:
        html.Div: Topbar component.
    """

    return html.Div(
        [
            html.Div(
                [
                    html.Span(
                        "●",
                        className="status-indicator online",
                    ),
                    html.Span(
                        "System Online",
                        className="status-label",
                    ),
                ],
                className="topbar-status",
            ),

            html.Div(
                [
                    html.Span(
                        "Active Nodes: --",
                        id="topbar-active-nodes",
                        className="topbar-metric",
                    ),
                    html.Span(
                        "Alerts: --",
                        id="topbar-alert-count",
                        className="topbar-metric",
                    ),
                ],
                className="topbar-metrics",
            ),
        ],
        className="dashboard-topbar",
    )
