"""
dashboard/layouts/main_layout.py

Main dashboard layout assembly for Sentinel-43.
"""

from __future__ import annotations

from dash import dcc, html

from dashboard.layouts.footer import build_footer
from dashboard.layouts.header import build_header
from dashboard.pages.remote_operations import build_remote_operations_page


def build_main_layout() -> html.Div:
    """
    Build the primary Sentinel-43 dashboard layout.

    Returns:
        html.Div: Complete dashboard shell.
    """
    return html.Div(
        [
            dcc.Location(id="url", refresh=False),

            html.Div(
                [
                    build_header(),

                    html.Main(
                        [
                            html.Div(
                                id="page-content",
                                children=build_remote_operations_page(),
                                className="page-content-inner",
                            )
                        ],
                        className="dashboard-main",
                    ),

                    build_footer(),
                ],
                className="dashboard-shell",
            ),
        ],
        className="dashboard-root",
    )
