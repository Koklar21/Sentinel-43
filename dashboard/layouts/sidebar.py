"""
dashboard/layouts/sidebar.py

Sentinel-43 dashboard sidebar navigation.
"""

from __future__ import annotations

from dash import dcc, html


def build_sidebar() -> html.Div:
    """
    Build dashboard sidebar navigation.

    Returns:
        html.Div: Sidebar component.
    """

    nav_items = [
        ("Dashboard", "/"),
        ("Remote Operations", "/remote-operations"),
        ("System Health", "/health"),
        ("Activity Feed", "/activity"),
        ("Audit Logs", "/audit"),
        ("Watchtower", "/watchtower"),
        ("Settings", "/settings"),
    ]

    return html.Div(
        [
            html.Div(
                [
                    html.H3(
                        "Sentinel-43",
                        className="sidebar-title",
                    ),
                    html.Hr(className="sidebar-divider"),
                ]
            ),

            html.Nav(
                [
                    dcc.Link(
                        label,
                        href=route,
                        className="sidebar-link",
                    )
                    for label, route in nav_items
                ],
                className="sidebar-nav",
            ),
        ],
        className="dashboard-sidebar",
    )
