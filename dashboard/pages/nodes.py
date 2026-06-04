"""
dashboard/pages/nodes.py

Node overview page for Sentinel-43 Dashboard.
"""

from __future__ import annotations

from dash import html

from dashboard.components.node_card import build_node_card


def build_nodes_page() -> html.Div:
    """
    Build the node overview page.

    Returns:
        html.Div: Nodes page layout.
    """

    node_items = [
        {
            "name": "Watchtower",
            "status": "ACTIVE",
            "description": "System oversight, degradation tracking, and escalation monitoring.",
        },
        {
            "name": "Remote Gateway",
            "status": "CONNECTED",
            "description": "Remote command intake, event submission, and operator-facing control bridge.",
        },
        {
            "name": "Audit Layer",
            "status": "READY",
            "description": "Audit trail review, integrity checks, and event traceability.",
        },
        {
            "name": "Health Monitor",
            "status": "ONLINE",
            "description": "API readiness, dependency checks, and operational health reporting.",
        },
    ]

    return html.Div(
        [
            html.Div(
                [
                    html.H2("Nodes", className="page-title"),
                    html.P(
                        "Review registered Sentinel-43 system nodes and their current operating state.",
                        className="page-subtitle",
                    ),
                ],
                className="page-header",
            ),

            html.Div(
                [
                    build_node_card(
                        name=node["name"],
                        status=node["status"],
                        description=node["description"],
                    )
                    for node in node_items
                ],
                className="nodes-grid",
            ),
        ],
        className="nodes-page",
    )
