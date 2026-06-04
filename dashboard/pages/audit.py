"""
dashboard/pages/audit.py

Audit log page for Sentinel-43 Dashboard.
"""

from __future__ import annotations

from dash import html


def build_audit_page() -> html.Div:
    return html.Div(
        [
            html.Div(
                [
                    html.H2("Audit Logs", className="page-title"),
                    html.P(
                        "Review system events, operator actions, and integrity records.",
                        className="page-subtitle",
                    ),
                ],
                className="page-header",
            ),

            html.Section(
                [
                    html.Div(
                        "No audit records loaded.",
                        id="audit-table-container",
                        className="audit-table-container",
                    ),
                ],
                className="audit-section card",
            ),
        ],
        className="audit-page",
    )
