"""
dashboard/pages/settings.py

Settings page for Sentinel-43 Dashboard.
"""

from __future__ import annotations

from dash import dcc, html


def build_settings_page() -> html.Div:
    """
    Build the dashboard settings page.

    Returns:
        html.Div: Settings page layout.
    """

    return html.Div(
        [
            html.Div(
                [
                    html.H2("Settings", className="page-title"),
                    html.P(
                        "Configure dashboard display options and operational preferences.",
                        className="page-subtitle",
                    ),
                ],
                className="page-header",
            ),

            html.Section(
                [
                    html.H3("Dashboard Preferences", className="section-title"),

                    html.Div(
                        [
                            html.Label("Theme", className="form-label"),
                            dcc.Dropdown(
                                id="settings-theme-dropdown",
                                options=[
                                    {"label": "Dark", "value": "dark"},
                                    {"label": "Light", "value": "light"},
                                ],
                                value="dark",
                                clearable=False,
                                className="settings-dropdown",
                            ),
                        ],
                        className="settings-field",
                    ),

                    html.Div(
                        [
                            html.Label("Refresh Interval", className="form-label"),
                            dcc.Dropdown(
                                id="settings-refresh-dropdown",
                                options=[
                                    {"label": "5 seconds", "value": 5},
                                    {"label": "15 seconds", "value": 15},
                                    {"label": "30 seconds", "value": 30},
                                    {"label": "60 seconds", "value": 60},
                                ],
                                value=15,
                                clearable=False,
                                className="settings-dropdown",
                            ),
                        ],
                        className="settings-field",
                    ),
                ],
                className="settings-section card",
            ),

            html.Section(
                [
                    html.H3("Operational Controls", className="section-title"),

                    dcc.Checklist(
                        id="settings-operational-checklist",
                        options=[
                            {
                                "label": "Enable remote status polling",
                                "value": "remote_polling",
                            },
                            {
                                "label": "Show degraded nodes in topbar",
                                "value": "show_degraded",
                            },
                            {
                                "label": "Enable audit event highlighting",
                                "value": "audit_highlight",
                            },
                        ],
                        value=[
                            "remote_polling",
                            "show_degraded",
                            "audit_highlight",
                        ],
                        className="settings-checklist",
                    ),
                ],
                className="settings-section card",
            ),

            html.Div(
                [
                    html.Button(
                        "Save Settings",
                        id="settings-save-button",
                        className="primary-button",
                    ),
                    html.Div(
                        id="settings-save-status",
                        className="settings-save-status",
                    ),
                ],
                className="settings-actions",
            ),
        ],
        className="settings-page",
    )
