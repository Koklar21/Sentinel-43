"""
dashboard/app.py

Dash application factory for Sentinel-43 Dashboard.
"""

from __future__ import annotations

import os

from dash import Dash

from dashboard.layouts.main_layout import build_main_layout


def create_dashboard_app() -> Dash:
    """
    Create and configure the Sentinel-43 Dash app.
    """

    app = Dash(
        __name__,
        title="Sentinel-43 Dashboard",
        suppress_callback_exceptions=True,
        assets_folder="assets",
    )

    app.layout = build_main_layout()

    return app


app = create_dashboard_app()


if __name__ == "__main__":
    host = os.getenv("DASH_HOST", "0.0.0.0")
    port = int(os.getenv("DASH_PORT", "8050"))
    debug = os.getenv("DASH_DEBUG", "false").lower() == "true"

    app.run(
        host=host,
        port=port,
        debug=debug,
    )
