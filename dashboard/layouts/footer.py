"""
dashboard/layouts/footer.py

Dashboard footer layout component.
"""

from dash import html


def build_footer() -> html.Footer:
    """
    Build application footer.

    Returns:
        html.Footer: Dashboard footer component.
    """
    return html.Footer(
        [
            html.Div(
                [
                    html.Span("Sentinel-43"),
                    html.Span(" | "),
                    html.Span("Operational Monitoring Platform"),
                ],
                className="footer-content",
            )
        ],
        className="dashboard-footer",
    )
