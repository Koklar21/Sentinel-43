"""
dashboard/tests/test_dashboard.py

Tests for Sentinel-43 dashboard page layout.
"""

from __future__ import annotations

from dash import html

from dashboard.pages.dashboard import build_dashboard_page


def test_build_dashboard_page_returns_div() -> None:
    page = build_dashboard_page()

    assert isinstance(page, html.Div)


def test_dashboard_page_has_expected_class_name() -> None:
    page = build_dashboard_page()

    assert page.className == "dashboard-page"


def test_dashboard_page_contains_header_and_sections() -> None:
    page = build_dashboard_page()

    class_names = [
        getattr(child, "className", None)
        for child in page.children
    ]

    assert "page-header" in class_names
    assert "dashboard-status-grid" in class_names
    assert "dashboard-panel-grid" in class_names
    assert "dashboard-activity-section" in class_names


def test_dashboard_page_title_is_system_overview() -> None:
    page = build_dashboard_page()

    header = page.children[0]
    title = header.children[0]

    assert title.children == "System Overview"
