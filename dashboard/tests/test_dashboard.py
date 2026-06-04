"""
Sentinel-43 Dashboard Tests
Dashboard Application
"""

from __future__ import annotations

from dashboard.app import dashboard_app


def test_available_pages_returns_list() -> None:
    pages = dashboard_app.available_pages()

    assert isinstance(pages, list)
    assert "dashboard" in pages


def test_dashboard_page_loads() -> None:
    result = dashboard_app.get_page("dashboard")

    assert isinstance(result, dict)
    assert "content" in result


def test_health_page_loads() -> None:
    result = dashboard_app.get_page("health")

    assert isinstance(result, dict)
    assert "content" in result


def test_unknown_page_returns_error() -> None:
    result = dashboard_app.get_page("definitely_not_real")

    assert "error" in result
