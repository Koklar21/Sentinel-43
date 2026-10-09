"""Router ingress credential edge cases (no live network required)."""
import pytest
from fastapi import HTTPException
from core.api.routers import router_telemetry as ingress


def test_unicode_supplied_token_is_unauthorized(monkeypatch):
    monkeypatch.setenv("S43_ROUTER_INGEST_TOKEN", "a" * 40)
    with pytest.raises(HTTPException) as error:
        ingress._authorize("Bearer " + "é" * 40)
    assert error.value.status_code == 401


def test_unicode_configured_token_fails_closed(monkeypatch):
    monkeypatch.setenv("S43_ROUTER_INGEST_TOKEN", "é" * 40)
    with pytest.raises(HTTPException) as error:
        ingress._authorize("Bearer " + "é" * 40)
    assert error.value.status_code == 503


@pytest.mark.parametrize("header", [None, "", "Basic " + "a" * 40, "Bearer wrong", "Bearer "])
def test_missing_or_invalid_router_auth_is_unauthorized(monkeypatch, header):
    monkeypatch.setenv("S43_ROUTER_INGEST_TOKEN", "a" * 40)
    with pytest.raises(HTTPException) as error:
        ingress._authorize(header)
    assert error.value.status_code == 401


def test_valid_router_auth_remains_supported(monkeypatch):
    monkeypatch.setenv("S43_ROUTER_INGEST_TOKEN", "a" * 40)
    assert ingress._authorize("Bearer " + "a" * 40) is None
