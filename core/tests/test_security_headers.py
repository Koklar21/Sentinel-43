# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_security_headers.py
#
# Beta-execution Phase 2 (F-TLS-1) -- SecurityHeadersMiddleware + the
# TrustedHost allow-list + the non-local HTTPS-origin startup assertion.
# =============================================================================

from __future__ import annotations

import importlib

import pytest

from core.api.middleware import security_headers as sh


# ---------------------------------------------------------------------------
# _effective_scheme / _peer_is_trusted_proxy (unit)
# ---------------------------------------------------------------------------

def _scope(client_ip="203.0.113.9", xfp=None, scheme="http"):
    headers = []
    if xfp is not None:
        headers.append((b"x-forwarded-proto", xfp.encode()))
    return {
        "type": "http",
        "scheme": scheme,
        "client": (client_ip, 12345),
        "headers": headers,
    }


def test_forwarded_proto_ignored_without_trusted_proxies(monkeypatch):
    monkeypatch.delenv("S43_TRUSTED_PROXIES", raising=False)
    assert sh._effective_scheme(_scope(xfp="https")) == "http"


def test_forwarded_proto_trusted_only_from_configured_cidr(monkeypatch):
    monkeypatch.setenv("S43_TRUSTED_PROXIES", "172.28.0.0/24")
    # peer inside the CIDR -> believe X-Forwarded-Proto
    assert sh._effective_scheme(_scope(client_ip="172.28.0.2", xfp="https")) == "https"
    # peer outside the CIDR -> ignore it
    assert sh._effective_scheme(_scope(client_ip="203.0.113.9", xfp="https")) == "http"


def test_direct_https_scope_is_secure(monkeypatch):
    monkeypatch.delenv("S43_TRUSTED_PROXIES", raising=False)
    assert sh._effective_scheme(_scope(scheme="https")) == "https"


# ---------------------------------------------------------------------------
# response headers via the app
# ---------------------------------------------------------------------------

@pytest.fixture()
def _client(monkeypatch):
    monkeypatch.setenv("S43_JWT_SECRET", "test-secret-security-headers")
    monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("SENTINEL_ENV", "test")
    from fastapi.testclient import TestClient
    import core.api.main as main_module

    return TestClient(main_module.app)


def test_static_hardening_headers_always_present(_client):
    r = _client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["cross-origin-opener-policy"] == "same-origin"
    assert r.headers["cross-origin-resource-policy"] == "same-site"
    assert "permissions-policy" in r.headers


def test_no_hsts_in_local_environment(_client):
    r = _client.get("/health")
    assert "strict-transport-security" not in r.headers


def test_hsts_emitted_when_forced_in_non_local(monkeypatch):
    monkeypatch.setenv("S43_JWT_SECRET", "test-secret-hsts")
    monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("SENTINEL_ENV", "test")  # keep app startup local-friendly
    monkeypatch.setenv("S43_HSTS_FORCE", "true")

    # SecurityHeadersMiddleware reads env at request time; but the local-env
    # gate is also request-time -> flip SENTINEL_ENV for the request only.
    from fastapi.testclient import TestClient
    import core.api.main as main_module

    client = TestClient(main_module.app)
    monkeypatch.setenv("SENTINEL_ENV", "production")
    r = client.get("/health")
    assert r.headers.get("strict-transport-security", "").startswith("max-age=")
    assert "includeSubDomains" in r.headers["strict-transport-security"]


def test_csp_is_opt_in(monkeypatch):
    monkeypatch.setenv("S43_JWT_SECRET", "test-secret-csp")
    monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("SENTINEL_ENV", "test")
    from fastapi.testclient import TestClient
    import core.api.main as main_module

    client = TestClient(main_module.app)
    assert "content-security-policy" not in client.get("/health").headers

    monkeypatch.setenv("S43_CONTENT_SECURITY_POLICY", "default-src 'self'")
    assert client.get("/health").headers["content-security-policy"] == "default-src 'self'"
