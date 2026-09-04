# =============================================================================
# Sentinel-43 -- target acceptance: READ-ONLY edge checks.
#
# No login, no credentials, no mutation. Verifies the deployed target's TLS
# edge and public surface the way a browser sees it. Separate from the
# authenticated acceptance suite on purpose.
# =============================================================================

from __future__ import annotations

import socket
import urllib.error
import urllib.request

from _targetlib import target_request, tls_context


def test_edge_certificate_is_trusted_by_a_real_ca(target_base_url):
    host = target_base_url.split("://", 1)[1].split("/", 1)[0]
    hostname, _, port = host.partition(":")
    ctx = tls_context()
    with socket.create_connection((hostname, int(port or 443)), timeout=15) as s:
        with ctx.wrap_socket(s, server_hostname=hostname) as ss:
            # If we got here the chain validated and the hostname matched
            # (incl. a valid wildcard) -- the library did it, not a string
            # compare.
            assert ss.version().startswith("TLSv1.")


def test_health_and_ready_are_served_over_https(target_base_url):
    for path in ("/health", "/ready"):
        status, _ = target_request("GET", path)
        assert status == 200, (path, status)


def test_the_served_spa_loads_over_the_real_edge(target_page, target_base_url):
    resp = target_page.goto(target_base_url + "/dashboard")
    assert resp is not None and resp.status == 200
    target_page.wait_for_selector("#s43-login-overlay")
    assert target_page.evaluate("typeof window.SentinelAuth === 'object'")
    assert target_page._s43_tls_errors == [], target_page._s43_tls_errors


def test_docs_surface_is_not_publicly_served(target_base_url):
    for path in ("/docs", "/redoc", "/openapi.json"):
        status, _ = target_request("GET", path)
        assert status in (401, 403, 404), (path, status)


def test_hsts_is_present_at_the_edge(target_base_url):
    req = urllib.request.Request(target_base_url + "/health",
                                 headers={"User-Agent": "s43-target-acceptance"})
    with urllib.request.urlopen(req, timeout=15, context=tls_context()) as resp:
        hsts = resp.headers.get("Strict-Transport-Security", "")
    assert "max-age=" in hsts and "max-age=0" not in hsts, hsts


def test_plain_http_redirects_without_downgrade(target_base_url):
    host = target_base_url.split("://", 1)[1]
    hostname = host.split(":", 1)[0]

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    try:
        resp = opener.open(urllib.request.Request(f"http://{hostname}/health"),
                           timeout=15)
        status, location = resp.status, resp.headers.get("Location", "")
    except urllib.error.HTTPError as exc:
        status, location = exc.code, exc.headers.get("Location", "")
    assert status in (301, 302, 307, 308), status
    assert location.startswith(f"https://{hostname}"), location
