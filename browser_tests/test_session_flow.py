# =============================================================================
# Sentinel-43 -- browser SPA session-flow smoke (next-PR Phase C).
#
# Real headless Chromium -> nginx TLS edge -> API -> disposable PostgreSQL.
# The served SPA and its shipped JS are under test; no endpoint is mocked.
#
# NOTE: Playwright's APIRequestContext (page.request.*) does NOT honour the
# browser's --host-resolver-rules, so every in-app HTTP assertion here goes
# through page.evaluate(fetch(...)) -- which also exercises the real
# same-origin cookie / CSRF behaviour. Out-of-band admin calls use the
# stack["request"] helper (loopback + Host header).
# =============================================================================

from __future__ import annotations

import pytest

from _spa import do_login


def page_fetch(page, path: str, method: str = "GET", headers: dict | None = None,
               body: str | None = None) -> dict:
    """fetch() inside the page (same-origin, real cookies). Returns
    {status, text}."""
    return page.evaluate(
        """async ({path, method, headers, body}) => {
            const r = await fetch(path, {
                method, headers: headers || {}, body: body || undefined,
                credentials: 'same-origin', cache: 'no-store',
            });
            return { status: r.status, text: await r.text() };
        }""",
        {"path": path, "method": method, "headers": headers or {}, "body": body},
    )


def _storage_dump(page) -> dict:
    return page.evaluate(
        """() => ({
            local: Object.fromEntries(Object.entries(localStorage)),
            session: Object.fromEntries(Object.entries(sessionStorage)),
        })"""
    )


def test_page_and_shipped_assets_load_without_fatal_js_errors(stack, page):
    resp = page.goto(stack["base_url"] + "/dashboard")
    assert resp is not None and resp.status == 200

    for asset in ("auth.js", "websocket.js", "dashboard.js"):
        r = page_fetch(page, f"/assets/js/{asset}")
        assert r["status"] == 200, asset
        assert "function" in r["text"] or "const" in r["text"]

    page.wait_for_selector("#s43-login-overlay")
    assert page.evaluate("typeof window.SentinelAuth === 'object'")
    assert page._s43_console_errors == [], page._s43_console_errors


def test_login_through_the_real_ui_reaches_an_authorized_view(stack, page):
    do_login(page, stack["base_url"], *stack["admin"])
    assert page.evaluate("window.SentinelAuth.hasToken()") is True

    # A session request from the page (no X-S43-Password anywhere) reaches a
    # protected route.
    r = page_fetch(
        page, "/users", "GET",
        {"Authorization": f"Bearer {page.evaluate('window.SentinelAuth.getToken()')}"},
    )
    assert r["status"] == 200, r


def test_no_credentials_persisted_in_web_storage_or_url(stack, page):
    do_login(page, stack["base_url"], *stack["admin"])
    token = page.evaluate("window.SentinelAuth.getToken()")
    assert token

    dump = _storage_dump(page)
    blob = repr(dump).lower()
    assert token.lower() not in blob
    for k in dump["local"]:
        assert "jwt" not in k.lower() and "token" not in k.lower()
    assert "SENTINEL_JWT" not in dump["session"]
    assert "s43_refresh" not in page.evaluate("document.cookie")      # HttpOnly
    assert "s43_csrf" in page.evaluate("document.cookie")             # double-submit
    assert "token" not in page.url.lower()


def test_reload_restores_the_session_without_a_fresh_login(stack, page):
    do_login(page, stack["base_url"], *stack["admin"])
    page.reload()
    page.wait_for_function("!!window.SentinelAuth && window.SentinelAuth.hasToken()")
    overlay = page.locator("#s43-login-overlay")
    assert overlay.count() == 0 or overlay.evaluate("el => el.style.display === 'none'")


def test_two_tabs_and_a_reload_do_not_wedge_the_ui(stack, page, context):
    do_login(page, stack["base_url"], *stack["admin"])
    second = context.new_page()
    second.goto(stack["base_url"] + "/dashboard")
    second.wait_for_function("!!window.SentinelAuth && window.SentinelAuth.hasToken()")
    page.reload()
    page.wait_for_function("window.SentinelAuth.hasToken()")
    assert page.evaluate("window.SentinelAuth.hasToken()")
    assert second.evaluate("window.SentinelAuth.hasToken()")
    second.close()


def test_logout_revokes_the_session_and_old_token_cannot_return(stack, page):
    do_login(page, stack["base_url"], *stack["admin"])
    token = page.evaluate("window.SentinelAuth.getToken()")

    page.evaluate("window.SentinelAuth.logout()")
    page.wait_for_selector("#s43-login-overlay", state="visible")

    # the pre-logout token is dead server-side (checked out-of-band so the
    # page's own logged-out state doesn't matter)
    s, _ = stack["request"]("GET", "/users", headers={"Authorization": f"Bearer {token}"})
    assert s == 401

    r = page_fetch(page, "/auth/refresh", "POST", {"X-S43-CSRF": "whatever"})
    assert r["status"] in (401, 403)


def test_refresh_requires_csrf_and_an_allowed_origin(stack, page):
    do_login(page, stack["base_url"], *stack["admin"])

    # missing CSRF header (same-origin fetch => browser sets Origin correctly)
    r1 = page_fetch(page, "/auth/refresh", "POST")
    assert r1["status"] == 403, r1

    csrf = page.evaluate("document.cookie.match(/s43_csrf=([^;]+)/)?.[1] || ''")
    assert csrf

    # valid
    r3 = page_fetch(page, "/auth/refresh", "POST", {"X-S43-CSRF": csrf})
    assert r3["status"] == 200, r3

    # disallowed Origin -- forced via the out-of-band client
    s, _ = stack["request"](
        "POST", "/auth/refresh",
        headers={"Origin": "https://evil.example", "X-S43-CSRF": csrf,
                 "Cookie": f"s43_csrf={csrf}"},
    )
    assert s == 403


def test_non_admin_operator_is_denied_admin_only_account_management(stack, page):
    do_login(page, stack["base_url"], *stack["operator"])
    r = page_fetch(
        page, "/users", "GET",
        {"Authorization": f"Bearer {page.evaluate('window.SentinelAuth.getToken()')}"},
    )
    assert r["status"] == 403, r


def test_admin_disable_invalidates_the_targets_live_session(stack, page):
    do_login(page, stack["base_url"], *stack["operator"])
    op_token = page.evaluate("window.SentinelAuth.getToken()")

    req = stack["request"]
    s, b = req("POST", "/auth/login",
               {"username": stack["admin"][0], "password": stack["admin"][1]})
    admin_token = b.get("access_token") or b.get("token")
    s, users = req("GET", "/users", headers={"Authorization": f"Bearer {admin_token}"})
    op_id = next(u["user_id"] for u in users if u["username"] == stack["operator"][0])

    s, _ = req("PATCH", f"/users/{op_id}", {"is_active": False},
               headers={"Authorization": f"Bearer {admin_token}"})
    assert s == 200, s

    s, _ = req("GET", "/users", headers={"Authorization": f"Bearer {op_token}"})
    assert s == 401  # operator's live token rejected immediately

    req("PATCH", f"/users/{op_id}", {"is_active": True},
        headers={"Authorization": f"Bearer {admin_token}"})


def test_real_wss_connects_and_authenticates_then_logout_drops_it(stack, page):
    do_login(page, stack["base_url"], *stack["admin"])

    page.wait_for_function(
        "window.SentinelWS && window.SentinelWS.connected && window.SentinelWS.authenticated",
        timeout=20_000,
    )
    # secure page => wss:// socket
    assert page.evaluate("window.SentinelWS.connected")

    page.evaluate("window.SentinelAuth.logout()")
    page.wait_for_function(
        "!(window.SentinelWS && window.SentinelWS.authenticated)",
        timeout=30_000,
    )


def test_reconnect_backoff_survives_repeated_pre_auth_closes(stack, page):
    """Regression for 6a0f96f (fix(ws): preserve backoff until authentication
    succeeds).

    Before that fix, websocket.js reset _reconnectAttempts to 0 in the raw
    transport's 'open' handler -- before authentication. A backend outage
    that accepts the transport and then closes with 1011 (e.g.
    service_unavailable) therefore reset the counter on every single cycle,
    so every retry waited only the initial ~1s instead of the growing
    bounded exponential backoff, letting every dashboard hammer the failing
    dependency. The real shipped websocket.js (not a rewritten copy) is
    exercised here through the actual SPA, with only the browser's WebSocket
    CONSTRUCTOR stubbed to simulate the outage -- the reconnect logic under
    test is untouched.
    """
    do_login(page, stack["base_url"], *stack["admin"])
    page.wait_for_function(
        "window.SentinelWS && window.SentinelWS.connected && window.SentinelWS.authenticated",
        timeout=20_000,
    )

    # Simulate an auth-backend outage: every new transport opens, then the
    # server immediately closes it with 1011/service_unavailable, before any
    # auth frame could ever be accepted. Real WebSocket close/open event
    # semantics (order, async dispatch) are preserved; only the connection
    # outcome is forced.
    page.evaluate(
        """() => {
            window.SentinelWS.disconnect();
            const RealWebSocket = window.WebSocket;
            class OutageSocket extends EventTarget {
                constructor(url) {
                    super();
                    this.url = url;
                    this.readyState = RealWebSocket.CONNECTING;
                    setTimeout(() => {
                        this.readyState = RealWebSocket.OPEN;
                        this.dispatchEvent(new Event('open'));
                        setTimeout(() => {
                            this.readyState = RealWebSocket.CLOSED;
                            this.dispatchEvent(new CloseEvent('close', {
                                code: 1011, reason: 'service_unavailable', wasClean: false,
                            }));
                        }, 0);
                    }, 0);
                }
                send() {}
                close() { this.readyState = RealWebSocket.CLOSED; }
            }
            OutageSocket.CONNECTING = RealWebSocket.CONNECTING;
            OutageSocket.OPEN = RealWebSocket.OPEN;
            OutageSocket.CLOSING = RealWebSocket.CLOSING;
            OutageSocket.CLOSED = RealWebSocket.CLOSED;
            window.WebSocket = OutageSocket;
            window.__s43RealWebSocket = RealWebSocket;
            window.SentinelWS.connect();
        }"""
    )

    # A reset-on-open bug plateaus at reconnectAttempts <= 1 forever (each
    # cycle's spurious reset undoes the previous cycle's single increment).
    # The fix lets it climb past that on every full outage cycle.
    page.wait_for_function("window.SentinelWS.reconnectAttempts >= 3", timeout=15_000)
    attempts_at_three = page.evaluate("window.SentinelWS.reconnectAttempts")
    assert attempts_at_three >= 3, (
        "reconnectAttempts did not grow past a pre-auth close reset -- "
        f"backoff was not preserved (stuck around {attempts_at_three})"
    )

    # Restore the real WebSocket so later tests/teardown are unaffected.
    page.evaluate(
        """() => {
            window.SentinelWS.disconnect();
            window.WebSocket = window.__s43RealWebSocket;
            delete window.__s43RealWebSocket;
        }"""
    )
