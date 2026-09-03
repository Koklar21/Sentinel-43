# =============================================================================
# Sentinel-43 -- target acceptance: AUTHENTICATED session flow.
#
# Runs against a DESIGNATED beta operator test account (login / refresh /
# logout / WSS). Admin-mutation scenarios live in test_target_admin_mutation.py
# and require their own dedicated account + explicit scope.
#
# Nothing here creates, disables, or role-changes an account. Credentials come
# from a file (conftest._read_cred) and are never printed.
# =============================================================================

from __future__ import annotations

from _targetlib import target_request


def _login(page, base_url, username, password):
    page.goto(base_url + "/dashboard")
    page.wait_for_selector("#s43-login-overlay")
    page.fill("#s43-username", username)
    page.fill("#s43-password", password)
    page.click("#s43-login-btn")
    page.wait_for_selector("#s43-login-overlay", state="hidden", timeout=15_000)


def test_designated_operator_can_log_in_through_the_real_ui(
        target_page, target_base_url, operator_cred):
    _login(target_page, target_base_url, *operator_cred)
    assert target_page.evaluate("window.SentinelAuth.hasToken()") is True
    assert target_page._s43_tls_errors == [], target_page._s43_tls_errors


def test_no_credentials_persisted_in_web_storage(
        target_page, target_base_url, operator_cred):
    _login(target_page, target_base_url, *operator_cred)
    token = target_page.evaluate("window.SentinelAuth.getToken()")
    dump = target_page.evaluate(
        "() => JSON.stringify({l: {...localStorage}, s: {...sessionStorage}})")
    assert token and token.lower() not in dump.lower()


def test_refresh_requires_csrf_then_succeeds(target_page, target_base_url, operator_cred):
    _login(target_page, target_base_url, *operator_cred)
    r_no_csrf = target_page.evaluate(
        """async () => (await fetch('/auth/refresh', {method:'POST',
            credentials:'same-origin'})).status""")
    assert r_no_csrf in (401, 403)
    r_ok = target_page.evaluate(
        """async () => {
            const c = document.cookie.match(/s43_csrf=([^;]+)/);
            const r = await fetch('/auth/refresh', {method:'POST',
                credentials:'same-origin', headers:{'X-S43-CSRF': c ? c[1] : ''}});
            return r.status;
        }""")
    assert r_ok == 200


def test_logout_revokes_the_session_server_side(target_page, target_base_url, operator_cred):
    _login(target_page, target_base_url, *operator_cred)
    token = target_page.evaluate("window.SentinelAuth.getToken()")
    target_page.evaluate("window.SentinelAuth.logout()")
    target_page.wait_for_selector("#s43-login-overlay", state="visible")
    status, _ = target_request("GET", "/v1/status",
                               headers={"Authorization": f"Bearer {token}"})
    assert status == 401


def test_real_wss_connects_and_authenticates_then_logout_drops_it(
        target_page, target_base_url, operator_cred):
    _login(target_page, target_base_url, *operator_cred)
    target_page.wait_for_function(
        "window.SentinelWS && window.SentinelWS.connected && window.SentinelWS.authenticated",
        timeout=20_000)
    target_page.evaluate("window.SentinelAuth.logout()")
    target_page.wait_for_function(
        "!(window.SentinelWS && window.SentinelWS.authenticated)", timeout=30_000)
