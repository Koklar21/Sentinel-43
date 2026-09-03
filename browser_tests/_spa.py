# =============================================================================
# Sentinel-43 -- shared SPA login helper for the DISPOSABLE browser suite.
# In its own module (not conftest.py) so `from _spa import do_login` cannot be
# shadowed by browser_tests/target/conftest.py during a whole-tree collection.
# =============================================================================

from __future__ import annotations


def do_login(page, base_url, username, password):
    page.goto(base_url + "/dashboard")
    page.wait_for_selector("#s43-login-overlay")
    page.fill("#s43-username", username)
    page.fill("#s43-password", password)
    page.click("#s43-login-btn")
    try:
        page.wait_for_selector("#s43-login-overlay", state="hidden", timeout=10_000)
    except Exception:
        err = ""
        try:
            err = page.text_content("#s43-login-err") or ""
        except Exception:
            pass
        raise AssertionError(
            f"login overlay did not hide for {username!r}; "
            f"#s43-login-err={err!r}; console={getattr(page, '_s43_console_errors', None)}"
        )
