# =============================================================================
# Sentinel-43 -- browser SPA smoke tests (next-PR Phase C).
#
# Exercises the ACTUAL served SPA (dashboard/sentinel_43_dashboard.html + its
# shipped auth.js / websocket.js / dashboard.js) through the real nginx TLS
# edge, the real API, and a disposable PostgreSQL -- in a headless Chromium.
#
# Nothing here mocks an auth endpoint or swaps the SPA for a test page.
#
# The stack is docker-compose.yml + docker-compose.browser.yml under project
# `s43browser`. browser_tests/run.sh brings it up, runs pytest, tears it down.
# When S43_BROWSER_BASE_URL is already set (run.sh, CI), these fixtures attach
# to the running stack instead of managing it.
# =============================================================================

from __future__ import annotations

import json
import os
import pathlib
import secrets
import ssl
import subprocess
import time
import urllib.request

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_CERTS = pathlib.Path(__file__).resolve().parent / "certs"

HOSTNAME = "s43.beta.test"
HTTPS_PORT = 8443
BASE_URL = os.environ.get("S43_BROWSER_BASE_URL", f"https://{HOSTNAME}:{HTTPS_PORT}")
# The browser gets `s43.beta.test` via --host-resolver-rules; plain Python
# does not, so the fixture's own API calls go to loopback with a Host header.
LOOPBACK_URL = f"https://127.0.0.1:{HTTPS_PORT}"

ADMIN_USERNAME = "browser-admin"
ADMIN_PASSWORD = "browser-admin-" + secrets.token_urlsafe(12)
OPERATOR_USERNAME = "browser-operator"
OPERATOR_PASSWORD = "browser-operator-" + secrets.token_urlsafe(12)


def _spki_pin() -> str:
    txt = (_CERTS / "spki.txt").read_text().strip()
    # SPKI_SHA256_BASE64=<value>
    return txt.split("=", 1)[1].strip()


def _insecure_ctx() -> ssl.SSLContext:
    # The fixture's own plumbing calls (health poll, bootstrap, account
    # setup) go to loopback; TLS correctness is asserted by the *browser*
    # (SPKI-pinned), not here, so this context does not verify.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _request(method: str, path: str, body: dict | None = None, headers: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    h = {
        "Content-Type": "application/json",
        "Origin": BASE_URL,
        # loopback connection, but the API's TrustedHostGuard checks Host
        "Host": f"{HOSTNAME}:{HTTPS_PORT}",
        "Content-Length": str(len(data) if data else 0),
    }
    h.update(headers or {})
    req = urllib.request.Request(LOOPBACK_URL + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=10, context=_insecure_ctx()) as resp:
            raw = resp.read().decode()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        return exc.code, json.loads(raw) if raw else {}


@pytest.fixture(scope="session")
def stack():
    """Wait for the browser stack to be serving, then bootstrap a fresh admin
    + a non-admin operator through the real API. Assumes run.sh (or CI) has
    already `compose up`-ed the s43browser project."""
    deadline = time.monotonic() + 120
    last = None
    while time.monotonic() < deadline:
        try:
            status, _ = _request("GET", "/health")
            if status == 200:
                break
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(1)
    else:  # pragma: no cover
        raise RuntimeError(f"browser stack not serving at {BASE_URL}: {last}")

    status, body = _request("GET", "/bootstrap/status")
    if status == 200 and not body.get("initialized"):
        s, b = _request(
            "POST", "/bootstrap/admin",
            {"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        )
        assert s in (200, 201), (s, b)

    # An admin session to create the operator account.
    s, b = _request(
        "POST", "/auth/login",
        {"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
    )
    assert s == 200, (s, b)
    admin_token = b.get("access_token") or b.get("token")

    s, b = _request("GET", "/users", headers={"Authorization": f"Bearer {admin_token}"})
    existing = {u["username"] for u in b} if isinstance(b, list) else set()
    if OPERATOR_USERNAME not in existing:
        s, b = _request(
            "POST", "/users",
            {"username": OPERATOR_USERNAME, "password": OPERATOR_PASSWORD, "role": "operator"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert s in (200, 201), (s, b)

    return {
        "base_url": BASE_URL,
        "admin": (ADMIN_USERNAME, ADMIN_PASSWORD),
        "operator": (OPERATOR_USERNAME, OPERATOR_PASSWORD),
        "request": _request,
    }


@pytest.fixture(scope="session")
def browser_type_launch_args(browser_type_launch_args):
    # DISPOSABLE stack only: trust exactly our throwaway test leaf by its SPKI
    # hash (NOT a blanket --ignore-certificate-errors) and map the test
    # hostname to loopback so no hosts-file edit is needed.
    #
    # In TARGET-ACCEPTANCE mode (browser_tests/target/, S43_TARGET_BASE_URL
    # set) neither of these is applied -- a real target must pass with an
    # ordinary trusted-CA chain and real DNS. See browser_tests/target/.
    if os.environ.get("S43_TARGET_BASE_URL"):
        return browser_type_launch_args
    return {
        **browser_type_launch_args,
        "args": [
            *browser_type_launch_args.get("args", []),
            f"--ignore-certificate-errors-spki-list={_spki_pin()}",
            f"--host-resolver-rules=MAP {HOSTNAME} 127.0.0.1",
        ],
    }


@pytest.fixture
def page(page):
    page.set_default_timeout(15_000)
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page._s43_console_errors = errors  # type: ignore[attr-defined]
    return page


# do_login lives in browser_tests/_spa.py (re-exported here for back-compat)
# so `from _spa import do_login` is collision-proof against target/conftest.py.
from _spa import do_login  # noqa: E402,F401
