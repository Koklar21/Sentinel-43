# Browser SPA smoke (`browser_tests/`)

Real headless **Chromium → nginx TLS edge → API → disposable PostgreSQL**.
The tests drive the *actually served* SPA
(`dashboard/sentinel_43_dashboard.html` + the shipped `auth.js` /
`websocket.js` / `dashboard.js`). No auth endpoint is mocked and the SPA is
never replaced with a test page.

Added in the next-PR integration pass (Phase C). Complements — does not
replace — the disposable-PostgreSQL suites (`test_auth_session_pg.py`,
`test_ws_session_pg.py`, `test_users_admin.py`, …) that prove the same
contracts at the API layer.

## What it covers

| Test | Behaviour |
|---|---|
| `test_page_and_shipped_assets_load_without_fatal_js_errors` | `/dashboard` + `/assets/js/*.js` served; `auth.js` runs; zero console/page errors |
| `test_login_through_the_real_ui_reaches_an_authorized_view` | type into the real login overlay → session established → protected `/users` reachable with **no `X-S43-Password`** |
| `test_no_credentials_persisted_in_web_storage_or_url` | access token only in memory (`window.SentinelAuth.getToken()`), not `localStorage`/`sessionStorage`/URL; `s43_refresh` absent from `document.cookie` (HttpOnly); `s43_csrf` present (double-submit) |
| `test_reload_restores_the_session_without_a_fresh_login` | reload → refresh-cookie exchange → no login overlay |
| `test_two_tabs_and_a_reload_do_not_wedge_the_ui` | second tab + reload stay authenticated; no rotation/replay revoke loop |
| `test_logout_revokes_the_session_and_old_token_cannot_return` | logout → overlay returns; the pre-logout bearer token 401s; refresh 401/403 |
| `test_refresh_requires_csrf_and_an_allowed_origin` | missing `X-S43-CSRF` → 403; bad `Origin` → 403; valid → 200 |
| `test_non_admin_operator_is_denied_admin_only_account_management` | operator session → `/users` → 403 |
| `test_admin_disable_invalidates_the_targets_live_session` | admin disables operator → operator's live token 401s immediately |
| `test_real_wss_connects_and_authenticates_then_logout_drops_it` | `wss://` connects + authenticates; logout drops it |

## Running it

```bash
python -m venv .venv-browser
.venv-browser/Scripts/python -m pip install -r requirements-browser.txt
.venv-browser/Scripts/python -m playwright install chromium   # add --with-deps on Linux/CI

./browser_tests/run.sh            # up (project s43browser) → pytest → down -v
./browser_tests/run.sh -k logout  # pass args straight through to pytest
```

`run.sh` uses a dedicated Compose project (`s43browser`), renames every
container, publishes the proxy only on `127.0.0.1:8443` / `8081`, and uses
its own `172.29.0.0/24` subnet — it never touches another running stack.
It generates fresh disposable secrets into `.env.browser` (gitignored) each
run and `down -v`s on exit.

## TLS trust

`certs/generate-test-ca.sh` makes a throwaway CA + a leaf for
`CN=s43.beta.test`. Chromium is launched with:

* `--ignore-certificate-errors-spki-list=<base64 sha256 of the leaf SPKI>` —
  trusts **exactly this cert**, not a blanket `--ignore-certificate-errors`;
* `--host-resolver-rules=MAP s43.beta.test 127.0.0.1` — no hosts-file edit.

**This does not close F-TLS-1.** A local test CA proves the browser⇄nginx
integration only. Closure needs the real target hostname, a CA the intended
clients already trust, and this suite passing against that deployment.

## Environment note

Needs Docker + a Chromium that Playwright can launch. If a sandbox blocks
browser download/execution, the harness and the CI job (`.github/workflows/
k8s.yml`, `browser-smoke`) are still the deliverable — run them on a runner
that allows it; do not claim a pass without one.
