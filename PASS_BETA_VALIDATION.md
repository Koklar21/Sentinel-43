# PASS_BETA_VALIDATION.md

Beta-execution validation record — Phases 1-6. Evidence for
`BETA_EXECUTION.md`, `MIGRATION_DEPLOYMENT_BETA.md`, `AUTH_SESSION_BETA.md`,
`SERVICE_INTEGRATION_BETA.md`.

- **Branch:** `integration/beta-hardening-20260901`
- **Starting HEAD:** `8614f9b` (verified Pass 5AM HEAD, 7 commits on `7a72976`)
- **Working clone:** `C:\Users\heero\Sentinel-43-work` (non-synced; push
  disabled on both remotes). Original OneDrive repo untouched (`e859b61`).

---

## 1. Environment

| tool | version |
|---|---|
| Python | 3.13.5 |
| Docker Engine / Compose | 29.7.2 / v5.4.0 |
| PostgreSQL (disposable + stack) | 16.3 |
| Alembic | 1.19.1 · SQLAlchemy 2.0.52 · asyncpg 0.31.0 · psycopg 3.3.5 |
| FastAPI 0.141.1 · uvicorn 0.52.4 · starlette (bundled) · PyJWT 2.13.0 · argon2-cffi 25.1.0 |
| pytest | 9.1.1 |
| nginx (proxy image) | `nginx:1.27-alpine` |

**Test-run note.** The user's own Compose stack (project `sentinel-43`, from
the OneDrive checkout) was running throughout — an active dev session, left
untouched. While it runs the host resolves `s43-core` slowly, so every test
that builds a `TestClient` lifespan ran with
`S43_WATCHTOWER_URL=http://127.0.0.1:9` `S43_WATCHTOWER_TIMEOUT=0.5` (instant
ECONNREFUSED). This changes no test's meaning — the Watchtower is unreachable
in tests either way — and `git stash` confirmed the slowdown is present on
the pre-change tree too (purely environmental).

---

## 2. Test suites (disposable PostgreSQL 16.3)

| Suite | Result |
|---|---|
| Full isolated suite at `8614f9b` (inherited Pass 5AM baseline) | 385 passed / 0 failed / 0 skipped |
| Full isolated suite after **P1+P2** (`d529f04`) | **429 passed** / 0 failed / 0 skipped (191 s) |
| Full isolated suite after **P3** (`1acc423`) | **449 passed** / 0 failed / 0 skipped (259 s) |
| Full isolated suite after **P4-P6** (final, `aa64658`) | **454 passed** / 0 failed / 0 skipped (259 s) |
| `test_migrations_pg.py` (incl. 0003) | 28 passed |
| `test_auth_session_pg.py` (browser session e2e) | 12 passed |
| `test_ws_session_pg.py` | 4 passed |
| `test_break_glass_pg.py` (#11) | 4 passed |
| `test_schema_version_pg.py` + `test_schema_authority.py` | 20 passed |
| `test_deploy_migration_wiring.py` | 6 passed |
| `test_backup_restore_pg.py` (real pg_dump → separate DB) | 2 passed |
| `test_security_headers.py` + `test_tls_posture.py` | 26 passed |
| Legacy-contract regression (`test_auth_login` / `test_jwt_auth` / `test_v1_auth` / `test_users_admin` / `test_ws_auth`) | green |
| Service ⇄ human identity separation (`test_service_identity_separation.py`) | 12 passed |
| k8s policy check — `overlays/dev` + `overlays/beta` rendered | 114 / 117 assertions, PASS |

`test_bootstrap.py` / `test_system_smoke.py` excluded per the standing
no-live-HTTP rule (consistent with Passes 1-5A).

---

## 3. Migration deployment (P1)

Manual verification, disposable PG:

| step | result |
|---|---|
| `alembic upgrade head` (CLI, fresh DB) | 0001 → 0002 → 0003; `alembic_version = 0003_users_role_check`; `alembic check` → "No new upgrade operations detected" |
| `schema_report()` states | fresh/behind/ahead/unstamped → `serving_blocked=True` (non-local); ok / local / no-DATABASE_URL → False (see §5 states table in `MIGRATION_DEPLOYMENT_BETA.md`) |
| `/ready` 503 when behind, 200 at head | `test_schema_version_pg.py` |
| `init_models()` no-op in non-local | `test_schema_authority.py` |
| 0003 up / down / up round-trip | constraint added, dropped, re-added; refuses (RuntimeError) on a pre-existing violating row, changes nothing |
| pg_dump → restore into a **separate** DB | users + sessions byte-identical; a pre-backup-revoked session restores **revoked** (`is_live() == False`); `alembic_version` restored |

**Live stack (P5 smoke):** `s43-migrate` container ran `alembic upgrade head`,
logged the three revisions, **exited 0**; `s43-api` started only after it
completed (`depends_on: service_completed_successfully`).

---

## 4. Secure transport (P2) — live stack

Compose beta stack behind `s43-proxy` (nginx, TLS terminator), self-signed
localhost cert, `SENTINEL_ENV=beta` (non-local):

| check | result |
|---|---|
| `GET https://localhost:.../health` | `200 {"status":"ok",...,"environment":"beta"}` |
| `GET https://localhost:.../ready` | `200 {"status":"ready"}` (schema at head) |
| `GET http://localhost:.../health` | `308` → `https://…/health` |
| HSTS header | `Strict-Transport-Security: max-age=15552000; includeSubDomains` (edge + app) |
| `X-Content-Type-Options` / `X-Frame-Options` / `Referrer-Policy` | present |
| backend host-published? | **no** — only `s43-proxy` publishes 80/443; `s43-api` is `expose` only |
| forged `X-Forwarded-For` (client claims a trusted IP) | request still needs auth → **401**, no bypass |
| WSS upgrade through the proxy | `101 Switching Protocols`; first frame `{"type":"auth_required",...}` received |
| `TrustedHostGuard`: data route with `Host: s43-api` | **400** `invalid_host` |
| `TrustedHostGuard`: `/health` `/ready` with any Host | **200** (probe paths exempt — k8s probes send `Host: <podIP>`) |
| container log scan for `S43_JWT_SECRET` / pepper / DB password / watchtower token / operator password / Bearer tokens / `postgresql://…:…@` / cookies | **0 hits** across api / core / migrate / proxy |

**F-TLS-1 status: still OPEN.** A local self-signed cert proves the
integration (app behind TLS, forwarded headers, secure cookies, WSS). It does
not prove certificate issuance/validation/renewal against a real hostname +
CA. `deploy/proxy/README.md` documents that; F-TLS-1 closes only when that is
verified on a named target.

---

## 5. Browser session end to end (P3) — live stack

Through the HTTPS proxy, `SENTINEL_ENV=beta`:

| flow | result |
|---|---|
| `POST /bootstrap/admin` | `{"username":"smokeadmin","role":"admin"}` |
| `POST /auth/login` (Origin set) | 200; `Set-Cookie: s43_refresh=…; HttpOnly; Max-Age=604800; Path=/auth; SameSite=strict; Secure` + `s43_csrf=…; …; Secure` (NOT HttpOnly) |
| `GET /users` with the session token, **no X-S43-Password** | **200** (Phase B — session-bound token authenticates alone) |
| `POST /auth/refresh` with CSRF | 200, cookie rotated |
| `POST /auth/refresh` without `X-S43-CSRF` | **403** |
| `POST /auth/refresh` with a disallowed `Origin` | **403** |
| `POST /auth/logout` then `POST /auth/refresh` | logout 200, refresh **401** |
| replay of a rotated refresh value (isolated PG test) | 401 + whole session revoked |
| disabled user / expired session / admin password reset (isolated PG tests) | next request **401**, immediate |
| WS `{token}`-only frame / legacy `{token,password}` / revoke-mid-stream | `test_ws_session_pg.py` — all pass |
| #11: env operator inert once a DB admin exists / armed / DB-down | `test_break_glass_pg.py` |
| legacy Bearer + `X-S43-Password` still accepted | `test_v1_auth`, `test_users_admin`, `test_ws_auth` green |

---

## 6. Ops (P5) — live stack

| check | result |
|---|---|
| clean image build (`docker compose build s43-api`) | 36 s, success |
| full stack up (`docker compose … up -d`) | all 6 containers healthy; ordering db→migrate→api→proxy correct |
| in-network load: 2000 req, 50 concurrent, `/health` | **6617 req/s, p50 = p95 = p99 = 8 ms, 0 failed** |
| resource snapshot (idle) | api 65 MiB / postgres 40 MiB / core 39 MiB / proxy 16 MiB / redis 3 MiB |
| `docker compose restart s43-api` | healthy again; admin persists; re-login 200 |
| `docker compose up --force-recreate s43-db` (same volume) | `/bootstrap/status` still `initialized:true` — `users` row survived container recreation |
| backup/restore (`pg_dump -Fc` → `pg_restore` into `s43_restore`) | 1 user, 6 sessions, 2 still revoked, `alembic_version` restored |
| bounded restart test | api + db recreation, data intact throughout |

**Finding #13 fixed:** `S43_SECRETS_ROTATED_AT` (and the session env vars) are
now forwarded by `docker-compose.yml` and present in the k8s base ConfigMap —
before this, a non-local API crash-looped on
`bootstrap_expectations()` with "S43_SECRETS_ROTATED_AT is missing". Found by
the P5 smoke.

**Windows loopback caveat:** a load test through the *published* HTTPS port
(Docker Desktop's userland proxy) measured p50 ≈ 2 s under 20 concurrent TLS
handshakes — a known Windows Docker Desktop port-forwarding limit, not a
Sentinel-43 characteristic (in-network: 8 ms). Any real load assessment is a
named-target task.

---

## 7. Boundaries honoured

- No push / force-push / merge / PR / repo-settings change / OneDrive-repo
  change / branch or tag deletion.
- **The user's running Compose stack (`sentinel-43`) was never touched.** The
  P5 smoke ran as a separate project (`s43smoke`) with renamed containers and
  ports 18443/18080; torn down (`down -v`) after.
- No migration run against a non-disposable database. All disposable PG was
  `--rm --tmpfs` or a throw-away Compose volume, destroyed after.
- No production deployment. No secret values in this document, any commit, or
  any test log (verified). `.env.smoke` / `docker-compose.smoke.yml` are
  gitignored.
- F-TLS-1, and the deferred P3-8 / #19 / #14 / #16 / #18 — recorded, not
  claimed resolved.

---

## 8. STOP conditions (none triggered)

Repository state stable throughout (`8614f9b` base). Every phase's code is
behavioural-test-backed. Nothing required a live database, a production
deploy, a push, or a target-specific decision that could not be deferred to
the final report's single open question.

---

## 9. Integration pass — next PR (2026-09-02/03)

Branch pushed `a8a5678` → `origin`. `main` had advanced to `eb7780f`
(merged PR #250 CI/container hardening + PR #248). Merged `main` into the
branch (`f3d93e2`); see `BETA_EXECUTION.md §7` and the merge commit for the
by-behaviour conflict resolution.

| Suite | Result |
|---|---|
| Full isolated suite after the merge (`f3d93e2`, `.venv-pass1`, disposable PG :55440) | **457 passed / 0 failed / 0 skipped** (= 454 beta baseline + 3 new `test_app_route_registration.py`) |
| Merge-affected files (`test_users_admin`, `test_bootstrap_isolated`, `test_v1_auth`, `test_auth_login`, `test_firewall_trusted_proxy_config`, `test_health_check_log_filter`, `test_internal_broadcast_auth`, `test_actions_test_inject_auth`) | 88 passed |
| **Browser SPA smoke** (`browser_tests/`, Playwright + real Chromium → nginx TLS → API → disposable PG, project `s43browser`) | **10 passed / 0 failed** (19 s) |
| Full isolated suite after all Phase C/D/E changes (`.venv-pass1`, disposable PG :55440) | **457 passed / 0 failed / 0 skipped** (260 s, exit 0) |
| `scripts/ci_live_tests.py` (live API + `test_bootstrap` + `test_system_smoke`, disposable PG :5432, `GITHUB_ACTIONS=true`) | **13 passed / 1 skipped** (exit 0) after the `07686bc` fix (see below) |

**CI (`.github/workflows/k8s.yml` on PR #251).** Two issues surfaced and
were fixed in-branch:
- `7dc4e4d` — `pytest` job's `ci_live_tests.py` step failed: post-merge the
  live API had no schema (`init_models()` is a non-local no-op) + inert
  env-operator (`#11`, after `test_bootstrap` makes an admin). Fixed
  `07686bc` (`alembic upgrade head` first + `S43_BREAK_GLASS_ARMED`).
- `07686bc` — `browser SPA smoke` job failed on a cert bind-mount nested
  inside the base proxy's (empty on a fresh checkout) cert dir. Fixed
  `1840237` (mount the test cert dir over it; `s43.crt` = leaf+CA chain).

**Run 33717346210 on `1840237` — all six jobs green:**
`validate-manifests` ✓ · **`pytest (disposable PostgreSQL)` ✓** (beta's
nine `*_pg.py` suites, none skipped — the gate this pass added) ·
`pytest` ✓ · `browser SPA smoke (Playwright)` ✓ ·
`Build image + vulnerability scan` ✓ (Alpine + Trivy HIGH/CRITICAL +
container test stage) · `kind smoke deploy` ✓ (Calico, migration Job,
non-root + read-only-rootfs, `/health` + `/bootstrap`).

### Browser smoke — what actually ran

Real headless Chromium (SPKI-pinned to the throwaway test leaf; hostname
`s43.beta.test` mapped to loopback), driving the *served* SPA
(`sentinel_43_dashboard.html` + shipped `auth.js`/`websocket.js`/
`dashboard.js`) through the nginx TLS edge:

| check | result |
|---|---|
| `/dashboard` + `/assets/js/*.js` served; `auth.js` runs; **0 console/page errors** | pass |
| type into the real login overlay → session established → protected `/users` reachable, **no `X-S43-Password`** | pass |
| access token **only in memory** (`window.SentinelAuth.getToken()`); not in `localStorage`/`sessionStorage`/URL; `s43_refresh` absent from `document.cookie` (HttpOnly); `s43_csrf` present | pass |
| reload → refresh-cookie exchange → no re-login | pass |
| two tabs + reload → both stay authenticated, no revoke loop | pass |
| logout → overlay returns; pre-logout bearer token 401s; refresh 401/403 | pass |
| `/auth/refresh` — missing CSRF 403, bad Origin 403, valid 200 | pass |
| operator session → `/users` → 403 | pass |
| admin disables operator → operator's live token 401s immediately | pass |
| real `wss://` connects + authenticates; logout drops it | pass |

### Frontend fixes made to pass the browser checks

1. SPA was **hardwired to `http://localhost:8000`** (meta tags + JS
   fallbacks + CSP `connect-src`) — could not talk to a same-origin HTTPS
   beta. Now: `connect-src 'self'`, meta tags empty, `API_BASE` →
   `location.origin`, WS URL → `wss://<same-origin>/ws`.
2. Access token moved from `sessionStorage` to module memory (auth.js
   v1.8.0), exposed as `window.SentinelAuth.getToken()`.
3. **websocket.js multi-socket race** — auth.js's login handler calls
   `disconnect()` then `connect()`; a stale socket's late `close` handler
   nulled the live `_ws` and dispatched a spurious `auth_failed`, which
   re-showed the login overlay right after a successful login. Handlers are
   now bound per-socket and no-op once `_ws` has moved on. This is the fix
   that turned the browser suite green.

**F-TLS-1 stays OPEN** — a throwaway test CA proves browser⇄nginx only.

### Boundaries honoured (this pass)

- Branch pushed to `origin` (authorised); **no merge to `main`**, no force,
  no branch deletion, no production deploy, no live-DB migration.
- The user's running **Docker Desktop Kubernetes** stack (`sentinel43` ns)
  was never touched. The browser stack ran as project `s43browser` on its
  own `172.29.0.0/24` subnet, ports `127.0.0.1:8443/8081`, `down -v` after.
- `.venv-pass1` was briefly perturbed by a `pip install playwright` (pulled
  `pytest<9`); restored to `pytest==9.1.1` + `greenlet==3.5.5` and the full
  suite re-run clean. Browser deps live in a separate `.venv-browser`.
- No secret values in any commit, doc, or test log. `.env.browser` /
  `browser_tests/certs/*` gitignored.

---

## 10. Post-merge verification pass — REV 2 (2026-09-03)

PR #251 was **merged to `main`** (`0bd375a`) between REV 1 and REV 2. This
pass adds four verification items on a new branch
(`beta/post-merge-verification-20260903` ← `0bd375a`) and a new PR.

### New / changed tests

| test | what it proves |
|---|---|
| `test_auth_session_pg.py::test_reject_legacy_auth_off_default_still_accepts_legacy` | flag OFF (default): legacy Bearer+password → 200 on `/v1` |
| `test_auth_session_pg.py::test_reject_legacy_auth_on_blocks_legacy_v1_and_users_not_the_session` | flag ON: legacy → **401** on `/v1` AND `/users`; session token → 200 on both; flag back OFF → legacy 200 again |
| `test_ws_session_pg.py::test_reject_legacy_auth_on_blocks_the_legacy_frame_not_the_session` | flag ON: legacy `{token,password}` WS frame rejected; session `{token}` frame connects |
| `test_migrations_pg.py::test_refresh_hash_uniqueness_is_the_partial_active_scoped_shape` | **direct** `pg_indexes` / `pg_index.indpred` / `pg_constraint` introspection after `alembic upgrade head`: `uq_sessions_active_refresh_hash` is a partial UNIQUE index on `(refresh_hash)` `WHERE (revoked_at IS NULL)` (shape B); no unconditional table-level UNIQUE (shape A) |

### Results

| suite | result | how run |
|---|---|---|
| isolated (no PG, `.venv-pass1`) | **368 passed / 89 skipped / 0 failed** (exit 0) | `pytest core/tests/ --ignore test_bootstrap --ignore test_system_smoke` |
| the 4 new/changed tests, disposable PG `postgres:16.3` :55440 | **4 passed** | targeted |
| `test_migrations_pg` + `test_auth_session_pg` + `test_ws_session_pg` (full) | **48 passed** | targeted |
| full isolated + PG suite | _below_ | `pytest core/tests/ --ignore …` with `S43_TEST_PG_DSN` |
| CI on the REV 2 PR head | _final report_ | `.github/workflows/k8s.yml` |

Full isolated + PG suite (REV 2, `.venv-pass1`, disposable PG :55440):
**461 passed / 0 failed / 0 skipped** (273 s, exit 0) = REV 1's 457 + the 4
new tests above.

### deploy_preflight.py — single replica AND single worker

Compose mode: exactly one `s43-api` container (no `--scale`), one uvicorn
worker process, `WEB_CONCURRENCY` not > 1. Kube mode: `spec.replicas == 1`,
`readyReplicas == 1`, no HPA, no `--workers > 1` in the container command,
`WEB_CONCURRENCY` not > 1. `py_compile` clean; placeholder-hostname run
exits 1.

### Boundaries (REV 2)

- PR #251 merge was the **owner's** action, not this pass. This pass did
  **not** merge to `main`, force-push, or deploy.
- Docker Desktop was found stopped (user had shut it down); restarted to run
  the PG suites. The user's `sentinel43` k8s namespace pods were not touched
  (`s43-api`/`s43-core` `ErrImageNeverPull` ~33 d — pre-existing).
- `.venv-pass1` still `pytest 9.1.1`. Disposable PG `--rm --tmpfs`.
