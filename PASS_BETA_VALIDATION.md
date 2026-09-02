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
| Full isolated suite after **P4-P5** (final) | _RECORD HERE_ |
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
