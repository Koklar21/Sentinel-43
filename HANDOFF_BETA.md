# HANDOFF_BETA.md

Sentinel-43 — beta-execution handoff. Migration deployment integration,
secure transport, browser/session authentication, #11 remediation, service
integration, operational hardening, and beta validation, on top of the
Pass 5A-Migration foundation.

**Read the three conclusions in §10 before treating anything here as
"production-ready" — it is not.**

Companions: `BETA_EXECUTION.md` (checkpoint — §9 has the REV 3 release-tooling
corrections), `MIGRATION_DEPLOYMENT_BETA.md`, `deploy/proxy/README.md`.
(`AUTH_SESSION_BETA.md`, `SERVICE_INTEGRATION_BETA.md`, `PASS_BETA_VALIDATION.md`
and other superseded design/validation docs were removed on `main`; their live
content now lives in this file and `BETA_EXECUTION.md`.) Pass 5A/5AM docs
unchanged.

---

## A. Verified starting state

| | |
|---|---|
| Working clone | `C:\Users\heero\Sentinel-43-work` (non-synced; `origin` + `evidence-local` push disabled) |
| Branch | `integration/beta-hardening-20260901` |
| HEAD at start | `8614f9b` — the Pass 5AM HEAD, **7** commits on `7a72976` (`git rev-list --count 7a72976..8614f9b` = 7; the Pass 5AM completion report's prose "6" was wrong — corrected in `BETA_EXECUTION.md §1`) |
| `git status` at start | clean |
| Original OneDrive repo | untouched — `e859b61` |
| Inherited baseline | full isolated suite 385 passed / SI 13/13 (Pass 5AM) |
| Pre-work recovery | `…\sentinel43-recovery\beta-execution-20260902\PRE.bundle` (verified) + `HEAD-PRE.txt` |

## B. Ending commit

Substantive tip **`aa64658`** on `integration/beta-hardening-20260901`,
followed by the Phase-7 docs commit (this file). `git log --oneline
8614f9b..HEAD` for the exact tip. Working tree clean. Branch **not pushed**.
Original OneDrive repo still `e859b61`.

| commit | phase | scope |
|---|---|---|
| `d529f04` | P1 + P2 | migration deployment integration (Compose `s43-migrate`, k8s Job → `alembic upgrade head`, `schema_version` gate on `/ready`, `init_models()` no-op in non-local) + secure transport (`deploy/proxy/` nginx TLS terminator, `SecurityHeadersMiddleware`, non-local plaintext-origin startup refusal, k8s ingress HSTS) |
| `1acc423` | P3 | browser session end to end — `/auth/refresh` + `/auth/logout` + cookies + CSRF, Phase-B dual contract in all 4 enforcement points, revoke hooks, #11 break-glass, `legacy_auth_request_total` + `S43_REJECT_LEGACY_AUTH`, `auth.js`/`websocket.js` v1.7.0 |
| `aa7f2b1` | P4 | `0003_users_role_check` (P3-7) + `SERVICE_INTEGRATION_BETA.md` |
| `5c06dbe` | P4-P5 | stack-smoke fixes — **#13** (`S43_SECRETS_ROTATED_AT` not forwarded), `TrustedHostGuard` (probe-path exempt), proxy static-IP collision, `PASS_BETA_VALIDATION.md` |
| `aa64658` | P6 | `test_backup_restore_pg` — computed head + `DROP DATABASE … FORCE` (test-only; surfaced by the final suite run) |

No push · no merge · no PR · no deploy · no live-DB access · no
OneDrive-repo change · no `docker compose` action against the user's running
stack.

## C. What was implemented

### C.1 Migration deployment (P1)
- **Compose:** one-shot `s43-migrate` (`alembic upgrade head`); `s43-api`
  `depends_on: s43-migrate: service_completed_successfully`. Idempotent.
- **Kubernetes:** `base/migration-job.yaml` command → `["alembic","upgrade","head"]`;
  single actor, `restartPolicy: Never`, Secret-sourced env, RO rootfs, WARN
  engine logger (no connection string in logs). Fresh / adopt-existing
  (`alembic stamp 0001_baseline`) / incompatible-refusal all documented in
  `deploy/kubernetes/README.md`.
- **`core/auth/schema_version.py`** (new): `/ready` returns **503** in a
  non-local env when `alembic_version` is behind / ahead / unstamped / fresh
  / unreachable. `/health` (liveness) never touches the DB. `S43_SCHEMA_
  VERSION_CHECK` overrides.
- **`init_models()`** is a no-op in non-local (`_schema_is_alembic_managed`);
  `create_all` can no longer race the migration Job. `S43_SCHEMA_CREATE_ALL`
  overrides.
- Recovery proven with a real `pg_dump` restored into a **separate** DB
  (`test_backup_restore_pg.py`); downgrade is never the rollback plan.

### C.2 Secure transport (P2, F-TLS-1)
- **`deploy/proxy/`** (new): nginx TLS terminator for Compose — terminates
  TLS, 308-redirects HTTP→HTTPS, sets `X-Forwarded-Proto`/`-For`, HSTS +
  hardening headers at the edge, upgrades `/ws`, forwards to the **internal**
  `s43-api:8000` (no longer host-published). Self-signed dev-cert helpers.
  `README.md` covers real provisioning / validation / renewal / expiry
  monitoring.
- **`SecurityHeadersMiddleware`** (new): HSTS only when the request arrived
  over HTTPS (scope scheme, or `X-Forwarded-Proto` from a trusted proxy) and
  never local; static COOP / CORP / Permissions-Policy / nosniff / frame-deny
  / referrer; opt-in CSP.
- **`TrustedHostGuard`** (new): `S43_TRUSTED_HOSTS` allow-list, leading-dot
  wildcard, **probe paths always exempt** (k8s `Host: <podIP>`).
- **`_validate_security_config()`**: a non-local start with a plaintext
  non-loopback `S43_ALLOWED_ORIGINS` entry now **refuses** (opt-out
  `S43_ALLOW_INSECURE_ORIGINS`).
- k8s `overlays/beta/ingress.yaml`: HSTS + hardening headers pinned;
  `configmap-patch.yaml` adds `S43_TRUSTED_HOSTS` / https origin placeholders.

### C.3 Browser session (P3)
- `POST /auth/refresh`, `POST /auth/logout`; `/auth/login` creates a
  server-side session + sets `s43_refresh` (HttpOnly; Secure*; SameSite=Strict;
  Path=/auth) and `s43_csrf` cookies + a `sid`-bound 15-min access token for
  DB accounts. Env operator → legacy 8h token, no cookie.
- **Phase-B dual contract** in `require_operator`, `require_admin`,
  `_get_operator`, `dashboard_websocket`: a live session-bound token
  authenticates alone (no `X-S43-Password`); an old-style token still needs
  it. `resolve_session_subject()` = one read-only PK lookup + one user lookup
  per request → **immediate** revocation.
- Revoke hooks (same transaction): disable / role change / password reset →
  `revoke_all_user_sessions`.
- WS: `{token}`-only frame; `S43_WS_SESSION_RECHECK_SECONDS` mid-stream
  re-check; `_ws_safe_close(reason=...)` (finding #6). `websocket.js` v1.7.0.
- **#11:** `_env_operator_allowed()` — env operator is break-glass only
  (no admin / DB down / `S43_BREAK_GLASS_ARMED`).
- `legacy_auth_request_total` counter on `/metrics`; `S43_REJECT_LEGACY_AUTH`
  cutover flag (default **off**).
- `auth.js` v1.7.0: refresh-on-load, `/auth/logout`, `{token}` WS frame.
  **Not browser-verified** — see §E.

### C.4 Service integration (P4)
- `0003_users_role_check` — `CHECK (role IN ('operator','admin'))`, fail-closed
  pre-check; model matches; `alembic check` clean; up/down/up verified.
- Service-integration map (feature → entrypoint / auth / permission /
  dependency / check; container network; `/events/proxy` HTTP-ingest vs
  WS-rebroadcast distinction) was written in `SERVICE_INTEGRATION_BETA.md`;
  that file was removed on `main` with the other superseded design docs.
- P3-8 (case-insensitive uniqueness): **deferred** to `0004` with a precise
  plan — Informational, needs a real-target collision inventory.

### C.5 Ops (P5)
- **Finding #13 fixed** — `S43_SECRETS_ROTATED_AT` + the session env vars are
  forwarded by `docker-compose.yml` and present in the k8s base ConfigMap.
- `generate-dev-cert.sh` MSYS guard; `s43-setup` `generate_secrets.py` path
  (A5); proxy static IP `172.28.0.250`.

## D. Measured validation

- Full isolated suite: 385 (start) → 429 (P1+P2) → 449 (P3) → **454** (P4-P6).
  0 failed / 0 skipped throughout. SI: `test_service_identity_separation` 12/12.
- Live stack smoke (Compose beta, HTTPS, `SENTINEL_ENV=beta`): image build
  36s; 6 containers healthy; `s43-migrate` ran the 3 revisions and exited 0;
  HTTPS `/health`+`/ready`; HTTP→HTTPS 308; HSTS; backend not published;
  forged XFF → 401; WSS `101`; bootstrap → login → session `/users` **without**
  `X-S43-Password` → 200; refresh/logout/CSRF-403/Origin-403; restart +
  `s43-db` recreation persist data; `pg_dump` → restore into a separate DB
  (revoked sessions stay revoked). In-network load: **6617 req/s, p50=8ms,
  0 failed**. Container log scan: **0** credential / token / cookie /
  connection-string hits.
- k8s: `overlays/dev` + `overlays/beta` render + pass `k8s_policy_check.py`
  (114 / 117 assertions). Not applied to a cluster.

## E. Not done / needs verification

| item | why | how to close |
|---|---|---|
| **F-TLS-1** | a local self-signed cert proves the *integration*, not issuance/renewal against a real hostname + CA | complete `overlays/beta/ingress.yaml` (real host, `ClusterIssuer`, verified cert-manager Secret) **or** a config-managed proxy cert on the Compose host; run `deploy_preflight.py --phase verify` and `browser_tests/run_target.sh` against the named target |
| **Browser SPA smoke** | The disposable run (`browser_tests/`, 10/10) verified the shipped SPA's **application behaviour** against a **local disposable stack** — a throwaway test CA accepted via a Chromium SPKI exception + a `CERT_NONE` fixture context. It is **not** certificate-chain validation and **not** a real-target result. | `browser_tests/run.sh` for the disposable check; **`browser_tests/run_target.sh`** (`S43_TARGET_BASE_URL=https://<fqdn>`, trusted-CA verification, dedicated test accounts) against the deployed beta — that is F-TLS-1's browser half |
| **`S43_REJECT_LEGACY_AUTH` cutover** | Phase E; needs `run_target.sh` green + an observation window with `legacy_auth_request_total._all == 0` + operator sign-off | after the above, set it true (one-var rollback) |
| **P3-8** case-insensitive uniqueness | Informational; needs a real-target collision inventory | migration `0004` — **deferred**, needs the collision inventory first (do not introduce it without one) |
| **Multi-replica login throttle** | still in-process/per-pod (`overlays/beta` runs 2 replicas → 2× the limit) | pin beta to **1 replica + 1 worker** (`deploy_preflight.py --phase verify` checks both) — the recommended config; a shared limiter is a separate change only if a confirmed requirement needs it |
| **k8s cluster apply** | no cluster tested here | `kubectl apply -k overlays/beta` on a NetworkPolicy-enforcing CNI; `kubectl wait job/s43-migration`; the CI `k8s.yml` kind-smoke covers the mechanism |
| #19 proxy `raw` rebroadcast · #14 anon status detail · #16 Docker Scout · #18 image digest pinning | lower severity; recorded | tracked; `deploy_preflight.py` PASSes image identity only on a `repo@sha256:<digest>` reference or a recorded local `--image-id` + `--source-revision` |
| Windows-loopback load number (p50≈2s through the published port) | Docker Desktop for Windows userland-proxy limit, not the app (in-network 8ms) | a real load test belongs on the named target |

## F. Supported beta configuration

- **Audience:** a controlled closed beta — trusted operators, behind edge
  TLS. Not public-internet, not government-facing without a separate
  assessment (§10).
- **Replicas:** **1** `s43-api` for the login throttle to be correct
  (`overlays/beta` ships 2 + a PDB — override to 1, or accept the doubled
  rate limit, until the limiter is shared).
- **Supported features:** bootstrap; login / refresh / logout (session) +
  legacy Bearer+password; `/users` admin; `/v1` operator API (with a real
  engine/store factory or `S43_ENABLE_DEV_*` off); dashboard actions + WS;
  Watchtower bridge; audit; remote gateway; Fenrir report bridge.
- **Excluded / not validated for beta:** public exposure of `/docs` `/redoc`
  `/openapi.json` (FastAPI default, unauthenticated — operator's call);
  Redis-backed anything (nothing in `core/` uses Redis); Sparta / governance
  / Jormungandr feature flags (off by default); external-repo integrations
  (none exist).
- **Required env** (`.env` / Secret): `POSTGRES_PASSWORD`, `REDIS_PASSWORD`,
  `DATABASE_URL`, `S43_JWT_SECRET` (≥32B), `S43_AUTH_PEPPER` (≥32B),
  `S43_JWT_ISSUER`, `S43_JWT_AUDIENCE`, `S43_OPERATOR_PASSWORD_HASH`,
  `S43_WATCHTOWER_SERVICE_TOKEN`, `SENTINEL_LOG_SALT`,
  `SENTINEL_REMOTE_TOKEN_{OWNER,ADMIN,AUDITOR}`, `S43_FENRIR_API_TOKEN`,
  **`S43_SECRETS_ROTATED_AT`** (the generator writes it — #13), and for the
  beta profile `SENTINEL_ENV` (non-local), `S43_ALLOWED_ORIGINS` (https),
  `S43_TRUSTED_HOSTS`, `S43_TRUSTED_PROXIES`.

## G. Reproducible startup

**Docker Compose (documented default):**
```bash
git clone <repo> && cd Sentinel-43
python core/scripts/generate_secrets.py --write .env
python core/scripts/generate_secrets.py --password-hash   # paste S43_OPERATOR_PASSWORD_HASH into .env
# beta profile: set in .env — SENTINEL_ENV=beta (or production),
#   S43_ALLOWED_ORIGINS=https://<host>, S43_TRUSTED_HOSTS=<host>
./deploy/proxy/generate-dev-cert.sh <host>          # or drop a real cert at deploy/proxy/certs/s43.{crt,key}
docker compose up -d                                # s43-migrate runs alembic, then s43-api starts
curl -k https://localhost/health                    # -> {"status":"ok",...}
curl -k https://localhost/ready                     # -> {"status":"ready"} once migrated
curl -k -X POST https://localhost/bootstrap/admin -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<12+ chars>"}'
```
Existing pre-Alembic DB: `docker compose run --rm s43-migrate alembic stamp 0001_baseline` once, then `docker compose up -d`.

**Kubernetes (public-beta path):** `deploy/kubernetes/README.md` — provision
`sentinel43-secrets`, set the `overlays/beta` CHANGEMEs (host, `ClusterIssuer`,
image digest, `S43_TRUSTED_PROXIES`, `S43_SECRETS_ROTATED_AT`),
`kubectl apply -k deploy/kubernetes/overlays/beta`,
`kubectl wait --for=condition=Complete job/s43-migration -n sentinel43`.

## H. Rollout / backup / rollback

- **Rollout:** migrate first (Job / `s43-migrate`), then the API. API pods
  self-gate on `/ready` (503 until the schema matches) so a `RollingUpdate`
  never routes to a replica ahead of/behind the schema. `maxUnavailable: 0`.
- **Backup (before any migration on an existing beta DB):**
  `docker compose exec s43-db pg_dump -U s43 -Fc s43 > s43-$(date +%Y%m%dT%H%M%S).dump`
  (k8s: `kubectl exec s43-db-0 -- pg_dump …`).
- **Rollback of a bad migration:** **restore the backup** into a fresh
  database and swap — NOT `alembic downgrade`. `0001_baseline` has no
  supported downgrade; `0002_sessions` downgrade **destroys all active
  session state**; `alembic downgrade base` is a fail-safe no-op.
  A restore brings back sessions that were live at backup time; sessions
  revoked before the backup stay revoked. Revoke anything that should not
  survive (`revoke_all_user_sessions` / disable the account).
- **Rollback of a bad app deploy:** `kubectl rollout undo deployment/s43-api`
  / redeploy the previous image. No schema change needed if the migration
  chain is unchanged.
- **`S43_REJECT_LEGACY_AUTH` rollback:** set it back to false — one env var,
  no code change (the legacy path is retained).

## I. Confirmation — no prohibited actions

No push / force-push / merge to main / `origin/main` change / PR / GitHub
settings / visibility change / OneDrive-repo change / production deploy /
live-DB access-migrate-modify / `ALTER ROLE` / credential rotation /
deployment-secret change / secret exposure / branch or tag deletion / recovery
-bundle removal. **The user's running Compose stack (`sentinel-43`) was never
started / stopped / restarted / rebuilt / touched** — the P5 smoke ran as a
separate project (`s43smoke`, renamed containers, ports 18443/18080) and was
`down -v`'d after. All migration validation used disposable `postgres:16.3`
(`--rm --tmpfs`) or a throw-away Compose volume.

## J. State of the tree

- **Committed:** everything in §B (5 commits, `8614f9b..5c06dbe`).
- **Pushed:** nothing.
- **Deployed locally:** the P5 smoke stack — brought up, verified, torn down
  (`down -v`). Not running now.
- **Deployed externally:** nothing.

---

## K. Integration pass — next PR (2026-09-02/03)

Adds one reviewable PR: `integration/beta-hardening-20260901` → `main`.
Full detail in `BETA_EXECUTION.md §7` (and §8/§9 for the follow-ups).

- **Branch pushed** to `origin`; **PR #251** (`integration/beta-hardening-20260901`
  → `main`). Tip `07686bc` = 6 commits on `a8a5678`. No force, `main` untouched,
  no merge performed.
- **`main` had advanced** to `eb7780f` (merged PR #250 — CI/container
  hardening, canonical JWT verify, users-router wiring — and PR #248). All
  0 PRs open now; #247 closed unmerged.
- **Merge commit `f3d93e2`** — `main` → the branch, conflicts resolved by
  behaviour (newer session/auth contract kept, CI/container fixes adopted).
  Two semantic merge defects fixed: a duplicate `users_router`
  registration and a `Dockerfile` with both Alpine and Debian user-creation
  blocks. Post-merge full isolated suite **457 passed / 0 / 0**.
- **Browser SPA smoke** — `browser_tests/` (Playwright + real Chromium →
  nginx TLS → API → disposable PG), **10/10**. Uncovered that the SPA was
  hardwired to `http://localhost:8000`; fixed to same-origin
  (`connect-src 'self'`, `location.origin`, `wss://<same-origin>/ws`),
  moved the access token to memory-only, and fixed a websocket.js
  multi-socket race. `auth.js`/`websocket.js`/`dashboard.js` → v1.8.0.
  **Scope (REV 3):** this run proves the SPA's *application behaviour*
  against a **local disposable stack** only — its "TLS" is a throwaway test
  CA via an SPKI exception + `CERT_NONE` fixture, i.e. not certificate-chain
  validation and not a real-target result. Real-target browser acceptance is
  `browser_tests/target_acceptance/` + `run_target.sh` (§K REV 3).
- **CI** (`.github/workflows/k8s.yml`) — new `pg-tests` job runs beta's nine
  `*_pg.py` suites against a disposable PostgreSQL and **fails on any skip**
  (green on the first PR run); new `browser-smoke` job runs
  `browser_tests/run.sh`; `build-and-scan` + `kind-smoke-deploy` now
  `needs: pg-tests`. `scripts/ci_live_tests.py` fixed (`07686bc`) to run
  `alembic upgrade head` + arm break-glass for its disposable DB.
- **Deployment preflight** — `scripts/deploy_preflight.py` (read-only;
  `compose` / `kube` modes). **Superseded by the phase-aware rewrite —
  see §K REV 3 and `BETA_EXECUTION.md §9`.**

### Startup addendum (Compose) — the SPA is same-origin now

No SPA config needed for the supported setup: the API serves
`/dashboard` + `/assets` and the nginx proxy terminates TLS, so `/auth/*`,
`/api/*` and `/ws` are all same-origin. Only a *split-origin* dev setup
needs `window.SENTINEL_API_BASE_URL` / `SENTINEL_WS_URL` (and that origin
added to the page's `connect-src`).

### `docker-compose.browser.yml` / `browser_tests/`

Two suites, kept apart:
- **`browser_tests/` (disposable)** — `./browser_tests/run.sh` stands up an
  isolated `s43browser` project (own subnet `172.29.0.0/24`, proxy on
  `127.0.0.1:8443`), runs the Playwright suite, `down -v`s. Never touches
  another stack. `run.sh` now **refuses** a foreign `S43_BROWSER_BASE_URL`.
- **`browser_tests/target_acceptance/` (target acceptance)** — `run_target.sh` against a
  **real deployed target**: explicit `S43_TARGET_BASE_URL=https://<fqdn>`
  used for both browser and API, standard trusted-CA verification (optional
  `S43_TARGET_CA_BUNDLE`, never disabled), **never** starts/stops/`down -v`s a
  stack, **never** bootstraps an admin, credentials read from files
  (`S43_TARGET_OPERATOR_CRED_FILE`; admin-mutation needs
  `S43_TARGET_ADMIN_SCOPE=explicit-dedicated-account` + dedicated throwaway
  accounts). Missing credentials → an errored (INCOMPLETE) run, not a green
  skip.

### Post-merge verification pass (REV 2, after PR #251 merged)

PR #251 merged to `main` as `0bd375a`. A follow-up PR from
`beta/post-merge-verification-20260903` adds: (1) the documented merge-diff
review showing the merge left every auth/session/authz file byte-identical
to the pre-merge branch (`BETA_EXECUTION.md §7/§8`); (2) `S43_REJECT_LEGACY_AUTH`
tested in **both** states (`test_auth_session_pg.py`, `test_ws_session_pg.py`)
— on: legacy Bearer/JWT and legacy WS frame rejected on `/v1`, `/users`, and
`/ws`, session auth unaffected; (3) a **direct schema-introspection** check
that the `sessions.refresh_hash` uniqueness guard is still the partial,
`revoked_at IS NULL`-scoped index after the merge
(`test_migrations_pg.py`, in the `pg-tests` CI job); (4) `deploy_preflight.py`
now checks **one replica AND one uvicorn worker** (no `--scale`,
`--workers > 1`, or `WEB_CONCURRENCY > 1`) in both modes.

### Release-tooling corrections (REV 3, 2026-09-03) — `BETA_EXECUTION.md §9`

The REV 1/REV 2 "target-independent work finished" claim was premature for
the **tooling**: findings A–E were still reproducible. This pass corrects
their causes (auth/migration/session results unchanged):

- **`deploy_preflight.py` is now phase-aware.** `--phase {prepare,verify}` is
  **required** (no default). Exit `0` = every mandatory check for that phase
  passed; `1` = a confirmed FAIL; `2` = a mandatory check **INCOMPLETE** —
  never silently 0. `prepare` = deploy inputs, nothing running (and a pass is
  labelled "inputs in order", **not** beta acceptance). `verify` = the live
  target (edge TLS via the real trust store or `--ca-bundle`, redirect
  without following it, `/health`+`/ready`, HSTS, docs surface by real
  response, one instance **and** one worker, structured compose/kube
  inspection that never treats an error or a missing resource as a pass).
- **Image identity:** PASS only on `repo/name@sha256:<64-hex>` or a plain tag
  **plus** `--image-id sha256:<id>` + `--source-revision <git-sha>`. A
  `:sha256-…` tag is rejected — it is not digest pinning.
- **Browser target acceptance split out** (`browser_tests/target_acceptance/`,
  `run_target.sh`) — see the `browser_tests/` note above.
- `core/tests/test_deploy_preflight.py` (53 tests) in the `test` job; the
  `browser-smoke` job lints both runners and collects (never runs) the
  target suite.

## §10 — three separate conclusions

1. **Implementation verified locally: YES.** Every phase's behaviour is
   backed by behavioural tests (disposable PostgreSQL, not mocks) and, for
   the deployment/transport/session/ops surface, by an end-to-end run of the
   real Compose beta stack over HTTPS. Full isolated suite green.

2. **Ready for a controlled beta on a named, validated target: BLOCKED —
   on target-dependent verification and one operational choice:**
   - **F-TLS-1** — `deploy_preflight.py --phase verify` and
     `browser_tests/run_target.sh` both green against the real hostname + CA
     on the target. The disposable browser run (10/10) is
     **application-behaviour evidence against a local stack only** — it does
     not validate a real certificate chain.
   - The operational choice in §F: **1 replica + 1 worker** for the login
     throttle (both now checked by `deploy_preflight.py --phase verify`), or a
     shared throttle.
   Everything target-independent is in place and reproducible; the tooling
   defects that made the earlier "finished" claim premature are fixed
   (REV 3 / `BETA_EXECUTION.md §9`).

3. **Production / public / government readiness: NO.** *This conclusion is a
   status report only — it states where readiness stands, and is not
   authorization for, or a step toward, certification or compliance work
   (that work is out of scope).* This is a controlled-beta candidate.
   Production would require the actual target and its applicable requirements
   to be assessed by whoever owns that decision — the k8s path is explicitly
   "public-beta, not production-certified" (`deploy/kubernetes/README.md`),
   HA Postgres/Redis is out of scope, `/docs` exposure is an open owner
   decision, and no certification or compliance claim is made or implied by
   any test count in this repository.

---

## The single remaining target-specific decision

**Name the beta target** — provide: target type (Docker Compose host, or
Kubernetes context + namespace); the hostname (FQDN); the certificate
approach (public CA / cert-manager `ClusterIssuer` / a config-managed proxy
cert, and any private CA bundle); and whether the database is fresh or
existing. Then:

1. `python scripts/deploy_preflight.py {compose|kube} --phase prepare
   --hostname <fqdn> [--env-file .env | --context <ctx> --namespace <ns>]
   --image <repo@sha256:… | tag --image-id … --source-revision …>`
2. fill `overlays/beta` CHANGEMEs / `.env` with real values; provision the
   edge cert
3. deploy (migrate first — Job / `s43-migrate` — then the API; §G–H)
4. `python scripts/deploy_preflight.py {compose|kube} --phase verify
   --hostname <fqdn> …` — must exit 0 from an external vantage point
5. `S43_TARGET_BASE_URL=https://<fqdn> S43_TARGET_OPERATOR_CRED_FILE=…
   bash browser_tests/run_target.sh` — closes F-TLS-1's browser half

Until then, every target-independent artifact and procedure above is ready;
F-TLS-1 stays open and no certification/compliance claim is made.
