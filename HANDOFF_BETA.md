# HANDOFF_BETA.md

Sentinel-43 — beta-execution handoff. Migration deployment integration,
secure transport, browser/session authentication, #11 remediation, service
integration, operational hardening, and beta validation, on top of the
Pass 5A-Migration foundation.

**Read the three conclusions in §10 before treating anything here as
"production-ready" — it is not.**

Companions: `BETA_EXECUTION.md` (checkpoint), `MIGRATION_DEPLOYMENT_BETA.md`,
`AUTH_SESSION_BETA.md`, `SERVICE_INTEGRATION_BETA.md`, `PASS_BETA_VALIDATION.md`,
`deploy/proxy/README.md`. Pass 5A/5AM docs unchanged.

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

### C.3 Browser session (P3, AUTH_SESSION_BETA.md)
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
- `SERVICE_INTEGRATION_BETA.md` — every feature → entrypoint / auth /
  permission / dependency / check; container network; `/events/proxy`
  HTTP-ingest vs WS-rebroadcast distinction.
- P3-8 (case-insensitive uniqueness): **deferred** to `0004` with a precise
  plan — Informational, needs a real-target collision inventory.

### C.5 Ops (P5)
- **Finding #13 fixed** — `S43_SECRETS_ROTATED_AT` + the session env vars are
  forwarded by `docker-compose.yml` and present in the k8s base ConfigMap.
- `generate-dev-cert.sh` MSYS guard; `s43-setup` `generate_secrets.py` path
  (A5); proxy static IP `172.28.0.250`.

## D. Measured validation (PASS_BETA_VALIDATION.md has the detail)

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
| **F-TLS-1** | a local self-signed cert proves the *integration*, not issuance/renewal against a real hostname + CA | complete `overlays/beta/ingress.yaml` (real host, `ClusterIssuer`, verified cert-manager Secret) **or** a config-managed proxy cert on the Compose host; re-run the login→refresh→logout + WSS flow over real HTTPS (`deploy/proxy/README.md`) |
| **Browser SPA smoke** | no headless browser in this environment; `auth.js`/`websocket.js` v1.7.0 changes are graceful-degradation but unrun in a real browser | load the dashboard against the beta stack, confirm: login, reload stays logged in (refresh-on-load), logout, WS connects with `{token}` only, a revoked session drops the socket |
| **`S43_REJECT_LEGACY_AUTH` cutover** | Phase E; needs the browser smoke + an observation window with `legacy_auth_request_total._all == 0` + operator sign-off | after the above, set it true (one-var rollback) |
| **P3-8** case-insensitive uniqueness | Informational; needs a real-target collision inventory | migration `0004` per `SERVICE_INTEGRATION_BETA.md §4` |
| **Multi-replica login throttle** | still in-process/per-pod (`overlays/beta` runs 2 replicas → 2× the limit) | Redis-backed limiter, or pin beta to 1 replica and document it |
| **k8s cluster apply** | no cluster tested here | `kubectl apply -k overlays/beta` on a NetworkPolicy-enforcing CNI; `kubectl wait job/s43-migration`; the CI `k8s.yml` kind-smoke covers the mechanism |
| #19 proxy `raw` rebroadcast · #14 anon status detail · #16 Docker Scout · #18 image digest pinning | lower severity; recorded | `SERVICE_INTEGRATION_BETA.md §4` |
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

## §10 — three separate conclusions

1. **Implementation verified locally: YES.** Every phase's behaviour is
   backed by behavioural tests (disposable PostgreSQL, not mocks) and, for
   the deployment/transport/session/ops surface, by an end-to-end run of the
   real Compose beta stack over HTTPS. Full isolated suite green.

2. **Ready for a controlled beta on a named, validated target: NOT YET —
   blocked on two verifications, both listed in §E:**
   - **F-TLS-1** — edge TLS proven against a real hostname + CA on the target.
   - **Browser SPA smoke** — the v1.7.0 dashboard exercised in a real browser
     against the beta stack.
   Plus the operational choice in §F (1 replica, or a shared throttle).
   Everything else needed for a controlled beta is in place and reproducible.

3. **Production / public / government readiness: NO.** This is a controlled-
   beta candidate. Production requires the actual target and its applicable
   requirements assessed — the k8s path is explicitly "public-beta, not
   production-certified" (`deploy/kubernetes/README.md`), HA Postgres/Redis is
   out of scope, `/docs` exposure is an open owner decision, and no
   certification/compliance claim is made or implied by any test count here.

---

## The single remaining target-specific decision

**Name the beta target** (a Docker host + hostname, or a Kubernetes
context/cluster/namespace + hostname), so that: (a) the edge-TLS cert can be
provisioned and F-TLS-1 verified against it, (b) `overlays/beta` CHANGEMEs /
`.env` can be filled with real values, (c) the migration can be run on that
target's database as an explicit operator step, and (d) the browser smoke can
be done against it. Until then, this branch is the finished release candidate
and every rollout artifact + procedure above is ready.
