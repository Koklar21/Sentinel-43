# BETA_EXECUTION.md

Sentinel-43 — alpha → working beta. The single execution checkpoint for the
beta-hardening phases that follow Pass 5A-Migration. Re-read at every phase
boundary and after any context compaction. **Subordinate to code + test
evidence** — if this file and the code disagree, the code wins; fix this file.

- **Branch:** `integration/beta-hardening-20260901`
- **Working clone:** `C:\Users\heero\Sentinel-43-work` (NOT the OneDrive copy).
  `origin` (GitHub) and `evidence-local` (OneDrive repo) both have push
  disabled (`DISABLED_NO_PUSH`). Fresh venv `.venv-pass1` (Python 3.13.5).
- **Original OneDrive repo:** `C:\Users\heero\OneDrive\...\Sentinel-43`, HEAD
  `e859b61`, left untouched.

---

## 1. Verified starting point (2026-09-02)

| Fact | Verified value |
|---|---|
| HEAD at start | `8614f9b` |
| Ancestry | `7a72976` (Pass 5A HEAD) is an ancestor; `git merge-base 7a72976 HEAD == 7a72976` |
| Commits `7a72976..HEAD` | **7** (`f218e30`, `6b37aa4`, `167aa27`, `d5f402d`, `84f749b`, `58177a7`, `8614f9b`). The Pass 5AM completion report said "6" in its prose — **that count was wrong**; `git rev-list --count 7a72976..HEAD` = 7. HANDOFF_PASS5AM §B lists all seven correctly (five substantive + two doc-hash-sync). Corrected here per the beta instruction. |
| `git status` | clean |
| Worktree | single (`C:\Users\heero\Sentinel-43-work`) |
| Alembic | 1.19.1 · SQLAlchemy 2.0.52 · asyncpg 0.31.0 · FastAPI 0.141.1 · uvicorn 0.52.4 · pytest 9.1.1 |
| Pre-work recovery | `C:\Users\heero\AppData\Local\sentinel43-recovery\beta-execution-20260902\PRE.bundle` (verified "records a complete history") + `HEAD-PRE.txt` |
| Baseline full suite | _RUNNING — record here_ (Pass 5AM recorded 385 passed / 0 failed / 0 skipped / exit 0) |
| Baseline security invariants | Pass 5AM recorded 13/13 — re-confirm |

**DB-shape rule honoured:** "historical model code does not establish the
shape of a real database." Every migration-path claim in this pass is checked
against a real disposable PostgreSQL 16.3 through
`migrations/baseline.py::check_users_baseline` / `assert_users_baseline`, not
by reading the ORM.

---

## 2. Invariants carried in (do not regress)

1. **Two metadata objects.** `core.auth.users.Base` → `users`;
   `core.auth.sessions.SessionBase` → `sessions`. `init_models()` builds only
   `users`. Alembic `target_metadata` is the combined view for autogenerate.
2. **refresh_hash uniqueness = shape B** — partial unique index
   `WHERE revoked_at IS NULL` (model + `0002_sessions` agree).
3. **`fk_sessions_user_id_users` = ON DELETE RESTRICT** (§15 Case 2 — no
   user-deletion pathway exists).
4. **`0001_baseline` downgrade is unsupported**; `alembic downgrade base`
   fail-safe rolls back. Session-table downgrade **destroys active session
   state** — never the default rollback plan.
5. **Alembic is the sole production schema authority.** No second migration
   system. Do not rewrite an applied revision to hide drift — add a new one.
6. **Service ≠ human identity.** No path where a human session/access token
   satisfies a service verifier (Watchtower / Fenrir / Sparta / remote-gateway
   / admin-token), or vice versa. SI script stays 13/13.
7. **Legacy auth stays working until its migration is proven** — Bearer JWT +
   `X-S43-Password`, `require_operator`/`require_admin`, `/auth/login`
   contract, WebSocket `{token,password}` frame, the `dev-operator` local
   fallback. Dual-contract (Phase B) before any rejection (Phase E).
8. **Helpers flush, routes commit** (Pass 3 transaction boundary).
   `rotate_refresh` revoke-and-raise branches (reuse / owner-inactive) require
   the caller to `commit()` before surfacing 401.
9. Firewall fail-closed startup, trusted-proxy right-to-left hop walk,
   `--forwarded-allow-ips 127.0.0.1`, `:9100` not host-published (Pass 1/2).

---

## 3. Open blockers carried in

| ID | State |
|---|---|
| **F-TLS-1** | BLOCKING for browser-session cutover. No secure production TLS posture from repo evidence. Phase 2 of this pass builds the smallest deployment-compatible solution + local HTTPS test; stays open for any unverified target-specific portion. |
| **#11** env-operator | Open. Un-salted fast SHA-256, checked on every failed login + reverify fall-through. Pass 4 recommendation: Option C (scoped break-glass) with fallback to Option A (removal). Phase 5. |
| **X-S43-Password** | Not retired. Reusable password on every protected request + WS frame. Phase 5: inventory consumers, ship the cookie-session replacement, reject in the beta profile once proven. |
| P3-7 | `User.role` has no DB CHECK constraint. Rides an Alembic migration this pass. |
| P3-8 | username/email not case-folded; `unique` is case-sensitive. Needs a live-data collision inventory + migration. |
| #6 | `_ws_safe_close` passes no `reason` → `websocket.js` can't classify auth failures. Phase 4. |
| multi-replica login throttle | in-process only. Beta is single-replica or needs shared enforcement. Phase 5. |
| schema-version startup check | designed (MIGRATION_ARCHITECTURE §14), not built. Phase 1. |
| create_all vs Alembic | `bootstrap.py` + `migration-job.yaml` still call `init_models()`. Phase 1. |

---

## 4. Phases + acceptance gates

| Phase | Scope | Gate |
|---|---|---|
| **P1 — migration deployment** | Compose one-shot `s43-migrate` (db-healthy → migrate-complete → api-start); k8s Job → `alembic upgrade head`; `schema_version` check on readiness (not liveness), gated non-local; stop prod `create_all`; fresh + compatible-baseline + incompatible-refusal paths tested; backup-restore proof. | fresh migrate + baseline adopt + incompatible refuse + runtime version check all pass on disposable PG; stack starts in the right order; full suite green |
| **P2 — secure transport** | Compose reverse proxy (TLS terminator) + local test cert; security headers; explicit trusted hosts/origins; narrow trusted-proxy `X-Forwarded-Proto`; backend not directly reachable; HTTPS integration test (forged XFF, HTTP handling, secure-cookie, WSS upgrade). | login/WSS work through the proxy over local HTTPS; forged forwarding headers rejected; backend port not published; F-TLS-1 updated (target-specific parts stay open) |
| **P3 — auth end-to-end** | `/auth/login` → session + refresh cookie + `sid` access token + CSRF; `/auth/refresh`; `/auth/logout`; revoke hooks on disable/role/password; Phase B dual contract in `require_*` + `_get_operator` + WS; `{token}`-only WS frame; #11 break-glass; X-S43-Password inventory + beta-profile rejection; throttle replica model. | login/refresh/logout/CSRF-reject/expiry/replay/disabled-user all pass through the deployed test stack; legacy path still green; SI 13/13; service-identity separation intact |
| **P4 — service & docker integration** | route inventory → entrypoint/authn/permission/dep/check map; container-network exercise; Watchtower/bridge restrictions preserved; WS close-helper `reason`; P3-7 + P3-8 migrations. | each beta feature: authed OK / unauthed fail / dependency-failure / recovery; `/events/proxy` HTTP-ingest vs WS-rebroadcast kept distinct |
| **P5 — release & ops hardening** | clean-checkout image build + stack bring-up; least-priv; secrets outside SCC; structured sanitized logs + correlation; size/timeout/resource limits; bounded smoke/load/restart; persistence across recreation; backup/restore with synthetic session state. | clean checkout builds+starts via documented commands; log scan finds no credential/cookie/hash/DSN; smoke/load/restart measured; restore documented to not reactivate revoked sessions |
| **P6 — beta validation** | run focused checks per change + full required suite against the final implementation; no mocks for DB/stack integration; no weakened security checks. | §8 acceptance list; three separate conclusions (local / named-target / production) |
| **P7 — finish & handoff** | logical commits; update existing arch/deploy docs; final report; maintain this checkpoint. | final report with actual start/end commits, measured results, supported beta config, startup + rollout + backup/rollback procedure, remaining blockers + evidence to close each |

---

## 5. Current checkpoint

**PHASE: P6→P7 — validation + handoff.** Commit chain on `8614f9b`:
`d529f04` (P1+P2) · `1acc423` (P3) · `aa7f2b1` (P4) · `5c06dbe` (P4-P5).
Full stack smoke green end to end (`PASS_BETA_VALIDATION.md`). Final full
regression suite running; then recovery snapshot + `HANDOFF_BETA.md` + STOP
at the single target-specific decision.

### P4 done
- `0003_users_role_check` (P3-7 CHECK, fail-closed pre-check); model
  `__table_args__` matches; `alembic check` clean.
- P3-8: **deferred** to `0004` with a precise plan (`SERVICE_INTEGRATION_BETA.md §4`).
- `SERVICE_INTEGRATION_BETA.md` — feature→entrypoint map, container network,
  finding statuses.

### P5 done (live stack, separate project `s43smoke`, torn down after)
- clean image build; 6 containers healthy; migrate→api ordering verified.
- HTTPS through `s43-proxy`; HSTS; backend not published; forged XFF → 401;
  WSS `101`; bootstrap→login→session `/users` without `X-S43-Password` → 200;
  refresh/logout/CSRF/Origin; restart + volume persistence; pg_dump→restore.
- **Finding #13 fixed** (`S43_SECRETS_ROTATED_AT` not forwarded — API
  crash-looped); `TrustedHostGuard` (probe paths exempt); proxy static-IP
  collision fixed.
- in-network load 6617 req/s p50=8ms 0 failed. Log scan: 0 credential hits.

### P3 done (browser session end to end)
- `/auth/refresh`, `/auth/logout`; login creates a session + sets HttpOnly
  refresh cookie + JS-readable CSRF cookie + sid-bound 15-min token for DB
  accounts (env operator → legacy token, no cookie).
- Phase-B dual contract in all 4 enforcement points: a live session-bound
  token skips `X-S43-Password`; old-style token still requires it.
  `resolve_session_subject()` = 1 read-only PK lookup/request →
  **immediate** revocation (logout / disable / role / password / replay).
- WS: `{token}`-only frame for session tokens; `S43_WS_SESSION_RECHECK_
  SECONDS` mid-stream re-check; `_ws_safe_close(reason=...)` (finding #6).
- `revoke_all_user_sessions` wired into PATCH/password routes (same txn).
- #11: `_env_operator_allowed()` — env operator is break-glass only
  (no admin / DB down / `S43_BREAK_GLASS_ARMED`).
- `legacy_auth_request_total` counter (on `/metrics`); `S43_REJECT_LEGACY_
  AUTH` cutover flag (default off).
- `auth.js` v1.7.0 / `websocket.js` v1.7.0 — refresh-on-load, logout
  endpoint, `{token}` WS frame. **Not browser-verified** (no browser here).
- Tests: `test_auth_session_pg` (12), `test_ws_session_pg` (4),
  `test_break_glass_pg` (4). `AUTH_SESSION_BETA.md`.

### P0 completed
- Repo state verified (§1). Commit-count discrepancy (7 vs 6) resolved: 7.
- Pre-work recovery bundle written + verified.
- Full architecture read.
- Baseline: inherited from Pass 5AM (**385 passed / 0 failed / 0 skipped**;
  no runtime code changed between `8614f9b` and the start of this session).
  SI 13/13 inherited.

### P1 + P2 done — commit `d529f04`
- P1: `core/auth/schema_version.py`; `/ready` 503 gate (non-local, DB not at
  head); `init_models()` no-op in non-local; `s43-migrate` compose one-shot;
  k8s Job → `alembic upgrade head`; A5 fix; `MIGRATION_DEPLOYMENT_BETA.md`.
- P2: `deploy/proxy/` nginx TLS terminator + dev-cert helpers;
  `SecurityHeadersMiddleware` (HSTS gated on real HTTPS); `TrustedHostMiddleware`
  (`S43_TRUSTED_HOSTS`); non-local plaintext-origin startup refusal;
  backend no longer host-published; k8s beta ingress HSTS.
- Recovery proof: `test_backup_restore_pg.py` — real `pg_dump` → restore into
  a separate DB; a pre-backup-revoked session restores revoked.
- Full isolated suite **429 passed / 0 failed / 0 skipped** (191s, fast-
  watchtower env). k8s dev+beta overlays render + policy-pass.

### Remaining
P3 (auth end-to-end) → P7 per §4.

### P2 — still open on F-TLS-1
The Compose proxy + k8s ingress are the mechanism; a **local self-signed
cert** proves the integration only. F-TLS-1 stays OPEN until edge TLS is
verified against a real hostname + CA on a named target (see
`deploy/proxy/README.md`). Live HTTPS integration test (forged XFF, HTTP
handling, secure-cookie, WSS through the proxy) is a P3/P6 stack test —
not yet run.

### Environment note (test-run speed)
The user's OWN Docker Compose stack (from the OneDrive repo, project
`sentinel-43`) was brought up mid-session (~12:16, 2026-09-02). It is an
**active development session — do not touch it** (§6). Side effect: while it
runs, the host resolves `s43-core` slowly (~2.7 s per lookup instead of an
instant NXDOMAIN), so every `TestClient(app)` lifespan (which calls the
Watchtower 3×) takes ~19 s instead of ~1 s — the full suite appears to hang.
**Fix for test runs only:** `S43_WATCHTOWER_URL=http://127.0.0.1:9`
`S43_WATCHTOWER_TIMEOUT=0.5` (instant ECONNREFUSED). This changes no test
semantics — the Watchtower is unreachable in tests either way. Verified with
`git stash`: the slowdown is present on the pre-change tree too, so it is
purely environmental.

### Exact resumption
```
cd C:/Users/heero/Sentinel-43-work
git status ; git log --oneline 7a72976..HEAD
# disposable PGs used this session: 55440 (s43pg_beta), 55441 (s43pg_p1)
MSYS_NO_PATHCONV=1 docker run -d --rm --name s43pg_beta --tmpfs /var/lib/postgresql/data \
  -e POSTGRES_PASSWORD=x -e POSTGRES_DB=s43t -e POSTGRES_USER=s43t -p 127.0.0.1:55440:5432 postgres:16.3
export S43_TEST_PG_DSN="postgresql+asyncpg://s43t:x@127.0.0.1:55440/s43t"
export S43_TEST_PG_CONTAINER=s43pg_beta          # for test_backup_restore_pg.py
export S43_WATCHTOWER_URL=http://127.0.0.1:9     # only while the user's compose stack is up
export S43_WATCHTOWER_TIMEOUT=0.5
.venv-pass1/Scripts/python.exe -m pytest core/tests/ -q -p no:cacheprovider -rsxX \
  --ignore=core/tests/test_bootstrap.py --ignore=core/tests/test_system_smoke.py
```

---

## 7. Integration pass — next PR (2026-09-02, after push of `a8a5678`)

**Goal:** one reviewable PR — `integration/beta-hardening-20260901` → `main` —
that preserves the beta implementation, folds in the now-merged upstream
(`main` = `eb7780f`), proves the browser flow in a real browser, and makes a
named-target deploy reproducible.

### Repository facts re-verified

| Fact | Value |
|---|---|
| Branch pushed | `integration/beta-hardening-20260901` @ `a8a5678` → `origin` (Koklar21/Sentinel-43), no force, `main` untouched |
| `7a72976..8614f9b` (Pass 5AM) | **7** commits |
| `8614f9b..a8a5678` (beta-execution) | **6** commits (`d529f04`,`1acc423`,`aa7f2b1`,`5c06dbe`,`aa64658`,`a8a5678`) — the completion report's "seven after 8614f9b" was wrong; there is no missing 7th |
| Open PRs | **0**. #250 MERGED (`c1b8ad0`), #249 MERGED, #248 MERGED (`eb7780f`), #247 CLOSED unmerged |
| merge-base(`a8a5678`,`main`) | `6dd3a7e` (Pass 1 watchtower work is shared history — beta already has it) |
| Pre-merge recovery | `sentinel43-recovery/pre-main-merge-20260902.bundle` + tag `pre-main-merge-20260902` |

### Phase A — baseline established. Merge commit `f3d93e2`.

`git merge main` → 7 conflicts, resolved by behaviour (newer session/auth
contract wins; CI/container fixes retained). Full detail in the merge commit
message. Semantic (non-flagged) issues fixed: duplicate `users_router`
import + `include_router` in `main.py`; a broken `Dockerfile` with both
Alpine and Debian user-creation blocks. Net `main...HEAD` change from the
merge itself: 5 files. Merge-affected tests: **88 passed**.

Adopted from `main` unchanged: `.github/workflows/k8s.yml` (Trivy scan,
disposable PG service, Calico waits, watchtower service token, read-only
rootfs assertion), `scripts/ci_live_tests.py`, Watchtower health-log filter.

**CI gap (Phase D) — CLOSED:** the standard `test` job's `postgres` service
does not export `S43_TEST_PG_DSN`, so the `*_pg.py` suites skip there. The
new **`pg-tests`** job (Phase D) runs all nine `*_pg.py` files against a
dedicated disposable PostgreSQL and **fails on any skip**.

**#248 reconciliation:** `authenticate_user` stays read-only (no
`update_last_login=`); `_validate_credentials` owns the one `record_login`
write at real login; `reverify_password` never writes. Same end state #248
intended ("don't update last-login on every authenticated request").

#### Merge-diff review — auth/session/authz files (REV 2 evidence)

`git diff f3d93e2^1 f3d93e2` (the merge against the **pre-merge beta
branch** `a8a5678` — i.e. what the merge actually did to the branch):

```
 .github/workflows/k8s.yml     | 83 +   (CI — not auth)
 core/api/Dockerfile           | 24 +   (container — not auth)
 core/api/main.py              |  6 +   (users_router registration only)
 core/monitoring/watchtower.py | 16 +   (health-log filter — not auth)
 scripts/ci_live_tests.py      | 129 +  (new CI helper — not auth)
```

**Every authentication / session / authorization module is byte-identical
to the pre-merge beta branch after the merge** — `git diff f3d93e2^1
f3d93e2` touches **0 lines** in `core/api/deps/deps.py`,
`core/api/routers/auth.py`, `core/api/routers/users.py`,
`core/auth/users.py`, `core/auth/sessions.py`,
`core/middleware/sentinel_firewall.py`. The conflict resolution for those
files was "keep the branch's version"; the result is the beta
implementation verbatim, not a blend and not a revert to an older `main`.

The **one** auth-adjacent change, in `main.py` (6 lines): the
`users_router` import moved up next to `auth_router`, the
`include_router(users_router)` call moved to right after `auth_router`
(from the end of the list), and the **second** `include_router(users_router)`
that the 3-way merge produced was deleted. Same router object, same
router-level `Depends(require_admin)`, registered exactly once. No
authorization behaviour change. Pinned by
`core/tests/test_app_route_registration.py` (no APIRouter included twice;
`require_admin` still gates `/users`).

`main`'s own PR #250 changes to these files (the `scope`-claim role
fallback in `require_operator`, the self-committing `set_user_*` helpers,
the `update_last_login=` parameter) were **discarded** by the resolution —
they are strictly older/narrower than, or incompatible with, the beta
contract. See the resolution table in the `f3d93e2` commit message.

### Active dev session to preserve

User is now running Sentinel-43 on **Docker Desktop Kubernetes** (namespace
`sentinel43`: `s43-db`/`s43-redis`/`s43-core`/`s43-api`, up ~2 h as of
22:00). Do not touch it. (The Compose stack `sentinel-43` from earlier in
beta-execution is gone.)

### Phase checkpoint

- [x] **A** — integration baseline + merge (`f3d93e2`). Post-merge full
      isolated suite **457 passed / 0 failed / 0 skipped** (`.venv-pass1`,
      disposable PG on :55440). = 454 beta baseline + 3 new route-registration
      guards.
- [x] **B** — combined auth/deploy path review + regression tests
- [~] **C** — browser SPA smoke (Playwright) — `browser_tests/` **10/10**.
      **Scope correction (REV 3 / §9):** this verified the SHIPPED SPA's
      *application behaviour* against a **local disposable stack** (throwaway
      test CA, SPKI-pinned, `s43.beta.test` mapped to loopback). It did **not**
      validate a real target's certificate chain, DNS, or edge — and because
      `run.sh` pins its own base URL, an external `S43_BROWSER_BASE_URL` was
      silently ignored. Real-target browser acceptance is `browser_tests/target_acceptance/`
      (§9), still pending a named target.
- [x] **D** — CI validates the beta implementation
- [~] **E** — beta deployment preflight. **Superseded by the phase-aware
      rewrite in §9** (the original conflated pre-deploy and running-target
      checks and could exit 0 with mandatory verification still open).
- [x] docs + PR — final full suite (all Phase A–E) **457 passed / 0 / 0**

### Phase B — done

- `core/tests/test_app_route_registration.py` (3 tests): no APIRouter
  included twice (the exact merge defect), `users_router` wired + router-level
  `Depends(require_admin)`, `/auth/{login,refresh,logout}` in the schema.
- Verified the Phase-B session contract survived the merge in **both**
  `require_operator` (`/v1`) and `require_admin` (`/users`): existing
  `test_auth_session_pg.py::test_session_bound_token_reaches_v1_without_password_header`
  and `::test_admin_password_reset_revokes_target_sessions` (admin uses a
  session token, no `X-S43-Password`) cover it; both green in the 457-suite.
- `authenticate_user` reconciliation (#248): read-only, no `update_last_login=`
  kwarg; `_validate_credentials` owns the single `record_login` write.

### Phase C — real-browser harness + SPA deployment-correctness fixes

Found while wiring the browser stack: the shipped SPA was **hardwired to
`http://localhost:8000`** (meta tags + JS fallbacks + a `connect-src`
allowing it) — it could not talk to a same-origin HTTPS beta at all.

- `dashboard/sentinel_43_dashboard.html` — `connect-src 'self'` (dropped the
  `http://localhost:8000 ws://localhost:8000` entries); `sentinel-api-base` /
  `sentinel-ws-url` meta tags emptied (→ same origin).
- `dashboard/assets/js/dashboard.js` v1.8.0 — `API_BASE` defaults to
  `location.origin`; real session token read from
  `window.SentinelAuth.getToken()`.
- `dashboard/assets/js/websocket.js` v1.8.0 — WS URL defaults to
  `wss://<same-origin>/ws`; token from `window.SentinelAuth.getToken()`.
- `dashboard/assets/js/auth.js` v1.8.0 — **bearer access token held in module
  memory only** (was `sessionStorage["SENTINEL_JWT"]`); `getToken()` exposed;
  old sessionStorage token cleared on load. init() already refreshes on load
  so nothing is lost on reload.
- `browser_tests/` — Playwright (Python) suite driving the *actual* served
  SPA through nginx TLS → API → disposable PG. `run.sh` brings up an isolated
  `s43browser` Compose project (own `172.29.0.0/24`, proxy on
  `127.0.0.1:8443`), Chromium trusts the throwaway test leaf by **SPKI pin**
  (not `--ignore-certificate-errors`), `--host-resolver-rules` maps
  `s43.beta.test`. `requirements-browser.txt`, `docker-compose.browser.yml`.
- Also fixed: a **websocket.js multi-socket race** — auth.js's login handler
  `disconnect()`s then `connect()`s, and a stale socket's late `close`
  handler nulled the live `_ws` + dispatched `auth_failed`, re-showing the
  login overlay right after login. Handlers are now bound per-socket. This
  was the fix that made the browser suite green.
- **Result: 10 passed / 0 failed.** **What that actually verified (REV 3):**
  the shipped SPA + JS behave correctly against a **local disposable HTTPS
  stack**. TLS "trust" here is a throwaway test CA accepted via a Chromium
  SPKI exception + a `ssl.CERT_NONE` fixture context — this is
  application-behaviour evidence, **not** certificate-chain validation and
  **not** a real-target result.
- **F-TLS-1 stays OPEN** — a local test CA proves browser⇄nginx only.

### Phase D — CI

`.github/workflows/k8s.yml`:
- new `pg-tests` job — a dedicated disposable PostgreSQL service +
  `S43_TEST_PG_DSN`/`S43_TEST_PG_CONTAINER`, runs beta's nine `*_pg.py`
  suites, then **fails if any were skipped** (JUnit XML check). Closes the
  gap where those suites silently skipped in CI. **Green on the first PR
  run.**
- new `browser-smoke` job — installs Playwright+Chromium, runs
  `browser_tests/run.sh`, uploads `test-results/` on failure.
- `build-and-scan` + `kind-smoke-deploy` now also `needs: pg-tests`.
- triggers widened: `migrations/**`, `dashboard/**`, `browser_tests/**`,
  `deploy/**`, `docker-compose*.yml`.

`scripts/ci_live_tests.py` fix (`07686bc`) — the first PR CI run failed
here: the merge left the live API with **no schema** (`init_models()` is a
non-local no-op) and the **env-operator inert** (`#11` break-glass, once
`test_bootstrap` makes an admin). Fix: run `alembic upgrade head` first
(as a real deployment does) and set `S43_BREAK_GLASS_ARMED=true` for the
disposable CI DB. Verified locally: `alembic upgrade head` + 13 passed / 1
skipped.

### Phase E — deployment preflight

> **Superseded by §9 (REV 3).** The version described below conflated
> pre-deploy and running-target checks and returned exit 0 while
> TARGET-REQUIRED items were still open. §9 replaces it with an explicit
> `prepare` / `verify` phase split and a distinct INCOMPLETE (exit 2) state.

`scripts/deploy_preflight.py` — strictly **read-only** (no admin bootstrap,
no DB write, no manifest apply). `compose` and `kube` modes. Checks:
tooling, hostname is a real FQDN + resolves, cert chain/SAN/expiry against
the hostname, HTTPS 200 + HTTP→HTTPS redirect + HSTS + no version banner,
`/docs` `/redoc` `/openapi.json` not publicly served, every required secret
present + non-placeholder + `S43_SECRETS_ROTATED_AT` ≤ 90 days,
origins/hosts/trusted-proxy match the real hostname, backend/watchtower not
host-published, single uvicorn worker / single replica / no HPA, no
`CHANGEME` in k8s ConfigMaps, ClusterIP services. Placeholder hostnames
(`*.example.invalid`, `CHANGEME`) fail the run. Target-dependent items
(WSS through the edge, external port scan, image digest) are reported
TARGET-REQUIRED, not silently passed.

---

## 8. Post-merge verification pass — REV 2 (2026-09-03, after PR #251 merged)

**PR #251 was MERGED to `main`** (merge commit `0bd375a`, 2026-09-03
14:53Z) between REV 1 and REV 2. All the §7 work is on `main` now. This pass
delivers the REV 2 additions on a **new branch off merged `main`**
(`beta/post-merge-verification-20260903` ← `0bd375a`) and a **new PR** — #251
cannot be reopened.

Starting HEAD: `0bd375a` (= merged `main`). Commit-count prose corrected:
`8614f9b..a8a5678` is **six** beta-execution commits, no missing seventh
(already fixed in `§7`; restated).

### A — merge-diff review (retrospective evidence)

See `§7 → Merge-diff review` above: `git diff f3d93e2^1 f3d93e2` proves the
merge left every auth/session/authz module **byte-identical** to the
pre-merge beta branch; the only auth-adjacent change is the 6-line
`users_router` de-dup in `main.py`.

### B — legacy-rejection flag, BOTH states

`S43_REJECT_LEGACY_AUTH` was only ever tested OFF (the fixtures `delenv` it).
Added:
- `test_auth_session_pg.py::test_reject_legacy_auth_off_default_still_accepts_legacy`
- `test_auth_session_pg.py::test_reject_legacy_auth_on_blocks_legacy_v1_and_users_not_the_session`
  — flag ON: legacy Bearer+password → **401** on `/v1` **and** `/users`;
  a live session token → still 200 on both; flipping the flag back off
  restores the legacy contract (one-var rollback).
- `test_ws_session_pg.py::test_reject_legacy_auth_on_blocks_the_legacy_frame_not_the_session`
  — flag ON: legacy `{token,password}` WS frame → rejected;
  session `{token}` frame → still connects.

### D — refresh-hash constraint, direct schema introspection

`test_migrations_pg.py::test_refresh_hash_uniqueness_is_the_partial_active_scoped_shape`
— after `alembic upgrade head` on the current tree, queries
`pg_indexes.indexdef` + `pg_index.indpred` + `pg_constraint` directly and
asserts `uq_sessions_active_refresh_hash` is a **partial UNIQUE index on
`(refresh_hash)` with predicate `WHERE (revoked_at IS NULL)`** (shape B),
and that there is **no** unconditional table-level `UNIQUE` (shape A). Not a
behavioural inference. Runs in the `pg-tests` CI job (already lists
`test_migrations_pg.py`).

### E — single replica AND single worker

`deploy_preflight.py` strengthened: compose mode now also checks exactly one
`s43-api` container (no `--scale`), one uvicorn **worker** process, and
`WEB_CONCURRENCY` not > 1; kube mode also checks `readyReplicas == 1`, no
`--workers > 1` in the container command, and `WEB_CONCURRENCY` not > 1.

### Conclusion 3 wording

`HANDOFF_BETA.md §10` conclusion 3 now states it is a **status report
only** — where production/public/government readiness stands — and does not
authorize or step toward certification work (excluded by Section 1).

### Validation (REV 2)

| suite | result |
|---|---|
| isolated (no PG, `.venv-pass1`) | **368 passed / 89 skipped** (the `*_pg.py` skip without a DB) / 0 failed |
| the 4 new/changed PG tests, disposable PG :55440 | **4 passed** |
| `test_migrations_pg` + `test_auth_session_pg` + `test_ws_session_pg` (full) | **48 passed** |
| full isolated + PG suite (`.venv-pass1`, disposable PG :55440) | **461 passed / 0 failed / 0 skipped** (273 s) |
| CI on the REV 2 PR head | _recorded in the final report_ |

Docker Desktop was down at the start of this pass (user had stopped it);
restarted it to run the PG suites. The user's k8s `sentinel43` namespace
pods are still defined (`s43-db`/`s43-redis` were healthy earlier;
`s43-api`/`s43-core` have been `ErrImageNeverPull` for ~33 days — a
pre-existing state, untouched).

---

## 9. Release-tooling corrections — REV 3 (2026-09-03)

A focused follow-up on the deployment **preflight** and browser **target-
validation** tooling. No change to the verified auth / migration / session /
CI work. Started from `beta/post-merge-verification-20260903` (open PR #252);
merged current `main` first (`18d1dbe` — main had deleted a batch of
superseded `.md` files; `PASS_BETA_VALIDATION.md` among them, so its live
content is folded here and into `HANDOFF_BETA.md`).

### Correction to the prior completion claim

REV 1/REV 2 reported Phases A–E complete and "every target-independent
artifact ready". Findings A–E below **were all still reproducible** in that
delivered state, so that claim was premature for the tooling. This pass
fixes the actual causes; the auth/migration/session conclusions are
unaffected.

### Findings reproduced, and the fix

| # | Reproduced defect | Fix |
|---|---|---|
| **A** | `deploy_preflight.py` returned **exit 0** with `TARGET-REQUIRED` items unresolved; one pass covered both pre-deploy and running-target checks | phase-aware: `--phase {prepare,verify}` **required, no default**; three exit codes — `0` all mandatory checks for the phase passed, `1` a confirmed FAIL, `2` a mandatory check INCOMPLETE (never silently 0); `prepare` never touches a running service |
| **B** | HTTP check used `urlopen` (follows redirects) then asserted a 3xx — a correct server *failed* it; HTTP URL derived from the HTTPS port; later HTTPS calls dropped the non-standard port | `http_probe()` does **not** follow redirects; `classify_http_redirect()` checks status ∈ {301,302,307,308}, `Location` scheme=https, same host, expected port; separate `--http-port` / `--https-port`; every URL built by one `_url()` helper |
| **C** | `docker compose` calls carried no `-p` / `--env-file` / `-f`; only NDJSON `ps` parsed; `{{.Publishers}}` arrow-string parsing; failed `kubectl get hpa` read as "no HPA"; `--workers` substring match; `containers[0]` assumed to be the API; missing Service → PASS | `compose_base_cmd()` threads project + env-file + files through **every** call; `parse_compose_ps()` handles the array and NDJSON forms; structured `Publishers[].PublishedPort`; `k8s_api_container()` finds the API by name/heuristic (INCOMPLETE if ambiguous); `k8s_worker_flag()` handles `--workers N`, `--workers=N`, `-w N`, `WEB_CONCURRENCY`; `hpa_targets()` matches `scaleTargetRef.name == s43-api`; every inspection failure → INCOMPLETE, never a silent pass |
| **D** | origins/hosts checked by **substring** (`https://h` ⊂ `https://h.evil`); trusted-proxy only rejected exact `0.0.0.0/0`; any `--image` string passed; `:sha256-…` treated as a digest | `origin_exact_member()` / `host_exact_member()` — exact normalized membership (scheme+host+port; mirrors `TrustedHostGuard`, rejects `*`); `validate_trusted_proxies()` via `ipaddress`, rejects malformed and anything wider than /24; `validate_image_reference()` — `repo/name@sha256:<64-hex>` = PASS, `:sha256-…` tag = FAIL, plain tag = INCOMPLETE unless `--image-id sha256:<id>` + `--source-revision` given |
| **E** | `run.sh` pinned `S43_BROWSER_BASE_URL` so an external value was ignored; `conftest.py` used a fixed loopback URL + `Host` override; auto-bootstrapped an admin; `ssl.CERT_NONE` + a Chromium SPKI exception (not real trust) | `run.sh` now refuses a foreign `S43_BROWSER_BASE_URL` and points at the new runner; a separate **`browser_tests/target_acceptance/`** suite + **`run_target.sh`** for real targets — explicit `S43_TARGET_BASE_URL` (same endpoint for browser and API), standard trusted-CA verification (optional `S43_TARGET_CA_BUNDLE`, never disabled), **no** stack control, **no** bootstrap, credentials read from files, missing creds = an errored (incomplete) run |

### prepare vs verify

- **prepare** — tools, target hostname is a real FQDN, image is an immutable
  identity, `.env` secrets present + non-placeholder + rotated ≤ 90 d,
  `SENTINEL_ENV` non-local, exact origin/host membership, proxy CIDR narrow,
  (kube) `sentinel43-secrets` keys + no `CHANGEME` ConfigMaps. **A pass is
  "inputs in order", explicitly *not* beta acceptance.**
- **verify** — hostname resolves; edge cert validates against the real trust
  store (or `--ca-bundle`) with library hostname matching; not near expiry;
  HTTP→HTTPS redirect correct (no downgrade); HTTPS `/health` + `/ready`
  separately; HSTS; `/docs` `/redoc` `/openapi.json` not served (by actual
  response — a connection error is INCOMPLETE, not "protected"); exactly one
  running API instance **and** one worker; backend/db/redis not
  host-published; (kube) `replicas==1`, `readyReplicas==1`, rollout complete,
  no HPA targeting `s43-api`, migration Job succeeded, `ClusterIP` services.
  External port-scan and WSS-through-edge are mandatory-but-INCOMPLETE from
  this vantage point → `verify` exits 2 until run from outside / via
  `run_target.sh`.

### Commands

```
# before deploying — nothing running yet
python scripts/deploy_preflight.py compose --phase prepare \
  --hostname beta.example.org --env-file .env \
  --image ghcr.io/OWNER/sentinel43-api@sha256:<64-hex>
#   locally-built image instead of a registry digest:
#   --image sentinel43-api:beta --image-id sha256:<64-hex> --source-revision <git-sha>

# after deploying — against the running target
python scripts/deploy_preflight.py compose --phase verify \
  --hostname beta.example.org --project s43 --env-file .env \
  -f docker-compose.yml -f docker-compose.beta.yml
python scripts/deploy_preflight.py kube --phase verify \
  --context <ctx> --namespace <ns> --hostname beta.example.org [--ca-bundle ca.pem]

# browser: disposable (unchanged) vs real target
bash browser_tests/run.sh
S43_TARGET_BASE_URL=https://beta.example.org \
  S43_TARGET_OPERATOR_CRED_FILE=/secure/op.json \
  bash browser_tests/run_target.sh
```

Target-account scope: `run_target.sh` read-only edge checks need only the
URL. Authenticated acceptance needs a **designated** beta operator account
(`S43_TARGET_OPERATOR_CRED_FILE`). Admin-mutation scenarios (disable / role /
password / replay) additionally need `S43_TARGET_ADMIN_SCOPE=
explicit-dedicated-account` + **dedicated throwaway** admin/operator accounts
— never an owner's ordinary account.

### Tests + CI

`core/tests/test_deploy_preflight.py` — **53** behavioural tests (phase
required not defaulted; mandatory-incomplete ⇒ exit 2; redirect recognised
not followed; wrong-host/downgrade fail; non-standard ports; exact
origin/host vs substring lookalikes; malformed/broad proxy CIDR; compose
selection reaches every call; both `ps` JSON forms; 0/1/2 API instances;
unknown worker state ≠ pass; kube inspection error stays INCOMPLETE;
unrelated HPA distinguished; `:sha256-` tag ≠ digest). Runs in the existing
`test` job. `browser-smoke` job now also `bash -n`s both runners and
`--collect-only`s `browser_tests/target_acceptance/` (never executes it — no target).

### Validation (REV 3)

| gate | result |
|---|---|
| `core/tests/test_deploy_preflight.py` | **53 passed** |
| full isolated suite (`.venv-pass1`, no PG) | **421 passed / 93 skipped / 0 failed** (= prior 368 + 53 new) |
| disposable browser smoke `run.sh` | **10 passed** |
| `browser_tests/target_acceptance/` | **13 collected** (needs a real target to run) |
| CI on the pushed head | _recorded in the final report_ |

### Still target-dependent (unchanged)

**F-TLS-1 is NOT closed.** Closing it needs a named target where `verify`
passes edge TLS (real chain + hostname + expiry), HTTP→HTTPS, HSTS, docs
surface, one-replica/one-worker, and `run_target.sh` passes
login/refresh/logout/WSS over a trusted-CA chain. P3-8 stays **deferred**
(`0004`, pending a real-target collision inventory). One `s43-api` replica
and one worker remain the recommended controlled-beta configuration; a
shared throttle is a separate change only if a confirmed requirement needs
one.

---

## 6. Not authorized by this instruction (finish RC + procedure, then ask)

Changing a live database · exposing a service publicly · merging protected
branches · force-push · deleting branches · deploying to production. No
inventing a hostname, live target, credential, infra capability, or
permission. If external access is missing, continue all independent local
work and record the single specific missing input.
