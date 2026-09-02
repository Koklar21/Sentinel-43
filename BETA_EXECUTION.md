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

**PHASE: P4 — service & docker integration.** P1+P2 = `d529f04`; P3 done
(commit pending). Full isolated suite **449 passed / 0 failed / 0 skipped**.
Next: route inventory map, container-network exercise, WS close-helper
`reason` (done in P3), P3-7 + P3-8 migrations, dependency-outage tests.

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

## 6. Not authorized by this instruction (finish RC + procedure, then ask)

Changing a live database · exposing a service publicly · merging protected
branches · force-push · deleting branches · deploying to production. No
inventing a hostname, live target, credential, infra capability, or
permission. If external access is missing, continue all independent local
work and record the single specific missing input.
