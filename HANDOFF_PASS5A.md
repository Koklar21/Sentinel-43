# HANDOFF_PASS5A.md

Sentinel-43 — Pass 5A handoff. Authentication foundation / migration
readiness. **Pass 5A is complete and STOPPED at the mission §14 / §30
boundary.** Do not begin Pass 5B without explicit authorization.

---

## A. State

| | |
|---|---|
| Branch | `integration/beta-hardening-20260901` (NOT pushed) |
| HEAD at start | `2f0c749` |
| HEAD at handoff | working tree has uncommitted Pass 5A changes (see §C); commit is the last step, pending your review |
| Working clone | `C:\Users\heero\Sentinel-43-work` — non-synced; `origin`+`evidence-local` push disabled |
| Original OneDrive repo | untouched, HEAD `e859b61` |
| venv | `.venv-pass1` |
| Recovery | `C:\Users\heero\AppData\Local\sentinel43-recovery\pass5a-20260901\` (to be created with the commit — bundle + docs) |
| Disposable PG | `postgres:16.3` container on `127.0.0.1:55433`, torn down |
| s43 Compose stack | not started / not touched |

---

## B. What Pass 5A was authorized to do, and did

| # | Authorized item | Status |
|---|---|---|
| §4 | TLS posture from repo evidence | **done** → `AUTH_TLS_POSTURE_PASS5A.md`; blocking finding **F-TLS-1** raised |
| §6 | Backward-compatible `jti`/`sid` access-token claims | **done** — `_issue_token(..., sid=)`, `verify_jwt_token` tolerant shape-check, `token_is_session_bound()` |
| §7 | Session domain model in application code | **done** — `SessionRecord` (own `SessionBase`), `SessionView` |
| §7 | Refresh-credential entropy documented | **done** — 256-bit CSPRNG → SHA-256 verifier, justified |
| §8–§10 | Refresh generate / rotate / single-step reuse detection | **done** — `generate_refresh_secret`, `rotate_refresh`, `RefreshReuseError` + auto-revoke |
| §11 | Logout service logic (idempotent, service-layer) | **done** — `logout_by_refresh`, `revoke_session`, `revoke_all_user_sessions` |
| §12 | CSRF primitives (double-submit, not activated) | **done** — `generate_csrf_token`, `csrf_tokens_match` |
| §13 | Alembic vs minimal runner evaluation + ONE recommendation | **done** → `SESSION_MIGRATION_DECISION_PASS5A.md` → **Alembic** |
| §14 | MANDATORY STOP + interim decision report | **done** — stopped; report is §6 of the migration-decision doc |
| §15 | Disposable-PG validation of the proposed schema | **done** — `test_session_layer_pg.py`, 17 passed on `postgres:16.3` |
| §16 | Concurrency tests (2×refresh, refresh vs logout, refresh vs disablement, repeated logout, expiry vs refresh) | **done** — all in `test_session_layer_pg.py` |
| §17–§18 | Role-change / disablement session behaviour | **done (design + helper + disablement test)**; route wiring is Pass 5B |
| §19 | `#11` — preferred target Option C, DO NOT implement | **not implemented** (unchanged) |
| §20 | Multi-replica throttle — document repo evidence, no Redis/schema | **documented** (§F below); no change |
| §21 | WebSocket — implementation notes only, no contract change | **notes below (§E)**; contract unchanged |
| §22 | Human/service identity separation regression tests | **done** — `test_service_identity_separation.py`, 12 passed |
| §23–§24 | Audit redaction + fail-closed semantics for new logic | **done** — reviewed in `SESSION_MODEL_PASS5A.md` §8 |
| §25–§26 | Re-run Pass 1–4 invariants + full suite | **done** — `PASS5A_VALIDATION.md` §4 |

---

## C. Files

**Changed:** `core/api/routers/auth.py` (+91/−1) — `_issue_token` gains
keyword-only `sid`/`jti` (legacy `sid is None` path unchanged);
`verify_jwt_token` shape-checks `sid`/`jti` when present (never requires
them); `token_is_session_bound()` + regexes added.

**New:**
- `core/auth/sessions.py` — the whole foundation (model, primitives, service
  logic). **Imported by nothing at app-startup scope.**
- `core/tests/test_session_primitives.py` (25), `core/tests/test_session_layer_pg.py`
  (17, PG-only), `core/tests/test_service_identity_separation.py` (12)
- `AUTH_TLS_POSTURE_PASS5A.md`, `SESSION_MODEL_PASS5A.md`,
  `SESSION_MIGRATION_DECISION_PASS5A.md`, `PASS5A_VALIDATION.md`, this file

**Unchanged (verify before trusting any later doc that says otherwise):**
`core/auth/users.py`, `core/api/routers/users.py`,
`core/api/routers/bootstrap.py`, `core/api/deps/*`, `core/api/main.py`,
`core/monitoring/watchtower.py`, all of `deploy/`, `docker-compose.yml`,
`.env*`.

---

## D. Validation summary

- `test_session_primitives.py` — **25 passed**
- `test_session_layer_pg.py` — **17 passed** (`postgres:16.3`, disposable)
- `test_service_identity_separation.py` — **12 passed**
- Security-invariant script — **13/13** (no regression to `5332d54` /v1 fix
  or the `require_admin` gate)
- `test_jwt_auth`+`v1_auth`+`ws_auth` — **56 passed**
- `test_account_transactions_pg.py` (Pass 3) — **9 passed**
- combined `jwt_auth`+`auth_login`+`v1_auth`+`ws_auth`+`login_throttle`+`users_admin`+`bootstrap_isolated` — **106 passed**
- Full suite (`--ignore` `test_bootstrap.py` / `test_system_smoke.py`, PG DSN
  set): **354 passed, 0 failed** (Pass 3 baseline 300 + 54 new Pass 5A tests)

---

## E. WebSocket — implementation notes only (mission §21, NO contract change)

The dashboard WebSocket (`core/api/main.py::dashboard_websocket`) is
**unchanged** in Pass 5A. Its contract today: first frame carries
`{token: <JWT>, password: <plaintext>}`; `verify_jwt_token(token)` then
`reverify_password(subject, password)`; re-checks are driven off the same
per-request password gate as HTTP.

For Pass 5B / the eventual browser-session cutover (target architecture from
`AUTH_ARCHITECTURE_PASS4.md`), the notes are:

1. **Cookies do not reach the WS handler usefully cross-origin.** The
   dashboard connects with `S43_ALLOWED_ORIGINS` possibly on a different
   origin; browsers *do* send cookies on same-origin WS upgrades, but the
   refresh cookie is `Path=/auth` and `SameSite=Strict`, so it is **not** on
   the `/ws` upgrade. Correct model: the client obtains a short-lived access
   token via `/auth/refresh` (cookie + CSRF), then opens the WS and sends
   that **access token** in the first frame — same shape as today, minus the
   password field.
2. **`X-S43-Password` removal in the WS frame is Phase C+ of the migration**
   (`AUTH_MIGRATION_PASS4.md`), gated exactly like the HTTP header removal.
   Until then the frame keeps both fields; the server keeps calling
   `reverify_password`.
3. **`sid`-bound WS liveness** (the "≤60-second recheck" target): when the
   frame's access token carries `sid`, a background task re-checks
   `SessionRecord.is_live(sid)` on an interval and closes the socket on
   revoke/expire. This needs the sessions table live and a bounded
   per-replica `sid` cache — **both deferred** (mission §6, §21). Pass 5A
   deliberately did not add the hot-path `sid` lookup.
4. **No leeway change.** WS verification stays aligned with
   `verify_jwt_token` (no clock leeway today; the ±30s `nbf`/`iat` leeway is
   a separate, later, whole-verifier change from `AUTH_ARCHITECTURE_PASS4.md`
   §3.5 — not in scope here).
5. **Multi-replica**: a WS is pinned to one replica; `sid` liveness recheck
   is a local DB read, so it is replica-safe (unlike the in-process
   throttle).

No code was written for any of the above.

---

## F. Multi-replica support — repo evidence (mission §20)

- `deploy/kubernetes/README.md` "Known limitations": *"The firewall's rate
  limiter is in-process, not Redis-backed … `overlays/beta` runs 2 `s43-api`
  replicas — rate limits are therefore enforced per replica."* Same applies
  to the Pass 3 `/auth/login` per-username throttle (in-process `dict` +
  `threading.Lock`).
- `overlays/beta/resources-patch.yaml` sets `replicas: 2` + a
  `PodDisruptionBudget`. `base` and `overlays/dev` are single-replica.
- **Session rotation is DB-backed** (`SELECT … FOR UPDATE` on the shared
  Postgres) → **replica-safe**. The reuse/rotation invariant holds across
  replicas with no extra infra.
- **The login throttle is NOT replica-safe.** A multi-replica beta gets up to
  Nx the configured failure budget. `AUTH_ARCHITECTURE_PASS4.md` §6 marks a
  `login_attempts` table (or Redis) **OPTIONAL for single-replica /
  REQUIRED for multi-replica**. Pass 5A adds neither (mission §20).
- **Recommendation carried forward**: treat multi-replica beta as *supported
  for sessions, not yet for brute-force throttling*. Either run beta
  single-replica until a `login_attempts` table lands (rides the Alembic
  migration pass), or accept the weakened throttle and document it in the
  beta runbook.

---

## G. `#11` env-operator (mission §19)

Unchanged. `S43_OPERATOR_USERNAME` / `S43_OPERATOR_PASSWORD_HASH` (SHA-256)
still work exactly as before. Pass 4's recommendation (Option C scoped
break-glass, or Option A removal) still stands and still needs operator
sign-off + a `.env` contract change — **out of scope for Pass 5A and 5B's
first cut**.

---

## H. F-TLS-1 — blocking deployment finding

Repository evidence does not establish a secure production TLS posture
(`AUTH_TLS_POSTURE_PASS5A.md` §7). Summary:

- The app never terminates TLS and has zero transport-security awareness (no
  HSTS, no scheme check, no HTTPS-required guard).
- Docker Compose (the documented default) is plaintext HTTP with no TLS
  terminator provided or required.
- The only TLS artifact (`overlays/beta/ingress.yaml`) is 100% placeholder
  and depends on operator-installed ingress-nginx + cert-manager the repo
  does not provide.
- No production target exists (`DEPLOYMENT_RUNBOOK.md` Phase 14 blocker).

**Gate**: the `Secure` refresh cookie is worthless until every
production-reachable listener is HTTPS-fronted. F-TLS-1 must be resolved
before Phase B+ of the `X-S43-Password` retirement and before any "browser
sessions on" cutover. Implementation may proceed in isolated dev; it must not
be called production-ready.

Non-blocking follow-up (a deployment pass, not Pass 5B): grow
`_validate_security_config()` an HTTPS / `https://`-origin assertion for
non-local environments, and an HSTS response header in production. **Not
implemented in Pass 5A** — it changes startup behaviour for existing
plaintext deployments.

---

## I. Migration decision + MANDATORY STOP

`SESSION_MIGRATION_DECISION_PASS5A.md`:

- **Recommendation: Alembic** (Option A). Rationale: a migration backlog
  already exists (`sessions`, P3-7 role CHECK, P3-8 citext uniqueness); a
  bespoke runner is "minimal" only at n=1; Alembic is the minimal *correct*
  choice for SQLAlchemy and the `migration-job.yaml` operational pattern
  already fits it.
- **Proposed `sessions` DDL** (production form with `inet`, partial indexes,
  `ON DELETE CASCADE`) is specified. Rollback = `DROP TABLE sessions`
  (additive, safe until sessions are live).
- **STOPPED before**: adding `alembic`/any migration dep; creating
  `alembic.ini` / `migrations/` / a `schema_migrations` table; any
  migration-history file entering the repo; changing `init_models()`; changing
  `migration-job.yaml` / compose bootstrap; creating `sessions` in any
  tracked/production DB.
- **Decision requested from the owner**: approve Alembic + authorize a
  dedicated migration pass for `0001_baseline` (stamp existing `users`) then
  `0002_sessions`.

---

## J. Pass 5B (proposed — DO NOT START without authorization)

Ordered, each independently verifiable. **P5B-1 and P5B-2 are STOP-for-
authorization gates.**

1. **[GATE]** Migration pass: introduce Alembic, `0001_baseline` +
   `alembic stamp`, `0002_sessions`. Wire `migration-job.yaml` /
   compose. — needs the §I decision.
2. **[GATE]** Confirm F-TLS-1 remediation for the target environment (edge
   TLS + HSTS) OR an explicit owner acceptance that browser sessions ship
   dev-only for now.
3. Wire `/auth/login` to also `create_session(...)` + set the refresh cookie
   (`HttpOnly; Secure; SameSite=Strict; Path=/auth`) + issue a `sid`-bound
   15-min access token via `_issue_token(..., sid=...)`. Legacy 8-h token +
   `X-S43-Password` still accepted (Phase B dual contract).
4. Add `POST /auth/refresh` (cookie + `X-S43-CSRF` double-submit →
   `rotate_refresh` → new cookie + new access token; on `RefreshReuseError` /
   `SessionOwnerInactiveError` **commit the revocation** then 401+clear-cookie).
5. Add `POST /auth/logout` (cookie + CSRF → `logout_by_refresh` → clear
   cookie; idempotent 2xx).
6. Wire `revoke_all_user_sessions` into `set_user_password` /
   `set_user_active(False)` / `set_user_role` in `core/api/routers/users.py`.
7. `legacy_auth_request_total` metric (Phase D of the migration).
8. WebSocket: drop the password field from the frame once Phase C completes
   (see §E).
9. `sid` liveness recheck (HTTP hot-path LRU + WS ≤60s) — with load data
   (`AUTH_ARCHITECTURE_PASS4.md` §3.3, deferred from Pass 5A).
10. Frontend: memory-only access token, `/auth/refresh` on 401, CSRF header
    plumbing.
11. `login_attempts` table for multi-replica throttle (optional; rides #1).
12. Phase E: remove `X-S43-Password` (one reversible commit; gated on zero
    legacy requests ≥16h + operator sign-off — `AUTH_MIGRATION_PASS4.md`).

---

## K. Rollback of Pass 5A itself

`git revert`/reset the single Pass 5A commit. Effects: `core/auth/sessions.py`
and the three test files vanish; `core/api/routers/auth.py` returns to the
`2f0c749` version. **No runtime behaviour depends on Pass 5A** (nothing calls
the new code), so the revert is inert beyond removing the (unused) capability.
No DB state to unwind (the sessions table was only ever in disposable
containers).

---

## L. Boundaries honoured

No push / PR / merge / history rewrite / tag. No migration infra / history /
`sessions` in tracked state. `X-S43-Password` kept; legacy tokens accepted;
protected-route, WebSocket, and service-token contracts unchanged; env-operator
unchanged; no `.env` change. No `sid` hot-path lookup. Disposable PG only; live
stack untouched. No secrets in docs/logs/commits. Single writer, one
invocation.

---

## M. Immediate next action for the owner

1. Review the `core/api/routers/auth.py` diff and `core/auth/sessions.py`.
2. Decide on **Alembic** (§I) and whether to authorize the migration pass.
3. Acknowledge **F-TLS-1** (§H) and decide dev-only vs. block-until-TLS for
   browser sessions.
4. Authorize the Pass 5A commit (task-owned files only, secret-scanned) and
   the `pass5a-20260901` recovery snapshot.
5. Then, and only then, authorize Pass 5B starting at J-1.
