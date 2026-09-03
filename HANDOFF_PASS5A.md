# HANDOFF_PASS5A.md

Sentinel-43 — Pass 5A handoff. Authentication **foundation / migration
readiness** — NOT the authentication cutover. Structured per authorization
§29 (sections A–S). **Pass 5A is complete and STOPPED at the §14 / §30
boundary. Do not begin Pass 5B without explicit authorization.**

---

## A. Exact starting state

| | |
|---|---|
| Working clone | `C:\Users\heero\Sentinel-43-work` (non-synced; `origin` + `evidence-local` push disabled) |
| Branch | `integration/beta-hardening-20260901` |
| HEAD at start | `2f0c74904edd4a49564bc50a8b99deeb8b331859` (`2f0c749`) — matched expectation |
| `git status` | clean |
| `git fsck` | 0 problems |
| merge-base with `origin/main` | `8d2b80f` (== `origin/main`) |
| Pass 3 validated runtime (`86c9aab`) ancestor of HEAD | yes; runtime code **unchanged** since (Pass 4 was docs-only) |
| Pass 4 docs present | 5/5 (`AUTH_{ARCHITECTURE,THREAT_MODEL,MIGRATION,TEST_SPEC}_PASS4.md`, `HANDOFF_PASS4.md`) |
| Original OneDrive repo | untouched — HEAD `e859b61`, clean, fsck 0 |
| venv | `.venv-pass1` (Python 3.13.5, pytest 9.1.1) |

No repository state was repaired. Starting state matched the authorization
exactly.

## B. Exact ending state

| | |
|---|---|
| Branch | `integration/beta-hardening-20260901` (NOT pushed) |
| HEAD at handoff | the Pass 5A commit(s) on top of `2f0c749` (see `git log`); working tree clean |
| Original OneDrive repo | still `e859b61`, untouched |
| Disposable PostgreSQL | `postgres:16.3` container (`--rm --tmpfs`, `127.0.0.1:55433`) — used for tests, then removed |
| s43 Compose stack | never started / stopped / touched |
| Recovery snapshot | `C:\Users\heero\AppData\Local\sentinel43-recovery\pass5a-20260901\` — `git bundle --all` (verified), the 5 docs, `sessions.py`, `HEAD.txt`, `log.txt` |

**Files changed** (task-owned only, secret-scanned, no blanket-stage):

```
 core/api/routers/auth.py                       modified  (+~110/-2)
 core/auth/sessions.py                          new
 core/tests/test_session_primitives.py          new
 core/tests/test_session_layer_pg.py            new
 core/tests/test_service_identity_separation.py new
 AUTH_TLS_POSTURE_PASS5A.md                     new
 SESSION_MODEL_PASS5A.md                        new
 SESSION_MIGRATION_DECISION_PASS5A.md           new
 PASS5A_VALIDATION.md                           new
 HANDOFF_PASS5A.md                              new
```

**Unchanged** (verify before trusting any later claim otherwise):
`core/auth/users.py`, `core/api/routers/users.py`,
`core/api/routers/bootstrap.py`, `core/api/deps/*`, `core/api/main.py`,
`core/monitoring/*`, all of `deploy/`, `docker-compose.yml`, every `.env*`.

## C. TLS posture findings (authorization §4)

Full analysis in `AUTH_TLS_POSTURE_PASS5A.md`. Answers:

| Question | Answer |
|---|---|
| Does Sentinel-43 itself terminate TLS? | **No** — uvicorn plain HTTP `:8000` everywhere; no `--ssl-*` in Dockerfile / compose / k8s. |
| TLS expected at an ingress/proxy? | Only in the k8s **beta** overlay's `ingress.yaml`, and every value there is a `CHANGEME` placeholder depending on operator-installed ingress-nginx + cert-manager the repo does not provide. Compose and k8s-dev have no TLS terminator. |
| HTTPS mandatory in documented production deployment? | **No** — no production target exists (`DEPLOYMENT_RUNBOOK.md` Phase 14 blocker); k8s path is "public-beta, not production-certified". |
| Are secure-cookie assumptions valid? | Only on k8s-beta once an operator completes the ingress. Not on Compose / k8s-dev (plaintext → a `Secure` cookie is never returned). `http://localhost` is a browser "secure context" so local dev can still exercise the flow. |
| Can a production-like config expose the API over plain HTTP? | **Yes**, multiple ways, and the app has **no** guard: no HSTS, no scheme check, no `https://`-origin assertion, `_validate_security_config()` is silent on transport. |
| WebSocket upgrades through TLS? | Only implicitly on the k8s-beta ingress path; Compose / k8s-dev are `ws://` plaintext. |

> **F-TLS-1 (blocking, deployment)** — repository evidence does **not**
> establish a secure production TLS posture. Implementation proceeded in
> isolated dev; the browser-session design is **not** claimed
> production-ready. F-TLS-1 gates Phase B+ of the `X-S43-Password` retirement
> and any "browser sessions on" cutover. Remediation prerequisites are listed
> in `AUTH_TLS_POSTURE_PASS5A.md` §7.1 (name a production target; guarantee
> edge TLS + HSTS; optional app-level `https://`-origin / HSTS assertions in
> non-local envs — **not** implemented in Pass 5A as it changes startup
> behaviour for existing plaintext deployments).

## D. Implemented backward-compatible token-claim support (§6)

`core/api/routers/auth.py`:

- `_issue_token(subject, role="operator", user_id=None, *, sid=None, jti=None)`.
  - `sid is None` (every caller today, incl. `/auth/login`): payload
    **byte-for-byte unchanged** — `{sub, username, iss, aud, iat, nbf, exp,
    role}` (+`user_id` for DB accounts). TTL = `S43_JWT_TTL_SECONDS`
    (default 8h). No `sid`, no `jti`.
  - `sid` supplied: adds `sid` (validated UUID shape) + `jti`
    (`secrets.token_urlsafe(16)`, or a supplied well-formed one); TTL drops
    to the session-access TTL — approved target **15 min**
    (`S43_SESSION_ACCESS_TTL_SECONDS`, default 900, clamped 60s–1h). No
    reusable secret is ever placed in the JWT.
- `verify_jwt_token()`: unchanged core (sig, `require [sub,exp,iss,aud]`,
  iss/aud, `role ∈ {operator,admin}`, no leeway). Added: **if** `sid`/`jti`
  present they must be well-formed (`sid` = UUID, `jti` =
  `^[A-Za-z0-9_-]{1,128}$`) else 401 — a crafted/corrupt token, fail closed.
  **Neither is required.** No sessions-table read on this path (§ "no sid
  hot-path").
- `token_is_session_bound(claims)` — the explicit new-vs-legacy
  discriminator: `True` iff a well-formed `sid` is present. Issuer-set, never
  inferred. `jti` alone ≠ session-bound.
- Legacy tokens are **not** rejected. Confirmed: `test_jwt_auth.py`,
  `test_v1_auth.py`, `test_ws_auth.py`, `test_auth_login.py`, and the 13/13
  security-invariant script all pass unchanged.

## E. Session-domain model (§7)

`core/auth/sessions.py` — `SessionRecord` on its **own** `SessionBase`
(`DeclarativeBase`), NOT `core.auth.users.Base`. Consequence:
`users.init_models()` (`users.Base.metadata.create_all`) still creates
**only `users`** — the sessions table does not enter production bootstrap
(verified: `users.Base.metadata.tables == {'users'}`; nothing imports
`sessions` at app-startup scope).

Fields: `sid` (uuid PK), `user_id` (uuid, logical FK), `refresh_hash`
(sha-256 hex, unique), `prev_refresh_hash` (sha-256 hex, nullable — one-step
reuse detection), `refresh_generation` (int), `issued_at`, `last_seen_at`,
`rotated_at`, `expires_at` (absolute cap), `revoked_at`, `revoked_reason`,
`client_ip` (≤45, truncated), `user_agent` (≤256, truncated). **No `role`
column** — so refresh naturally picks up the current role (§R / §18).
`SessionRecord.is_live(now=…)`. `SessionView` = frozen dataclass read model
with **no hash field**.

The raw refresh credential is never stored.

## F. Refresh credential design (§8)

- `generate_refresh_secret()` = `secrets.token_urlsafe(32)` → **256 bits**
  CSPRNG, opaque, not a JWT, carries no account data / role / password.
- Stored verifier: single `SHA-256` hex, compared with
  `hmac.compare_digest`. **Entropy justification**: a 256-bit uniformly
  random value has no dictionary and no precomputable table, so a
  memory-hard KDF or a per-row salt buys nothing (those defend low-entropy
  human secrets); a DB dump yields only unrecoverable digests. This is the
  standard opaque-token construction.
- Optional, **not enabled**, no `.env` change: `S43_SESSION_HASH_PEPPER` —
  if set, verifier becomes `HMAC-SHA256(pepper, secret)`. All hashing
  funnels through one `_digest()` so a deployment pass can require it later.
- `verify_refresh_hash()` / `csrf_tokens_match()` fail closed (return
  `False`) on any malformed input; never raise.

## G. Rotation / replay behavior (§9, §10)

`rotate_refresh(session, *, presented_secret, new_refresh_secret, now=None)`
— single source of truth. Ordered, all fail closed:

1. locate + **row-lock** (`SELECT … FOR UPDATE`) the session whose
   `refresh_hash` **or** `prev_refresh_hash` == `sha256(presented)`
2. no match → `RefreshInvalidError`
3. matched the **previous** generation → **revoke the session**
   (`refresh_reuse`), flush, `RefreshReuseError(sid)`
4. already revoked → `SessionRevokedError(sid)`
5. `expires_at <= now` → `SessionExpiredError(sid)`
6. owning `users` row inactive → **revoke the session** (`owner_inactive`),
   flush, `SessionOwnerInactiveError(sid)`
7. rotate: `prev ← current`, `current ← sha256(new)`, `generation += 1`,
   `last_seen = rotated = now`; flush; `(row, RefreshOutcome.ROTATED)`

Never commits (caller owns the transaction). **Contract on branches 3 & 6**:
the revocation is flushed-not-committed — the route MUST `commit()` before
returning 401 or the theft/disablement response is lost. Branches 2/4/5 make
no writes.

Rotation is transactional: one successful refresh ⇒ old invalid, new valid,
same `sid`. A failure produces neither two valid generations nor "success
with no generation" nor partial state — proven under concurrency (§N).

Reuse detection is **single-session-scoped**: replaying a superseded refresh
revokes that one logical session and 401s; it is **not** a global account
logout. `RefreshReuseError.sid` lets the route emit an audit event without
the credential.

## H. Logout service behavior (§11)

- `logout_by_refresh(session, *, presented_secret, now=None) -> bool` —
  row-locks the session matching the current **or** superseded generation,
  revokes it (`logout`). **Idempotent** — unknown / garbage / already-revoked
  → `False`, never raises (double logout, or logout after cookie expiry, is a
  clean 2xx at the route). "Wrong user/session association" is not a failure
  mode: the opaque refresh secret **is** the capability; there is no separate
  (user, session-id) pair to mismatch.
- `revoke_session(session, sid, *, reason) -> bool` — admin/by-id path,
  row-locked, idempotent (absent/already-revoked → `False`).
- `revoke_all_user_sessions(session, user_id, *, reason) -> int` — the Pass
  5B hook for password change / disablement / role change. Row-locks all
  live sessions, idempotent.
- No production/browser contract changed (no schema, no cookie, no route).
- Tests: valid logout, repeated logout, already-revoked, nonexistent id,
  garbage credential, flush-not-commit (caller rollback discards).

## I. CSRF primitive design (§12)

- `generate_csrf_token()` = `secrets.token_urlsafe(32)` (256-bit).
- `csrf_tokens_match(cookie_value, header_value)` = `hmac.compare_digest`,
  **fails closed** if either half missing/empty.
- Double-submit only. **Nothing sets or checks a CSRF cookie in a live path
  in Pass 5A.**
- Intended Pass 5B wiring (documented, not built): `/auth/refresh` and
  `/auth/logout` require `cookie[csrf] == header[X-S43-CSRF]`. The CSRF token
  is compared, never grants access — it is not an authentication credential.

## J. Migration-tool comparison (§13)

`SESSION_MIGRATION_DECISION_PASS5A.md` §2 evaluates **Alembic** vs a
**minimal project-native runner** across: SQLAlchemy compatibility,
PostgreSQL support, forward migration, rollback, ordering, state tracking,
CI/testing, production deployment behaviour, operational complexity.
Option C (status quo `create_all`) is rejected — it cannot add a column,
constraint, or index and has no rollback/ordering/history.

## K. Recommended migration mechanism (§13)

**Alembic.** Rationale: a migration backlog already exists (`sessions`, P3-7
role CHECK, P3-8 citext uniqueness, maybe `login_attempts`); a bespoke runner
is "minimal" only at n=1 and becomes a maintenance tax (checksums, partial
failure, no autogenerate drift-check, no community docs); Alembic **is** the
minimal correct choice for SQLAlchemy and fits the existing
`migration-job.yaml` "run migrations as a Job before serving" pattern.
Provided in the doc: directory layout (`alembic init -t async migrations`),
config approach, connection-source approach (reuse `DATABASE_URL`),
`0001_baseline` + `alembic stamp` for existing deployments, `0002_sessions`,
rollback (`downgrade` = `DROP TABLE sessions`), CI validation
(`alembic upgrade head` + `--autogenerate` drift check).

## L. Exact proposed `sessions` schema (§14, §15)

`SESSION_MIGRATION_DECISION_PASS5A.md` §4 — production DDL:

```sql
CREATE TABLE sessions (
    sid uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    refresh_hash text NOT NULL,
    prev_refresh_hash text,
    refresh_generation integer NOT NULL DEFAULT 0,
    issued_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    rotated_at timestamptz,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoked_reason varchar(64),
    client_ip inet,
    user_agent varchar(256)
);
CREATE UNIQUE INDEX ux_sessions_refresh_hash      ON sessions (refresh_hash);
CREATE INDEX ix_sessions_prev_refresh_hash        ON sessions (prev_refresh_hash) WHERE prev_refresh_hash IS NOT NULL;
CREATE INDEX ix_sessions_user_id_live             ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX ix_sessions_expires_at               ON sessions (expires_at);
```

Constraints: PK on `sid`; FK `user_id → users(user_id) ON DELETE CASCADE`
(additive, non-destructive); UNIQUE on `refresh_hash`; `NOT NULL` on
`refresh_hash`, `refresh_generation`, `issued_at`, `last_seen_at`,
`expires_at`. Indexes: unique `refresh_hash`, partial `prev_refresh_hash`,
partial `user_id WHERE revoked_at IS NULL`, `expires_at`. Rollback:
`DROP TABLE sessions` (safe while nothing writes to it; once sessions are
live it is a coupled code+schema rollback). Deployment: `alembic upgrade
head` in `migration-job.yaml` + a one-shot compose service; `kubectl wait
--for=condition=Complete job/s43-migration` before serving a fresh DB.
Compatibility: additive only; `users` untouched; no impact on legacy auth.

**This schema is NOT in repository migration state.** It exists only as the
ORM model on an isolated `MetaData` and in test setup.

## M. Disposable PostgreSQL results (§15)

- `postgres:16.3` (matches `docker-compose.yml`), `docker run --rm --tmpfs
  /var/lib/postgresql/data -p 127.0.0.1:55433:5432`, torn down after.
- Isolation: default **READ COMMITTED**. Correctness of the session layer
  relies only on `SELECT … FOR UPDATE` blocking a second writer + READ
  COMMITTED predicate re-check (EvalPlanQual) — **not** SERIALIZABLE. The
  session layer uses **no** advisory lock (unlike the `users` first-admin
  invariant).
- Schema created via `SessionBase.metadata.create_all` (test-only).
- `core/tests/test_session_layer_pg.py` — **19 passed**: create/persistence/
  transaction-ownership, rotation, single-step reuse + auto-revoke,
  revocation, logout, expiry, disablement, unique `refresh_hash`, role
  change, service-token cannot drive the layer, + the §16 concurrency set.

## N. Concurrency results (§16)

| Scenario | Test | Outcome |
|---|---|---|
| A — two (and five) refreshes, same current credential | `test_two_concurrent_refreshes_yield_exactly_one_successor[2,5]` | exactly **one** `ROTATED` (generation → 1); loser(s) → `RefreshReuseError`; session ends `refresh_reuse`-revoked. **Never > 1 successor generation.** |
| B — refresh racing logout | `test_refresh_racing_logout_never_issues_after_logout` | whichever wins, session ends revoked; no live successor credential exists |
| C — refresh racing account disablement | `test_refresh_racing_disablement` | after the race, account disabled + `revoke_all_user_sessions` → no refresh possible |
| D — repeated logout | `test_repeated_logout_is_clean` | first `True`, all subsequent `False`, no error |
| E — expiration racing refresh | `test_expiration_racing_refresh_is_atomic` | outcome is exactly `{rotated, gen 1}` or `{SessionExpiredError, gen 0}` — never a torn row |

## O. Service-identity regression results (§22)

`core/tests/test_service_identity_separation.py` — **12 passed** — plus
`test_session_layer_pg.py::test_service_token_cannot_drive_the_session_layer`:

- human access JWT (operator/admin, plain **and** session-bound) → Watchtower
  `_require_service_token`, API `_require_fenrir_service_token`, Watchtower
  `_require_admin_token` all **401**
- refresh credential → not a JWT → `verify_jwt_token` 401; → service verifiers
  401
- service shared-secret token → `verify_jwt_token` 401,
  `_validate_env_credentials` 401, cannot be a `sid`, hash never collides with
  a session's; → `rotate_refresh` `RefreshInvalidError`, `logout_by_refresh`
  `False`
- guard rail: service-verifier source contains no `verify_jwt_token` /
  `_issue_token`, does use `compare_digest`
- sanity: a service verifier still **accepts its own** token

Watchtower / Fenrir / Sparta / remote-gateway verifier code is **byte-for-byte
unchanged** in Pass 5A.

## P. Legacy-auth compatibility results (§5, §25)

| Invariant | Result |
|---|---|
| Security-invariant script (13 checks: `/v1` scope-bypass closed, `/users` admin gate, Watchtower authz + probe openness, users router mounted) | **13/13** |
| `test_jwt_auth` + `test_v1_auth` + `test_ws_auth` | **56 passed** |
| `test_auth_login` + `test_login_throttle` + `test_bootstrap_isolated` + `test_users_admin` | pass |
| `test_account_transactions_pg` (Pass 3, real PG) | **9 passed** |
| Legacy `_issue_token` payload shape | byte-identical (asserted) |
| Legacy Bearer JWT + `X-S43-Password` on protected routes | unchanged |
| WebSocket auth contract | unchanged; tests pass |
| `init_models()` still creates only `users` | verified |

## Q. Full regression suite (§26)

`pytest core/tests/ -q -rsxX --ignore=test_bootstrap.py
--ignore=test_system_smoke.py`, `S43_TEST_PG_DSN` set to the disposable PG:

**360 collected, 360 passed, 0 failed, 0 errors, 0 skipped, 0 xfail/xpass,
5 warnings (all pre-existing, none from Pass 5A), exit 0, 852 s.**

360 = Pass 3 baseline 300 + 60 new Pass 5A tests. `test_bootstrap.py` /
`test_system_smoke.py` excluded per the standing no-live-HTTP / no-`requests`
rule (consistent with Passes 1–3). Full metadata table (versions, per-suite
A–M mapping) in `PASS5A_VALIDATION.md` §7.

## R. Unresolved findings

1. **F-TLS-1 (blocking, deployment)** — no secure production TLS posture in
   repo evidence. Gates Phase B+ of `X-S43-Password` retirement and browser
   cutover. (§C, `AUTH_TLS_POSTURE_PASS5A.md`.)
2. **Migration mechanism** — Alembic recommended; not introduced. Needs owner
   approval + a dedicated migration authorization (§14 STOP).
3. **Session layer not wired** — no `/auth/refresh`, `/auth/logout`, cookie,
   or CSRF activation. Pass 5B, gated on #2 and #1.
4. **`#11` env-operator** — unchanged. Pass 4's Option C (scoped break-glass)
   still needs operator sign-off + a `.env` contract change. Not Pass 5A/5B
   first-cut.
5. **Multi-replica throttle** — repo evidence (k8s README "Known
   limitations") says the in-process rate limiter / login throttle is
   per-pod; `overlays/beta` runs 2 replicas. **Session rotation is DB-backed
   → replica-safe.** The throttle is not. A `login_attempts` table (or
   Redis) is a separately authorized schema decision; not done (§20). Beta
   should run single-replica for auth, or accept + document the weakened
   throttle.
6. **Role-change / disablement stateless window** — an already-issued access
   token stays valid up to its TTL (15 min for session-bound) on routes that
   trust the `role` claim. `require_admin` still does a **live** DB check on
   `/users`. Not "immediate revocation" — documented as an explicit trade
   (§17, §18).
7. **App-level transport hardening** (HSTS header, `https://`-origin
   assertion in non-local envs) — recommended for a deployment pass, **not**
   done in Pass 5A (changes startup behaviour for existing plaintext
   deployments).
8. Carried from earlier passes: P3-7 role CHECK constraint, P3-8 citext
   uniqueness (both need migrations + a live-data collision inventory).

**None of #1–#8 are marked RESOLVED** (authorization §27).

## S. Exact authorization needed for Pass 5B

Pass 5B (route wiring) must be authorized explicitly and cannot start until:

1. **Migration authorization** — approve **Alembic** and authorize a
   dedicated migration pass to (a) introduce Alembic + `0001_baseline` +
   `alembic stamp` on existing deployments, (b) add `0002_sessions` (§L
   DDL), (c) wire `alembic upgrade head` into `migration-job.yaml` + a
   one-shot compose migrate step. Optionally fold in P3-7 / P3-8 /
   `login_attempts`.

2. **F-TLS-1 disposition** — either (a) confirm the target environment
   terminates TLS at the edge with HSTS, or (b) explicitly accept that
   browser sessions ship **dev-only** until then.

3. **Pass 5B scope sign-off** — wire `/auth/login` to also
   `create_session()` + set the refresh cookie (`HttpOnly; Secure;
   SameSite=Strict; Path=/auth`) + issue a `sid`-bound 15-min access token;
   add `POST /auth/refresh` (cookie + `X-S43-CSRF` → `rotate_refresh` →
   new cookie + token; commit the revoke on `RefreshReuseError` /
   `SessionOwnerInactiveError` then 401+clear-cookie); add `POST
   /auth/logout` (cookie + CSRF → `logout_by_refresh`); wire
   `revoke_all_user_sessions` into `set_user_password` /
   `set_user_active(False)` / `set_user_role`. Legacy Bearer JWT +
   `X-S43-Password` stay accepted (Phase B dual contract). `sid` hot-path
   liveness, WebSocket password-field removal, frontend cutover, and Phase E
   `X-S43-Password` removal are **later**, separately gated steps.

---

## Boundaries honoured (authorization §28, §30)

No push / force-push / merge / PR / repo-settings / OneDrive-repo change /
stack start-stop-rebuild / live-DB touch / production migration / credential
rotation / deployment-secret change / deploy / secret disclosure / recovery
removal. No migration infra, no migration-history file, no `sessions` table
in tracked or production state, `init_models()` and `migration-job.yaml`
untouched (§14 / §30 STOP). `X-S43-Password` kept; legacy tokens accepted;
protected-route, WebSocket, and service-token contracts unchanged;
env-operator unchanged; no `.env` contract change. No `sid` hot-path
polling/LRU. Disposable PostgreSQL only. Single writer, one invocation.

## Immediate next action for the owner

1. Review the `core/api/routers/auth.py` diff and `core/auth/sessions.py`.
2. Decide **Alembic** (§K) + authorize the migration pass (§S-1).
3. Acknowledge **F-TLS-1** (§C) and choose dev-only vs block-until-TLS (§S-2).
4. Then authorize Pass 5B (§S-3).

---

## Appendix — WebSocket migration notes (authorization §21, implementation notes only)

**No WebSocket code changed in Pass 5A.** `core/api/main.py::dashboard_websocket`
keeps its exact contract: first frame `{token: <JWT>, password: <plaintext>}`
→ `verify_jwt_token(token)` → `reverify_password(subject, password)`.
`test_ws_auth.py` passes unchanged.

For the eventual migration to token-only initial auth + periodic checks
(target architecture from `AUTH_ARCHITECTURE_PASS4.md`):

1. **Initial auth becomes token-only.** The client obtains a short-lived
   `sid`-bound access token via `/auth/refresh` (cookie + CSRF), then opens
   the WS and sends `{token: <access token>}` — same frame shape, minus the
   `password` field. The refresh cookie is `Path=/auth; SameSite=Strict`, so
   it is deliberately **not** on the `/ws` upgrade; the access token is the
   WS credential.
2. **`X-S43-Password` removal in the frame is Phase C+** of
   `AUTH_MIGRATION_PASS4.md`, gated exactly like the HTTP-header removal.
   Until then the frame keeps both fields and the server keeps calling
   `reverify_password`.
3. **Periodic session/account recheck (≤60 s target).** When the frame's
   access token carries `sid`, a per-connection background task re-checks
   `SessionRecord.is_live(sid)` (a single indexed DB read) on an interval and
   closes the socket on revoke / expiry / owner-disablement. This needs the
   `sessions` table live and a bounded per-replica `sid` cache — **both
   deferred** (authorization §6, §21). Pass 5A intentionally did not add any
   `sid` hot-path lookup.
4. **No leeway change.** WS verification stays aligned with `verify_jwt_token`
   (no clock leeway today; the ±30 s `nbf`/`iat` leeway is a separate,
   whole-verifier change from `AUTH_ARCHITECTURE_PASS4.md` §3.5, not in
   scope).
5. **Multi-replica**: a WS is pinned to one replica and the recheck is a
   local DB read, so it is replica-safe (unlike the in-process login
   throttle, §R-5).

None of the above is implemented. The building block that exists today is
`SessionRecord.is_live()` and the `sid` claim.
