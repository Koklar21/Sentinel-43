# Sentinel-43 — Authentication Migration Plan (Pass 4, design only)

Consumer inventory, compatibility matrix, the `X-S43-Password` retirement
phases, the #11 recommendation, and the ordered Pass 5 implementation
sequence. **Nothing here is implemented.** Companions:
`AUTH_ARCHITECTURE_PASS4.md`, `AUTH_THREAT_MODEL_PASS4.md`,
`AUTH_TEST_SPEC_PASS4.md`.

---

## 1. Consumer inventory (deliverable C)

Every known consumer of Sentinel-43 authentication, from a repo-wide search.

| # | Consumer | Class | Transport | Endpoint(s) | Credential today | Token lifetime expectation | Logout today | Compat risk of the redesign |
|---|---|---|---|---|---|---|---|---|
| C1 | **Dashboard SPA** (`dashboard/assets/js/auth.js` v1.6.0 + `dashboard.js`) | BROWSER / HUMAN INTERACTIVE | HTTPS `fetch` | `/auth/login`, `/auth/verify`, all `/...` protected routes | login form ⇒ JWT in `sessionStorage` + password in JS memory; every request `Bearer` + `X-S43-Password` | tolerates the 8 h JWT; re-logs-in on every reload | client-side only (`clearToken()`) | **HIGH** — the biggest change. New: access token in memory, refresh cookie, `/auth/refresh` on load, `/auth/logout`. `X-S43-Password` removed. Needs a coordinated JS rewrite. |
| C2 | **Dashboard WebSocket** (`dashboard/assets/js/websocket.js`) | BROWSER / WEBSOCKET | WSS | `/ws` | first frame `{token, password}` | connection persists indefinitely | reconnect loop on `auth_failed` | **HIGH** — frame becomes `{token}` only; handler adds exp / disablement re-check + close codes. |
| C3 | **`/v1/*` API** (`require_operator`) | HUMAN INTERACTIVE (via dashboard) or CLI/AUTOMATION (unknown) | HTTPS | `/v1/assess`, `/v1/actions/*` | `Bearer` + `X-S43-Password` | 8 h | n/a | **MEDIUM** — same token change; any non-browser `/v1` caller must adopt the new flow. **No such caller is known** — recorded UNKNOWN (C9). |
| C4 | **`/users` admin API** (`require_admin`) | HUMAN INTERACTIVE | HTTPS | `/users`, `/users/{id}`, `/users/{id}/password` | `Bearer` + `X-S43-Password` | 8 h | n/a | **MEDIUM** — token change only; `require_admin`'s live DB check is unchanged. |
| C5 | **`/bootstrap/*`** | HUMAN INTERACTIVE (first run) | HTTPS | `/bootstrap/status`, `/bootstrap/admin` | **unauthenticated** (self-gating) | n/a | n/a | **LOW** — no auth today; unchanged. `/bootstrap/admin` still creates the first DB admin. |
| C6 | **dashboard status/config/system routes** (`_get_operator` / `_require_operator`) | HUMAN INTERACTIVE | HTTPS | `/actions`, `/vault/stats`, `/watchtower/status`, `/system/*`, `/fenrir/*`, `/dependencies/report/*`, `/governance/pending`, `/core/*` (some) | `Bearer` + `X-S43-Password` (or `dev-operator` local fallback) | 8 h | n/a | **MEDIUM** — token change; the `SENTINEL_ENV in {dev,local,test}` `dev-operator` fallback stays as-is. |
| C7 | **Watchtower internal service** (`_require_service_token`) | SERVICE IDENTITY | HTTP over `s43_net` | `/watchtower/status,/modules,/analyze,...` | `Bearer <S43_WATCHTOWER_SERVICE_TOKEN>` | long-lived shared secret | n/a | **NONE** — untouched. Test asserts a human token is still rejected here. |
| C8 | **Fenrir → API** (`_require_fenrir_service_token`) | SERVICE IDENTITY | HTTP | `/internal/events/broadcast`, `/watchtower/events` | `Bearer <S43_FENRIR_API_TOKEN>` | long-lived | n/a | **NONE** — untouched. |
| C8b | **Sparta node API** (`Sparta_core.py`) | INTERNAL COMPONENT | HTTP | `/node/*` | `Bearer <S43_SPARTA_NODE_TOKEN>` + body credential | long-lived | n/a | **NONE** — untouched. |
| C8c | **Remote gateway operators** (`_resolve_operator_role`) | SERVICE IDENTITY / HUMAN-via-mobile | HTTPS | `/remote-gateway/*` | `Bearer <SENTINEL_REMOTE_TOKEN_{OWNER,ADMIN,AUDITOR}>` | long-lived per-role token | n/a | **NONE by default** — separate `OperatorRole` model, separate tokens. **Open question:** should the mobile/remote operator eventually use the human session model instead of a static per-role token? Recorded as a future decision, not this redesign. |
| C9 | **CLI / automation clients** | CLI/AUTOMATION | ? | ? | ? | ? | ? | **UNKNOWN** — none found in the repo (`core/cli/` has only `generate_secrets.py`, which does no API auth). If one exists or is planned it needs a device-code or PAT flow, not username+password per call. **Does not block the migration** — recorded UNKNOWN. |
| C10 | **`GET /auth/verify`** | BROWSER | HTTPS | `/auth/verify` | `Bearer` only (no password) | n/a | n/a | **LOW** — keep as a cheap access-token structural check, or fold into `/auth/refresh`. |
| C11 | **env-var operator** (`_validate_env_credentials`) | HUMAN / break-glass | HTTPS | `/auth/login`, per-request `reverify_password` | `S43_OPERATOR_USERNAME` + SHA-256(`S43_OPERATOR_PASSWORD_HASH`) | issues a `role=operator` 8 h JWT with no `user_id` | n/a | **DECISION REQUIRED** — see §3 (#11). Currently set in the deployed `.env`. |
| C12 | Docker / K8s health probes | INTERNAL COMPONENT | HTTP | `/health`, `/ready`, `/watchtower/health`, `/watchtower/ready` | **none** (unauthenticated by design, Pass 1) | n/a | n/a | **NONE**. |
| C13 | Test suite (12 files) | — | TestClient | all of the above | encodes the current contract | — | — | **HIGH churn** — the contract tests are rewritten per `AUTH_TEST_SPEC_PASS4.md`; the *invariant* tests (Pass 1/2/3) must keep passing. |
| C14 | `core/s34_auth/*` | DEAD | — | — | — | — | — | no live importers; excluded; delete in a cleanup pass. |

**Classification tally:** BROWSER 2 · WEBSOCKET 1 · HUMAN INTERACTIVE 5 ·
SERVICE IDENTITY 4 · INTERNAL COMPONENT 3 · CLI/AUTOMATION 0 known ·
UNKNOWN 1 (C9) · DEAD 1.

**Human ≠ service is preserved:** every SERVICE IDENTITY row (C7, C8, C8b,
C8c) keeps its own env secret and its own verifier; the redesign adds no path
where a human session token satisfies them.

---

## 2. Compatibility matrix (deliverable P)

| Consumer | Current auth | Proposed auth | Migration required | Breaking? | Rollback path | Test required |
|---|---|---|---|---|---|---|
| C1 Dashboard SPA | JWT(8h) + `X-S43-Password` every req | access token(15m, memory) + refresh cookie; `/auth/refresh` on load; no password after login | **yes — JS rewrite** | yes, at Phase E | serve the old `auth.js`/`dashboard.js` bundle; backend keeps accepting legacy until Phase E | `AUTH_TEST_SPEC` Login/Token/Revocation + a browser smoke |
| C2 Dashboard WS | `{token,password}` frame; infinite session | `{token}` frame; exp + disablement re-check; close codes | **yes — JS + handler** | yes, at Phase E | old `websocket.js`; backend accepts legacy frame until Phase E | `AUTH_TEST_SPEC` WebSocket |
| C3 `/v1/*` | `Bearer` + `X-S43-Password` | `Bearer` (new token), no password | consumer unknown (C9); backend change is compat-layered | yes, at Phase E | backend accepts legacy until Phase E | `test_v1_auth.py` rewritten + kept as an invariant |
| C4 `/users` | `Bearer` + `X-S43-Password` | `Bearer` only | backend only | yes, at Phase E | as above | `test_users_admin.py` |
| C6 dashboard routes | `Bearer` + `X-S43-Password` (+ `dev-operator`) | `Bearer` only | backend only; `dev-operator` fallback kept | yes, at Phase E | as above | `test_actions_test_inject_auth.py`, new |
| C5 `/bootstrap/*` | none | none | none | no | — | `test_bootstrap_isolated.py` unchanged |
| C7 Watchtower service | service token | service token | **none** | no | — | `test_watchtower_service_auth.py` + new "human token rejected" |
| C8 Fenrir | service token | service token | **none** | no | — | `test_internal_broadcast_auth.py` + new |
| C8b Sparta node | node token | node token | **none** | no | — | existing |
| C8c Remote gateway | per-role token | per-role token | **none** (default) | no | — | existing remote-gateway tests |
| C10 `/auth/verify` | `Bearer` | `Bearer` (or fold in) | trivial | no | keep the endpoint | small |
| C11 env operator | SHA-256 | **decision, §3** | see §3 | possibly (Phase E or #11 removal) | keep the env path until the decision lands | `test_auth_login.py` (currently exercises this path) |
| C12 probes | none | none | none | no | — | existing |
| C9 CLI (UNKNOWN) | UNKNOWN | would need device-code / PAT | UNKNOWN | UNKNOWN | n/a | n/a — recorded UNKNOWN, does not block |

Unknown consumers remain explicitly UNKNOWN. The migration is safe to design
around them because the compatibility layer (Phase A–D) keeps the legacy
contract working the whole time.

---

## 3. RELEASE_FINDINGS #11 — env-var operator recommendation (deliverable M)

### Dependency trace

`_validate_env_credentials` is reached from:
1. `_validate_credentials` (POST /auth/login) — whenever the DB path returns
   no user: **DB unavailable, table missing, OR simply a wrong/unknown
   username on a healthy DB**.
2. `reverify_password` (every protected request) — same fall-through.

Deployment reality: the running `.env` sets `S43_OPERATOR_USERNAME` and
`S43_OPERATOR_PASSWORD_HASH`. `test_auth_login.py` exercises this path as its
primary case. `core/cli/generate_secrets.py` does **not** register these two
(they're operator-authored). So the env operator **is** live and is the
current "how do I log in before I've bootstrapped a DB admin / if the DB is
down" answer.

### Options

| Option | What | Compat | Recovery access | Bootstrap impact | Op risk | Migration | Rollback |
|---|---|---|---|---|---|---|---|
| **A. Remove** | delete `_validate_env_credentials` + the two env vars; `/bootstrap/admin` is the only way in on a fresh deploy | breaks any deploy relying on it; `test_auth_login.py` rewritten | **none if the DB is down** — need a documented break-glass (restore DB, or run `create_first_admin` via a one-off script against the DB) | unchanged — `/bootstrap/admin` still makes the first DB admin | low once documented; higher during the transition | remove the vars from `.env.example` + the K8s/compose config + docs; announce | re-add the function + vars |
| **B. Keep, Argon2** | store `S43_OPERATOR_PASSWORD_HASH` as an Argon2 hash; verify with `verify_password` | **breaking `.env` change** — operators regenerate the hash | unchanged | unchanged | medium — every deploy must regenerate the hash on cutover | ship a `generate_secrets` helper for the new hash; dual-accept SHA-256 + Argon2 for one release, then drop SHA-256 | keep dual-accept |
| **C. Scoped break-glass token** | replace the permanent password with `S43_BREAK_GLASS_TOKEN` that only authenticates when `count_active_admins() == 0` **or** an explicit `S43_BREAK_GLASS_ARMED=true` is set; always `role=admin`, never a normal login | breaks the "env operator as a daily account" use (if anyone does that) | works when the DB is up but empty; a separate runbook for DB-down | tightens it — break-glass is exactly for "no admin exists yet" | low — narrow surface, off by default after bootstrap | new env var; remove the old two; docs | re-add the old path |

### Recommendation

**Option C, with a fallback to Option A** if the operator confirms nobody uses
the env operator as a routine account.

Rationale: the env operator's *legitimate* job is break-glass /
first-run-before-DB. Option C keeps exactly that and removes the "a permanent,
un-salted, fast-hashed password that is checked on every failed login" surface
(T15, T7, T8). It is not a breaking `.env` change for anyone using it
correctly (as break-glass). Option B keeps the daily-account use but doesn't
shrink the surface and forces a hash regeneration.

**Decision needs operator input** and does **not** happen in Pass 4 — the
`.env` contract is untouched here (mission §15, §26). Recorded as open
question #2 in `AUTH_ARCHITECTURE_PASS4.md` §7.

---

## 4. `X-S43-Password` retirement — phased migration (deliverable N)

### Phase A — baseline (current state)
Contract: `Bearer` + `X-S43-Password` on every protected request; WS frame
`{token, password}`. `require_operator` / `require_admin` / `_get_operator` /
`dashboard_websocket` all require the password.
**Entry criterion:** none (this is today). **Exit criterion:** the Phase B
code passes `AUTH_TEST_SPEC_PASS4.md` in full and every Pass 1/2/3 invariant
still passes.

### Phase B — dual contract (backend only)
Add: `sessions` table (migration — STOP for authorization), `POST /auth/refresh`,
`POST /auth/logout`, CSRF cookie/header, access token with `jti`+`sid` and a
15-min default TTL, `kid` keyring, ±30 s `iat`/`nbf` leeway.
`verify_jwt_token` accepts **both** old (8 h, no `sid`) and new tokens.
`require_*` and `dashboard_websocket`:
- if the token is **new-style** (`sid` present + session live) ⇒ **do not
  require `X-S43-Password`**;
- if the token is **old-style** ⇒ require `X-S43-Password` exactly as today.
The `dev-operator` local fallback is unchanged.
**Entry criterion:** Phase A exit met + migration authorized.
**Exit criterion:** new path validated end-to-end in an isolated stack
(compose project with its own DB); legacy path unchanged; all invariant tests
green.

### Phase C — migrate consumers
- C1 dashboard SPA: memory access token, refresh-on-load, logout.
- C2 dashboard WS: `{token}` frame, re-check loop, close codes.
- C10 `/auth/verify`: keep or fold in.
- C11 env operator: apply the #3 decision (Option C or A).
- C9 (if any CLI surfaces): device-code / PAT flow.
**Entry criterion:** Phase B exit met.
**Exit criterion:** every KNOWN consumer emits new-style tokens and no
`X-S43-Password`; a `legacy_auth_request_total` counter exists (per route).

### Phase D — deprecate legacy (observable)
`require_*` / `dashboard_websocket`: when a request carries `X-S43-Password`
**or** an old-style token, increment `legacy_auth_request_total` and emit a
**rate-limited, credential-free** `logger.warning("legacy X-S43-Password auth
from sub=%s route=%s — migrate to session tokens", sub, route)`. Still accept
it.
**Entry criterion:** Phase C exit met.
**Exit criterion:** `legacy_auth_request_total == 0` for a defined
observation window (recommend **≥ 2× the maximum legacy token TTL = 16 h**, or
one full beta cycle, whichever the operator chooses) **and** operator sign-off.

### Phase E — reject legacy (cutover)
`require_*` / `dashboard_websocket`: a request carrying `X-S43-Password` **or**
an old-style token ⇒ **401** with `detail: "Legacy authentication is no
longer accepted. Log in again."` Remove `reverify_password`,
`_validate_env_credentials` (if #11 → Option A), the WS-frame `password` field,
the `X-S43-Password` redaction entries (no longer needed). `PASSWORD_HEADER_NAME`
and the header constant are deleted.
**Entry criterion:** Phase D exit met.
**Rollback:** revert the Phase E commit ⇒ back to Phase D (dual accept). This
is the single "breaking" step and it has a one-commit rollback because Phase B
kept the legacy code intact until here.

### Phase-gate summary

| Gate | Criterion |
|---|---|
| A → B | Pass 4 test spec green + Pass 1/2/3 invariants green + **migration (sessions table) separately authorized** |
| B → C | new flow validated in an isolated compose stack; legacy unchanged |
| C → D | all known consumers migrated; `legacy_auth_request_total` metric live |
| D → E | `legacy_auth_request_total == 0` for ≥ 16 h (or a beta cycle) + operator sign-off |

---

## 5. Ordered migration plan (deliverable R)

| Step | Change | Type | Rollback checkpoint |
|---|---|---|---|
| M0 | this design + test spec + operator decisions on OQ #1–#8 | docs | n/a |
| M1 | **`sessions` table migration** — pick a migration tool (project has none; Alembic recommended) or a guarded `CREATE TABLE IF NOT EXISTS` in a dedicated `core/auth/migrations/` runner; exercise on a disposable DB | **schema — STOP for separate authorization** | drop table (no data yet) |
| M2 | access-token changes: `jti`, `sid`, 15-min default, `kid` keyring, `iat`/`nbf` leeway; `verify_jwt_token` accepts old + new | code | revert commit ⇒ old token only |
| M3 | `POST /auth/refresh`, `POST /auth/logout`, CSRF cookie/header, session create on `/auth/login` | code | revert ⇒ no refresh/logout; `/auth/login` still works |
| M4 | `require_*` + `dashboard_websocket`: new-style token ⇒ skip `X-S43-Password` (Phase B behaviour) | code | revert ⇒ password always required |
| M5 | session-revocation hooks: `set_user_active(false)` / `set_user_role` / `set_user_password` / logout ⇒ delete affected `sessions` rows (in the same transaction — Pass 3 boundary) | code | revert ⇒ revocation only via token expiry |
| M6 | WS handler: track `exp`, ≤ 60 s `sid`/`is_active` re-check, sanitized close codes | code | revert ⇒ infinite WS session |
| M7 | throttle: add IP dimension; move counter to `login_attempts` table (or Redis) **[OPTIONAL / multi-replica]** | code (+ schema if table) | revert ⇒ Pass 3 in-process throttle |
| M8 | #11: apply Option C (or A) | code + `.env`/docs — **STOP for separate authorization** | re-add the env path |
| M9 | dashboard SPA + WS JS rewrite (C1, C2) | frontend | serve the old bundle |
| M10 | Phase D: `legacy_auth_request_total` + deprecation warning | code | revert |
| M11 | observation window; operator sign-off | ops | — |
| M12 | Phase E: reject legacy; delete `reverify_password` / `_validate_env_credentials` / `X-S43-Password` | code | **revert the single commit ⇒ Phase D** |
| M13 | delete `core/s34_auth/*` (cleanup, independent) | code | revert |

Every schema step (M1, M8 if it adds a table, M7 if table) is an explicit
STOP for separate authorization (mission §20, §23). Every breaking step (M12)
has a one-commit rollback because the legacy code is retained until then.

---

## 6. Pass 5 implementation sequence (deliverable S)

Small, independently testable. **None executed in Pass 4.**

| P5-step | Files expected to change | Behaviour introduced | Tests required | Migration? | Compat effect | Rollback point | STOP condition |
|---|---|---|---|---|---|---|---|
| P5-1 | `core/auth/users.py` (or new `core/auth/sessions.py`), a migration runner | `sessions` table + `Session` model + `create_session` / `get_session_by_refresh` / `rotate_session` / `revoke_session` / `revoke_user_sessions` helpers (flush-not-commit, Pass 3 style) | `test_sessions_pg.py` (disposable PG): create / rotate / expire / revoke / reuse-detection / cascade-on-user-delete | **YES — STOP first** | none (additive) | drop table | schema migration not authorized; disposable-PG semantics can't be reproduced |
| P5-2 | `core/api/routers/auth.py` | `_issue_token` adds `jti`+`sid`; TTL default 900; `kid` keyring in `_issue_token` + `verify_jwt_token`; ±30 s `iat`/`nbf` leeway; `verify_jwt_token` still accepts a `sid`-less token | `test_jwt_auth.py` extended: new claims, keyring accept-both, leeway bounds, old token still valid | no | additive | revert | `verify_jwt_token` is imported by main.py + deps + WS — a signature/contract change that breaks any of them |
| P5-3 | `core/api/routers/auth.py`, `core/api/main.py` (CORS credentials) | `POST /auth/login` creates a session + sets the refresh cookie; `POST /auth/refresh`; `POST /auth/logout`; CSRF cookie/header | `test_auth_session.py`: login sets cookie; refresh rotates + new access token; refresh after logout ⇒ 401; refresh with reused value ⇒ session revoked; CSRF missing ⇒ 403; disabled user ⇒ refresh 401 | no | additive (new endpoints) | revert | cookie flags wrong; CSRF design gap; CORS-credentials change breaks an existing origin |
| P5-4 | `core/api/deps/deps.py`, `core/api/main.py` (`_get_operator`), `core/api/routers/auth.py` (`reverify_password` gate) | Phase B: new-style token (valid `sid`) ⇒ `X-S43-Password` not required; old-style ⇒ required exactly as today | `test_v1_auth.py`, `test_users_admin.py`, `test_ws_auth.py`, `test_auth_login.py` — legacy cases unchanged + new-token-no-password cases; **Pass 1 SI script still 13/13** | no | dual contract | revert ⇒ password always required | any legacy case regresses; SI-1/SI-2 regress |
| P5-5 | `core/auth/users.py` set_user_* + `core/api/routers/users.py` + `core/auth/deps.py` | revoke affected sessions on disablement / role change / password reset / logout, in the route's transaction | `test_account_transactions_pg.py` extended: disable ⇒ sessions gone; role change ⇒ sessions gone; all atomic | no | tighter revocation | revert ⇒ revoke-by-expiry only | Pass 3 transaction boundary broken; partial revoke |
| P5-6 | `core/api/main.py::dashboard_websocket` | `{token}`-only frame accepted; `exp` tracked; ≤ 60 s `sid`/`is_active` re-check; sanitized close codes; legacy `{token,password}` still accepted (Phase B) | `test_ws_auth.py` extended: connect w/o password (new token); expiry ⇒ close `token_expired`; disable mid-connection ⇒ close `session_revoked`; legacy frame still works | no | dual contract | revert ⇒ infinite session, password frame | WS contract change breaks `websocket.js` before C9 rewrite |
| P5-7 | `core/api/routers/auth.py` (throttle) | IP dimension + shared-store counter | `test_login_throttle.py` extended; `test_login_throttle_pg.py` if a table | maybe (table) — STOP if so | none | revert ⇒ Pass 3 throttle | table migration not authorized |
| P5-8 | `dashboard/assets/js/*` | SPA: memory token, `/auth/refresh` on load, `/auth/logout`; WS: `{token}` frame | a browser smoke test (Pass 6 `run` skill) + the existing JS-referencing tests | no | frontend cutover | serve old bundle | dashboard breaks for a real operator |
| P5-9 | `core/api/routers/auth.py`, `core/api/main.py`, `core/api/deps/deps.py` | Phase D: `legacy_auth_request_total` + rate-limited deprecation warning | `test_*` assert the metric increments and no credential is logged | no | none | revert | metric leaks a credential |
| P5-10 | #11 (Option C or A) | scoped break-glass or removal | `test_auth_login.py` rewritten; `test_break_glass.py` | maybe `.env` — **STOP** | breaking for env-operator users | re-add | `.env` contract change not authorized |
| P5-11 | delete `reverify_password`, `_validate_env_credentials` (if A), `X-S43-Password`, WS `password` | Phase E cutover | full suite; SI script; the legacy cases now assert **401** | no | **breaking** | **revert this one commit ⇒ Phase D** | `legacy_auth_request_total != 0`; operator hasn't signed off |
| P5-12 | delete `core/s34_auth/*` | cleanup | full suite (nothing imports it) | no | none | revert | something imports it after all |

---

## 7. Confirmation

Pass 4 changed no runtime auth code, no env var, no schema, no migration, no
JWT claim, no route, no header contract, no frontend behaviour, no dependency.
Five documents added to the integration branch. No push, no deploy, no
live-system access. All Pass 1/2/3 invariants intact; no finding marked
resolved.
