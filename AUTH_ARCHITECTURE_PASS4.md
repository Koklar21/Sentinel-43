# Sentinel-43 — Authentication Architecture (Pass 4, design only)

Specification. **Nothing in this document has been implemented.** No runtime
auth behaviour was changed in Pass 4. Companion: `AUTH_THREAT_MODEL_PASS4.md`,
`AUTH_MIGRATION_PASS4.md`, `AUTH_TEST_SPEC_PASS4.md`.

Branch `integration/beta-hardening-20260901`, analysed at `86c9aab`.

---

## 1. Current authentication architecture (as traced from the code)

### 1.1 Human / operator authentication

```
POST /auth/login  {username, password}        core/api/routers/auth.py
  -> _login_check_throttled(username)          per-username lockout (Pass 3)
  -> _validate_credentials(username, password)
        DB path:   authenticate_user(session,u,p)   Argon2id verify (off-loop, Pass 3)
                   -> on success: record_login + commit; return (username, role, user_id)
        fallback:  _validate_env_credentials(u,p)    SHA-256(password) == S43_OPERATOR_PASSWORD_HASH
                   -> reached whenever the DB path returns no user
                      (DATABASE_URL unset, DB down, table missing, OR wrong username)
  -> _issue_token(subject, role, user_id)      HS256 JWT
  -> LoginResponse {token, token_type:"bearer", subject, expires_at}

every protected HTTP request
  -> verify_jwt_token(bearer)                  sig + {sub,exp,iss,aud} + iss/aud match + role in {operator,admin}
  -> reverify_password(subject, X-S43-Password) authenticate_user() again  (SELECT + Argon2 verify)
                                                OR _validate_env_credentials() fallback
  (require_admin additionally: get_user_by_username(session, subject) -> role=='admin' & is_active)

WebSocket /ws                                  core/api/main.py::dashboard_websocket
  -> Origin check against S43_ALLOWED_ORIGINS
  -> first frame {"type":"auth","payload":{"token":..., "password":...}}
  -> verify_jwt_token(token) + reverify_password(sub, password)
  -> connection then lives indefinitely — NO re-check of exp / is_active / role
```

### 1.2 The access token today

| Property | Value |
|---|---|
| Type | JWT, **HS256** (only algorithm accepted — `APPROVED_JWT_ALGORITHMS`) |
| Signing key | `S43_JWT_SECRET` (symmetric, shared by every replica) |
| Lifetime | `S43_JWT_TTL_SECONDS`, **default 28800 s (8 h)**, clamped [60, 86400] |
| Claims | `sub`, `username` (= sub), `iss` (`sentinel-43`), `aud` (`sentinel-43-dashboard`), `iat`, `nbf` (= iat), `exp`, `role` (`operator`\|`admin`), `user_id` (DB accounts only) |
| Session id / `jti` | **none** |
| Clock leeway on verify | **none** |
| Revocation | **none** — an issued token is valid until `exp` no matter what |
| Refresh | **none** — no `/auth/refresh`; `/auth/*` is only `POST /login`, `GET /verify` |
| Logout | **none server-side** — `auth.js` `logout()` just clears client state |

### 1.3 Why `X-S43-Password` exists

Because the token has no revocation, the per-request password re-check is the
de-facto "is this session still valid" gate:

- catches **password change** (old password stops working immediately),
- catches **account disablement** (`authenticate_user` returns `None` for
  `not is_active`),
- does **not** catch **token + password theft** (attacker has both),
- does **not** catch **role change** for `require_operator` / `_get_operator`
  (they trust the token's `role` claim); `require_admin` re-reads the DB so
  `/users` is live.

### 1.4 Credential stores

| Store | Scheme | Used by | Notes |
|---|---|---|---|
| `users` table (`core/auth/users.py`) | **Argon2id** (argon2-cffi defaults t=3 / 64 MiB / p=4) | primary | `user_id, username(unique), email(unique,null), password_hash, role, is_active, created_at, last_login_at`. **No** `password_changed_at`, `token_version`, `disabled_at`. |
| env-var operator | **SHA-256(password)**, un-salted, constant-time compare | `_validate_env_credentials` fallback | `S43_OPERATOR_USERNAME` / `S43_OPERATOR_PASSWORD_HASH` — both currently set in the deployed `.env`. **RELEASE_FINDINGS #11.** |

### 1.5 Service / machine identities (already separate — must stay separate)

| Identity | Secret env var | Verifier | Transport | Fail mode |
|---|---|---|---|---|
| Watchtower internal service | `S43_WATCHTOWER_SERVICE_TOKEN` (shared s43-api ↔ s43-core) | `core/monitoring/watchtower.py::_require_service_token` | `Authorization: Bearer` | 503 if unset, 401 otherwise; token never echoed |
| Watchtower `/state/{name}` admin | `S43_ADMIN_TOKEN` (**on top of** the service token) | `_require_admin_token` | `X-S43-Admin-Token` header | 401 if unset/mismatch |
| Fenrir → API | `S43_FENRIR_API_TOKEN` | `core/api/main.py::_require_fenrir_service_token` | `Authorization: Bearer` | 503 if unset, 401 otherwise |
| Sparta node API | `S43_SPARTA_NODE_TOKEN` | `core/monitoring/Sparta_core.py` | `Authorization: Bearer` + body credential | fail closed if unset |
| Remote gateway operators | `SENTINEL_REMOTE_TOKEN_{OWNER,ADMIN,AUDITOR}` | `core/api/routers/remote_gateway.py::_resolve_operator_role` | `Authorization: Bearer` | **503 if none configured**; role resolved server-side; own `OperatorRole` model (owner/admin/auditor) — separate from the `{operator,admin}` API roles |

**None of these accept a human operator JWT.** `_require_fenrir_service_token`
was specifically changed (Pass 1, F-06) to stop requiring operator auth. The
redesign **must not** issue human session tokens to any of these, and must not
let a human token satisfy any of these verifiers.

### 1.6 Dead / legacy

`core/s34_auth/*` (14 files: `manager.py`, `middleware.py`, `dependencies.py`,
`fenrir_auth.py`, `s34_seckey.py`, `hashing.py`, `models.py`, `ledger.py`,
`extract_token.py`, `globals.py`, `constants.py`, `exceptions.py`,
`watchtower.py`, `__init_.py`) — **no live importers** (only referenced in
comments/docstrings). `s34_auth/watchtower.py` `NameError`s on import.
Classified UNKNOWN→DEAD; excluded from the redesign; deletion is a cleanup pass.

### 1.7 Browser (dashboard)

`dashboard/assets/js/auth.js` v1.6.0:
- JWT → `sessionStorage["SENTINEL_JWT"]` (survives reload within the tab).
- Password → **module-scope JS variable only** (`_sessionPassword`), never
  persisted. Cleared on reload / navigation / tab close / logout / auth
  failure. ⇒ **every page reload forces a fresh login** ("a token surviving a
  refresh has no matching in-memory password and cannot drive any protected
  route", auth.js).
- Every `fetch` (`dashboard.js::_authHeaders`): `Authorization: Bearer <jwt>`
  + `X-S43-Password: <password>`.
- `websocket.js`: first frame `{token, password}`.
- `GET /auth/verify` was neutered in v1.6.0 (stored-token verification
  removed — pointless without the in-memory password).

### 1.8 Tests that encode the contract

`test_auth_login.py`, `test_jwt_auth.py` (canonical `verify_jwt_token`),
`test_v1_auth.py`, `test_ws_auth.py`, `test_users_admin.py`,
`test_bootstrap_isolated.py`, `test_login_throttle.py`,
`test_password_verification.py`, `test_internal_broadcast_auth.py`,
`test_actions_test_inject_auth.py`, `test_watchtower_service_auth.py`,
`test_watchtower_bridge_auth.py`.

---

## 2. Wire contract today (deliverable D)

| What | Sent on | Header/frame | Reusable? | Persisted client-side? |
|---|---|---|---|---|
| Access JWT | every protected HTTP request; WS auth frame | `Authorization: Bearer` / `payload.token` | yes, for 8 h | `sessionStorage` (browser) |
| Operator password | **every** protected HTTP request; WS auth frame | `X-S43-Password` / `payload.password` | **yes — the actual reusable password, every request** | JS memory only (browser); N/A for CLI |
| Watchtower service token | s43-api ↔ s43-core calls | `Authorization: Bearer` | yes (shared secret) | env |
| Fenrir token | Fenrir → API | `Authorization: Bearer` | yes | env |
| cookies | — | none used anywhere | — | — |
| query-string credentials | — | **none** (good) | — | — |

**Application-message plaintext credential:** YES — `X-S43-Password` carries
the reusable operator password in every protected request and in the WS auth
frame.

**On-network plaintext:** **cannot be asserted from the repo.** No TLS
termination is configured in `docker-compose.yml`, the Dockerfile, or
`deploy/kubernetes/base/*` (the `beta` overlay adds an Ingress but TLS is the
operator's responsibility, flagged in `docs/security/trusted_proxy_handling.md`
and the k8s README). If a deployment runs the API without TLS in front, the
password is on the wire in cleartext. If TLS terminates at an ingress, it is
not — but see the cost below regardless.

**Cost of repeatedly transmitting a reusable password even under TLS:**
1. The browser must hold the plaintext password in JS memory for the entire
   session → an XSS payload exfiltrates the **password**, not just a
   time-boxed token.
2. Every request re-exposes it to: reverse-proxy access/error logs if
   `X-S43-Password` isn't in a redaction list; APM/tracing; the app's own
   exception handlers; the `/events/proxy` `raw` rebroadcast
   (RELEASE_FINDINGS #19); any future request-logging middleware.
3. It is verified with Argon2 on **every** protected request (Pass 3 bounded
   the cost — off-loop, ≤ pool size — but it still couples request latency to
   the hash and lets an authenticated attacker drive hash work).
4. It forces a full re-login on every browser reload (bad UX; no worse
   security, but it trains nothing useful).

---

## 3. Recommended target architecture (deliverable F)

**Model B — short-lived access token + server-side refresh session.** One new
table. No Redis required. Reuses the existing stateless `verify_jwt_token`
for the request hot path. Removes `X-S43-Password` entirely at the end of the
migration.

### 3.1 Shape

```
POST /auth/login {username, password}
  -> validate credentials (unchanged: Argon2 DB path + throttle)
  -> create a session row  (sid, user_id, refresh_hash, issued_at, expires_at, ...)
  -> return:
       body:  { access_token, token_type:"bearer", expires_in:900, subject, role }
       Set-Cookie: s43_refresh=<opaque>; HttpOnly; Secure; SameSite=Strict; Path=/auth; Max-Age=<refresh ttl>

<access token>  = HS256 JWT, 15 min, claims: sub, user_id, role, iss, aud, iat, exp, jti, sid
                  (NO password, NO refresh token, NO other secret in claims)

every protected HTTP request
  -> verify_jwt_token(bearer)    sig + claims + iss/aud + role   (stateless, fast — unchanged core)
  -> [migration Phase E] NOTHING ELSE.  X-S43-Password gone.
  -> require_admin still does its live DB role/active check (unchanged, Pass 1)

POST /auth/refresh   (cookie sent automatically; CSRF header required)
  -> look up session by cookie value hash; check not expired / not revoked; check user.is_active
  -> rotate: new refresh value, new sid-bound access token; update session row (refresh_hash, last_seen)
  -> 401 + clear cookie on any failure

POST /auth/logout    (cookie + CSRF header)
  -> delete the session row; Set-Cookie: s43_refresh=; Max-Age=0

GET /auth/verify     -> keep as a cheap "is this access token still structurally valid" check for the UI
```

### 3.2 The `sessions` table (deliverable O — REQUIRED for model B)

```
sessions(
  sid            uuid       primary key,
  user_id        uuid       not null references users(user_id) on delete cascade,
  refresh_hash   text       not null,        -- sha-256 of the opaque refresh value; never store the value
  issued_at      timestamptz not null default now(),
  last_seen_at   timestamptz not null default now(),
  expires_at     timestamptz not null,       -- absolute cap (e.g. issued_at + 7d)
  revoked_at     timestamptz,                -- null = live
  client_ip      inet,                       -- trustworthy post-Pass-2; for the operator's own session list
  user_agent     text                        -- truncated
)
index sessions(user_id) where revoked_at is null
index sessions(expires_at)
```

Refresh token = a 256-bit random opaque string (not a JWT). Stored only as
`sha-256(value)`. Sliding: each successful `/auth/refresh` issues a new value
+ new `refresh_hash`, bumps `last_seen_at`, keeps the same `sid`, keeps
`expires_at` (absolute cap). Reuse of a superseded refresh value ⇒ treat as
theft: revoke the whole session (`revoked_at = now`) and 401.

### 3.3 Access-token validation stays mostly stateless

The hot path (`verify_jwt_token`) stays signature + claims only — **no DB read
per request**. Revocation of a *still-unexpired access token* is bounded to
≤ 15 min for routes that trust the `role` claim. That is an explicit,
documented trade (see `AUTH_THREAT_MODEL_PASS4.md` §Revocation). Immediate
revocation exists for: the refresh path (session row gone), `/users`
(`require_admin` live DB check — unchanged), and any route we choose to add a
`sid`-liveness check to.

Optional hardening (NOT required): a per-replica in-memory LRU of
recently-revoked `sid`s, populated by `/auth/logout` and by a short
(e.g. 30 s) poll of `sessions WHERE revoked_at > now()-1m`, checked in
`verify_jwt_token`. Bounds access-token revocation to ≤ poll interval at the
cost of one small periodic query. Deferred — decide in Pass 5 with load data.

### 3.4 Signing key

Keep **HS256 + `S43_JWT_SECRET`** for now — the whole stack (main.py, WS,
`/v1`, `verify_jwt_token`) is HS256, and every replica already shares the
secret. Add a `kid` header + a 2-entry keyring (`S43_JWT_SECRET` +
`S43_JWT_SECRET_PREVIOUS`) so a secret rotation doesn't invalidate every live
session at once: sign with the current key, accept either. Moving to an
asymmetric algorithm (EdDSA/RS256, so verifiers don't hold the signing key)
is a **separate** improvement — flagged, not required by this redesign.

### 3.5 What does NOT change

- `verify_jwt_token`'s core (sig + `require ["sub","exp","iss","aud"]` + iss/aud
  + role ∈ `{operator,admin}`) — extended to also require `jti`/`sid` on
  new-style tokens, still no leeway (add a small ±30 s `nbf`/`iat` leeway for
  multi-replica clock skew — see threat model).
- `require_admin`'s live DB role/active check (Pass 1).
- The `{operator, admin}` role model — no new roles (deliverable §17).
- Every service-identity verifier (§1.5) — untouched.
- Argon2id password hashing (Pass 3) — untouched.
- The Pass 3 login throttle — extended (see §14 / migration).

---

## 4. Human vs service identity separation (deliverable I)

| | Human operator | Service identity |
|---|---|---|
| Credential | username + password ⇒ access JWT (`aud=sentinel-43-dashboard`) + refresh session cookie | long-lived shared secret in an env var |
| Verifier | `verify_jwt_token` (+ session for refresh) | `_require_service_token` / `_require_fenrir_service_token` / `_require_admin_token` / remote-gateway resolver |
| Audience | `sentinel-43-dashboard` (human) | N/A — opaque bearer, not a JWT |
| Roles | `operator`, `admin` | fixed per token (Watchtower service = "trusted internal"; remote gateway = owner/admin/auditor) |
| Rotation | password change ⇒ session-wide revoke; secret rotation ⇒ keyring | operator rotates the env var + restarts / re-rolls |
| Revocation | logout / disablement / role change (bounded, §3.3) | remove/blank the env var + restart |
| Logging | login/logout/refresh/failure events, redacted | auth-failure events, token never logged |

**Enforced boundary:** a human access JWT has `aud=sentinel-43-dashboard` and
is only accepted by `verify_jwt_token`. The service verifiers do a
constant-time compare against a specific env secret and never call
`verify_jwt_token`. The redesign adds no code path where a human token
satisfies a service verifier or vice-versa. New: assert this with tests
(`AUTH_TEST_SPEC_PASS4.md` §Migration — "service identities unaffected").

---

## 5. Authorization must stay distinct (deliverable §17)

Four concepts asked for: authenticated-user / operator / admin / service.

- **service** — separate tokens, §1.5, unchanged.
- **admin** — `role == "admin"`, checked live against the DB by
  `require_admin` (`/users`); also a token claim used by `/v1` and dashboard.
- **operator** — `role == "operator"` (or admin, which is a superset for
  `require_operator`).
- **authenticated-user with no operator rights** — **Sentinel-43 has no such
  concept today.** Every human account is at least `operator`. `/auth/login`
  issues `role` from the account; the lowest is `operator`.

**Recommendation:** keep `{operator, admin}`. Do **not** add a
"read-only user" / "viewer" tier — no evidence in the code or the findings
that Sentinel-43 needs one. If the dashboard later needs read-only viewers,
that is its own scoped change with its own role.

---

## 6. Persistent / infrastructure impact (deliverable O)

| Item | Classification | Note |
|---|---|---|
| `sessions` table | **REQUIRED** (model B) | additive, non-destructive; needs a real migration mechanism (project has none — `create_all` only) |
| `login_attempts` table (or Redis) for cross-replica throttle | **OPTIONAL** single-replica beta / **REQUIRED** multi-replica | consistent with adding the `sessions` table; upsert `(key, window_start, count)` |
| `users.password_changed_at` | **OPTIONAL** | lets `verify_jwt_token` reject "issued before last password change" without a session read; the session-delete-on-password-change already covers it |
| `users` role CHECK constraint (P3-7) | OPTIONAL, orthogonal | carry from Pass 3 |
| Redis | **NOT REQUIRED** | the shared Postgres is sufficient for sessions + throttle at beta scale; recommend Redis only when session/throttle read volume justifies it |
| Asymmetric signing keys + rotation infra | **NOT REQUIRED** | HS256 + a 2-key `kid` ring is enough; asymmetric is a later, separate improvement |
| CSRF-token infrastructure | **REQUIRED (small)** | double-submit cookie/header pair for `/auth/refresh` + `/auth/logout` |

**No schema change is made in Pass 4 or Pass 5 without a separate migration
authorization** (mission §20, §26). The `sessions` table is the one hard
migration dependency of the recommended design and is called out as a STOP
point in `AUTH_MIGRATION_PASS4.md`.

---

## 7. Open questions (deliverable T)

1. **TLS posture** — does every real deployment terminate TLS in front of the
   API? If not, the on-wire exposure is real *today* and is a higher priority
   than the redesign. (Operator input; also a Pass 6 item.)
2. **#11 env operator** — remove entirely, or keep as a hardened break-glass?
   Needs operator sign-off (the deployed `.env` sets it). See
   `AUTH_MIGRATION_PASS4.md` §#11.
3. **Access-token TTL** — 15 min proposed. Shorter (5 min) = tighter
   revocation window, more `/auth/refresh` traffic. Decide with the session
   table's read cost.
4. **Immediate access-token revocation** — accept the ≤ TTL window, or add
   the `sid`-revocation poll/LRU (§3.3)? Decide in Pass 5 with load data.
5. **Multi-replica deployment** — is it in scope for beta? Drives whether the
   throttle table / Redis is required now.
6. **CLI consumers** — are there any? None found in the repo. If an operator
   CLI is planned, it needs a device-code or PAT flow (not username+password
   on every call). Recorded UNKNOWN.
7. **`GET /auth/verify`** — keep, or fold into `/auth/refresh`? Low stakes.
8. **Dashboard hosting** — is the dashboard always same-origin with the API
   (it is served by the API today at `/dashboard`)? If it can be served
   cross-origin, the cookie `SameSite`/CORS story needs revisiting.

---

## 8. What Pass 4 did NOT do

No code path, env var, schema, migration, JWT claim, route, header contract,
frontend behaviour, or dependency was changed. Only these five documents were
added. Every Pass 1/2/3 security invariant remains authoritative and
un-touched; no auth finding is marked resolved on the basis of this design
(mission §25).
