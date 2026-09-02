# SESSION_MODEL_PASS5A.md

Sentinel-43 — Pass 5A: the authentication foundation implemented in this pass.
Application-level session domain model, token-claim extension, refresh
cryptographic primitives, refresh/rotation/reuse/logout service logic, and
CSRF primitives — **built, tested, and NOT wired into any live request
path.** Legacy auth (Bearer JWT + `X-S43-Password`) is unchanged.

Reference design: `AUTH_ARCHITECTURE_PASS4.md` "Model B". This document
records what Pass 5A actually landed and how it was validated.

Code state: integration branch `integration/beta-hardening-20260901`.
New/changed files:

| File | Change |
|---|---|
| `core/auth/sessions.py` | **new** — session model + all foundation primitives/logic |
| `core/api/routers/auth.py` | `_issue_token()` gains keyword-only `sid`/`jti`; `verify_jwt_token()` shape-checks `sid`/`jti` when present; `token_is_session_bound()` helper added |
| `core/tests/test_session_primitives.py` | **new** — 25 in-process tests |
| `core/tests/test_session_layer_pg.py` | **new** — 17 disposable-PostgreSQL tests |
| `core/tests/test_service_identity_separation.py` | **new** — 12 human/service boundary tests |
| `AUTH_TLS_POSTURE_PASS5A.md` | **new** — Section 4 deliverable |

---

## 1. Non-goals for Pass 5A (explicit)

Not done, by authorization (mission Pass 5A §6, §14, §19–§21, §30):

- No `sessions` table in repository migration state / production bootstrap.
- No Alembic or migration runner infrastructure added.
- No route calls any function in `core/auth/sessions.py`. `/auth/login`,
  `/auth/verify`, `require_operator`, `require_admin`, the WebSocket handler,
  and every service verifier are byte-for-byte behaviourally unchanged.
- `X-S43-Password` is **not** removed and legacy tokens are **not** rejected.
- No `sid` liveness lookup / per-replica LRU on the request hot path.
- No WebSocket contract change.
- No `.env` contract change (one *optional*, default-off var is documented
  below but not required and not in any example file).
- No `#11` env-operator change.

---

## 2. Access-token claim model (backward compatible)

### 2.1 What changed

`_issue_token(subject, role="operator", user_id=None, *, sid=None, jti=None)`.

- **`sid is None`** (every caller today, including `/auth/login`): payload is
  exactly what it was — `{sub, username, iss, aud, iat, nbf, exp, role}` plus
  `user_id` for DB accounts. **No `sid`, no `jti`.** Verified byte-shape-identical
  in `test_session_primitives.py::test_legacy_issuance_is_byte_identical_shape`.
- **`sid` supplied** (a server-side session id, canonical UUID): the token
  becomes *session-bound* — gains `sid` and a `jti` (generated with
  `secrets.token_urlsafe(16)` unless a well-formed one is passed). A malformed
  `sid` raises 500 at issue time (never mint a bad session id into a token).

### 2.2 `verify_jwt_token()` — tolerant, never requiring

Unchanged core: signature, `require ["sub","exp","iss","aud"]`, `iss`/`aud`
match, `role ∈ {operator, admin}`, no clock leeway.

Added: **if** a token carries `sid` or `jti`, each must be a well-formed
string (`sid` = UUID shape, `jti` = `^[A-Za-z0-9_-]{1,128}$`); a malformed
value → 401 (a crafted/corrupt token, fail closed). **Neither is required** —
a legacy token carrying neither verifies exactly as before. No sessions-table
read happens here (mission §6).

### 2.3 The new-vs-legacy discriminator

`token_is_session_bound(claims)` (router) / `claims_are_session_bound(claims)`
(sessions module) — both return `True` iff a **well-formed `sid`** is present.
This is an *explicit issuer-set* signal, never inferred from timing or overall
shape. `jti` alone does **not** make a token session-bound (`sid` is the
discriminator). Both helpers never raise.

### 2.4 Why this is safe to land now

- Nothing calls `_issue_token(..., sid=...)` yet, so no token in the wild
  changes.
- `verify_jwt_token` gains only stricter rejection of a claim shape that no
  current token uses.
- Confirmed no regression: `test_jwt_auth.py`, `test_v1_auth.py`,
  `test_ws_auth.py`, `test_auth_login.py` (56 + N) all pass unchanged; the
  13/13 security-invariant script passes.

---

## 3. Session domain model

### 3.1 `SessionRecord` (SQLAlchemy) — on a **separate** `Base`

`core/auth/sessions.py` defines `class SessionBase(DeclarativeBase)` and
`class SessionRecord(SessionBase)`. **It does not use
`core.auth.users.Base`.** Consequence:
`core.auth.users.init_models()` → `users.Base.metadata.create_all` still
creates **only `users`**. The sessions table therefore does not enter
production DB bootstrap in this pass (mission §14). Verified: `init_models`
source unchanged; `SessionBase.metadata.tables == {"sessions"}`.

Columns:

| column | type | notes |
|---|---|---|
| `sid` | `Uuid` PK | client-side `uuid4` default, mirrors `User.user_id` |
| `user_id` | `Uuid` not null, indexed | logical FK to `users.user_id` (real `REFERENCES … ON DELETE CASCADE` is in the production DDL, §SESSION_MIGRATION_DECISION) |
| `refresh_hash` | `String(64)` not null, **unique**, indexed | SHA-256 hex of the current refresh secret |
| `prev_refresh_hash` | `String(64)` null, indexed | SHA-256 hex of the single immediately-superseded secret — powers one-step reuse detection |
| `refresh_generation` | `Integer` not null default 0 | increments on each rotation |
| `issued_at` | `timestamptz` not null | |
| `last_seen_at` | `timestamptz` not null | bumped on rotation |
| `rotated_at` | `timestamptz` null | last rotation time |
| `expires_at` | `timestamptz` not null | absolute cap; rotation never extends it |
| `revoked_at` | `timestamptz` null | null = live |
| `revoked_reason` | `String(64)` null | `logout` / `refresh_reuse` / `owner_inactive` / `password_change` / `disabled` / … |
| `client_ip` | `String(45)` null | for the operator's own "active sessions" list (trustworthy post-Pass-2) |
| `user_agent` | `String(256)` null | truncated |

`SessionRecord.is_live(now=…)` = `revoked_at is None and expires_at > now`.

### 3.2 `SessionView` (frozen dataclass) — the read model

`SessionView.of(row)` projects a `SessionRecord` to an immutable view with
**no hash fields** — for surfacing a session to its owner without leaking the
verifier. `test_...::test_create_then_commit...` asserts `SessionView` has no
`refresh_hash` attribute.

### 3.3 Entropy & verifier construction (mission §7 — "document the assumptions")

- **Refresh secret**: `secrets.token_urlsafe(32)` → **256 bits** from
  `os.urandom`, uniformly random, opaque, *not a JWT*.
- **Stored verifier**: a single `SHA-256` (hex) of that value, compared with
  `hmac.compare_digest` (constant time).
- **Why SHA-256 and not Argon2/bcrypt/PBKDF2 or a per-row salt**: those
  defend *low-entropy human secrets* against offline guessing. A 256-bit
  CSPRNG value has no dictionary and no precomputable table, so a slow KDF or
  a salt buys nothing. A stolen DB dump yields only SHA-256 digests; the
  256-bit pre-images are unrecoverable. This is the standard construction for
  opaque session/refresh tokens.
- **Optional future hardening (NOT in Pass 5A)**: `S43_SESSION_HASH_PEPPER` —
  if set, the verifier becomes `HMAC-SHA256(pepper, secret)`, so a DB dump
  alone cannot be replayed against another deployment. The code funnels
  through one `_digest()` function and already honours this var if present;
  it is undocumented in `.env.example` and defaults to plain SHA-256. A
  deployment pass can decide to require it. `test_...::test_optional_pepper_
  changes_the_digest` covers it.

### 3.4 CSRF primitives

- `generate_csrf_token()` = `secrets.token_urlsafe(32)` (256-bit).
- `csrf_tokens_match(cookie_value, header_value)` = constant-time equality,
  **fails closed** if either half is missing/empty.

Double-submit only; nothing sets or checks a CSRF cookie in a live path in
Pass 5A. Intended wiring (Pass 5B): `/auth/refresh` and `/auth/logout` require
`cookie[csrf] == header[X-S43-CSRF]`.

---

## 4. Refresh / rotation / reuse / logout service logic

All in `core/auth/sessions.py`. **Transaction ownership: none of these
commit.** They validate, mutate ORM state, `flush()`. The caller (a future
`/auth/*` route) commits on success / rolls back on failure — the same
contract Pass 3 set for `core/auth/users.py`.

### 4.1 `create_session(session, *, user_id, refresh_secret, client_ip=None, user_agent=None, ttl_seconds=None, now=None) -> SessionRecord`

`refresh_generation=0`, `expires_at = now + ttl` (`ttl` defaults to
`refresh_ttl_seconds()` = env `S43_SESSION_REFRESH_TTL_SECONDS`, default 7d,
clamped 5 min .. 30 d). Stores only `hash_refresh_secret(refresh_secret)`.
Flush, no commit.

### 4.2 `rotate_refresh(session, *, presented_secret, new_refresh_secret, now=None) -> (SessionRecord, RefreshOutcome.ROTATED)`

The single source of truth for refresh semantics. Ordered, all fail closed:

1. Locate + **row-lock** (`SELECT … FOR UPDATE`) the session whose
   `refresh_hash` **or** `prev_refresh_hash` equals `sha256(presented)`.
2. No match → `RefreshInvalidError`.
3. Matched the **previous** generation (not current) → **revoke the session**
   (`revoked_reason="refresh_reuse"`), flush, `RefreshReuseError(sid)`.
4. Session already revoked → `SessionRevokedError(sid)`.
5. `expires_at <= now` → `SessionExpiredError(sid)`.
6. Owning `users` row is `is_active = False` → **revoke the session**
   (`revoked_reason="owner_inactive"`), flush, `SessionOwnerInactiveError(sid)`.
7. Otherwise rotate: `prev_refresh_hash ← refresh_hash`,
   `refresh_hash ← sha256(new)`, `refresh_generation += 1`,
   `last_seen_at = rotated_at = now`. Flush. Return `(row, ROTATED)`.

**Caller contract on branches 3 & 6**: the revocation is *flushed but not
committed* — the route MUST `commit()` before returning 401 or the
theft/disablement response is lost. Branches 2/4/5 make no writes.

### 4.3 `revoke_session(session, sid, *, reason, now=None) -> bool`

Row-locked, **idempotent** (revoking an absent or already-revoked session →
`False`, no error). `True` iff this call transitioned live→revoked.

### 4.4 `revoke_all_user_sessions(session, user_id, *, reason, now=None) -> int`

Row-locks and revokes every live session for a user (the Pass 5B hook for
password change / disablement / role change). Returns count newly revoked.
Idempotent.

### 4.5 `logout_by_refresh(session, *, presented_secret, now=None) -> bool`

Row-locks the session matching the current **or** superseded generation and
revokes it (`reason="logout"`). **Idempotent** — unknown/garbage/already-revoked
credential → `False`, never raises. So a double logout, or a logout after the
cookie expired, is a clean 2xx at the route layer.

### 4.6 `purge_expired_sessions(session, *, older_than=None, now=None) -> int`

Housekeeping: hard-deletes rows past `expires_at` (revoked-but-unexpired rows
are kept for audit until they too expire). Not wired to any scheduler.

### 4.7 `get_session_by_sid(session, sid, *, for_update=False)`

Direct lookup by id, optionally `FOR UPDATE`.

---

## 5. Concurrency correctness (mission §16) — proven on PostgreSQL 16.3

`core/tests/test_session_layer_pg.py`, disposable `postgres:16.3` container
(`--rm --tmpfs`, `127.0.0.1:55433`, torn down). Default isolation **READ
COMMITTED**. The argument relies only on `SELECT … FOR UPDATE` blocking a
second writer until the first commits, plus READ COMMITTED re-evaluating the
lock predicate against the newest committed row version (PostgreSQL
EvalPlanQual) — **not** SERIALIZABLE.

| Scenario | Test | Result |
|---|---|---|
| Two (and 5) concurrent refreshes, same credential | `test_two_concurrent_refreshes_yield_exactly_one_successor` | exactly **one** `ROTATED` (generation → 1), the loser(s) get `RefreshReuseError`, session ends `revoked_reason="refresh_reuse"`. **Never >1 successor generation.** |
| Refresh racing logout | `test_refresh_racing_logout_never_issues_after_logout` | whichever wins, session ends revoked and no live successor credential exists |
| Refresh racing account disablement | `test_refresh_racing_disablement` | after the race, account disabled + `revoke_all_user_sessions` → no session may refresh |
| Repeated logout | `test_repeated_logout_is_clean` | first call `True`, all subsequent `False`, no error |
| Expiration around the boundary | `test_expiration_racing_refresh_is_atomic` | outcome is exactly `{rotated, gen 1}` **or** `{SessionExpiredError, gen 0}` — never a torn row |
| Single-step reuse | `test_reusing_superseded_secret_revokes_the_session` | replaying gen-0 after one rotation → `RefreshReuseError` + whole session revoked; even the legit current secret then fails |
| `refresh_hash` uniqueness | `test_refresh_hash_is_unique` | duplicate hash → `IntegrityError` at flush |
| Transaction ownership | `test_create_session_does_not_commit`, `test_create_then_commit_persists…` | helper flush-only; caller commit required for persistence |

Full: **17 passed** (`test_session_layer_pg.py`), **25 passed**
(`test_session_primitives.py`), **12 passed**
(`test_service_identity_separation.py`).

---

## 6. Account state ↔ session behaviour (mission §17, §18)

- **Disablement** (`users.is_active = False`): `rotate_refresh` step 6 refuses
  and revokes the session. The Pass 5B route wiring also calls
  `revoke_all_user_sessions(user_id, reason="disabled")` when an admin
  disables an account (helper exists; not wired here). Covered:
  `test_disabled_owner_cannot_refresh_and_session_is_revoked`.
- **Password change**: Pass 5B wires
  `revoke_all_user_sessions(user_id, reason="password_change")` into
  `reset_account_password`. Helper exists; not wired. (Design note: this makes
  "session-delete-on-password-change" the revocation mechanism, so a
  `users.password_changed_at` column is **not** required — consistent with
  `AUTH_ARCHITECTURE_PASS4.md` §6.)
- **Role change**: the access token's `role` claim is trusted for ≤ its TTL
  (15 min target) on stateless routes — an explicit, documented trade
  (`AUTH_THREAT_MODEL_PASS4.md`). `require_admin` already does a **live** DB
  role check on `/users` (Pass 1, unchanged). Pass 5B additionally calls
  `revoke_all_user_sessions(user_id, reason="role_change")` on role changes so
  the next refresh mints a token with the new role. Not wired in Pass 5A.

Pass 5A does **not** change `core/auth/users.py` behaviour or
`core/api/routers/users.py` — only adds the (unused) revoke helper it will
call later.

---

## 7. Human vs service identity boundary (mission §22)

`core/tests/test_service_identity_separation.py` pins the boundary the
redesign must never erode:

- A human access JWT (operator **or** admin, plain **or** session-bound) →
  `_require_service_token` (Watchtower), `_require_fenrir_service_token`
  (API), `_require_admin_token` (Watchtower) all **401**.
- A refresh credential → not a JWT → `verify_jwt_token` **401**; → service
  verifiers **401**.
- A service shared-secret token → `verify_jwt_token` **401**; →
  `_validate_env_credentials` **401**; cannot be `sid` (`claims_are_session_bound`
  **False**); its hash never collides with a real session's.
- Guard rail: the service verifiers' source contains no `verify_jwt_token` /
  `_issue_token` reference and does use `compare_digest`.
- Sanity: a service verifier still **accepts its own** token (boundary, not
  blanket deny).

---

## 8. Fail-closed / redaction review of the new code (mission §23, §24)

- Every predicate primitive (`verify_refresh_hash`, `csrf_tokens_match`,
  `claims_are_session_bound`, `token_is_session_bound`) returns `False` /
  raises `ValueError` on malformed input — never silently "passes".
- `rotate_refresh` raises a typed `SessionError` subclass on every non-happy
  path; there is no code path that returns a rotated token without passing
  all six checks.
- The opaque refresh secret is **never** stored, logged, or placed in an
  exception message. `SessionError` messages carry only the `sid` (a random
  UUID, not a secret). `RefreshReuseError`/`SessionExpiredError`/
  `SessionRevokedError`/`SessionOwnerInactiveError` expose `.sid` for the
  route to log an audit event; they do not carry the credential.
- `SessionView` (the only object intended to reach a response body) has no
  hash field.
- `client_ip` / `user_agent` are truncated (45 / 256) before store.

---

## 9. TLS dependency (mission §4)

`AUTH_TLS_POSTURE_PASS5A.md` records **blocking finding F-TLS-1**: repository
evidence does not establish a secure production TLS posture. The refresh
cookie spec is therefore issued **`Secure`-unconditional** (never
scheme-derived — §4 of that doc shows the app has no trustworthy scheme
signal). This foundation is **not** production-ready until F-TLS-1 is
resolved; that gates Phase B+ of the `X-S43-Password` retirement.
