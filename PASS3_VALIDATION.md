# Sentinel-43 — Pass 3 Validation

Account transaction ownership · bootstrap concurrency · auth hardening.
Exact commands and outcomes. Companion to `RELEASE_FINDINGS.md`,
`PASS1_VALIDATION.md`, `PASS2_VALIDATION.md`.

## Starting state (verified before any change)

| Item | Value |
|---|---|
| Work clone / branch | `C:\Users\heero\Sentinel-43-work` · `integration/beta-hardening-20260901` |
| HEAD at start | `ca328ea` (Pass 2 handoff); validated Pass 2 code state `f245cf3` |
| `git status` | clean · `git fsck --full` 0 errors |
| merge-base with `origin/main` | `8d2b80f` (== `origin/main`) · `f245cf3` is an ancestor of HEAD |
| Original OneDrive repo | HEAD `e859b61`, `## main...origin/main [ahead 1]`, unchanged (re-checked at end) |

## Disposable PostgreSQL (never the live stack)

```
docker run -d --rm --name s43pass3_pgtest --tmpfs /var/lib/postgresql/data \
  -e POSTGRES_PASSWORD=pass3_throwaway -e POSTGRES_DB=s43pass3 -e POSTGRES_USER=s43t \
  -p 127.0.0.1:55432:5432 postgres:16.3
```
- PostgreSQL **16.3** (Debian). `--rm` + `--tmpfs` ⇒ nothing persisted, removed on stop.
- Bound to `127.0.0.1:55432` only. Distinct name / port / volume from every `s43_*`.
- DSN for the tests: `postgresql+asyncpg://s43t:pass3_throwaway@127.0.0.1:55432/s43pass3`
  (asyncpg 0.31.0). Torn down at the end of the pass.
- The s43 Compose stack was **down** throughout Pass 3 and was not touched.

## C. Account / auth call graph

```
POST /auth/login
  -> _login_check_throttled(username)            # 429 if locked, BEFORE any hashing
  -> _validate_credentials(username, password)
       async with get_sessionmaker()() as session:          # owns the session
         authenticate_user(session, u, p)                    # READ ONLY: SELECT + off-loop Argon2 verify
         if user: record_login(session, user); session.commit()   # the ONLY write on this path
       else: _validate_env_credentials(u, p)                 # SHA-256, no DB  (finding #11)
  -> _issue_token(...)                                       # no DB
  -> _login_clear(username)   (on success)  /  _login_record_failure  (on 401)

every protected HTTP request
  -> require_operator / require_admin / _get_operator
       verify_jwt_token(token)                               # HMAC, cheap
       reverify_password(subject, X-S43-Password)
         async with get_sessionmaker()() as session:         # own short-lived session
           authenticate_user(session, subject, pw)           # READ ONLY: SELECT + off-loop verify. NO write.
         else _validate_env_credentials                      # SHA-256 fallback
     require_admin additionally: get_user_by_username(get_db_session, subject)  # admin role from live DB

POST /bootstrap/admin
  -> init_models()                                           # CREATE TABLE IF NOT EXISTS (own txn)
  -> create_first_admin(get_db_session, ...)                 # advisory lock -> count==0 -> create_user (flush)
       (raises FirstAdminExistsError / UsernameTakenError -> 409)
  -> session.commit()                                        # route owns the commit; lock released here

POST /users            -> create_user (flush)          -> session.commit()   [IntegrityError -> 409, rollback]
GET  /users            -> list_users                   -> (read only)
PATCH /users/{id}      -> [advisory lock if admin-count-moving] -> _would_orphan_admins
                          -> set_user_role (flush) + set_user_active (flush)  -> session.commit()   (ONE txn)
POST /users/{id}/pw    -> set_user_password (flush)     -> session.commit()
```

## D. Transaction-ownership map (after Pass 3)

| Helper (`core/auth/users.py`) | commits? | flushes? | rolls back? | mutates ORM? | can partial-persist? | hashes? | writes last_login_at? |
|---|---|---|---|---|---|---|---|
| `create_user` | **no** | yes | no | yes (`add`) | no | yes (off-loop) | no |
| `create_first_admin` | **no** | via create_user | no | yes | no | via create_user | no |
| `authenticate_user` | **no** | **no** | no | **no** | no | verify only (off-loop) | **no** |
| `record_login` | **no** | yes | no | yes | no | no | **yes** |
| `set_user_active` / `set_user_role` | **no** | yes | no | yes | no | no | no |
| `set_user_password` | **no** | yes | no | yes | no | yes (off-loop) | no |
| `count_active_admins` / `get_user_by_*` / `list_users` | no | no | no | no | no | no | no |
| `_pg_advisory_xact_lock` | no | no | no | no | no | no | no |

Commit points: `POST /bootstrap/admin`, `POST /users`, `PATCH /users/{id}`,
`POST /users/{id}/password`, `_validate_credentials` (login only).
Rollback: `core/auth/deps.py::get_db_session` on any exception through `yield`.

## E. `update_last_login=False` / read-only auth analysis

- The `update_last_login` parameter is **removed**. `authenticate_user()` has
  no write path on any branch — it does `get_user_by_username` (SELECT) +
  `verify_password_async` (Argon2 in a thread) and returns the row or `None`.
- `test_password_verification.py`: `test_authenticate_user_success_is_read_only`
  / `_wrong_password` / `_unknown_account` / `_disabled_account` all assert the
  recording session saw `(commits, flushes, rollbacks) == (0, 0, 0)` and
  `last_login_at is None`.
- `record_login()` is the only writer; only `_validate_credentials` (POST
  /auth/login) calls it, and it commits. `reverify_password()` calls
  `authenticate_user()` only.
- Argon2 **rehash**: there is **no `check_needs_rehash` logic anywhere in the
  codebase** — the intended contract is "no rehash". Pass 3 does not add one
  (it would put a write on the login path and the params are the argon2-cffi
  defaults, unchanged). Documented, not changed. If added later it belongs in
  `record_login()` (already the login-only writer).

## F. First-admin race — reproduction

Faithful copy of the pre-fix `bootstrap_admin` body, 8 contenders, each on its
own `AsyncSession` (independent asyncpg connection), released together:

```
  admin0..admin6: CREATED
  admin7: 409 (already initialized)
  contenders=8  CREATED responses=7  active admins in DB=7
  RACE REPRODUCED: True
```

With the fix (`create_first_admin` + `ADMIN_INVARIANT_LOCK_KEY`):

```
  first-admin: 8 contenders -> CREATED=1 409=7  active admins in DB=1
  last-admin: 2 concurrent demotions -> ['409-last-admin', 'DEMOTED']  admins remaining=1
```

In the suite: `test_account_transactions_pg.py::
test_first_admin_created_exactly_once_under_concurrency[2|8|20]` — `created`
count == 1 and `count_active_admins() == 1` for every contender count.

## G. Serialization candidates evaluated

| Candidate | Cross-process | Cross-replica | Crash behavior | Migration | Notes |
|---|---|---|---|---|---|
| count-then-create + in-process `threading.Lock` | ✗ | ✗ | n/a | none | the status quo — does not serialize independent workers |
| **PostgreSQL transaction advisory lock (`pg_advisory_xact_lock`)** | ✓ | ✓ | auto-released on backend disconnect / txn end | **none** | **chosen.** Transient, keyed on a fixed bigint. Verified released on ROLLBACK (`test_advisory_lock_released_on_rollback`). No-ops on non-PostgreSQL so the in-memory test fakes are unaffected. |
| dedicated `bootstrap_lock` row + `SELECT ... FOR UPDATE` | ✓ | ✓ | lock released at txn end | **new table** ⇒ migration | equivalent correctness, heavier; rejected to stay migration-free |
| partial unique index `UNIQUE (role) WHERE role='admin' AND is_active` | ✓ | ✓ | persistent | **new index** ⇒ migration | **rejected — wrong business rule.** Sentinel-43 supports multiple admins (`/users` creates them; `count_active_admins` is a count, not a bound). The invariant is "bootstrap initializes exactly once", not "one admin forever". |
| session-level advisory lock (`pg_advisory_lock`) | ✓ | ✓ | needs explicit unlock / disconnect | none | more footguns than the xact-scoped variant; rejected |

## H. Selected solution

`_pg_advisory_xact_lock(session, ADMIN_INVARIANT_LOCK_KEY)` — a PostgreSQL
transaction-scoped advisory lock (`SELECT pg_advisory_xact_lock(:k)`), key
`0x5334334200000001` (fixed, arbitrary 63-bit). Taken:
- in `create_first_admin()` before `count_active_admins()`, held through the
  INSERT and the route's `commit()` (which releases it);
- in `PATCH /users/{id}` before `_would_orphan_admins()` whenever the change
  can move the active-admin count.

**No schema migration.** `create_all` is untouched. Correct across processes
and replicas (all contenders serialize on the same lock in the same database).
No STOP condition from section 8/24 was triggered.

## I. Role validation

- **Application boundary:** `core/api/routers/users.py::_validate_role()` →
  422 for anything not in `APPROVED_ROLES` (`{"operator","admin"}`);
  `create_user()` / `set_user_role()` raise `ValueError`; `bootstrap_admin`
  hard-codes `role="admin"`.
- **Database:** `role` is `String(32)` `NOT NULL DEFAULT 'operator'` with **no
  CHECK constraint** — a direct SQL insert could store any ≤32-char string.
- Tests (`test_password_verification.py`): `test_create_user_rejects_bad_role`,
  `test_set_user_role_rejects_unknown_variants` (`""`, `"root"`, `"Admin"`,
  `" admin"`, `"operator "`, `"OPERATOR"` — all rejected, no normalization).
- **Recommendation (P3-7, deferred):** `ALTER TABLE users ADD CONSTRAINT
  users_role_check CHECK (role IN ('operator','admin'))` in a future
  migration, after inventorying existing `role` values.

## J. Username / email collision analysis

Current behavior, unchanged by Pass 3:
- `username`: stored `.strip()`ed (routes call `body.username.strip()`),
  **not case-folded**. `unique=True`, PostgreSQL default (case-sensitive)
  collation. `get_user_by_username()` is an exact `==` match.
- `email`: `unique=True`, nullable, stored `.strip()`ed or `None`, exact match.
- ⇒ `Admin`, `admin`, `ADMIN` are three distinct, independently-creatable
  accounts.

If case-insensitive uniqueness were introduced, the **collision class** is:
any existing pair of usernames (or emails) equal after `.strip().lower()`.
This was **not inventoried against live data** (no DB access; forbidden by
mission §22/§23). Pass 3 introduces **no normalization and no new
constraint** (§10). A future change needs: (1) a live-data collision
inventory, (2) a decision (reject-on-collision vs merge), (3) a migration
(`citext` column or a `lower(username)` functional unique index).

## K. Disabled-account behavior

| Path | Disabled account result |
|---|---|
| `POST /auth/login` (correct pw) | `authenticate_user` → `None` → `_validate_env_credentials` → 401 |
| `POST /auth/login` (wrong pw) | 401 (indistinguishable) |
| `reverify_password` on any protected route | `authenticate_user` → `None` → `require_*` → 401 |
| `require_admin` (disabled admin) | `not user.is_active` → 403 even if `reverify_password` somehow passed via env fallback |
| `PATCH /users` deactivating the last active admin | 409 (last-admin guard + advisory lock) |
| `/bootstrap/admin` when 0 active admins remain | reopens (P3-9) — only reachable by direct DB edits; the API's last-admin guard prevents the API from creating that state |

Tests: `test_password_verification.py::test_authenticate_user_disabled_account`;
`test_users_admin.py::test_deactivate_account_blocks_login` /
`test_reactivate_account_restores_login`; existing `test_v1_auth.py` etc.

## L. Password-verification failure behavior

`verify_password()` now returns `False` (fail closed, never raises) for:
`""`, whitespace, `"garbage"`, non-argon2 strings, argon2-shaped-but-corrupt
(`VerificationError`), truncated (`"$argon2id$"`), `None`, `int`, `bytes`;
and for a non-str **password** argument. 15 parametrized cases in
`test_password_verification.py`. A malformed stored credential does not
authenticate and does not crash the request (previously a corrupt-body hash
propagated `VerificationError` into `reverify_password`'s broad `except`,
silently routing to the env-var fallback).

## M. Argon2 rehash behavior

No rehash logic exists or is added (see E). `PasswordHasher()` uses the
argon2-cffi defaults (`t=3, m=65536 KiB, p=4`) — unchanged. Measured on this
machine: hash ≈ 32 ms, verify ≈ 34 ms. Tests do not weaken these params.

## N. Event-loop / offload behavior

- `hash_password_async` / `verify_password_async` = `asyncio.to_thread(...)`
  → the default `ThreadPoolExecutor` (`max_workers = min(32, cpu+4)` — bounded,
  no unbounded thread creation). Exceptions propagate normally; the sync
  `hash_password` / `verify_password` are unchanged for non-async callers.
- `authenticate_user`, `create_user`, `create_first_admin`, `set_user_password`
  use the async variants.
- Test `test_hashing_does_not_block_the_event_loop`: a 1 ms-tick ticker
  coroutine keeps advancing (≥20 ticks) while an Argon2 hash runs — proving
  the loop is not stalled. Without the offload the ticker would freeze ~30 ms.
- Smallest mechanism compatible with the architecture; no worker pool added.

## O. Rate-limit findings

| Endpoint | Before Pass 3 | After Pass 3 |
|---|---|---|
| `POST /auth/login` | firewall per-IP 300/60s only | + per-username sliding-window lockout: `S43_LOGIN_MAX_FAILURES`=10 in `S43_LOGIN_FAIL_WINDOW_SECONDS`=300 ⇒ 429 for `S43_LOGIN_LOCKOUT_SECONDS`=300. In-process (single-replica adequate; Redis for multi-replica — deferred). 429 short-circuits before `_validate_credentials`. |
| `reverify_password` (every protected request) | firewall per-IP only | unchanged — sits behind a valid-JWT gate (cheap HMAC first) and its Argon2 verify is now off-loop. A per-subject throttle here would risk locking out a legit operator on a fat-fingered header; deferred with rationale. |
| `POST /bootstrap/admin` | firewall per-IP + self-gating 409 | + advisory lock serializes contenders; still self-gates to 409 once initialized. No dedicated limiter added (first-run-only endpoint). |
| `/users/*` | firewall per-IP + `require_admin` | unchanged (admin-gated). |

Tests: `test_login_throttle.py` (5 cases).

## P. RELEASE_FINDINGS #11 status

**Investigated; deferred to Pass 4** with a precise exposure statement (see
`RELEASE_FINDINGS.md` #11). The env-var operator path (`_validate_env_credentials`,
SHA-256, un-salted, `S43_OPERATOR_PASSWORD_HASH` in `.env`) is still reachable
as the DB fallback. Pass 3's login throttle raises the online brute-force
cost. Changing the hash scheme is a breaking `.env` change and is entangled
with the Pass 4 question of whether the env operator should exist — not done
here (would enter the Pass 4 redesign, §24 STOP-adjacent).

## Q. RELEASE_FINDINGS #12 status

**RESOLVED.** Reproduced with independent DB connections (7/8 admins pre-fix),
fixed with the transaction advisory lock (1/8 post-fix), regression-tested at
2/8/20 contenders against real PostgreSQL 16.3. The last-admin invariant on
`PATCH /users` uses the same lock and is likewise concurrency-tested.

## R. Files changed

| File | Why |
|---|---|
| `core/auth/users.py` | helpers flush not commit; `authenticate_user` read-only; `verify_password` fail-closed; off-loop `*_async` hashers; dummy-verify timing equaliser; `_pg_advisory_xact_lock`; `create_first_admin`; `record_login`; `AccountError` hierarchy. |
| `core/auth/deps.py` | `get_db_session` rolls back on exception. |
| `core/api/routers/bootstrap.py` | `create_first_admin` + explicit commit; 409 mapping. |
| `core/api/routers/users.py` | explicit commits; advisory lock on admin-count-moving PATCH; single commit for role+active. |
| `core/api/routers/auth.py` | `record_login` on login; read-only reverify; per-username login throttle. |
| `RELEASE_FINDINGS.md` | #10/#11/#12 status; Pass 3 findings P3-1..P3-9. |
| `core/tests/test_account_transactions_pg.py` (new) | DB-backed transaction + concurrency (skipif no `S43_TEST_PG_DSN`). |
| `core/tests/test_password_verification.py` (new) | fail-closed verify, read-only auth, helper flush-not-commit, role validation, off-loop. |
| `core/tests/test_login_throttle.py` (new) | per-username lockout. |
| `core/tests/test_bootstrap_isolated.py`, `test_users_admin.py` | fakes updated for the new transaction boundary. |
| `PASS3_VALIDATION.md`, `HANDOFF_PASS3.md` (new) | this + the handoff. |

## S / T. Tests

Environment: `.venv-pass1`, Python **3.13.5**, pytest **9.1.1**,
fastapi 0.141.1 / starlette 1.6.0 / SQLAlchemy 2.0.52 / **asyncpg 0.31.0** /
argon2-cffi 25.1.0 / anyio 4.14.2. Disposable PostgreSQL **16.3**.
Run env: `S43_WATCHTOWER_URL=http://127.0.0.1:59999`,
`S43_WATCHTOWER_TIMEOUT=0.2`,
`S43_TEST_PG_DSN=postgresql+asyncpg://s43t:…@127.0.0.1:55432/s43pass3`.

Tested commit: **`86c9aab`**.

```
pytest core/tests/ --ignore=core/tests/test_bootstrap.py \
  --ignore=core/tests/test_system_smoke.py -q
```
Collection **300 items** (17 files, 2 ignored).
**300 passed · 0 failed · 0 skipped · 0 xfail · 0 xpass · exit 0** · ~77 s.
5 unique warning locations — unchanged from Pass 1/2 (`HTTP_422` /
testclient-httpx deprecations; pre-existing `core.monitoring.sparta_core`
ImportWarning). No new warnings.

Without `S43_TEST_PG_DSN`: **291 passed, 9 skipped** (the `test_account_
transactions_pg.py` cases) — clean CI behavior with no PostgreSQL.

Per-file (new/changed): `test_account_transactions_pg.py` 9 (PG) / 9 skipped
(no PG) · `test_password_verification.py` 33 · `test_login_throttle.py` 5 ·
`test_bootstrap_isolated.py` 4 · `test_users_admin.py` 25.

Standalone disposable-PostgreSQL evidence (not in the suite): the pre-fix
race reproduction and post-fix verification scripts described in F.

## U. Full regression suite

300 passed / 0 failed / exit 0 at `86c9aab` (above). `test_bootstrap.py` /
`test_system_smoke.py` still excluded — live HTTP to `localhost:8000`,
`requests` absent from `requirements.txt` — no-live-contact constraint,
same as Pass 1/2. Covered in-process by `test_bootstrap_isolated.py`.

## V. Pass 1 + Pass 2 security invariants — regression

| ID | Result |
|---|---|
| SI-1 `/v1` scope→role bypass closed | PASS (`test_v1_auth.py` 5; SI script 3/3) |
| SI-2 `require_admin` gates `/users` | PASS (`test_users_admin.py` 25; SI script 4/4) |
| SI-3 Watchtower bridge/service auth fail-closed | PASS (`test_watchtower_service_auth.py` 53, `test_watchtower_bridge_auth.py` 8; SI script 5/5) |
| SI-4 e859b61 divergent watchtower.py absent | PASS (unchanged this pass) |
| SI-5 `:9100` unexposed on host | PASS (`docker-compose.yml` `s43-core` has no `ports:`) |
| SI-6 firewall shim → real fields | PASS (`test_firewall_trusted_proxy_config.py` 2) |
| SI-7 `/users` mounted, auth-gated | PASS |
| Pass 2 firewall defaults / empty-trusted-proxy / malformed-config-fails-closed / required-registration-fails-closed / uvicorn pin | PASS — `test_firewall_config_hardening.py` 27 + `test_firewall_proxy_trust.py` 20 |

Pass 1 SI script: **13/13**. No prior-pass invariant regressed.

## W. Deferred / not done

- **#11** env-var operator SHA-256 → Pass 4.
- **P3-7** `role` DB CHECK constraint → future migration.
- **P3-8** username/email case-insensitive uniqueness → future migration + collision inventory.
- **P3-9** zero-active-admins reopens `/bootstrap/admin` → documented; unreachable via the API.
- `reverify_password` per-subject throttle → deferred (rationale in O).
- Multi-replica login throttle (Redis) → deferred.
- Argon2 rehash-on-login → not needed (no rehash contract); slot identified (`record_login`).
- Carried from Pass 1/2 (not this pass): test-ordering env fragility; `/users`
  500-vs-503 without `DATABASE_URL`; `HTTP_422_UNPROCESSABLE_ENTITY`
  deprecation; `require_admin`↔`require_operator` de-dup; `core.monitoring.
  sparta_core` casing; two physical `FirewallConfig` files;
  `docker-compose.yml` `s43-setup` path; RFC 7239 `Forwarded` parser.
