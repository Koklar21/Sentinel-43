# Sentinel-43 — Pass 3 Handoff

- Date: 2026-09-01
- Pass run: **Pass 3 only** — account transactions / bootstrap concurrency / auth hardening. Stopped here.
- Do NOT begin Pass 4 without explicit approval. No push. No deploy.

## Short outcome

Reproduced the first-admin race against real PostgreSQL (7 admins from 8
contenders) and closed it with a transaction advisory lock (1 from 8 after).
Refactored the account layer to a single deliberate transaction boundary
(helpers flush, routes commit, `get_db_session` rolls back) — `PATCH /users`
can no longer half-persist a role+is_active change. Made `verify_password`
fail closed on every malformed hash, moved Argon2 off the event loop, made
`authenticate_user` read-only, equalised the account-miss timing, and added a
per-username `/auth/login` brute-force lockout. Full suite **300 passed / 0
failed / exit 0**. All Pass 1 & Pass 2 invariants re-verified (13/13). Live
stack, live DB, original repo untouched.

---

## A. Exact starting state

Work clone `C:\Users\heero\Sentinel-43-work`, branch
`integration/beta-hardening-20260901`, HEAD `ca328ea` (Pass 2 handoff; code
state `f245cf3`, an ancestor of HEAD). Clean tree, `git fsck` 0 errors,
merge-base with `origin/main` = `8d2b80f`. Original OneDrive repo HEAD
`e859b61`, unchanged (re-verified at end).

Disposable PostgreSQL **16.3** for concurrency tests: `docker run -d --rm
--name s43pass3_pgtest --tmpfs /var/lib/postgresql/data ... -p
127.0.0.1:55432:5432 postgres:16.3` — distinct name/port/volume from every
`s43_*`, torn down at end. The s43 Compose stack was **down** all pass and
not touched.

## B. Exact ending commit

Branch `integration/beta-hardening-20260901`. **HEAD after this handoff
commit: `git rev-parse HEAD`**. Substantive/tested code state: **`86c9aab`**;
`2c4fde7` adds `PASS3_VALIDATION.md`; this file is the last commit.
`git diff ca328ea..86c9aab` = 12 files. Local branch only, not pushed.

## C. Account / auth call graph

Full version in `PASS3_VALIDATION.md` §C. Key points:
- `POST /auth/login` → throttle check → `_validate_credentials` (owns a
  session; `authenticate_user` read-only, then `record_login` + `commit`) →
  `_issue_token` → clear/record throttle.
- Every protected request → `reverify_password` opens its own short-lived
  session, `authenticate_user` (read-only SELECT + off-loop verify), **no
  write**. `require_admin` additionally reads the admin role from the
  request's `get_db_session`.
- `POST /bootstrap/admin` → `create_first_admin(session, ...)` (advisory lock
  → count → insert) → route `commit()`.
- `/users` CRUD → helpers flush → route `commit()` (once, even for
  role+is_active).

## D. Transaction-ownership map

`PASS3_VALIDATION.md` §D. Every helper: **commit? no. flush? yes (where a
result/error must surface). rollback? no.** Commit points: the four
account-mutating routes + `_validate_credentials`. Rollback:
`core/auth/deps.py::get_db_session` `except Exception: await
session.rollback(); raise`.

## E. `update_last_login=False` write analysis

The `update_last_login` param is **removed**. `authenticate_user()` has no
write on any branch. `record_login()` is the sole writer of `last_login_at`,
called only by `_validate_credentials` (POST /auth/login), which commits.
`reverify_password()` → `authenticate_user()` only. Proven by
`test_password_verification.py` (recording-session doubles assert
`commits == flushes == rollbacks == 0` and `last_login_at is None`).
**Argon2 rehash: no `check_needs_rehash` exists anywhere** — the contract is
"no rehash"; Pass 3 keeps it that way (adding it would put a write on the
login path). Slot identified for later: `record_login()`.

## F. First-admin race reproduction

Pre-fix (faithful copy of `bootstrap_admin`, 8 contenders, independent
`AsyncSession`s / asyncpg connections): **7 CREATED, 1 got 409, DB had 7
active admins.** RACE REPRODUCED. Post-fix (`create_first_admin` +
`ADMIN_INVARIANT_LOCK_KEY`): **1 CREATED, 7 got 409, DB had 1.** In the
suite: `test_account_transactions_pg.py::
test_first_admin_created_exactly_once_under_concurrency[2|8|20]`.

## G. Serialization candidates evaluated

Table in `PASS3_VALIDATION.md` §G. **Chosen: PostgreSQL transaction advisory
lock** — cross-process, cross-replica, auto-released on txn end / disconnect,
**no schema migration**, no-op on non-PostgreSQL. Explicitly **rejected: a
partial unique index `UNIQUE (role) WHERE role='admin'`** — Sentinel-43
supports multiple admins; the invariant is "bootstrap runs once", not "one
admin forever". Also rejected: dedicated lock table (needs a migration),
session-level advisory lock (footguns).

## H. Selected solution / migration recommendation

`_pg_advisory_xact_lock(session, ADMIN_INVARIANT_LOCK_KEY=0x5334334200000001)`:
- `create_first_admin()`: lock → `count_active_admins()==0` → INSERT, all in
  the caller's transaction, lock released at the route's `commit()`.
- `PATCH /users/{id}`: lock before `_would_orphan_admins()` whenever the
  change can move the active-admin count.

**No persistent schema migration.** `Base.metadata.create_all` untouched. No
`ALTER`/`CREATE INDEX` on any database. Section 8/24 STOP not triggered.

## I. Role-validation findings

App boundary validated (`_validate_role` → 422; helpers → `ValueError`;
bootstrap hard-codes `"admin"`). **DB has no CHECK constraint** on `role`
(`String(32)` only). No normalization (case/whitespace variants all
rejected). **P3-7 deferred:** recommend `CHECK (role IN ('operator','admin'))`
in a future migration after inventorying existing rows.

## J. Username / email collision analysis

Stored `.strip()`ed, **not case-folded**; `unique` is case-sensitive;
lookups exact-match ⇒ `Admin` / `admin` are distinct accounts. **No
normalization or new constraint introduced (§10).** Collision class if
case-insensitive uniqueness were added: any pair equal after
`.strip().lower()`. **Not inventoried against live data** (no DB access;
§22/§23). Future change needs the inventory + a decision + a migration
(`citext` / functional unique index). **P3-8 documented, deferred.**

## K. Disabled-account behavior

Matrix in `PASS3_VALIDATION.md` §K. Disabled accounts cannot log in
(`authenticate_user` → `None` → 401), cannot pass `reverify_password` (401 on
any protected route), cannot be admin (`require_admin` re-checks
`is_active` → 403). Miss vs wrong-password is timing-equalised (dummy Argon2
verify). **P3-9:** zero *active* admins reopens `/bootstrap/admin` — only
reachable by direct DB edits; the API's last-admin guard prevents the API
from creating that state. Documented.

## L. Password-verification failure behavior

`verify_password()` returns `False` (never raises, never authenticates) for:
`""`, whitespace, `"garbage"`, non-argon2 strings, argon2-shaped-but-corrupt
(`VerificationError` — previously **propagated**), `"$argon2id$"`, `None`,
`int`, `bytes`, and non-str password args. 15 cases in
`test_password_verification.py`. A malformed stored credential no longer
silently routes to the env-var fallback via a swallowed exception.

## M. Argon2 rehash behavior

None exists; none added (see E). `PasswordHasher()` = argon2-cffi defaults
(`t=3, m=64 MiB, p=4`), unchanged. Measured ~32 ms hash / ~34 ms verify.
Tests do not weaken params.

## N. Event-loop / offload behavior

`hash_password_async` / `verify_password_async` = `asyncio.to_thread` → the
default bounded `ThreadPoolExecutor` (`min(32, cpu+4)` workers; no unbounded
thread creation; exceptions propagate). Used by `authenticate_user`,
`create_user`, `create_first_admin`, `set_user_password`. Sync variants kept
for non-async callers. Test `test_hashing_does_not_block_the_event_loop`
proves the loop keeps ticking during a hash. Smallest mechanism compatible
with the architecture; no worker pool added.

## O. Rate-limit findings

`POST /auth/login`: **added** per-username sliding-window lockout —
`S43_LOGIN_MAX_FAILURES` (10) / `S43_LOGIN_FAIL_WINDOW_SECONDS` (300) ⇒ 429
for `S43_LOGIN_LOCKOUT_SECONDS` (300). In-process, keyed on normalized
username, bounded dict + GC, 429 short-circuits before any hash work,
cleared on success. In-process only — **Redis for multi-replica, deferred**.
`reverify_password` per-subject throttle **deferred** (behind a valid-JWT
gate, off-loop verify, risks locking out a legit operator on a fat-fingered
header). `/bootstrap/admin`: advisory lock + self-gating 409; no dedicated
limiter (first-run only). Global firewall rate-limiter **not touched**.
Tests: `test_login_throttle.py` (5).

## P. RELEASE_FINDINGS #11 status

**Investigated; deferred to Pass 4.** `_validate_env_credentials`
(SHA-256, un-salted, `S43_OPERATOR_PASSWORD_HASH` in `.env`, constant-time
compare) is still reachable as the DB fallback in `/auth/login` and
`reverify_password`. Pass 3's login throttle raises the online cost.
Changing the scheme is a breaking `.env` change and is entangled with the
Pass 4 question "should the env-var operator exist at all" — implementing it
now would enter the Pass 4 redesign (§24). Exposure recorded in
`RELEASE_FINDINGS.md` #11.

## Q. RELEASE_FINDINGS #12 status

**RESOLVED.** Reproduced (independent connections, 7/8 admins), fixed
(advisory lock, 1/8), regression-tested at 2/8/20 contenders against
PostgreSQL 16.3. The last-admin `PATCH /users` invariant uses the same lock
and is concurrency-tested (`test_last_two_admins_cannot_both_be_demoted_
concurrently`).

## R. Files changed and why

`PASS3_VALIDATION.md` §R. Code: `core/auth/users.py`, `core/auth/deps.py`,
`core/api/routers/{bootstrap,users,auth}.py`. Docs: `RELEASE_FINDINGS.md`.
Tests: 3 new (`test_account_transactions_pg.py`,
`test_password_verification.py`, `test_login_throttle.py`), 2 fake-store
updates (`test_bootstrap_isolated.py`, `test_users_admin.py`).

## S. Tests added

- `test_account_transactions_pg.py` — 9 items, **skipped unless
  `S43_TEST_PG_DSN`** points at a disposable PostgreSQL: `create_user`
  no-commit / commit-persists / atomic role+active / IntegrityError-at-flush;
  advisory lock released on rollback; first-admin exactly-once at 2/8/20
  contenders; last-two-admins can't both be demoted.
- `test_password_verification.py` — 33: fail-closed `verify_password`
  (15 malformed inputs), read-only `authenticate_user`
  (success/wrong/unknown/disabled + timing), every helper flush-not-commit,
  role validation, off-loop hashing.
- `test_login_throttle.py` — 5: per-username lockout, per-username isolation,
  cleared on success, case/whitespace-insensitive key, 429 before
  `_validate_credentials`.

## T. Disposable PostgreSQL validation results

PostgreSQL 16.3, asyncpg 0.31.0, DSN `…@127.0.0.1:55432/s43pass3`. The 9
`test_account_transactions_pg.py` cases **pass** with the DSN set; **skip**
cleanly without it. Standalone repro scripts: pre-fix 7/8 race demonstrated,
post-fix 1/8 + last-admin 1-blocked-1-demoted.

## U. Complete regression suite

Env: `.venv-pass1`, Python 3.13.5, pytest 9.1.1 (versions in
`PASS3_VALIDATION.md` §S). Tested commit **`86c9aab`**.
```
pytest core/tests/ --ignore=core/tests/test_bootstrap.py \
  --ignore=core/tests/test_system_smoke.py -q
```
**With `S43_TEST_PG_DSN`: 300 collected, 300 passed, 0 failed, 0 skipped,
exit 0**, ~77 s. **Without it: 291 passed, 9 skipped.** 5 warning locations,
unchanged from Pass 1/2 (no new warnings). `test_bootstrap.py` /
`test_system_smoke.py` still excluded (live HTTP + `requests` — no-live
constraint).

## V. Pass 1 + Pass 2 invariant regression

Pass 1 SI script **13/13**. `test_v1_auth` 5, `test_users_admin` 25,
`test_watchtower_service_auth` 53, `test_watchtower_bridge_auth` 8,
`test_firewall_config_hardening` 27, `test_firewall_proxy_trust` 20,
`test_firewall_trusted_proxy_config` 2, `test_ws_auth` 14 — all pass. SI-5
re-verified (`s43-core` no `ports:`). **No prior-pass invariant regressed.**

## W. Deferred / unresolved

`PASS3_VALIDATION.md` §W. Headline: #11 (env SHA-256) → Pass 4; P3-7 (role
CHECK) + P3-8 (identity normalization) → future migrations with inventories;
multi-replica login throttle → Redis; `reverify_password` throttle →
deferred with rationale; Pass 1/2 carry-overs unchanged.

## X. Confirmation — no live/external/prohibited mutations

Confirmed: no push / force-push / merge to `main` or `origin/main` / PR
create-merge-close / branch-tag-stash-object deletion / history rewrite /
`reset --hard` or `clean` on the original / repo-visibility or GitHub change
/ modification of the original OneDrive repo / any s43 Compose-stack
lifecycle command (it was down; not started/stopped/rebuilt/reconfigured) /
live-DB access or `ALTER ROLE` / migration against real data / credential
rotation / external deployment / secret disclosure / removal of Pass 0-2
recovery material.
Authorized mutations: 8 commits on the local branch in the non-synced work
clone; one disposable `postgres:16.3` container created and destroyed
(`--rm --tmpfs`, loopback-only, distinct name/port); `pip` not re-run (venv
unchanged); `…\sentinel43-recovery\pass3-20260901\` added.

## Y. Proposed Pass 4 scope

Per this mission's Pass 4 — **authentication redesign specification, then
approval** (produces a design + test spec, NOT an auto-rewrite; implement
only in a separately authorized invocation):

1. Confirm from the transport whether protected requests still carry both a
   Bearer JWT and `X-S43-Password` on every call (they do), and state the
   real cost: repeated password transmission + an Argon2 verify per request
   (now off-loop, throttled at login, but still per-request). Do **not**
   claim plaintext-on-the-wire without inspecting the transport.
2. Smallest compatible design for: login, bounded token/session lifetime,
   issuer/audience/signature validation (already via `verify_jwt_token`),
   role enforcement, account disablement propagation, revocation/logout,
   service-identity separation (Fenrir/Watchtower tokens already exist —
   keep them distinct from operator auth), brute-force protection (Pass 3
   added login throttle — extend or move to Redis), audit redaction,
   browser + WebSocket auth. Never put passwords / long-lived credentials in
   URLs. If cookies: `Secure`/`HttpOnly`/`SameSite` + CSRF. If browser-held
   tokens: storage/XSS tradeoff.
3. Resolve **#11**: should the env-var operator exist at all? If kept,
   Argon2 (breaking `.env` change — plan the migration) instead of SHA-256.
4. Inventory every client / CLI / service / WS consumer. Before removing the
   `X-S43-Password` gate, test the full existing matrix (token
   missing/malformed/expired/wrong-role/valid × password missing/wrong/valid)
   + independent service-token tests. After migration: new contract + legacy
   rejection. Auth failure ⇒ no protected side effects.
5. STOP for approval of the design + compatibility/migration plan +
   rollback. Implement only when separately authorized.

Also available as follow-ups: P3-7 role CHECK migration, P3-8 identity
normalization + collision inventory (both need live-DB access / a migration
window — likely Pass 6/deployment or a dedicated migration pass).

---
Stop. No Pass 4, no push, no deploy. Await explicit authorization.
