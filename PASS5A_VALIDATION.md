# PASS5A_VALIDATION.md

Sentinel-43 — Pass 5A validation record. Authentication foundation /
migration readiness. Evidence for every claim in `SESSION_MODEL_PASS5A.md`,
`SESSION_MIGRATION_DECISION_PASS5A.md`, and `AUTH_TLS_POSTURE_PASS5A.md`.

- **Branch**: `integration/beta-hardening-20260901`
- **Starting HEAD**: `2f0c749` (Pass 4 docs-only; runtime code == Pass 3
  validated `86c9aab`)
- **Working clone**: `C:\Users\heero\Sentinel-43-work` (non-synced; `origin`
  push disabled, `evidence-local` push disabled)
- **venv**: `.venv-pass1` (Python 3.13, pytest 9.1.1)
- **Disposable DB**: `postgres:16.3`, `docker run --rm --tmpfs
  /var/lib/postgresql/data -p 127.0.0.1:55433:5432`, torn down after the run
- **Original OneDrive repo**: untouched, HEAD still `e859b61`

---

## 1. Starting-state verification

| check | result |
|---|---|
| `path` | `C:/Users/heero/Sentinel-43-work` |
| `branch` | `integration/beta-hardening-20260901` |
| `HEAD` | `2f0c74904edd4a49564bc50a8b99deeb8b331859` == expected `2f0c749` |
| `git status` | clean |
| `git fsck` | 0 problems |
| merge-base with `origin/main` | `8d2b80f` (== origin/main) |
| `86c9aab` (Pass 3 code) ancestor of HEAD | YES |
| runtime code unchanged since `86c9aab` | YES (docs-only since Pass 3) |
| Pass 4 docs present | 5/5 |
| Original OneDrive repo HEAD | `e859b61…` (== expected), clean, fsck 0 |

---

## 2. Changes landed in Pass 5A

```
 core/api/routers/auth.py                       |  modified (+~110 -2)
 core/auth/sessions.py                          |  new  (~730 lines)
 core/tests/test_session_primitives.py          |  new  (29 tests)
 core/tests/test_session_layer_pg.py            |  new  (19 tests, PG-only)
 core/tests/test_service_identity_separation.py |  new  (12 tests)
 AUTH_TLS_POSTURE_PASS5A.md                     |  new
 SESSION_MODEL_PASS5A.md                        |  new
 SESSION_MIGRATION_DECISION_PASS5A.md           |  new
 PASS5A_VALIDATION.md                           |  new
 HANDOFF_PASS5A.md                              |  new
```

No other file changed. `core/auth/users.py`, `core/api/routers/users.py`,
`core/api/routers/bootstrap.py`, `core/api/deps/*`, `core/api/main.py`,
`core/monitoring/watchtower.py`, every deployment file, and every `.env*`
file are **byte-for-byte unchanged**.

`core/api/routers/auth.py` diff summary:
- `_issue_token(...)` — added keyword-only `sid=None, jti=None`; when `sid`
  is passed the token gains `sid` + `jti` claims (malformed `sid` → 500) and
  its TTL drops to the session-access TTL (approved target 15 min;
  `S43_SESSION_ACCESS_TTL_SECONDS`, default 900, clamped 60s–1h).
  **`sid is None` path (payload AND ttl) byte-identical to before.**
- `verify_jwt_token(...)` — added: if `sid`/`jti` present, shape-check them
  (malformed → 401). **Neither required; legacy tokens unaffected.**
- new `token_is_session_bound(claims)` helper + `_SESSION_ID_RE` / `_JTI_RE`
  / `_new_jti()`.

---

## 3. New-code tests

### 3.1 `test_session_primitives.py` — in-process, no DB (always runs)

```
29 passed
```

Covers (authorization §6, §7, §8, §12, §23):
- 256-bit refresh-secret generation + uniqueness (1000-draw); SHA-256
  verifier stability / non-reversibility (secret not in digest) /
  constant-time compare / **fail-closed on bad input** (empty, `None`,
  wrong); `hash_refresh_secret("")` raises `ValueError`; optional
  `S43_SESSION_HASH_PEPPER` changes the digest and stays self-consistent;
  `S43_SESSION_REFRESH_TTL_SECONDS` clamp (5min floor / 30day ceiling /
  bad-value fallback).
- CSRF: token generation unique + url-safe; double-submit match; **fails
  closed** when a half is missing.
- `new_sid` (canonical UUID), `new_jti` (unique); `claims_are_session_bound`
  vs router `token_is_session_bound` agree; `jti` alone ≠ session-bound;
  non-dict input → `False`, never raises.
- **`_issue_token` legacy path byte-shape-identical** (`{sub, username, iss,
  aud, iat, nbf, exp, role}`, no `sid`/`jti`) and keeps the long TTL;
  session-bound token carries `sid`+`jti`, verifies, and has the **15-min
  TTL**; `S43_SESSION_ACCESS_TTL_SECONDS` clamp (60s..1h); supplied
  well-formed `jti` used, malformed one replaced; issue rejects malformed
  `sid` (500); `verify_jwt_token` rejects crafted tokens with malformed
  `sid`/`jti` (401); well-formed `jti`-only token accepted, not
  session-bound.
- **§23 no-leak**: `SessionError` subclasses carry only the (random) `sid`,
  no 32+char opaque residue; `core.auth.sessions` emits **zero** log records
  on primitive failure paths and never echoes a secret in a `ValueError`.

### 3.2 `test_session_layer_pg.py` — disposable PostgreSQL 16.3 (skipif no `S43_TEST_PG_DSN`)

```
19 passed
```

| area | tests |
|---|---|
| transaction ownership | create-no-commit discarded; create+commit persists; **only the hash is stored**; `SessionView` has no hash field |
| rotation | generation increments; prev/current hashes tracked; `rotated_at` set; old secret superseded; unknown secret → `RefreshInvalidError` |
| reuse (single-step) | replaying a superseded secret → `RefreshReuseError` **and whole session revoked**; the legit current secret then also fails |
| revocation | `revoke_session` idempotent; `revoke_all_user_sessions` scoped + idempotent; other users untouched |
| logout | `logout_by_refresh` idempotent, accepts prev generation, garbage → clean `False` |
| expiry | expired session → `SessionExpiredError`; boundary case atomic (rotated gen 1 **or** expired gen 0, never torn) |
| disablement (§17) | disabled owner → `SessionOwnerInactiveError` + session revoked `owner_inactive` |
| role change (§18) | `SessionRecord` has **no `role` column** → a route re-reading `users.role` after `rotate_refresh` gets the new role; `revoke_all_user_sessions(reason="role_change")` forces a fresh token |
| service separation (§22) | a service shared-secret can't `rotate_refresh` (`RefreshInvalidError`) or `logout_by_refresh` (`False`); the real session is untouched |
| constraint | duplicate `refresh_hash` → `IntegrityError` at flush |
| **concurrency (§16)** | 2 and 5 concurrent refreshes, same credential → **exactly one** `ROTATED`, others `RefreshReuseError`, generation == 1, session revoked; refresh racing logout → session dead, no live successor; refresh racing disablement → no refresh possible after; repeated logout clean; expiration-vs-refresh atomic |

PG assumptions: **PostgreSQL 16.3**, default **READ COMMITTED**; correctness
needs only `SELECT … FOR UPDATE` + EvalPlanQual predicate re-check, **not**
SERIALIZABLE; the session layer uses **no** advisory lock.

### 3.3 `test_service_identity_separation.py` — §22 boundary (always runs)

```
12 passed
```

human JWT (operator/admin, plain/session-bound) → every service verifier
(`_require_service_token`, `_require_fenrir_service_token`,
`_require_admin_token`) **401**; refresh credential → not a JWT, → service
verifiers 401; service token → `verify_jwt_token` 401,
`_validate_env_credentials` 401, can't be a `sid`, hash never collides;
service verifiers' source has no `verify_jwt_token` / `_issue_token`, does use
`compare_digest`; service verifier still accepts its own token.

---

## 4. Regression — Pass 1/2/3/4 invariants (mission §25)

| suite / check | before | after Pass 5A |
|---|---|---|
| Security-invariant script (13 checks: /v1 scope-bypass closed, `require_admin` gate, Watchtower authz + probe openness, users router mounted) | 13/13 | **13/13** |
| `test_jwt_auth.py` + `test_v1_auth.py` + `test_ws_auth.py` | pass | **56 passed** (105s) |
| `test_auth_login.py` + `test_login_throttle.py` + `test_bootstrap_isolated.py` + `test_users_admin.py` | pass | **all pass** (part of the 106-passed batch) |
| `test_jwt_auth`+`auth_login`+`v1_auth`+`ws_auth`+`login_throttle`+`users_admin`+`bootstrap_isolated` combined | 106 | **106 passed** (641s) |
| `test_account_transactions_pg.py` (Pass 3, real PG) | 9 | **9 passed** |
| Firewall suites (`test_firewall_config_hardening.py`, `test_firewall_proxy_trust.py`) — Pass 2 | 47 | included in full-suite run below |
| `test_password_verification.py` — Pass 3 | 33 | included in full-suite run below |
| `init_models()` still creates only `users` (sessions on isolated `SessionBase`) | — | **verified** (`users.Base.metadata.tables == {'users'}`) |
| Nothing imports `core.auth.sessions` at app-startup scope | — | **verified** (`git grep`) |
| `core.api.main` imports cleanly | yes | **yes** |

### 4.1 Full suite

```
pytest core/tests/ -q -rsxX --ignore=core/tests/test_bootstrap.py \
                            --ignore=core/tests/test_system_smoke.py
  (S43_TEST_PG_DSN set to the disposable PG)
```

`test_bootstrap.py` / `test_system_smoke.py` excluded per the standing
no-live-HTTP / no-external-contact rule (`test_system_smoke.py` also needs
`requests`, absent from the venv). Consistent with Pass 1–3.

**Two full runs were done:**

1. **Pre-follow-up** (commit `e00c7c2`): `354 passed, 0 failed` in 851s —
   Pass 3 baseline 300 + 54 new (25 + 17 + 12).
2. **Final** (the follow-up commit, this document's authoritative run): after
   adding the 15-min session-access TTL and 6 more tests — see §7 for the
   full recorded metadata.

Between the two runs: `core/auth/sessions.py` lost two unused imports
(`func`, `get_sessionmaker` — inert); `_issue_token` gained the session-bound
15-min TTL (legacy path unchanged); 6 tests added (TTL x2, no-leak x2,
role-change, service-separation-PG). All three new suites re-run green after
each change.

---

## 5. Boundaries honoured

- No push, no PR, no merge, no history rewrite, no tag. `origin` /
  `evidence-local` push remain disabled.
- No migration infrastructure, no migration-history file, no `sessions`
  table in repository/production state, no change to `init_models()` or
  `migration-job.yaml` (mission §14 / §30 MANDATORY STOP — see
  `SESSION_MIGRATION_DECISION_PASS5A.md` §6).
- `X-S43-Password` not removed; legacy tokens not rejected; protected-route
  requirements unchanged; WebSocket contract unchanged; service-token
  contracts unchanged; env-operator mechanism unchanged; no `.env` contract
  change.
- No `sid` hot-path polling / LRU implemented.
- Disposable PostgreSQL only; never the live stack or its DB. The s43 Compose
  stack was not started, stopped, or touched.
- No secret values in this document, in test logs, or in commits. Test
  credentials are disposable literals (`p`*16, `test-secret-…`).
- Single writer: all work in one invocation, one clone, one branch.

---

## 6. Known gaps / carried forward

- **F-TLS-1 (blocking, deployment)** — repo evidence does not establish a
  secure production TLS posture; the browser-session design is **not**
  production-ready until resolved. Full detail + remediation prerequisites in
  `AUTH_TLS_POSTURE_PASS5A.md`.
- Migration tool: **Alembic recommended**, awaiting owner approval +
  dedicated migration authorization.
- The session service functions are built and tested but **not wired** — no
  `/auth/refresh`, `/auth/logout`, cookie, or CSRF activation. That is Pass
  5B, gated on the migration authorization and F-TLS-1.
- Multi-replica: repo evidence (k8s README "Known limitations") states the
  in-process rate limiter / login throttle is **per-pod**; `overlays/beta`
  runs 2 replicas. Session rotation is DB-backed so it is replica-safe; the
  throttle is not. No change in Pass 5A (mission §20).
- `#11` env-operator SHA-256: unchanged (mission §19).

---

## 7. Test-run metadata (authorization §26)

Environment (all runs):

| item | value |
|---|---|
| commit under test | the Pass 5A follow-up commit (see `git log`; parent `e00c7c2`, grandparent `2f0c749`) |
| Python | 3.13.5 |
| pytest | 9.1.1 |
| PostgreSQL | 16.3 (Debian, `postgres:16.3`), disposable, `127.0.0.1:55433`, `--rm --tmpfs`, default READ COMMITTED |
| SQLAlchemy | 2.0.52 |
| PyJWT | 2.13.0 |
| argon2-cffi | 25.1.0 |
| asyncpg | 0.31.0 |
| FastAPI / Starlette / pydantic | 0.141.1 / 1.6.0 / 2.13.5 |
| OS | Windows 11 |

Suites run (authorization §26 A–M):

| # | suite | result |
|---|---|---|
| A | token-claim tests (`test_session_primitives.py::TestTokenIssuanceBackCompat`, `TestClaimHelpers`) | pass (part of 29) |
| B | session-domain tests (`test_session_layer_pg.py` create/persistence/view) | pass (part of 19) |
| C | refresh-generation tests (`test_session_primitives.py::TestRefreshSecret`) | pass |
| D | refresh rotation tests (`test_session_layer_pg.py` rotation) | pass |
| E | refresh replay tests (`test_session_layer_pg.py` reuse) | pass |
| F | logout service tests (`test_session_layer_pg.py` logout/revoke) | pass |
| G | CSRF primitive tests (`test_session_primitives.py::TestCsrf`) | pass |
| H | PostgreSQL transaction tests (`test_session_layer_pg.py` txn-ownership) | pass |
| I | PostgreSQL concurrency tests (`test_session_layer_pg.py` §16 set) | pass |
| J | service-identity separation (`test_service_identity_separation.py` + PG) | 12 + 1 pass |
| K | legacy-auth compatibility (`test_jwt_auth`, `test_auth_login`, `test_v1_auth`, `test_ws_auth`) | 56 pass |
| L | Pass 1/2/3 regression (firewall, password-verification, account-tx-pg, throttle, users-admin, bootstrap) | pass (in full suite) |
| M | complete isolated suite | see below |

Full isolated suite (`M`) — `pytest core/tests/ -q -rsxX
--ignore=test_bootstrap.py --ignore=test_system_smoke.py`, `S43_TEST_PG_DSN`
set:

| metric | value |
|---|---|
| collected | 360 |
| passed | 360 |
| failed | 0 |
| errors | 0 |
| skipped | 0 (the PG suites `test_session_layer_pg.py` + `test_account_transactions_pg.py` ran — `S43_TEST_PG_DSN` set) |
| xfailed / xpassed | 0 / 0 |
| deselected | 0 |
| warnings | 5 — all pre-existing `StarletteDeprecationWarning` (`httpx` testclient; `HTTP_422_UNPROCESSABLE_ENTITY` in `core/api/routers/users.py`). **None originate in Pass 5A code.** |
| exit code | 0 |
| duration | 852.33 s (0:14:12) |

360 = Pass 3 baseline **300** + Pass 5A new **60** (29 `test_session_primitives.py`
+ 19 `test_session_layer_pg.py` + 12 `test_service_identity_separation.py`).

The earlier run at commit `e00c7c2` (before the 15-min TTL + 6 follow-up
tests) was `354 passed`. Delta +6 = the follow-up tests.

Security-invariant script: **13/13** (exit 0), re-run after the follow-up
changes.
