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
 core/api/routers/auth.py                       |  +91  -1
 core/auth/sessions.py                          |  new  (~560 lines)
 core/tests/test_session_primitives.py          |  new  (25 tests)
 core/tests/test_session_layer_pg.py            |  new  (17 tests, PG-only)
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
  is passed the token gains `sid` + `jti` claims (malformed `sid` → 500).
  **`sid is None` path unchanged.**
- `verify_jwt_token(...)` — added: if `sid`/`jti` present, shape-check them
  (malformed → 401). **Neither required; legacy tokens unaffected.**
- new `token_is_session_bound(claims)` helper + `_SESSION_ID_RE` / `_JTI_RE`
  / `_new_jti()`.

---

## 3. New-code tests

### 3.1 `test_session_primitives.py` — in-process, no DB (always runs)

```
25 passed in 0.51s
```

Covers: 256-bit refresh-secret generation + uniqueness; SHA-256 verifier
stability / non-reversibility / constant-time compare / fail-closed on bad
input; optional `S43_SESSION_HASH_PEPPER` changes the digest; TTL env
clamping; CSRF token generation + double-submit match + fail-closed;
`new_sid`/`new_jti`; `claims_are_session_bound` vs `token_is_session_bound`
agreement; **`_issue_token` legacy path byte-shape-identical** (`{sub,
username, iss, aud, iat, nbf, exp, role}`, no `sid`/`jti`); new-style token
carries `sid`+`jti` and verifies; malformed supplied `jti` replaced; issue
rejects malformed `sid`; `verify_jwt_token` rejects crafted tokens with
malformed `sid` / `jti`; well-formed `jti`-only token accepted and **not**
session-bound.

### 3.2 `test_session_layer_pg.py` — disposable PostgreSQL 16.3 (skipif no `S43_TEST_PG_DSN`)

```
17 passed in 2.91s
```

| area | tests |
|---|---|
| transaction ownership | create-no-commit discarded; create+commit persists; **only the hash is stored**; `SessionView` has no hash field |
| rotation | generation increments; prev/current hashes tracked; `rotated_at` set; old secret superseded; unknown secret → `RefreshInvalidError` |
| reuse (single-step) | replaying a superseded secret → `RefreshReuseError` **and whole session revoked**; the legit current secret then also fails |
| revocation | `revoke_session` idempotent; `revoke_all_user_sessions` scoped + idempotent; other users untouched |
| logout | `logout_by_refresh` idempotent, accepts prev generation, garbage → clean `False` |
| expiry | expired session → `SessionExpiredError`; boundary case atomic (rotated gen 1 **or** expired gen 0, never torn) |
| disablement | disabled owner → `SessionOwnerInactiveError` + session revoked `owner_inactive` |
| constraint | duplicate `refresh_hash` → `IntegrityError` at flush |
| **concurrency (§16)** | 2 and 5 concurrent refreshes, same credential → **exactly one** `ROTATED`, others `RefreshReuseError`, generation == 1, session revoked; refresh racing logout → session dead, no live successor; refresh racing disablement → no refresh possible after; repeated logout clean |

PG assumptions: READ COMMITTED; correctness needs only `SELECT … FOR UPDATE`
+ EvalPlanQual predicate re-check, not SERIALIZABLE; no advisory lock used by
the session layer.

### 3.3 `test_service_identity_separation.py` — §22 boundary (always runs)

```
12 passed in 0.62s
```

human JWT (operator/admin, plain/session-bound) → every service verifier
401; refresh credential → not a JWT, → service verifiers 401; service token →
`verify_jwt_token` 401, `_validate_env_credentials` 401, can't be a `sid`,
hash never collides; service verifiers' source has no `verify_jwt_token` /
`_issue_token`, does use `compare_digest`; service verifier still accepts its
own token.

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
pytest core/tests/ -q --ignore=core/tests/test_bootstrap.py \
                      --ignore=core/tests/test_system_smoke.py
  (S43_TEST_PG_DSN set to the disposable PG)
```

`test_bootstrap.py` / `test_system_smoke.py` excluded per the standing
no-live-HTTP / no-external-contact rule (`test_system_smoke.py` also needs
`requests`, absent from the venv). Consistent with Pass 1–3.

**Result: `354 passed, 0 failed` in 851s** (includes the 17 `test_session_layer_pg.py`
+ 9 `test_account_transactions_pg.py` PostgreSQL tests, plus the 25 + 12
always-on new suites). Pass 3's baseline was 300; the delta is +54 new Pass 5A
tests (25 + 17 + 12).

Post-run cosmetic edit: removed two unused imports (`func`,
`get_sessionmaker`) from `core/auth/sessions.py` after this full run. The
change is inert (unused names); the three new suites were re-executed
afterwards — `test_session_primitives.py` 25 ✓, `test_service_identity_separation.py`
12 ✓, `test_session_layer_pg.py` 17 ✓.

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
