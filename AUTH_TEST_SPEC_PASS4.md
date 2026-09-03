# Sentinel-43 — Authentication Test Specification (Pass 4, for Pass 5)

The test suite Pass 5 must satisfy **before** each migration phase lands.
Written now, ahead of implementation. **No test here is implemented in Pass 4.**
Companions: `AUTH_ARCHITECTURE_PASS4.md`, `AUTH_THREAT_MODEL_PASS4.md`,
`AUTH_MIGRATION_PASS4.md`.

Conventions:
- In-process tests use `fastapi.testclient` + monkeypatched credential stores
  (the Pass 1–3 pattern). DB-behaviour tests use a **disposable PostgreSQL**
  gated on `S43_TEST_PG_DSN` (the Pass 3 pattern) and `pytest.mark.skipif`.
- Every test asserts a **sanitized** response — no credential value in any
  body, header, log line, or close reason (grep the captured output).
- "invariant" = must also keep passing unchanged from Pass 1/2/3.

---

## A. LOGIN (`test_auth_login.py` — rewrite + extend)

| ID | Case | Expected |
|---|---|---|
| L1 | valid username + password (DB account) | 200; body has `access_token`, `token_type=bearer`, `expires_in≈900`, `subject`, `role`; `Set-Cookie: s43_refresh=...; HttpOnly; Secure; SameSite=Strict; Path=/auth`; a `s43_csrf` non-HttpOnly cookie |
| L2 | valid credentials, `is_active=false` | 401, `detail` identical to L3/L4; no cookie set; no session row |
| L3 | wrong password | 401, identical body + response-time band to L2/L4 |
| L4 | unknown username | 401, identical to L2/L3 (Pass 3 dummy-verify preserved) |
| L5 | `S43_LOGIN_MAX_FAILURES` failures then one more | 429 + `Retry-After`; the 429 is emitted **before** `_validate_credentials` (Pass 3 test carried over) |
| L6 | successful login clears the throttle counter | invariant (Pass 3) |
| L7 | login issues an access token that `verify_jwt_token` accepts and whose claims include `jti`, `sid`, `user_id`, `role`, `iss`, `aud`, 15-min `exp` | 200; decode + assert claims; **no** `password`/secret claim |
| L8 | login creates exactly one `sessions` row for the user, `refresh_hash` = sha-256 of the cookie value, `revoked_at` null, `expires_at` ≈ now + refresh TTL | DB test |
| L9 | env-operator path (until #11 decision) still issues a `role=operator` token with no `user_id` and **no** session row (or a session row, per the #11 outcome) | matches the chosen #11 option; documented |
| L10 | `POST /auth/login` with a body missing `username` / `password` | 422 (pydantic) — invariant |

## B. ACCESS TOKEN (`test_jwt_auth.py` — extend; keep every existing case)

| ID | Case | Expected |
|---|---|---|
| TK1 | valid new-style token | `verify_jwt_token` returns claims |
| TK2 | expired token | 401 `Token has expired.` — invariant |
| TK3 | malformed (bad shape) | 401 `Invalid token.`, before crypto — invariant |
| TK4 | bad signature | 401 `Invalid token.` — invariant |
| TK5 | wrong issuer | 401 `Invalid token.` (not distinguishable from TK6) — invariant |
| TK6 | wrong audience | 401 `Invalid token.` |
| TK7 | role claim missing / not in `{operator,admin}` | 403 — invariant (SI-1: a `scope`-only claim is still rejected) |
| TK8 | old-style token (8 h, no `sid`) during Phase B | accepted by `verify_jwt_token`; `require_*` then require `X-S43-Password` |
| TK9 | `kid` = current key | accepted |
| TK10 | `kid` = previous key (`S43_JWT_SECRET_PREVIOUS`) | accepted |
| TK11 | `kid` = unknown / absent when keyring configured | 401 |
| TK12 | `iat`/`nbf` 20 s in the future (within ±30 s leeway) | accepted |
| TK13 | `iat`/`nbf` 5 min in the future | 401 |
| TK14 | `exp` 1 s in the past even with leeway | 401 (leeway is not applied to `exp`) |
| TK15 | token for a user whose account is now disabled — on `/users` | 403 immediately (`require_admin` live check — invariant, Pass 1 SI-2) |
| TK16 | same, on `/v1/assess` (role-claim-trusting) during Phase E | succeeds until `exp` **unless** the `sid`-revocation option is enabled; the test encodes whichever choice ships and its documented bound |

## C. REFRESH (`test_auth_session.py` — new, in-process + DB)

| ID | Case | Expected |
|---|---|---|
| R1 | `POST /auth/refresh` with a valid cookie + CSRF header | 200; new `access_token`; `Set-Cookie` with a **new** refresh value; same `sid`; `sessions.refresh_hash` updated; `last_seen_at` bumped |
| R2 | refresh with no cookie | 401; no token |
| R3 | refresh with a valid cookie but no / wrong CSRF header | 403 |
| R4 | refresh after `POST /auth/logout` | 401; cookie cleared (`Max-Age=0`) |
| R5 | refresh with a **superseded** refresh value (used R1's old value again) | 401 **and** the whole session is revoked (`revoked_at` set) — reuse ⇒ theft response (T2) |
| R6 | refresh for a user disabled since login | 401; session revoked |
| R7 | refresh after `expires_at` (absolute cap) | 401; session revoked/expired |
| R8 | refresh does **not** extend `expires_at` (sliding value, fixed cap) | DB assert |
| R9 | two concurrent refreshes with the same cookie (race) | exactly one succeeds; the other gets 401 + the session is revoked (or a clean retry — the test pins whichever the impl guarantees); **DB test, independent connections** |
| R10 | refresh token value never appears in any response body or log | grep |

## D. LOGOUT / REVOCATION (`test_auth_session.py` + `test_account_transactions_pg.py`)

| ID | Case | Expected |
|---|---|---|
| RV1 | `POST /auth/logout` | 200/204; session row deleted (or `revoked_at` set); cookie cleared |
| RV2 | after logout, the still-unexpired access token on `/users` | 403 (live check) |
| RV3 | after logout, same access token on `/v1` | succeeds ≤ `exp` (documented bound) unless `sid` poll enabled |
| RV4 | `POST /users/{id}/password` (admin resets another user's pw) ⇒ that user's sessions revoked | DB test; atomic with the password write (Pass 3 boundary) |
| RV5 | `PATCH /users/{id}` disabling a user ⇒ their sessions revoked, same transaction | DB test |
| RV6 | `PATCH /users/{id}` changing a user's role ⇒ their sessions revoked (forced re-login with the new role) | DB test |
| RV7 | admin demotes themselves (allowed while another admin exists — Pass 3) ⇒ their own sessions revoked | DB test |
| RV8 | "log out everywhere": revoke all sessions for a user ⇒ every session's refresh fails | DB test |
| RV9 | signing-key rotation: set `PREVIOUS`=old, `SECRET`=new ⇒ old tokens valid for one TTL; drop `PREVIOUS` ⇒ old tokens rejected immediately; sessions survive (refresh with new key) | test |

## E. MIGRATION / DUAL CONTRACT (`test_auth_migration.py` — new)

| ID | Case | Expected |
|---|---|---|
| MG1 | Phase B: new-style token, **no** `X-S43-Password`, on `/v1` / `/users` / a dashboard route | 200/allowed |
| MG2 | Phase B: old-style token (8 h, no `sid`), **no** `X-S43-Password` | 401 (legacy still requires the password) |
| MG3 | Phase B: old-style token **with** correct `X-S43-Password` | 200 — legacy path unchanged (invariant) |
| MG4 | Phase B: new-style token **with** a (now-superfluous) `X-S43-Password` | 200 — accepted, password ignored |
| MG5 | **service identities unaffected**: a human access token (new or old) sent to `/watchtower/analyze` / `/internal/events/broadcast` / `/watchtower/state/{n}` | 401 — a human token never satisfies a service verifier (T11) |
| MG6 | a Watchtower/Fenrir service token sent to `/users` or `/v1` | 401 — a service token never satisfies `require_*` |
| MG7 | Phase D: a legacy request increments `legacy_auth_request_total{route=...}` and logs a **credential-free** deprecation warning (grep the log) | metric + log assert |
| MG8 | Phase E: any request with `X-S43-Password` **or** an old-style token | 401 `Legacy authentication is no longer accepted.` |
| MG9 | Phase E: `reverify_password`, `_validate_env_credentials` (if #11→A), `PASSWORD_HEADER_NAME` are gone | import/grep assert |

## F. WEBSOCKET (`test_ws_auth.py` — extend; keep every existing case)

| ID | Case | Expected |
|---|---|---|
| WS1 | connect with `{token}` (new style, no password) | accepted; `connected` frame |
| WS2 | connect with legacy `{token, password}` during Phase B | accepted (invariant) |
| WS3 | connect, no auth frame within 15 s | close 1008 — invariant |
| WS4 | connect, first frame not `auth` type | close 1008 — invariant |
| WS5 | bad origin | close 1008 `origin_rejected` — invariant |
| WS6 | expired token in the auth frame | close 1008 `token_expired` |
| WS7 | forged-signature token | close 1008 `invalid_token` — invariant |
| WS8 | unapproved role | close 1008 `insufficient_role` — invariant |
| WS9 | token expires **during** an open connection | server closes 1008 `token_expired` within ≤ the re-check interval |
| WS10 | the connected user is **disabled** during an open connection | server closes 1008 `session_revoked` within ≤ 60 s |
| WS11 | the connected user's **role changes** during an open connection | close 1008 `session_revoked` within ≤ 60 s |
| WS12 | after WS9/WS10/WS11, client reconnects with a fresh token | accepted |
| WS13 | close reasons contain no exception trace, no credential, no internal path | grep |
| WS14 | max clients reached | capacity error + close — invariant |

## G. MULTI-REPLICA (`test_auth_multireplica_pg.py` — new, disposable PG, 2 "replicas" = 2 engines/apps sharing one DB)

| ID | Case | Expected |
|---|---|---|
| MR1 | login on replica A, refresh on replica B | works (session in shared DB) |
| MR2 | logout on replica A ⇒ refresh on replica B fails | 401 |
| MR3 | disable a user on replica A ⇒ `/users` on replica B rejects immediately; `/v1` on replica B rejects within the documented bound | assert both |
| MR4 | throttle: 5 failures on replica A + 5 on replica B for the same username, `S43_LOGIN_MAX_FAILURES=8` | **with the shared-store throttle (M7): locked after 8 total.** With the Pass 3 in-process throttle: NOT locked (10 total, 5 per replica) — the test encodes whichever ships and its documented limitation |
| MR5 | concurrent login + logout for the same user across replicas | ends in a consistent state (either logged in with one live session, or logged out with none — never a dangling half-session); DB assert |

## H. SECURITY REGRESSION — every Pass 1/2/3 invariant (must stay green)

Re-run, unchanged, at every phase:
- **Pass 1 SI script** (`s43_step7.py`) — 13/13.
- SI-1 `/v1` scope→role bypass closed — `test_v1_auth.py`.
- SI-2 `require_admin` gates `/users`, live DB role — `test_users_admin.py` (25).
- SI-3 Watchtower service/bridge auth fail-closed — `test_watchtower_service_auth.py` (53), `test_watchtower_bridge_auth.py` (8).
- SI-4 e859b61 divergent watchtower.py absent — blob check.
- SI-5 `:9100` unexposed — `docker-compose.yml` parse.
- SI-6 firewall shim → real fields; empty trusted-proxy trusts nobody;
  malformed firewall config fails closed; required firewall registration
  fails closed; uvicorn `--forwarded-allow-ips` pinned —
  `test_firewall_config_hardening.py` (27), `test_firewall_proxy_trust.py` (20).
- SI-7 `/users` mounted, auth-gated.
- Pass 3: account helpers flush-not-commit; `authenticate_user` read-only;
  `verify_password` fail-closed; off-loop hashing; first-admin advisory lock
  (#12); last-admin lock — `test_account_transactions_pg.py` (9),
  `test_password_verification.py` (33), `test_login_throttle.py` (5).
- `_get_operator` `dev-operator` local fallback still works in
  `SENTINEL_ENV in {development,dev,local,test}` and is still refused by
  `_require_operator`.

**Full suite** (`pytest core/tests/ --ignore=test_bootstrap.py
--ignore=test_system_smoke.py`) must pass at every phase, with and without
`S43_TEST_PG_DSN`.

---

## I. Coverage requirement for Pass 5

Before Phase B lands: A + B + C + E(MG1–6) + F(WS1–8) + H green.
Before Phase E lands: **all** of A–H green, `legacy_auth_request_total == 0`
for the observation window, operator sign-off recorded in a
`PASS5_VALIDATION.md`.
