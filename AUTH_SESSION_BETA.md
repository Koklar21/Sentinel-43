# AUTH_SESSION_BETA.md

Beta-execution Phase 3 — the browser session wired end to end. Access token
stays the stateless request credential; an opaque server-side refresh session
in an HttpOnly cookie is the durable one. Dual contract with legacy Bearer +
`X-S43-Password` throughout (AUTH_MIGRATION_PASS4 Phase B).

Companions: `AUTH_ARCHITECTURE_PASS4.md` (design), `SESSION_MODEL_PASS5A.md`
(schema), `MIGRATION_DEPLOYMENT_BETA.md`, `BETA_EXECUTION.md`.

---

## 1. Wire contract now

```
POST /auth/login {username,password}   (+ Origin allow-listed)
  DB account  -> 200 {token, access_token, subject, role, expires_in:900,
                      session_bound:true}
                Set-Cookie: s43_refresh=<opaque>; HttpOnly; Secure*;
                            SameSite=Strict; Path=/auth; Max-Age=<refresh ttl>
                Set-Cookie: s43_csrf=<token>; Secure*; SameSite=Strict; Path=/
  env operator -> 200 {token, subject, session_bound:false}   (legacy 8h, no cookie)

POST /auth/refresh                     (cookie auto-sent; X-S43-CSRF == s43_csrf; Origin)
  -> 200 {token, access_token, subject, role, expires_in, session_bound:true}
         rotates s43_refresh; re-issues s43_csrf (same value, fresh Max-Age)
  -> 401 + clears both cookies on any failure
  -> 403 on CSRF / Origin failure

POST /auth/logout                      (cookie; X-S43-CSRF when cookie present; Origin)
  -> 200 {ok:true}; revokes the session; clears both cookies. Idempotent.

every protected HTTP request
  Authorization: Bearer <access token>
  session-bound token (well-formed sid) whose session is live + owner active
      -> authenticated, NO X-S43-Password
  session-bound token, session dead / owner disabled
      -> 401 "Session is no longer valid" / "Account is disabled"
  old-style (sid-less) token
      -> X-S43-Password required, exactly as before (unless S43_REJECT_LEGACY_AUTH)

WebSocket /ws first frame
  {"type":"auth","payload":{"token":<access>}}                 session-bound
  {"type":"auth","payload":{"token":<access>,"password":<pw>}}  legacy
  close code 1008 always carries a `reason` (invalid_token / invalid_password /
      session_revoked / token_expired / origin_rejected / capacity / ...)
```

`*Secure`: set unless `SENTINEL_ENV` is local (dev http://localhost is a
browser secure context). Never scheme-derived — the deployment guarantees
HTTPS (F-TLS-1).

---

## 2. Revocation guarantee

| Event | Access-token effect | Refresh-session effect |
|---|---|---|
| `POST /auth/logout` | **next request 401s** (session `revoked_at` set; `resolve_session_subject` re-checks per request) | cookie cleared; session revoked |
| refresh-value replay (theft) | next request 401s | whole session revoked (`refresh_reuse`) |
| `PATCH /users/{id}` disable | next request 401s | `revoke_all_user_sessions("account_disabled")` in the same txn; also `owner.is_active` re-checked per request |
| `PATCH /users/{id}` role change | next request 401s | `revoke_all_user_sessions("role_changed")` in the same txn |
| `POST /users/{id}/password` | next request 401s | `revoke_all_user_sessions("password_reset")` in the same txn |
| session `expires_at` reached | next request 401s | refresh 401s |
| WebSocket, any of the above mid-stream | connection closed within `S43_WS_SESSION_RECHECK_SECONDS` (default 60, test 1) with a `session_revoked` / `token_expired` reason | — |

**The guarantee is immediate**, not "≤ 15 min". `resolve_session_subject()`
does one indexed PK lookup on `sessions` + one indexed lookup on `users` per
protected request, **read-only** (no write on the hot path — Pass 3 P3-2
holds). This is a DB read per request; acceptable for the single-replica
beta. A future optimisation (revoked-`sid` LRU / short poll —
AUTH_ARCHITECTURE_PASS4 §3.3) is documented, not required.

The one bounded-staleness case: the access token's **`role` claim** is only
as fresh as the last refresh (≤ 15 min) for `require_operator` /
`_get_operator` (operator-vs-admin gating). `require_admin` re-reads the DB
role live, so `/users` is never stale. A role *downgrade* also revokes the
session, so the stale-role window is closed by revocation anyway.

---

## 3. CSRF + Origin

Cookie-authenticated state changes (`/auth/login`, `/auth/refresh`,
`/auth/logout`) require **both**:

- **Double-submit CSRF**: `X-S43-CSRF` header == `s43_csrf` cookie
  (constant-time compare, fail closed). The cookie is JS-readable (not
  HttpOnly) and `SameSite=Strict`. Missing / mismatched → **403**.
- **Origin/Referer**: if `Origin` is present it must be in
  `S43_ALLOWED_ORIGINS`; else `Referer`'s scheme+host must be; else (no
  browser context) allowed. Disallowed → **403**.

CORS is not CSRF protection — this is the server-side half. `/auth/refresh`
and `/auth/logout` are `Path`-scoped so the refresh cookie is only ever sent
to `/auth/*`, never to a data route.

---

## 4. #11 — env-operator is break-glass only

`_env_operator_allowed()` (`core/api/routers/auth.py`). The env credential
(`S43_OPERATOR_USERNAME` / `S43_OPERATOR_PASSWORD_HASH`, un-salted SHA-256)
authenticates **only** when:

- `S43_BREAK_GLASS_ARMED` is truthy, **or**
- there is no active admin in the DB (first-run window), **or**
- the DB is unreachable.

Once a DB admin exists and the DB is healthy, the env operator is **inert**.
No breaking `.env` change for anyone using it as break-glass. Not removed
(Option A) so a DB-down recovery path still exists. Tested:
`test_break_glass_pg.py`.

`.env` contract addition (documented, additive): `S43_BREAK_GLASS_ARMED`
(default off). `AUTH_TLS_POSTURE_PASS5A` F-TLS-1 unaffected.

---

## 5. `X-S43-Password` retirement status

| Phase | State |
|---|---|
| A baseline | — |
| **B dual contract** | **DONE** — session-bound token skips the password; old-style token still requires it. All 4 enforcement points (`require_operator`, `require_admin`, `_get_operator`, `dashboard_websocket`). |
| C migrate consumers | dashboard SPA + WS updated (`auth.js` v1.7.0, `websocket.js` v1.7.0): refresh-on-load, `/auth/logout`, `{token}`-only WS frame. **Needs a manual browser smoke** (no headless browser in this environment). No other known consumer (C9 UNKNOWN). |
| D observability | `legacy_auth_request_total()` counter (per route + `_all`), credential-free, incremented on every legacy-path auth. Exposed for the metrics route / tests. |
| **E reject** | behind `S43_REJECT_LEGACY_AUTH` (default **off**). When on: a request with `X-S43-Password` or an old-style token → 401 "Legacy authentication is no longer accepted." Flip only once `legacy_auth_request_total._all == 0` for the observation window + operator sign-off (per HANDOFF). One-env-var rollback. |

Consumer inventory (grep-verified, non-test): 4 enforcement points, 2 client
sites (`dashboard.js` `_authHeaders` already sends `X-S43-Password` only when
a password is held — no change needed; `websocket.js` auth frame — updated).

---

## 6. Files changed

| File | Change |
|---|---|
| `core/api/routers/auth.py` | `/auth/refresh`, `/auth/logout`; login creates a session + sets cookies for DB accounts; `resolve_session_subject()` (Phase-B gate); `_env_operator_allowed()` (#11); `legacy_auth_request_total` + `S43_REJECT_LEGACY_AUTH`; CSRF/Origin helpers. |
| `core/auth/sessions.py` | `resolve_live_session()` — read-only sid→(session,owner) or raise. |
| `core/api/deps/deps.py` | `require_operator` / `require_admin` — Phase-B dual contract. |
| `core/api/main.py` | `_get_operator` — Phase-B; `dashboard_websocket` — `{token}`-only frame, mid-stream session re-check (`S43_WS_SESSION_RECHECK_SECONDS`), `_ws_safe_close(reason=...)`. |
| `core/api/routers/users.py` | revoke sessions on disable / role change / password reset, in the route's transaction. |
| `dashboard/assets/js/auth.js` (v1.7.0), `websocket.js` (v1.7.0) | refresh-on-load, logout endpoint, `{token}`-only WS frame. |

## 7. Tests

- `test_auth_session_pg.py` (12) — login cookies + sid token, Origin 403,
  refresh rotation, CSRF 403, refresh-after-logout 401, replay→whole-session
  revoke, role-change-at-refresh, session-bound token on `/v1` without a
  password, disabled-user 401, expiry 401, admin-password-reset revokes,
  legacy dual contract.
- `test_ws_session_pg.py` (4) — `{token}`-only connect, legacy needs
  password, legacy with password connects, revoke-mid-stream drops.
- `test_break_glass_pg.py` (4) — #11 four states.
- Regression: `test_auth_login`, `test_jwt_auth`, `test_v1_auth`,
  `test_users_admin`, `test_ws_auth`, `test_service_identity_separation` all
  green (legacy contract preserved). SI script 13/13.

## 8. Not done in Phase 3

- Manual browser smoke of the SPA (no browser here) — the JS changes are
  graceful (refresh failure → login overlay; missing password on a
  session-bound path is fine) but a real operator run is a P6 item.
- Live HTTPS end-to-end through the Compose proxy (P6 stack test).
- `S43_REJECT_LEGACY_AUTH` stays off until the browser smoke + observation
  window + sign-off.
- Multi-replica login throttle — still in-process (P5).
