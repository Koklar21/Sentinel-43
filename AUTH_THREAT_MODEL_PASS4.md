# Sentinel-43 — Authentication Threat Model (Pass 4, design only)

Scope: human/operator authentication for the Sentinel-43 API + dashboard +
WebSocket. Service identities (`AUTH_ARCHITECTURE_PASS4.md` §1.5) are in scope
only for the boundary between them and human auth. **No control described
here is implemented** — "proposed" throughout.

Assets: (1) operator credentials; (2) an authenticated operator/admin session;
(3) the ability to approve/veto Sentinel-43 actions and manage accounts.

---

## 1. Threat → control map

| # | Threat | Today | Proposed control | Residual |
|---|---|---|---|---|
| T1 | **Stolen access token** (XSS, log leak, MITM w/o TLS) | usable 8 h; no revocation; but attacker also needs the password for protected routes | access token 15 min, `aud`-scoped, in JS memory only (not `sessionStorage`). No password needed ⇒ theft = full access for ≤ 15 min. | ≤ 15 min of access on the stateless path; immediate on `/users` (live DB check) and after `/auth/logout` if the `sid`-revocation option (§3.3 arch) is enabled |
| T2 | **Stolen refresh / session credential** | N/A (no refresh today) | opaque 256-bit refresh in `HttpOnly; Secure; SameSite=Strict; Path=/auth` cookie — unreadable by JS. Rotated every refresh; **reuse of a superseded value ⇒ revoke whole session** (theft detection). Stored only as `sha-256`. | attacker with the current cookie value can refresh until they trip rotation-reuse detection or the operator logs out / the absolute cap (7 d) hits |
| T3 | **Stolen reusable password** | password re-sent every request ⇒ huge exposure surface; XSS gets the password | password sent **only** to `POST /auth/login` over the login form; never held after login; `X-S43-Password` removed at migration Phase E | phishing / keylogger on the operator's machine — out of scope for the app |
| T4 | **Browser XSS** | steals the in-memory password + the `sessionStorage` JWT ⇒ persistent-ish full access | steals a ≤ 15-min access token; **cannot** read the `HttpOnly` refresh cookie ⇒ loses access at token expiry unless it also drives `/auth/refresh` from the page (same-origin) while the tab is open | an XSS that stays resident in the tab can keep refreshing. Mitigations are CSP / output encoding / dependency hygiene — dashboard hardening, separate track. The redesign caps the *durable* damage. |
| T5 | **CSRF** | none applicable (no cookies; every request needs an explicit header) | `/auth/refresh` + `/auth/logout` use cookies ⇒ `SameSite=Strict` + a double-submit CSRF token (`s43_csrf` non-HttpOnly cookie echoed in an `X-S43-CSRF` header). Protected API routes stay bearer-header-only ⇒ inherently CSRF-immune. | `SameSite=Strict` gaps on very old browsers — the double-submit token covers it |
| T6 | **Replay of a captured request** | password + token replay works for 8 h | token replay works for ≤ 15 min; no per-request secret to replay | ≤ 15 min; add `jti` + a short-window replay cache only if a concrete replay path is identified (not by default) |
| T7 | **Credential stuffing / brute force** | Pass 3 per-username in-process throttle (per replica) + firewall per-IP (Pass 2, trustworthy IP) | throttle on **both** username and client-IP dimensions; move the counter to the shared DB (`login_attempts`) or Redis for multi-replica; uniform 401 + timing (Pass 3 dummy-verify) | a distributed attacker still gets `throttle_limit` tries per (username, IP) window; acceptable with a low limit + alerting |
| T8 | **Account enumeration** | miss path Pass-3-equalised (dummy Argon2); same 401 detail | keep: identical 401 body + response-time band for unknown / wrong-password / disabled; throttle keyed the same way for all three | statistical timing over many samples — not fully closed; acceptable |
| T9 | **Disabled account** | `authenticate_user` returns `None` ⇒ login 401; `reverify_password` fails ⇒ every protected request 401; `require_admin` re-checks | login rejects; `/auth/refresh` checks `user.is_active` ⇒ session dies at next refresh (≤ 15 min); `require_admin` still immediate; sessions for that user deleted on disablement | ≤ 15 min on `role`-claim-trusting routes (`/v1`, dashboard non-admin) after disablement, unless the `sid` poll is enabled |
| T10 | **Role change / admin demotion mid-session** | `require_admin` catches it immediately for `/users`; `/v1` + dashboard trust the token `role` for ≤ 8 h | on role change: delete that user's sessions ⇒ forced re-login with the new role (immediate for the refresh path); `require_admin` still immediate; `/v1` bounded to ≤ 15 min | ≤ 15 min for `/v1` / dashboard non-admin routes; document it |
| T11 | **Service-token compromise** | out of scope of this redesign; per-service env secret | unchanged. Redesign asserts (test) that a human token can't satisfy a service verifier and vice-versa. Recommend the service tokens also get a documented rotation runbook (Pass 6). | a leaked service token is valid until the operator rotates the env var + restarts |
| T12 | **WebSocket session persistence** | connection lives indefinitely after the initial auth — no exp / disablement / role re-check | on connect: access token only (no password); handler tracks `exp` and closes `1008 token_expired` at expiry; periodic (≤ 60 s) `sid`/`is_active` re-check ⇒ close `1008 session_revoked`; client reconnects with a fresh token | up to the re-check interval (≤ 60 s) of stale access after disablement on an open socket |
| T13 | **Logout / revocation** | no server-side effect | `POST /auth/logout` deletes the session row + clears the cookie. "Log out everywhere" = `DELETE FROM sessions WHERE user_id=?`. | the pre-logout access token still verifies for ≤ its remaining ≤ 15 min (stateless path) |
| T14 | **Database compromise** | reads Argon2 hashes (slow to crack) + the plaintext `S43_JWT_SECRET` is **not** in the DB (env) | + reads `sessions.refresh_hash` (sha-256 of random 256-bit values ⇒ not brute-forceable) and can forge sessions if it can also write. Signing key stays in env. | full DB write compromise = game over regardless (attacker sets `role='admin'`); the redesign doesn't make this worse; adding a DB `role` CHECK (P3-7) narrows it slightly |
| T15 | **Env-var credential compromise** (`.env` leak) | `S43_OPERATOR_PASSWORD_HASH` (SHA-256, un-salted) ⇒ offline brute-force of the operator password; `S43_JWT_SECRET` ⇒ forge any token | **#11**: remove the env operator, or replace SHA-256 with Argon2, or replace with a scoped break-glass token (see `AUTH_MIGRATION_PASS4.md`). `S43_JWT_SECRET` leak ⇒ forge tokens for ≤ 15 min each and mint refresh-less access — the `sessions` table means a forged access token still can't `/auth/refresh` (no session row), and rotating the secret (keyring) kills forgeries immediately. | `.env` leak is severe regardless; the redesign reduces the blast radius of the JWT-secret half |
| T16 | **Logging / telemetry leakage** | `X-S43-Password` in every request ⇒ any request logger / APM / proxy log / `/events/proxy raw` leaks it | password only at `/auth/login`; access token is short-lived; **never log**: password, `X-S43-Password`, full bearer token, refresh value, CSRF token, service tokens. Log `sub`, `sid`, `jti` (first 8 chars), event type, redacted IP. Add `X-S43-Password` / `Authorization` / `Cookie` to any request-logging redaction list until Phase E removes the first. | a misconfigured external proxy still logs `Authorization` unless the operator redacts — documented |
| T17 | **Proxy / header spoofing** | Pass 2 fixed the firewall trusted-proxy handling + uvicorn pin | the throttle's IP dimension and `sessions.client_ip` use the Pass-2 `_resolve_client_ip` result ⇒ trustworthy when `S43_TRUSTED_PROXIES` is set correctly, else the direct peer | if `S43_TRUSTED_PROXIES` is misconfigured to trust too much, the IP dimension is spoofable — Pass 2 documented; the username dimension is unaffected |
| T18 | **Clock skew** (multi-replica) | `verify_jwt_token` has **zero leeway**; `nbf = iat = now` ⇒ a token minted on a replica whose clock is ahead is rejected as "not yet valid" on a replica whose clock is behind | add ±30 s leeway on `iat`/`nbf` (not on `exp` — keep `exp` strict); document an NTP requirement | a replica >30 s skewed still breaks — an ops problem, not an auth problem |
| T19 | **Signing-key rotation** | rotating `S43_JWT_SECRET` invalidates every live session at once (hard logout for all) | `kid` header + `{S43_JWT_SECRET, S43_JWT_SECRET_PREVIOUS}` keyring: sign with current, verify with either. Rotation = set PREVIOUS = old, SECRET = new, redeploy; old tokens keep working for one TTL; then drop PREVIOUS. | a compromised key still lets forgery until PREVIOUS is dropped — the operator chooses immediate (drop both, force re-login) vs graceful |
| T20 | **Multi-replica deployment** | JWT verify is stateless ⇒ fine; the Pass 3 throttle is per-replica ⇒ weaker; WS clients pin to one replica | sessions in the shared DB ⇒ refresh/logout/revocation are replica-agnostic; throttle in the shared DB/Redis; access-token verify stays stateless | the ≤ 15-min stateless-revocation window is the same on every replica — consistent, documented |

---

## 2. Revocation model summary (deliverable H)

**"Instant revocation" is NOT claimed for the stateless access token.** Per
event, the maximum time an already-issued *access token* stays usable:

| Event | Refresh path | `/users` (`require_admin` live check) | `/v1` + dashboard non-admin (trust `role` claim) | Open WebSocket |
|---|---|---|---|---|
| logout | **immediate** (row deleted) | immediate | ≤ access TTL (15 min) | ≤ WS re-check interval (≤ 60 s) |
| password change | **immediate** (all rows for user deleted) | immediate | ≤ 15 min | ≤ 60 s |
| account disablement | **immediate** | **immediate** | ≤ 15 min | ≤ 60 s |
| role change / admin demotion | **immediate** (rows deleted ⇒ re-login) | **immediate** | ≤ 15 min | ≤ 60 s |
| token theft reported (sid known) | **immediate** (that session revoked) | immediate | ≤ 15 min | ≤ 60 s |
| signing-key rotation (drop PREVIOUS) | immediate | immediate | immediate | immediate |

Optional `sid`-revocation poll/LRU in `verify_jwt_token` (arch §3.3) tightens
every "≤ 15 min" above to "≤ poll interval (e.g. 30 s)" at the cost of one
periodic small query per replica. Deferred to a Pass 5 decision.

---

## 3. Failure semantics (deliverable §18)

Sanitized, uniform. Never reveal which specific check failed beyond the
categories below; never echo a credential.

| Condition | HTTP | Body `detail` | WebSocket close | Notes |
|---|---|---|---|---|
| missing credentials | 401 | `Authentication required.` | 1008 `auth_required` then close | + `WWW-Authenticate: Bearer` |
| malformed token | 401 | `Invalid token.` | 1008 `invalid_token` | shape check before crypto (already done) |
| expired token | 401 | `Token has expired.` | 1008 `token_expired` | client should `/auth/refresh` |
| wrong issuer / audience | 401 | `Invalid token.` | 1008 `invalid_token` | do not distinguish iss vs aud |
| bad signature | 401 | `Invalid token.` | 1008 `invalid_token` | |
| disabled account | 401 (login/refresh), 403 (`require_admin`) | `Invalid credentials.` / `Account is not permitted.` | 1008 `session_revoked` | login: identical to wrong-password |
| insufficient role | 403 | `Operator role required.` / `Admin role required.` | 1008 `insufficient_role` | after successful authn |
| revoked session (refresh) | 401 | `Session is no longer valid.` | 1008 `session_revoked` | clear the cookie |
| malformed service token | 401 | `Invalid service token.` | n/a | unchanged (Pass 1) |
| auth backend unavailable (DB down, key unset) | 503 | `Authentication is temporarily unavailable.` | 1011 / 1013 | fail **closed** — never fall open to anonymous |
| throttled | 429 | `Too many failed login attempts. Try again later.` | n/a | `Retry-After` |

**Authentication failure produces no protected side effect** — no partial
action, no DB write, no state change. (Pass 3 already established the
transaction boundary; the redesign preserves it: authn happens before any
route body / commit.)

---

## 4. Audit / logging (deliverable §19)

**Log (structured, one event per line):** `login.success`, `login.failure`
(with a failure category: `unknown` / `bad_password` / `disabled` /
`throttled` — but the *response* stays uniform), `throttle.activated`,
`refresh.success`, `refresh.failure`, `refresh.reuse_detected`,
`logout`, `session.revoked` (with reason: `logout` / `password_change` /
`disablement` / `role_change` / `admin`), `account.disabled`,
`role.changed`, `signing_key.rotated`, `service_auth.failure`
(which verifier, no token).

**Fields:** `event`, `ts`, `sub` (username), `sid` (or `-`),
`jti[:8]`, `client_ip` (redacted per `SENTINEL_LOG_SALT` — the project already
has a log-pseudonymization salt), `user_agent[:120]`, `outcome`, `reason`.

**Never log:** plaintext password, `X-S43-Password` value, full bearer token,
refresh value, `sha-256` refresh hash, CSRF token, any `SENTINEL_REMOTE_TOKEN_*`
/ `S43_*_TOKEN` / `S43_JWT_SECRET`.

Correlation: `sid` ties a login to its later refreshes/logout; `jti[:8]` ties a
specific access token to the requests that used it (if request logging is
added). These are safe to log (opaque, per-session/per-token, not secrets).

---

## 5. Deliberately out of scope

- Dashboard CSP / XSS hardening (own track).
- TLS termination (Pass 6 / operator).
- Service-token rotation runbooks (Pass 6).
- `core/s34_auth/*` deletion (cleanup pass).
- MFA / WebAuthn — no evidence Sentinel-43 beta needs it; a clean later
  addition on top of the `sessions` table.
