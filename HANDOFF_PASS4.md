# Sentinel-43 — Pass 4 Handoff (authentication redesign — SPECIFICATION ONLY)

- Date: 2026-09-01
- Pass run: **Pass 4 only** — design + threat model + migration + test spec.
- **No authentication implementation.** No runtime code, env var, schema, JWT
  claim, route, header contract, frontend, or dependency was changed.
- Do NOT begin Pass 5 without explicit approval. No push. No deploy.

## Short outcome

Traced the full authentication surface (12+ paths, 5 service-identity
verifiers, a dead `s34_auth/` tree, the browser SPA + WS). Recommend
**Model B — 15-minute access JWT + a server-side refresh session (one new
`sessions` table, no Redis)** to retire the per-request `X-S43-Password`.
Delivered a threat model (T1–T20), a phased migration (A→E) that keeps the
legacy contract working until a single reversible cutover, a #11
recommendation (scoped break-glass token, or removal), and a Pass 5 test
spec + implementation sequence (P5-1..P5-12). Every Pass 1/2/3 invariant is
untouched and remains authoritative; no auth finding is marked resolved.

---

## A. Exact starting / ending state

| Item | Value |
|---|---|
| Work clone / branch | `C:\Users\heero\Sentinel-43-work` · `integration/beta-hardening-20260901` |
| HEAD at start | `93507e7` (Pass 3 handoff); code state `86c9aab` an ancestor |
| `git status` at start | clean · `git fsck` 0 errors · merge-base with `origin/main` = `8d2b80f` · `86c9aab` ancestor of HEAD |
| Changes this pass | **5 new `.md` files only** — `AUTH_ARCHITECTURE_PASS4.md`, `AUTH_THREAT_MODEL_PASS4.md`, `AUTH_MIGRATION_PASS4.md`, `AUTH_TEST_SPEC_PASS4.md`, `HANDOFF_PASS4.md`. `git diff 93507e7 HEAD` for tracked code = empty. |
| HEAD at end | this handoff commit (see `git rev-parse HEAD`) |
| Original OneDrive repo | HEAD `e859b61`, `## main...origin/main [ahead 1]`, fsck 0 — unchanged (re-verified) |

## B. Current authentication architecture

`AUTH_ARCHITECTURE_PASS4.md` §1. Summary:
- **Human:** `POST /auth/login` (username+password, Pass 3 throttle) →
  **HS256 JWT, 8 h default, claims `sub/username/iss/aud/iat/nbf/exp/role/
  user_id`, no `jti`, no `sid`, no revocation, no refresh, no logout.** Then
  **every** protected request re-sends `X-S43-Password` (the reusable
  plaintext password), re-verified with Argon2 (Pass 3: off-loop) or the
  SHA-256 env fallback.
- **Credential stores:** `users` table (Argon2id, no `password_changed_at` /
  `token_version` columns) + env-var operator (SHA-256, un-salted — #11 —
  reached on *any* failed DB auth, not just when the DB is down).
- **WebSocket:** `{token, password}` first frame; connection then lives
  indefinitely with **no** re-check of `exp` / `is_active` / `role`.
- **Service identities (already separate, keep):** `S43_WATCHTOWER_SERVICE_
  TOKEN`, `S43_FENRIR_API_TOKEN`, `S43_ADMIN_TOKEN` (for `/watchtower/state`,
  on top of the service token), `S43_SPARTA_NODE_TOKEN`,
  `SENTINEL_REMOTE_TOKEN_{OWNER,ADMIN,AUDITOR}` (own `OperatorRole` model).
  None accept a human JWT.
- **Dead:** `core/s34_auth/*` — no live importers.

## C. Consumer inventory

`AUTH_MIGRATION_PASS4.md` §1 (C1–C14). Tally: BROWSER 2 · WEBSOCKET 1 ·
HUMAN INTERACTIVE 5 · SERVICE IDENTITY 4 · INTERNAL COMPONENT 3 ·
CLI/AUTOMATION **0 known** · **UNKNOWN 1** (a hypothetical CLI — none in the
repo; recorded UNKNOWN, does not block the migration) · DEAD 1 (`s34_auth`).
Highest-risk: C1 dashboard SPA, C2 dashboard WebSocket, C13 contract tests.

## D. Current wire contract

`AUTH_ARCHITECTURE_PASS4.md` §2.
- **Application-message plaintext credential: YES** — `X-S43-Password` in
  every protected request and the WS frame.
- **On-network plaintext: cannot be asserted** — no TLS termination is
  configured in the repo (compose / Dockerfile / k8s base); the `beta`
  overlay adds an Ingress but leaves TLS to the operator. If a deployment
  runs the API without TLS in front, the password is on the wire.
- **No cookies, no query-string credentials** anywhere (good).
- Cost of re-transmitting a reusable password even under TLS: XSS gets the
  password (not just a token); every request re-exposes it to logs/APM/proxy/
  `/events/proxy raw`; Argon2 per request; full re-login on every browser
  reload.

## E. Threat model summary

`AUTH_THREAT_MODEL_PASS4.md` §1 (T1–T20) maps each threat to a proposed
control and a residual. Headlines:
- T1 stolen access token → 15-min TTL, memory-only, no password ⇒ ≤ 15 min.
- T2 stolen refresh → `HttpOnly` cookie, rotate-every-use, reuse ⇒ revoke session.
- T3/T4 stolen password / XSS → password only at `/auth/login`; XSS gets a
  ≤ 15-min token, not the password or the refresh cookie.
- T10/T12 role change / WS persistence → session revoke on role change; WS
  gets an `exp` + ≤ 60 s `is_active`/`sid` re-check.
- T15 `.env` leak → #11 shrinks the SHA-256 half; `kid` keyring lets a
  `S43_JWT_SECRET` rotation kill forgeries.
- T18 clock skew → add ±30 s `iat`/`nbf` leeway (never on `exp`).

## F. Recommended target architecture

`AUTH_ARCHITECTURE_PASS4.md` §3. **Model B: short-lived access JWT (15 min,
HS256, `+jti +sid`, memory-only client-side) + opaque server-side refresh
session in an `HttpOnly; Secure; SameSite=Strict; Path=/auth` cookie, backed
by one new `sessions` table.** Reuses the existing stateless
`verify_jwt_token` for the request hot path (no per-request DB read).
`POST /auth/refresh` (rotates), `POST /auth/logout` (revokes). `X-S43-Password`
removed at the end of the migration.

Rejected: Model A (short access token only — no logout / no revocation);
Model C (opaque server session — a DB read per request, diverges from the
existing JWT infra).

## G. Token / session design

`AUTH_ARCHITECTURE_PASS4.md` §3.1–3.4.
- Access: HS256, `S43_JWT_SECRET` + `kid` 2-key ring
  (`S43_JWT_SECRET_PREVIOUS`), 15-min default (`S43_JWT_TTL_SECONDS=900`),
  claims `sub, user_id, role, iss, aud, iat, exp, jti, sid` — **no password or
  secret in claims**, ±30 s `iat`/`nbf` leeway, strict `exp`.
- Refresh: 256-bit opaque random, **not a JWT**, stored only as `sha-256`,
  sliding value / fixed absolute cap (~7 d), reuse ⇒ session-wide revoke.
- `sessions(sid, user_id, refresh_hash, issued_at, last_seen_at, expires_at,
  revoked_at, client_ip, user_agent)` — **REQUIRED, additive, a migration**.
- Role: trusted from the token for `/v1` + dashboard (bounded ≤ 15 min);
  `require_admin` keeps its live DB check for `/users`.

## H. Revocation model

`AUTH_THREAT_MODEL_PASS4.md` §2. **"Instant revocation" is NOT claimed for the
stateless access token.** Per event, max time a pre-event access token stays
usable: **immediate** on the refresh path + `/users` + WS re-check (≤ 60 s);
**≤ 15 min** on `/v1` and dashboard non-admin routes (unless the optional
`sid`-revocation poll/LRU is enabled — deferred to a Pass 5 load decision).
Signing-key rotation (drop `PREVIOUS`) is immediate.

## I. Human / service identity separation

`AUTH_ARCHITECTURE_PASS4.md` §4. Human access JWT is `aud=sentinel-43-dashboard`
and only `verify_jwt_token` accepts it. Every service verifier does a
constant-time compare against a specific env secret and never calls
`verify_jwt_token`. The redesign adds **no** path where a human token
satisfies a service verifier or vice-versa. Asserted by `AUTH_TEST_SPEC` MG5,
MG6. No new roles (deliverable §17): keep `{operator, admin}` — Sentinel-43
has no "read-only user" concept and no evidence it needs one.

## J. Browser design

`AUTH_THREAT_MODEL_PASS4.md` T4/T5; `AUTH_ARCHITECTURE_PASS4.md` §3.1.
- Access token → **JS memory variable** (not `sessionStorage`/`localStorage`).
- Refresh token → `HttpOnly; Secure; SameSite=Strict; Path=/auth` cookie —
  unreadable by JS.
- CSRF: `SameSite=Strict` + double-submit (`s43_csrf` non-HttpOnly cookie
  echoed in `X-S43-CSRF`) on `/auth/refresh` + `/auth/logout`. Protected API
  routes stay bearer-header-only ⇒ CSRF-immune.
- Page load ⇒ `POST /auth/refresh` (cookie auto-sent) ⇒ fresh token in memory
  ⇒ **no re-login on reload** (the current model's worst UX).
- Logout ⇒ `POST /auth/logout` ⇒ server deletes session + `Set-Cookie …
  Max-Age=0`.
- CORS: `/auth/refresh` needs `Allow-Credentials: true` + explicit origin
  (already have `S43_ALLOWED_ORIGINS`).

## K. WebSocket design

`AUTH_THREAT_MODEL_PASS4.md` T12; `AUTH_TEST_SPEC_PASS4.md` §F.
- Connect: `{type:"auth", payload:{token}}` — **no password**. No credentials
  in the URL/query (already true).
- Handler tracks the access token's `exp`; closes `1008 token_expired` at
  expiry.
- Periodic (≤ 60 s) `sid`/`is_active` re-check ⇒ close `1008 session_revoked`
  on disablement or role change mid-connection.
- Reconnect: client fetches a fresh token via `/auth/refresh`, reconnects.
- Close codes: `1008` + sanitized reason (`token_expired`, `session_revoked`,
  `origin_rejected`, `insufficient_role`) — no traces, no credentials.

## L. Brute-force design

`AUTH_THREAT_MODEL_PASS4.md` T7/T8; `AUTH_MIGRATION_PASS4.md` M7.
Pass 3 added an in-process per-username lockout (per replica). Production
design: throttle on **both** username and the (Pass-2-trustworthy) client-IP;
move the counter to the shared DB (`login_attempts` table, upsert
`(key, window_start, count)`) — **REQUIRED for multi-replica**, OPTIONAL for
single-replica beta. Redis recommended only at scale. Uniform 401 + timing
band for unknown/wrong/disabled (account-enumeration resistance). **Nothing
added in Pass 4.**

## M. #11 recommendation

`AUTH_MIGRATION_PASS4.md` §3. **Option C — replace the permanent env password
with a scoped break-glass token** (`S43_BREAK_GLASS_TOKEN`, only valid when
`count_active_admins()==0` or explicitly armed, always `role=admin`), **with
Option A (remove entirely)** if the operator confirms nobody uses the env
operator as a routine account. Option B (keep + Argon2) is a breaking `.env`
change that doesn't shrink the "checked on every failed auth" surface — not
recommended. **Decision needs operator input; the `.env` contract is
untouched in Pass 4** (mission §15).

## N. Legacy `X-S43-Password` migration

`AUTH_MIGRATION_PASS4.md` §4. Five phases:
- **A** baseline (today).
- **B** dual contract (backend): add `sessions`/refresh/logout/CSRF/`jti`/`sid`;
  `verify_jwt_token` accepts old + new; `require_*` skip `X-S43-Password` for
  new-style tokens, still require it for old-style.
- **C** migrate consumers (dashboard SPA + WS, #11, any CLI).
- **D** deprecate: `legacy_auth_request_total` metric + rate-limited
  credential-free warning; still accept.
- **E** reject: any `X-S43-Password` or old-style token ⇒ 401; delete
  `reverify_password`, `_validate_env_credentials` (if #11→A), the header.
- **Gate D→E:** `legacy_auth_request_total == 0` for **≥ 16 h** (2× the max
  legacy token TTL) or a beta cycle, **plus operator sign-off**. Phase E is
  one reversible commit (Phase B keeps the legacy code intact until then).

## O. Persistent / infrastructure requirements

`AUTH_ARCHITECTURE_PASS4.md` §6.
- `sessions` table — **REQUIRED** (model B). Additive; the project has **no
  migration tool** (`create_all` only) — Pass 5 must pick one (Alembic
  recommended) or a guarded runner. **STOP for separate authorization.**
- `login_attempts` table (or Redis) — OPTIONAL (single-replica) / REQUIRED
  (multi-replica).
- `users.password_changed_at` — OPTIONAL.
- Redis — **NOT REQUIRED**.
- Asymmetric signing keys + rotation infra — **NOT REQUIRED** (HS256 + 2-key
  `kid` ring suffices; asymmetric is a later separate improvement).
- CSRF cookie/header pair — REQUIRED (small).
- Nothing created in Pass 4/5 without a separate migration authorization.

## P. Compatibility matrix

`AUTH_MIGRATION_PASS4.md` §2 — every consumer × current auth × proposed auth ×
migration required × breaking? × rollback path × test required. Unknown
consumers stay explicitly UNKNOWN; the compat layer (Phases A–D) keeps the
legacy contract working the whole time so an unknown consumer cannot be
silently broken before Phase E.

## Q. Pass 5 test specification

`AUTH_TEST_SPEC_PASS4.md` — sections A (Login, 10), B (Access token, 16),
C (Refresh, 10), D (Logout/revocation, 9), E (Migration/dual-contract, 9),
F (WebSocket, 14), G (Multi-replica, 5 — disposable PG), H (**every Pass 1/2/3
invariant**, re-run unchanged). Coverage gate: A+B+C+E(MG1–6)+F(WS1–8)+H
green before Phase B; **all** of A–H green + `legacy_auth_request_total == 0`
+ operator sign-off before Phase E.

## R. Ordered migration plan

`AUTH_MIGRATION_PASS4.md` §5 (M0–M13). STOP-for-authorization steps: **M1**
(`sessions` table), **M7** (if it adds a table), **M8** (#11 `.env` change).
Breaking step: **M12** (Phase E) — one-commit rollback to Phase D.

## S. Pass 5 implementation sequence

`AUTH_MIGRATION_PASS4.md` §6 (P5-1..P5-12) — each with files-expected-to-change,
behaviour, tests, migration flag, compat effect, rollback point, STOP
condition. **None executed in Pass 4.**

## T. Unresolved questions

`AUTH_ARCHITECTURE_PASS4.md` §7:
1. TLS posture of real deployments (higher priority than the redesign if
   there's no TLS).
2. #11: Option C vs A — operator sign-off.
3. Access-token TTL (15 min vs shorter) — decide with session-table read cost.
4. Enable the `sid`-revocation poll/LRU? — decide with load data.
5. Is multi-replica beta in scope? — drives whether the throttle table is
   required now.
6. Any CLI consumer? — none found; UNKNOWN.
7. Keep `GET /auth/verify` or fold into `/auth/refresh`?
8. Is the dashboard always same-origin with the API? — affects cookie/CORS.
9. (New) Should the remote-gateway mobile operator eventually move to the
   human session model instead of a static per-role token?

## U. Confirmation — no runtime / live / prohibited mutation

Confirmed: **no** modification of runtime authentication behaviour —
`X-S43-Password`, JWT issuance/validation, login, refresh (none added),
session storage (none added), cookies (none added), Redis (none), password
hashing, env-operator auth, WebSocket auth, service-token behaviour, database
schema, migrations, API contracts, frontend auth. No push / force-push /
merge to `main` or `origin/main` / PR / branch-tag-stash-object deletion /
history rewrite / repo-visibility change / original-OneDrive-repo change /
s43 Compose-stack lifecycle command (still `Exited (0)`, untouched) /
live-DB access / credential rotation / deployment / secret disclosure /
recovery-material removal.
Only mutation: 5 documentation commits to the integration branch in the
non-synced work clone (mission §3 authorizes documentation-only commits).
All Pass 1/2/3 security invariants intact; no auth finding marked resolved.

---
Stop. No Pass 5. No implementation. No push. No deploy. Await explicit
authorization for Pass 5.
