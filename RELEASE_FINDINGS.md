# Sentinel-43 — Release Findings Ledger

- Repo: `Sentinel-43` · Base commit: `4e281bc41566097899e0b5161d911e9a34aa9de7` (tag `pre-beta-hardening-20260830`)
- This ledger reflects work from two concurrent sessions: `sentinel-43-b8` (this branch, `release/beta-production-hardening`) and `sentinel-43-9d` (`pass1/watchtower-exposure`, Watchtower exposure/auth). The peer's detailed live-probe evidence (Phase 0A/0B: full route tables, root-cause analysis, F-01..F-07, a Compose-vs-K8s exposure comparison) lives in **their own committed doc, `MISSION_PASS1_WATCHTOWER_EXPOSURE.md` on `pass1/watchtower-exposure`** — not duplicated here to avoid re-losing a second copy of 300+ lines to the file-loss issue noted in `VALIDATION_REPORT.md`. Merge that branch's doc in when the branches merge.

## 19-item prior-review confirm/refute

All 19 confirmed true against `main` @ base commit. None false positive.

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Compose publishes Watchtower on host `9100` | High | **RESOLVED** — `pass1/watchtower-exposure` removed the port publish |
| 2 | Watchtower permits unauthenticated reads/mutations | Critical | **RESOLVED** — `pass1/watchtower-exposure`, service-token auth added |
| 3 | `/watchtower/status` + `/api/watchtower/status` call `_require_operator` | Informational | N/A — working as intended |
| 4 | `/events/proxy` is ordinary HTTP POST | Informational | N/A — confirmed correct, not a defect |
| 5 | `/events/proxy` requires bearer JWT + `X-S43-Password` | Informational | N/A — confirmed correct |
| 6 | `_ws_safe_close` accepts only `websocket`, `code` | Low | **RESOLVED** — beta-execution P3 (commit `1acc423`). `_ws_safe_close(websocket, code, reason)`; every WS rejection now passes a machine reason (`invalid_token`/`invalid_password`/`session_revoked`/`token_expired`/`origin_rejected`/`capacity`); `websocket.js` v1.7.0 classifies auth failures on it. |
| 7 | Firewall trusts XFF when trusted-proxy list is empty | **Critical** | **RESOLVED** — commit `326bed8` (Pass 2). NOTE: previously marked resolved by `3f65ca1`; that commit only fixed the env→field plumbing (finding #8). `_resolve_client_ip()` still trusted `X-Forwarded-For` from any peer when `trusted_proxy_cidrs` was empty (i.e. every default deployment). `326bed8`: empty trusted list ⇒ always the direct peer; when set, right-to-left hop walk. Tests: `test_firewall_proxy_trust.py`. |
| 8 | Firewall shim config keys don't match real fields | **Critical** | **RESOLVED** — commit `3f65ca1`. Re-verified against the real dataclass in Pass 2 (see PASS2_VALIDATION.md field-mapping audit); `_env_cidr_csv` added so a bad CIDR fails at config load. |
| 9 | Firewall init failure allows startup without firewall | High | **RESOLVED** — commit `9164f43` (Pass 2). Firewall registration failure is now a fail-closed `RuntimeError` at startup outside `SENTINEL_ENV` dev/local/test; degrades with a loud error in those envs. Also fixed the pre-existing `core/api/__init__.py` circular import this uncovered. Tests: `test_firewall_config_hardening.py`. |
| 10 | Protected requests resend plaintext password | Medium | Partially addressed — A1 role bypass closed (`5332d54`); Pass 3 moved the per-request Argon2 verify off the event loop and stopped it writing to the DB (commits `49b05a0`, `faf57e1`), so the amplification cost is bounded. The full plaintext-password-removal redesign remains **Pass 4**. |
| 11 | Env-account fallback uses bare SHA-256 | High | **RESOLVED (scoped) — beta-execution P3 (commit `1acc423`).** `_env_operator_allowed()` (`AUTH_MIGRATION_PASS4` §3 Option C): the env operator authenticates ONLY when there is no active DB admin (first-run), the DB is unreachable, or `S43_BREAK_GLASS_ARMED` is set — otherwise it is inert. This removes the "permanent fast-hashed password checked on every failed login" surface without a breaking `.env` change for anyone using it as break-glass. Not removed (Option A) so DB-down recovery still works. Tests: `test_break_glass_pg.py`. _(Original Pass 3 note:)_ **Investigated (Pass 3), deferred to Pass 4.** Reachable: `/auth/login` and `reverify_password()` fall back to `_validate_env_credentials()` (SHA-256 of the typed password vs `S43_OPERATOR_PASSWORD_HASH`, constant-time compare) when the DB is unavailable / has no matching user. Exposure: `S43_OPERATOR_PASSWORD_HASH` is un-salted, fast — brute-forceable offline if `.env` leaks, and there was no login throttle. Pass 3 added a per-username `/auth/login` throttle (commit `faf57e1`) which raises the online cost. Changing the scheme means a breaking `.env` change (operators regenerate the hash) and really belongs with the Pass 4 question "should the env-var operator exist at all" — deferred there with this exposure statement. |
| 12 | `/bootstrap/admin` concurrent first-admin race | Medium | **RESOLVED** — Pass 3, commits `49b05a0` + `9753919`. `create_first_admin()` holds a PostgreSQL transaction advisory lock (`ADMIN_INVARIANT_LOCK_KEY`) from before the `count_active_admins()==0` check through the INSERT and this route's commit. Reproduced against real PostgreSQL 16.3 with independent connections: 8 concurrent contenders created **7** admins pre-fix, **1** post-fix (2/8/20-contender cases). The last-admin invariant on `PATCH /users` uses the same lock. Tests: `test_account_transactions_pg.py` (needs `S43_TEST_PG_DSN`). |
| 13 | Prod requires `S43_SECRETS_ROTATED_AT`; Compose doesn't forward it | Medium | **RESOLVED** — beta-execution P5 (commit `5c06dbe`). Found by the live stack smoke: a non-local API crash-looped in `bootstrap_expectations()`. `docker-compose.yml` now forwards `S43_SECRETS_ROTATED_AT` (+ session env vars); the k8s base ConfigMap gains the same keys (it had none — a beta deploy would have failed too). |
| 14 | Unauthenticated status routes expose internal details | Low-Medium | Not started (this session's remaining lane — API's own `/config/status` etc.; Watchtower-side equivalents resolved by peer) |
| 15 | K8s CI claims to test auth, only requests public endpoints | High | Not started |
| 16 | Docker Scout `continue-on-error: true` | Medium | Not started |
| 17 | Compose runs API/Watchtower as root | High | **RESOLVED (image)** — this branch, commit `c7a7502`. Compose-side volume-ownership note still pending (deferred to avoid colliding with peer's in-flight `docker-compose.yml` edit). |
| 18 | Dependencies/base image not reproducibly locked | Medium | Not started |
| 19 | Proxy event ingestion rebroadcasts unrestricted `raw` | Medium | Not started |

## Additional findings (A1-A6, origin: `sentinel-43-b8`)

| ID | Finding | Severity | Status |
|---|---|---|---|
| A1 | `deps.py` second JWT verifier accepted `scope` claim as `role` substitute — live-exploitable, empirically proven (forged token: 401 on `/v1/assess` vs. 403 on `/watchtower/status` for the identical token) | **Critical** | **RESOLVED** — commit `5332d54` |
| A2 | CORS wildcard methods/headers + credentials, but explicit origin allow-list | — | False positive |
| A3 | ~244 `Koklar21-patch-*` remote branches, only 1 merge-eligible | Informational | Not actioned (Phase 11) |
| A4 | `core/monitoring/Sentinel_firewall .py` — orphaned, malformed filename | Low | Not actioned (recommend delete, see `CLEANUP_INVENTORY.md`) |
| A5 | `docker-compose.yml`'s `s43-setup` references nonexistent `scripts/generate_secrets.py` (real path: `core/scripts/`) | Medium | **RESOLVED** — beta-execution P1 (commit `d529f04`). `s43-setup` entrypoint + the header comments now point at `core/scripts/generate_secrets.py`. |
| A6 | `docs/security/trusted_proxy_handling.md` deleted from `main` | Medium | **RESOLVED** — restored in commit `3f65ca1`; corrected in Pass 2 (`5c…` docs commit) — the doc's "unset ⇒ trust nobody" claim was aspirational, see finding #7. |

## Pass 2 findings (firewall defaults / proxy trust / fail-closed startup)

Integration branch `integration/beta-hardening-20260901`. See `PASS2_VALIDATION.md`.

| ID | Finding | Severity | Status |
|---|---|---|---|
| P2-1 | `blocked_path_prefixes` silently wiped to `()` when `S43_FIREWALL_BLOCKED_PATHS` is unset (every deployment) — the `from_env()` shim passed the field unconditionally, overriding FirewallConfig's built-in dangerous-path list (`/.git`, `/.env`, `/wp-admin`, `/actuator`, `/debug`, `/vendor`, `/node_modules`, …). | **High** | **RESOLVED** — commit `326bed8`. Unset/blank env var ⇒ the dataclass default stands. Tests: `test_firewall_config_hardening.py`. |
| P2-2 | `_resolve_client_ip()` naive leftmost-wins XFF selection — a client can prepend arbitrary entries. | Medium | **RESOLVED** — commit `326bed8`, right-to-left hop walk. |
| P2-3 | RFC 7239 `Forwarded` header is not parsed. | Low | Not a defect — it is *ignored*, so it cannot spoof. Test confirms. Adding a parser is a feature, deferred. |
| P2-4 | Malformed firewall security config (bad bool / int / CIDR) was logged-and-defaulted, not rejected. | Medium | **RESOLVED** — commits `326bed8` (strict `_env_*` / `_parse_networks`) + `9164f43` (fail-closed at startup). |
| P2-5 | uvicorn `--forwarded-allow-ips` unset ⇒ `FORWARDED_ALLOW_IPS=*` (a container copy-paste) makes uvicorn rewrite the client IP from XFF for any peer, before SentinelFirewall. | Medium | **MITIGATED** — commit `52ea75d` pins `--forwarded-allow-ips 127.0.0.1` on the API command (Dockerfile / compose / k8s). Full deploy-time validation of TLS scheme handling deferred to the deployment pass. |

## Pass 3 findings (account transactions / bootstrap concurrency / auth hardening)

Integration branch `integration/beta-hardening-20260901`. See `PASS3_VALIDATION.md`.

| ID | Finding | Severity | Status |
|---|---|---|---|
| P3-1 | Every account helper (`create_user`, `authenticate_user`, `set_user_*`) committed independently. No caller owned the transaction, so `PATCH /users` changing role AND is_active was two transactions — a failure after the first left a partial account. | Medium | **RESOLVED** — commits `49b05a0` / `9753919` / `faf57e1`. Helpers flush, routes commit, `get_db_session` rolls back on error. Tests: `test_account_transactions_pg.py`, `test_password_verification.py`. |
| P3-2 | `authenticate_user()` wrote `last_login_at` + committed on the login path even though the same function ran on every protected request via `reverify_password()`. | Low | **RESOLVED** — `authenticate_user()` is now read-only; `record_login()` (login route only) does the write. |
| P3-3 | Argon2id hash/verify (~34 ms, ~64 MiB) ran on the asyncio event loop; `reverify_password()` runs a verify on every protected request. | Medium | **RESOLVED** — `hash_password_async` / `verify_password_async` (`asyncio.to_thread`, bounded default executor). Test: `test_password_verification.py::test_hashing_does_not_block_the_event_loop`. |
| P3-4 | `verify_password()` only caught `VerifyMismatchError` / `InvalidHash`. A stored hash that is argon2-shaped but corrupt raised `VerificationError` (base) which propagated; a `None`/non-str stored value raised `AttributeError`. | Low | **RESOLVED** — catches `(VerificationError, InvalidHash, TypeError, AttributeError)` ⇒ returns False, fail closed. |
| P3-5 | `POST /auth/login` had no per-credential rate limiting — only the firewall's coarse per-IP 300/60s. | Medium | **MITIGATED** — per-username sliding-window lockout (commit `faf57e1`), in-process. Multi-replica wants Redis (deferred). |
| P3-6 | Account-miss / disabled-account path skipped Argon2 ⇒ responded visibly faster than a wrong password (account-existence timing oracle). | Low | **MITIGATED** — one dummy Argon2 verify on the miss path. Not a hard constant-time guarantee. |
| P3-7 | `User.role` is validated at the application boundary but has **no DB CHECK constraint**. | Low | **RESOLVED** — beta-execution P4 (commit `aa7f2b1`). Migration `0003_users_role_check` adds `CHECK (role IN ('operator','admin'))` with a **fail-closed pre-check** (counts violating rows, raises + changes nothing if any exist — the required live-data inventory). Model `User.__table_args__` matches; `alembic check` clean; up/down/up verified. Tests: `test_migrations_pg.py::test_0003_*`. |
| P3-8 | Usernames/emails stored `.strip()`ed, not case-folded; `unique` is case-sensitive; lookups exact-match. | Informational | **Deferred to migration `0004`, with a precise plan** — `SERVICE_INTEGRATION_BETA.md §4`. Informational; needs a collision inventory on the real target data + a coordinated model + lookup + migration change. Not guessed into the beta cutover. |
| P3-9 | A deployment with zero *active* admins (all deactivated directly in the DB) reopens `/bootstrap/admin`. | Low | **Documented.** The API cannot reach that state — the last-admin guard blocks it. Only direct DB manipulation can. |

## Peer findings F-01..F-07 (origin: `sentinel-43-9d`, detail on `pass1/watchtower-exposure`)

All reported **RESOLVED** on that branch as of their last message: Watchtower service-token auth, `:9100` host publish removed, API-bridge `/watchtower/modules`+`/watchtower/check` now authenticated, minimal `/health`+`/ready` bodies, OpenAPI docs disabled on the internal Watchtower app, Fenrir→Watchtower reporting path fixed. Not independently re-verified by this session — see `VALIDATION_REPORT.md`.

## Not yet audited to the same depth

Rate limiting internals, Sparta integrity monitoring, full K8s overlay diff against every Phase 8 control, migration idempotency, full test-suite auth coverage.

## Reporting requirement

Each fix closes with: root cause · scope · files changed · tests · commands+exit status · commit SHA. Repo is not production-ready until every finding above is RESOLVED or explicitly accepted, and the final deployment gate (blocked, no target — see `RELEASE_HARDENING_PLAN.md`) completes.
