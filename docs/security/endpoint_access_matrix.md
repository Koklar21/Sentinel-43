# Sentinel-43 — Endpoint Access Matrix

Generated as part of the beta endpoint-hardening sprint. This is a
route-by-route inventory of every live FastAPI and WebSocket endpoint,
built by inspecting `app.routes` at runtime and reading each handler's
source — not from memory or the prior handoff doc.

Total live routes found: **65** HTTP routes + **1** WebSocket route + **1**
static mount (`/assets`).

## Access class legend

- **PUBLIC** — deliberately accessible with no credentials.
- **BOOTSTRAP-ONLY** — available only while `count_active_admins() == 0`.
- **AUTHENTICATED** — valid JWT required, no specific role.
- **OPERATOR** — valid JWT with `role` in `{operator, admin}` **and**
  `X-S43-Password` re-verification, via `_require_operator()` /
  `require_operator()` (both now call the same
  `core.api.routers.auth.verify_jwt_token()`).
- **INTERNAL-SERVICE** — dedicated machine/service credential, not a
  dashboard operator JWT.
- **PRIVATE-NOT-ROUTABLE** — registered but unreachable, or not actually
  mounted.

## HTTP routes

| Method | Route | Source file | Access class | Auth mechanism | Unauth result | Unauthorized result | Test coverage |
|---|---|---|---|---|---|---|---|
| GET | `/` | main.py:783 | PUBLIC | none | n/a | n/a | none (low risk, no secrets) |
| GET | `/health` | main.py:1490 | PUBLIC | none | n/a | n/a | none |
| GET | `/ready` | main.py:1499 | PUBLIC | none | n/a | n/a | none |
| GET | `/status` | main.py:1506 | PUBLIC | none | n/a | n/a | none |
| GET | `/version` | main.py:1521 | PUBLIC | none | n/a | n/a | none |
| GET | `/metrics` | main.py:1525 | PUBLIC | none | n/a | n/a | none |
| GET | `/dashboard`, `/dashboard.html` | main.py:944-950 | PUBLIC | none (static HTML shell; login is client-side JS) | n/a | n/a | manual (Phase 8) |
| * | `/assets/*` (StaticFiles mount) | main.py:934 | PUBLIC | none | n/a | n/a | none |
| GET,HEAD | `/docs`, `/docs/oauth2-redirect`, `/openapi.json`, `/redoc` | FastAPI built-in | PUBLIC | none | n/a | n/a | **flagged below** |
| POST | `/auth/login` | auth.py:488 | PUBLIC | credential check inside handler | n/a | 401 wrong creds | test_auth_login.py |
| GET | `/auth/verify` | auth.py:506 | AUTHENTICATED | Bearer JWT only (no password re-check — this route's entire job is "is this token still valid") | 401 | 401 bad/expired/forged, 403 bad role | test_auth_login.py, test_jwt_auth.py |
| GET | `/bootstrap/status` | bootstrap.py:101 | PUBLIC | none (must be, dashboard checks this pre-login) | n/a | n/a | test_bootstrap.py, test_bootstrap_isolated.py |
| POST | `/bootstrap/admin` | bootstrap.py:115 | BOOTSTRAP-ONLY | self-gating on `count_active_admins()==0` | n/a | 409 once initialized | test_bootstrap.py, test_bootstrap_isolated.py |
| GET | `/actions` | main.py:794 | OPERATOR | `_require_operator` | 401 | 403 bad role | test_auth_login.py (protected-route pattern), none route-specific |
| POST | `/actions/test-inject` | main.py:837 | DEV-ONLY + OPERATOR | `SENTINEL_ENV` local + `S43_ENABLE_TEST_INJECTION` flag (fail-closed gate), **then** `_require_operator` once enabled — fixed this pass, see finding #2 | 403 (flag off/prod) | 401/403 once enabled | test_actions_test_inject_auth.py (new) |
| POST | `/actions/{id}/approve` | main.py:814 | OPERATOR | `_require_operator` | 401 | 403 | none route-specific |
| POST | `/actions/{id}/veto` | main.py:843 | OPERATOR | `_require_operator` | 401 | 403 | none route-specific |
| GET | `/governance/pending` | main.py:872 | OPERATOR | `_require_operator` | 401 | 403 | none route-specific |
| GET | `/vault/stats` | main.py:799 | OPERATOR | `_require_operator` | 401 | 403 | none route-specific |
| POST | `/internal/events/broadcast` | main.py:1121 | **was OPERATOR, now INTERNAL-SERVICE** | previously `_require_operator` (broken for its actual caller — see Phase 5 finding) → now dedicated `S43_FENRIR_API_TOKEN` bearer check | 401/503 | 401 | test_internal_broadcast_auth.py (new) |
| POST | `/events/proxy` | main.py:1162 | OPERATOR | `_require_operator` | 401 | 403 | none route-specific — **flagged below** |
| GET | `/watchtower/health` | main.py:1212 | PUBLIC | none | n/a | n/a | none |
| GET | `/watchtower/status` | main.py:1216 | OPERATOR | `_require_operator` | 401 | 403 | test_bootstrap.py (uses this as its "protected route" probe) |
| GET | `/watchtower/ready` | main.py:1224 | PUBLIC | none | n/a | n/a | none |
| POST | `/watchtower/register` | main.py:1230 | OPERATOR | `_require_operator` (already present — prior handoff doc's "missing guard" note was stale) | 401 | 403 | none route-specific |
| POST | `/watchtower/heartbeat` | main.py:1235 | OPERATOR | `_require_operator` (already present — stale note) | 401 | 403 | none route-specific |
| GET | `/watchtower/modules` | main.py:1240 | PUBLIC | none | n/a | n/a | none |
| GET | `/watchtower/check` | main.py:1246 | PUBLIC | none | n/a | n/a | none |
| POST | `/watchtower/events` | main.py:1270 | OPERATOR | `_require_operator` | 401 | 403 | none route-specific |
| GET | `/core/status` | main.py:1293 | PUBLIC | none — **side-effecting** (reports to Watchtower + broadcasts to dashboard WS clients) | n/a | n/a | **flagged below** |
| GET | `/core/health` | main.py:1305 | PUBLIC | none — side-effecting (reports to Watchtower) | n/a | n/a | **flagged below** |
| POST | `/core/heartbeat` | main.py:1311 | PUBLIC | none — side-effecting (reports + broadcasts) | n/a | n/a | **flagged below** |
| GET | `/rules/status`, `/rules/` | main.py:1327-1333 | PUBLIC | none | n/a | n/a | none |
| GET | `/config/status`, `/config/` | main.py:1337-1344 | PUBLIC | none (reveals `SENTINEL_ENV` name only) | n/a | n/a | none |
| GET | `/dependencies/status` | main.py:1348 | PUBLIC | none | n/a | n/a | none |
| POST | `/dependencies/report/{name}/{state}` | main.py:1364 | OPERATOR | `_require_operator` | 401 | 403 | none route-specific |
| GET | `/system/status` | main.py:1376 | OPERATOR | `_require_operator` (already present — stale note) | 401 | 403 | none route-specific |
| GET | `/system/routes` | main.py:1403 | OPERATOR | `_require_operator` | 401 | 403 | none route-specific |
| GET | `/system/intercom/status` | main.py:1418 | OPERATOR | `_require_operator` (already present — stale note) | 401 | 403 | none route-specific |
| GET | `/fenrir/status` | main.py:1463 | OPERATOR | `_require_operator` | 401 | 403 | none route-specific |
| GET | `/fenrir/health` | main.py:1468 | OPERATOR | `_require_operator` | 401 | 403 | none route-specific |
| GET | `/fenrir/metrics` | main.py:1474 | OPERATOR | `_require_operator` | 401 | 403 | none route-specific |
| GET | `/api/ready` | main.py:1540 | PUBLIC | delegates to `ready()` | n/a | n/a | none |
| GET | `/api/status` | main.py:1544 | PUBLIC | delegates to `status()` | n/a | n/a | none |
| GET | `/api/version` | main.py:1548 | PUBLIC | delegates to `version()` | n/a | n/a | none |
| GET | `/api/config` | main.py:1552 | PUBLIC | delegates to `config_root()` | n/a | n/a | none |
| GET | `/api/rules` | main.py:1556 | PUBLIC | delegates to `rules_root()` | n/a | n/a | none |
| GET | `/api/watchtower/status` | main.py:1561 | OPERATOR | delegates to `api_watchtower_status()`, which itself calls `_require_operator` — guard correctly preserved through the compat wrapper | 401 | 403 | none route-specific |
| GET | `/api/watchtower/health` | main.py:1565 | PUBLIC | delegates | n/a | n/a | none |
| GET | `/api/watchtower/ready` | main.py:1569 | PUBLIC | delegates | n/a | n/a | none |
| GET | `/audit/health` | routers/audit.py:8 | PUBLIC | none | n/a | n/a | none |
| GET | `/remote-gateway/health` | remote_gateway.py:821 | INTERNAL-SERVICE | dedicated bearer token (`SENTINEL_REMOTE_TOKEN_*`), constant-time compare, rate-limited, fail-closed if unconfigured | 401/503 | 401 | (remote gateway has its own test coverage — not audited line-by-line this pass) |
| GET | `/remote-gateway/targets` | remote_gateway.py:841 | INTERNAL-SERVICE | same | 401/503 | 401 | same |
| POST | `/remote-gateway/events/activate` | remote_gateway.py:861 | INTERNAL-SERVICE | same + role-claim-vs-token-role mismatch detection (403 + Watchtower CRITICAL alert on mismatch) | 401/503 | 403 on role mismatch | same |
| GET | `/remote-gateway/audit/{correlation_id}` | remote_gateway.py:970 | INTERNAL-SERVICE | same + role-scoped audit visibility | 401/503 | 401 | same |
| POST | `/v1/assess` | routers.py:264 | OPERATOR | `require_operator` dependency on the `/v1` router (now consolidated onto `verify_jwt_token()`) | 401 | 403 | test_v1_auth.py (new) |
| POST | `/v1/actions/{id}/approve` | routers.py:284 | OPERATOR | same | 401 | 403 | none route-specific (covered indirectly by test_v1_auth.py's dependency test) |
| POST | `/v1/actions/{id}/veto` | routers.py:326 | OPERATOR | same | 401 | 403 | same |
| GET | `/v1/actions` | routers.py:376 | OPERATOR | same | 401 | 403 | same |
| GET | `/health` (shadowed) | routers.py:259 (`router.get("/health")`) | PRIVATE-NOT-ROUTABLE | Registered on `watchgate_router`/`router`, but `@app.get("/health")` (main.py:1490) is registered first, so Starlette's first-match routing means this second registration never actually serves a request. Not a security issue — the path it shadows is public anyway — but it is dead code. | — | — | — |
| * | `/node/*` (SpartaCore) | main.py:909-922 | PRIVATE-NOT-ROUTABLE | Import fails at startup (`cannot import name 'SpartaCore' from core.monitoring`), caught and logged as a warning; router is never mounted. Pre-existing, unrelated to auth. | — | — | — |

## WebSocket route

| Route | Access class | Auth mechanism | Notes |
|---|---|---|---|
| `WS /ws` | AUTHENTICATED + OPERATOR (role-gated) | Origin allowlist check → accept → (if `S43_WS_REQUIRE_AUTH`) first-frame `verify_jwt_token()` + `X-S43-Password`-equivalent `password` field via `reverify_password()` | See Phase 6 findings below for the one real gap (no explicit bootstrap-uninitialized gate — see analysis, not necessarily a bug) |

## Findings requiring a decision or flagged for awareness

These are **not** blanket-fixed in this pass — per the hardening spec's own
instruction not to guess from route names, each is listed for Justin's call:

1. **`POST /internal/events/broadcast` was misauthenticated — fixed this pass.**
   The route called `_require_operator()` (dashboard operator JWT +
   `X-S43-Password`), but its only real caller, `FenrirHunter`
   (`core/detection/feniri_hunter.py`), sends `Authorization: Bearer
   <S43_FENRIR_API_TOKEN>` and never an `X-S43-Password` header. Every real
   call from Fenrir was silently rejected with 401 and counted as a
   `broadcast_failure` — the dashboard-broadcast integration for Fenrir
   findings has likely never worked. See Phase 5.

2. **`POST /actions/test-inject` had no operator gate even when enabled —
   fixed this pass.** It's gated by `SENTINEL_ENV` (must be
   `development/dev/local/test`) and `S43_ENABLE_TEST_INJECTION=true`, both
   of which must fail closed in production per `_validate_security_config()`.
   Within a dev/test environment with the flag on, though, any
   unauthenticated caller could inject a synthetic action — a POST with a
   state-mutating effect. The route now calls `_require_operator()` after
   the env/flag check passes, so a disabled route still returns the same
   403 regardless of auth (no new information leak about whether the flag
   is on), but an enabled route now behaves like every other OPERATOR route:
   401 with no token, 403 with a valid token but the wrong role, 200 for a
   real operator. See `test_actions_test_inject_auth.py`.

3. **`GET/POST /core/status`, `/core/health`, `/core/heartbeat` are public
   and side-effecting.** They report to Watchtower and broadcast a
   `dependency_state` WS event on every call, with no auth. Low
   sensitivity (no secrets in the payload), but an unauthenticated caller
   can trigger dashboard broadcast traffic at will. Left public — this
   looks like it's meant to be hit by `s43_core`'s own container/health
   checks — but flagged since a health check normally wouldn't need to
   *mutate* state (broadcast + report) on every poll.

4. **`POST /events/proxy` is OPERATOR-gated but its docstring describes a
   "local proxy script" caller**, which suggests a machine caller similar
   to Fenrir rather than a human operator with a password. Unlike Fenrir,
   there is no dedicated `S43_*_API_TOKEN` env var wired up for this route
   in `docker-compose.yml`, so there's no evidence it's actually broken the
   way `/internal/events/broadcast` was — it may simply mean "run this
   script with an operator's credentials." Left as OPERATOR; flagged for
   Justin to confirm the intended caller.

5. **`GET /docs`, `/redoc`, `/openapi.json` are public** (FastAPI defaults).
   These expose the full route/schema surface (including internal routes)
   to anyone. Common to leave enabled in beta for internal debugging, but
   worth an explicit decision before a public beta — consider gating
   behind `_require_operator` or disabling via
   `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)` in
   production.

6. **`require_initialized` (core/auth/deps.py) is defined but never wired
   into any route.** It re-checks `count_active_admins()` per request and
   fails closed on a DB read error (does not treat a DB error as "zero
   admins" — this was verified, see Phase 3). No HTTP route currently
   requires it. This appears intentional: `/auth/login` deliberately
   supports the DB-then-env-var-fallback path so existing deployments
   still work without ever completing `/bootstrap/admin` (see
   `_validate_credentials()`'s docstring). Wiring `require_initialized`
   into `/auth/login` or elsewhere would remove that fallback and is an
   architecture decision, not a bug fix — not done here, flagged for
   Justin.

7. **`GET /health` is registered twice** (`main.py:1490` and
   `routers.py:259`, both literally `/health`). The first registration
   wins under Starlette's route matching, so the second is dead code, not
   a live behavior difference. No action taken — noted for awareness only.

8. **`/node/*` (SpartaCore) never mounts** due to a pre-existing import
   error (`cannot import name 'SpartaCore' from core.monitoring`), unrelated
   to this sprint. Out of scope; noted so it isn't mistaken for a
   hardening regression if someone diffs the route table later.
