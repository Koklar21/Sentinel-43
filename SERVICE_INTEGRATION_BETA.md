# SERVICE_INTEGRATION_BETA.md

Beta-execution Phase 4 — the runnable surface of the supported beta: every
feature mapped to its entrypoint, authentication, permission, dependencies,
and a check; the container network; the deferred findings resolved or
explicitly scheduled.

Companions: `AUTH_SESSION_BETA.md`, `MIGRATION_DEPLOYMENT_BETA.md`,
`deploy/kubernetes/README.md`, `deploy/proxy/README.md`.

---

## 1. Feature → entrypoint map

Auth column: **session** = live session-bound access token (no
`X-S43-Password`); **legacy** = old-style token + `X-S43-Password` (still
accepted, Phase B); **service** = a dedicated env token; **none** =
unauthenticated by design.

| Feature | Method + path | Auth | Permission | Depends on | Check |
|---|---|---|---|---|---|
| Liveness | `GET /health` | none | — | nothing (never touches DB) | `curl -f https://host/health` |
| Readiness | `GET /ready` | none | — | Postgres (schema revision) | `curl -f https://host/ready` → 503 until migrated |
| First-run setup | `GET /bootstrap/status`, `POST /bootstrap/admin` | none (self-gating) | refuses once an admin exists | Postgres `users` | `test_bootstrap_isolated.py`; `curl` status |
| Login | `POST /auth/login` | credentials + Origin | any user; env operator only as break-glass | Postgres `users`+`sessions` | `test_auth_session_pg.py::test_login_*` |
| Refresh | `POST /auth/refresh` | refresh cookie + CSRF + Origin | session owner | Postgres `sessions` | `test_auth_session_pg.py::test_refresh_*` |
| Logout | `POST /auth/logout` | refresh cookie + CSRF | session owner | Postgres `sessions` | `test_auth_session_pg.py::test_refresh_after_logout` |
| Token check | `GET /auth/verify` | Bearer | any operator role | none | `test_auth_login.py` |
| Dashboard actions | `GET /actions`, `POST /actions/{id}/approve|veto`, `GET /vault/stats` | session / legacy | operator | in-memory action store | `test_actions_test_inject_auth.py` |
| Dashboard WS | `WS /ws` | session / legacy first frame | operator | in-memory broadcast; re-checks `sessions`+`users` every `S43_WS_SESSION_RECHECK_SECONDS` | `test_ws_auth.py`, `test_ws_session_pg.py` |
| `/v1` assess/actions | `GET/POST /v1/*` | session / legacy | operator (`require_operator`) | engine + store factories (`S43_ENABLE_DEV_*` or a real `SENTINEL_*_FACTORY`) | `test_v1_auth.py` |
| Account management | `POST/GET/PATCH /users*`, `POST /users/{id}/password` | session / legacy | **admin, live DB check** (`require_admin`) | Postgres `users`+`sessions` | `test_users_admin.py`, `test_auth_session_pg.py::test_admin_password_reset_*` |
| Audit | `/audit/*` | see `routers/audit.py` | operator | — | existing tests |
| Watchtower bridge | `GET /watchtower/health\|ready` | **none** (probe openness, Pass 1) | — | s43-core | `test_watchtower_service_auth.py::test_ready_body_is_minimal` |
| Watchtower bridge (ops) | `GET /watchtower/status\|modules\|check`, `POST /watchtower/register\|heartbeat` | session / legacy operator | operator | s43-core `:9100` + `S43_WATCHTOWER_SERVICE_TOKEN` | `test_watchtower_bridge_auth.py` |
| Watchtower event ingest | `POST /watchtower/events` | **service** (`S43_FENRIR_API_TOKEN`) | Fenrir only | s43-core `/watchtower/analyze` | `test_internal_broadcast_auth.py` (sibling) |
| Internal broadcast | `POST /internal/events/broadcast` | **service** (`S43_FENRIR_API_TOKEN`) | Fenrir only | in-memory broadcast | `test_internal_broadcast_auth.py` |
| Proxy event ingest | `POST /events/proxy` | session / legacy operator | operator | in-memory broadcast | `test_v1_auth`-adjacent; see §3 |
| Remote gateway | `/remote-gateway/*` | **service** per-role (`SENTINEL_REMOTE_TOKEN_{OWNER,ADMIN,AUDITOR}`) | own `OperatorRole` model | — | existing remote-gateway tests |
| Sparta node | `/node/*` | **service** (`S43_SPARTA_NODE_TOKEN`) + body credential | Sparta only | — | existing |
| System/config/rules/deps status | `/system/*`, `/config/*`, `/rules/*`, `/dependencies/*` | session / legacy operator (mutating ones) | operator | s43-core for some | existing |

**Human ≠ service, verified:** `test_service_identity_separation.py` (12) —
no human session/access token satisfies any service verifier and vice versa.
Phase 3 added no such path.

---

## 2. Container network (Compose beta)

```
internet ──443/80──> s43-proxy (nginx, 172.28.0.2, TLS terminator)
                        │ http, X-Forwarded-Proto: https, X-Forwarded-For
                        ▼
                     s43-api:8000  (NOT host-published; expose only)
                        │                         ▲
       ┌────────────────┼──────────────┐          │ s43-core -> s43-api:8000
       ▼                ▼              ▼          │ (Fenrir report bridge, service token)
   s43-db:5432     s43-redis:6379   s43-core:9100 ─┘
   (Postgres)      (provisioned,    (Watchtower; service token on every
                    unused today)    op route; /health,/ready open)

   s43-migrate  ──(one-shot)──> s43-db   [runs `alembic upgrade head`, exits 0,
                                          BEFORE s43-api starts]
```

- DNS: compose service names (`s43-db`, `s43-redis`, `s43-core`, `s43-api`)
  on the `s43_net` bridge (fixed subnet `172.28.0.0/24`).
- Internal ports: Postgres 5432, Redis 6379, Watchtower 9100, API 8000 —
  **none host-published** except through `s43-proxy`.
- Health checks: `s43-db` `pg_isready`; `s43-redis` `redis-cli ping`;
  `s43-api` `GET /health`. `s43-api` `depends_on` s43-db healthy + s43-redis
  healthy + s43-core started + **s43-migrate completed successfully**.
- Shutdown: `s43-api` lifespan stops the heartbeat task, Fenrir, Sparta,
  MonitoringManager with 5s `wait_for` each; `terminationGracePeriodSeconds`
  30 (k8s).
- Retries: `_watchtower_request` has a single `timeout` (`S43_WATCHTOWER_
  TIMEOUT`, 2s) and **no retry loop** — a Watchtower outage degrades the
  bridge routes (they report `reachable: false`), it does not hang the API.
  The k8s migration Job retries via `backoffLimit: 3` (idempotent
  `alembic upgrade head`). No unbounded / non-idempotent retry anywhere.

---

## 3. `/events/proxy` — the two roles stay distinct

- **HTTP ingest**: `POST /events/proxy` — an operator-authenticated ordinary
  JSON POST from a local proxy script. Normalises the event, does **not**
  execute anything, broadcasts it to WS clients on the `"proxy"` channel.
- **WS rebroadcast**: dashboard WS clients subscribed to `"proxy"` receive
  the normalised event. They cannot POST back through the socket.

RELEASE_FINDINGS #19 (proxy ingest rebroadcasts unrestricted `raw`) is
**still open** — the route echoes `body` under `raw`. Beta mitigation: the
route is operator-gated (not anonymous) and the payload is broadcast only to
already-authenticated dashboard sockets. A field allow-list is a small
follow-up; recorded, not fixed here.

---

## 4. Deferred findings — resolved / scheduled

| # | State after Phase 4 |
|---|---|
| **P3-7** `role` CHECK | **DONE** — migration `0003_users_role_check` adds `CHECK (role IN ('operator','admin'))` with a **fail-closed pre-check** (counts violating rows, raises + changes nothing if any exist — the "live-data inventory" §9 asked for). Model `User.__table_args__` matches; `alembic check` clean; up/down/up verified. Tests: `test_migrations_pg.py::test_0003_*`. |
| **P3-8** case-insensitive username/email uniqueness | **Decision: deferred to a post-target migration `0004`, with a precise plan (below).** It is **Informational**, and doing it safely needs (a) a collision inventory on the *real* target data (`SELECT lower(username), count(*) … HAVING count(*)>1`), (b) a coordinated change: functional unique indexes `uq_users_username_lower` / `uq_users_email_lower` + `get_user_by_username()` switched to `func.lower(...) == func.lower(...)` + `create_user`/`bootstrap` case-fold-on-write + `alembic check` reconciliation + test updates. That is a self-contained change but it must run against known data. Not guessed, not rushed into the beta cutover. |
| #6 WS close-helper `reason` | **DONE** in Phase 3 — `_ws_safe_close(reason=...)` on every rejection; `websocket.js` v1.7.0 classifies. |
| #19 proxy `raw` rebroadcast | open; beta-mitigated (operator-gated, authenticated sockets only) — §3. |
| #11 env operator | **closed (scoped)** — `AUTH_SESSION_BETA.md §4`. |
| #13 `S43_SECRETS_ROTATED_AT` not forwarded by Compose | open — P5 item. |
| #14 unauthenticated status routes leak detail | partially — Watchtower side done (Pass 1); the API's own `/config/status` etc. still return `environment` / component names anonymously. Low; recorded. |
| #16 Docker Scout `continue-on-error` | CI-only; the scan still runs, just non-blocking without Docker Hub creds — P5 note. |
| #18 deps/base image not reproducibly locked | `requirements.txt` uses `>=` ranges + the image is `python:3.13-slim` (not digest-pinned). P5 item — see the release-hardening notes. |

### P3-8 migration `0004` plan (not applied)

```
upgrade():
  # 1. fail closed on existing collisions
  assert no rows in
     SELECT lower(username) FROM users GROUP BY 1 HAVING count(*) > 1
     (and the same for lower(email) WHERE email IS NOT NULL)
  # 2. functional unique indexes (keep the existing exact-case ones too)
  CREATE UNIQUE INDEX uq_users_username_lower ON users (lower(username));
  CREATE UNIQUE INDEX uq_users_email_lower    ON users (lower(email))
     WHERE email IS NOT NULL;
downgrade(): drop both.
code (same commit):
  - core/auth/users.py: get_user_by_username -> WHERE lower(username) = lower(:u)
  - core/auth/users.py User.__table_args__: add the two Index(func.lower(...), unique=True)
  - create_user / bootstrap_admin: username = username.strip()  (no case-fold on
    write — store as typed, match case-insensitively) OR .lower() — a product call
  - tests: test_users_admin, test_account_transactions_pg add a case-variant case
```

---

## 5. Not done in Phase 4

- Live container-network exercise (DNS, health ordering, shutdown, a real
  dependency-outage + recovery for each integration) — folded into the P5
  stack smoke.
- External-repo contract validation (medical-triage, Yggdrasil, etc.) — **no
  such integration exists in this repo**; nothing to validate. `/v1` and the
  remote gateway are validated against isolated peers / the dev factories.
