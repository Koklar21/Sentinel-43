# Pass 1 — Direct Watchtower Exposure

- Branch: `pass1/watchtower-exposure` (off `release/beta-production-hardening` @ `4e281bc4`)
- Commit: `59e9a73`
- PR: none opened
- Status: **complete**; regression tests pass; live acceptance green for the Pass 1 surface
- Owner: session `sentinel-43-9d` (scope split with `sentinel-43-b8`, who owns
  operator-auth / `deps.py` / firewall-config / docs)

## Proven root cause / defects

| ID | Defect | Proof |
| --- | --- | --- |
| Root cause | The anonymous `200` on `/watchtower/status` came from the separately published Watchtower service (`s43-core:9100`), not an auth-routing failure in the API. | Phase 0A live probes: `:9100/watchtower/status` → 200 anonymous, `:8000/watchtower/status` → 401. |
| F-04 | The entire Watchtower operational + mutation surface was anonymous: `GET /status,/modules,/dependencies,/events/recent`; `POST /analyze,/modules/register,/modules/heartbeat,/dependencies/report`. Only `POST /state/{name}` had a check. | `core/monitoring/watchtower.py` `create_watchtower_router` had no auth dependency on those routes; live probes returned 200 / 422 (past-auth). |
| Exposure | `docker-compose.yml` published `s43-core` `9100:9100` on `0.0.0.0`; only `s43-api` needs it, over `s43_net`. K8s already uses ClusterIP + NetworkPolicy. | `docker-compose.yml:96`; `deploy/kubernetes/base/s43-core-deployment.yaml` Service `type: ClusterIP`. |
| F-01 | `GET :8000/watchtower/modules` (API bridge) returned the full module registry anonymously. | `api_watchtower_modules` omitted the `_require_operator` call its sibling `api_watchtower_status` has. |
| F-02 | `GET :8000/watchtower/check` returned aggregated health/ready/status + the local registration snapshot anonymously. | `watchtower_check` had no auth call. |
| F-05 (partial) | Internal callers sent no auth to the Watchtower. | `core/api/main.py` and `core/monitoring/manager.py` `_watchtower_request` both sent only `Content-Type`. |

## Exact scope

In scope and done:
- Authenticate every Watchtower operational/mutation route with an internal-service
  bearer token (`S43_WATCHTOWER_SERVICE_TOKEN`), fail closed (503) when unset.
- Keep `/watchtower/health` and `/watchtower/ready` open (probe targets).
- Send the token from every internal caller (`core/api/main.py`,
  `core/monitoring/manager.py`).
- Close the two anonymous API-bridge routes (F-01, F-02).
- Remove the `9100` host publication from Compose; align with the K8s posture.
- Carry the new secret through `.env.example`, `core/cli/generate_secrets.py`,
  `deploy/kubernetes/base/secret.example.yaml`, and the K8s README provisioning
  command.
- Regression tests for direct-Watchtower access and the bridge routes.

Deliberately NOT in this pass:
- Human operator authentication redesign (Pass 6).
- `_ws_safe_close` reason propagation (Pass 5).
- `/events/proxy` payload schema / `raw` rebroadcast (Pass 7).
- Firewall config-field mismatch, trusted-proxy handling (Pass 3 — other session).
- Minimising `/watchtower/health` / `/watchtower/ready` / `/` output and the
  `/api/watchtower/*` compat aliases (Pass 5).
- `core/s34_auth/watchtower.py`: dead module (does not import — `NameError` at
  module load, no importers). No live risk; deletion deferred to Pass 8.
- F-06 (Fenrir → Watchtower reporting URL points at a non-existent
  `/watchtower/events` route on `s43-core`, and would use the wrong auth model):
  pre-existing and broken independent of this pass; deferred to Pass 7.

## Files changed (commit `59e9a73`)

| File | Change |
| --- | --- |
| `core/monitoring/watchtower.py` | `_require_service_token` dependency; `dependencies=[Depends(...)]` on `/status`, `/modules`, `/modules/register`, `/modules/heartbeat`, `/dependencies`, `/dependencies/report`, `/events/recent`, `/analyze`, `/state/{name}`; import `Depends`. |
| `core/monitoring/manager.py` | `_watchtower_request` attaches `Authorization: Bearer <token>` (read at call time). |
| `core/api/main.py` | `_watchtower_request` attaches the token; `api_watchtower_modules` and `watchtower_check` now `await _require_operator(request)`. |
| `core/cli/generate_secrets.py` | `S43_WATCHTOWER_SERVICE_TOKEN` added to `_REGISTRY` (required secret). |
| `docker-compose.yml` | remove `s43-core` `9100:9100`; add `S43_WATCHTOWER_SERVICE_TOKEN` to `s43-core` and `s43-api`; header docs. |
| `deploy/kubernetes/base/secret.example.yaml` | document `S43_WATCHTOWER_SERVICE_TOKEN`. |
| `deploy/kubernetes/README.md` | add the key to the `kubectl create secret` command + a note. |
| `.env.example` | document the new required var. |
| `core/tests/test_watchtower_service_auth.py` | **new** — 45 cases. |
| `core/tests/test_watchtower_bridge_auth.py` | **new** — 6 cases. |

## Tests added

`core/tests/test_watchtower_service_auth.py`:
- probe routes (`/health`, `/ready`) reachable with no credential, even when the
  token is unconfigured;
- every guarded route: 401 anonymous, 401 wrong token, 401 non-`Bearer` scheme,
  200 with the token;
- auth runs before body validation (empty `POST /modules/register` → 401, not 422;
  → 422 only once the token is supplied);
- unconfigured server token → 503 on every guarded route (never falls open);
- token never present in a 401 or 503 response body;
- non-ASCII bearer value → clean 401, not a 500 from `secrets.compare_digest`.

`core/tests/test_watchtower_bridge_auth.py`:
- `api_watchtower_modules` / `watchtower_check` raise `HTTPException(401)` when
  unauthenticated;
- both call the operator guard before reaching `_watchtower_request`.

## Commands and exit statuses

| Command | Result |
| --- | --- |
| `python -m pytest core/tests/test_watchtower_service_auth.py core/tests/test_watchtower_bridge_auth.py -q` | **51 passed** |
| `python -m pytest core/tests/ -q` | **132 passed, 3 failed, 3 skipped** — the 3 failures are all `test_bootstrap.py` live HTTP tests failing on `asyncpg InvalidPasswordError` (Postgres role password vs rotated `.env`; see "known issue" below). Not caused by this pass. |
| `docker compose config --quiet` | exit 0 |
| `docker compose build s43-api s43-core` | both images built |
| `docker compose up -d` + health wait | `s43_api` healthy |

## Runtime behavior — before and after (live stack)

| Check | Before | After |
| --- | ---: | ---: |
| Host `curl :9100/watchtower/status` | `200` (anon, full 12 KB node state) | connection refused (port unpublished) |
| `docker ps` s43_core ports | `0.0.0.0:9100->9100` | `8000/tcp` (unpublished) |
| Internal `s43-api → s43-core:9100/watchtower/status`, no token | `200` | `401` |
| Internal, wrong token | `200` | `401` |
| Internal, correct token | `200` | `200` |
| Internal `/watchtower/health`, `/watchtower/ready`, no token | `200` / `503` | `200` / `503` (unchanged — probes) |
| Internal `POST /watchtower/analyze`, no token | `200` (scanned) | `401` |
| Internal `POST /watchtower/modules/register`, no token | `422` (past auth) | `401` |
| `:8000/watchtower/modules` anon | `200` (full registry) | `401` |
| `:8000/watchtower/check` anon | `200` | `401` |
| `:8000/watchtower/status` anon | `401` | `401` (unchanged) |
| `:8000/watchtower/health`, `/ready` anon | `200` | `200` (unchanged) |
| API↔Watchtower registration/heartbeat | worked (anon) | works (token) — `sentinel-43-api` + `sentinel43-monitoring-manager` both registered |
| Token string in a 401/503 body | n/a | absent |

## Known issue surfaced (not a Pass 1 defect)

The other session rotated `.env` (`POSTGRES_PASSWORD` / `DATABASE_URL`) while the
stack was up. The `s43_pgdata` volume still holds the pre-rotation role password.
Recreating `s43-api` for this pass's live test picked up the new `DATABASE_URL`,
so the API now fails to reach Postgres (`asyncpg InvalidPasswordError`). This
blocks 3 DB-backed `test_bootstrap.py` live tests. It does not touch any
Watchtower code path. Fix is `ALTER ROLE s43 WITH PASSWORD '<current .env value>'`
(non-destructive, preserves the one bootstrapped `users` row) or wipe
`s43_pgdata` and re-bootstrap — pending the operator's / other session's call.

## Rollback procedure

- Code: `git checkout release/beta-production-hardening` (this pass is isolated on
  `pass1/watchtower-exposure`; nothing merged). Or `git revert 59e9a73`.
- Live stack: restore the `9100` publication with a `docker-compose.override.yml`
  (`services: {s43-core: {ports: ["9100:9100"]}}`), unset
  `S43_WATCHTOWER_SERVICE_TOKEN` in `.env`, `docker compose up -d --force-recreate
  s43-core s43-api`. With the token unset the Watchtower returns 503 on guarded
  routes (fail closed) — to fully revert to the old anonymous behavior, also
  `git checkout release/beta-production-hardening -- core/monitoring/watchtower.py`
  and rebuild.
- Recovery anchor unchanged: tag `pre-beta-hardening-20260830` → `4e281bc4`.

## Remaining findings deliberately deferred

See `RELEASE_FINDINGS.md` deferred-findings catalog. Pass-1-adjacent items left
for later passes: F-03 (`/watchtower/ready` over-disclosure → Pass 5), F-06
(Fenrir→Watchtower URL/auth → Pass 7), F-07 (`/docs` public → Pass 5),
`core/s34_auth/watchtower.py` removal (Pass 8), `/state/{name}` still depends on
an unset `S43_ADMIN_TOKEN` (fails closed; wire it up in the operator-auth pass).
