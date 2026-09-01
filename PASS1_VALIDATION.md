# Sentinel-43 — Pass 1 Integration Validation

Exact commands and outcomes. Companion to `RELEASE_FINDINGS.md` /
`VALIDATION_REPORT.md` (which describe the source branches' own validation).

## Integration branch

- Branch: `integration/beta-hardening-20260901`
- Base: `origin/main` @ `8d2b80f95d54c259ee119984fbf4d4f3d3ea9615`
- Integrated commit under test: `431f97c50cfc8fdb275f21a7547ff1c0022acde6`
- Built in a fresh non-synced clone: `C:\Users\heero\Sentinel-43-work`
  (`git clone --no-hardlinks` of the OneDrive repo; `origin` re-pointed at
  GitHub; the OneDrive repo kept as `evidence-local` remote; push disabled
  on both remotes).

## Commit sequence

| SHA | Step | What |
|---|---|---|
| `c0e46a0` | 1 | merge `origin/release/beta-production-hardening` @ `79a9d42` — 0 conflicts |
| `05d844b` | 2 | merge `origin/pass1/watchtower-exposure` @ `6dd3a7e` — 0 conflicts |
| `f8cd8bc` | 3 | user-management feature extracted from `e859b61` (hand-merged into deps.py) |
| `9431356` | 4 | users-router wiring in `core/api/main.py` (from `Koklar21-patch-295950`) |
| `431f97c` | 5 | add `test_health_check_log_filter.py` |

`git merge-tree --write-tree` dry-run before each of steps 1 and 2: exit 0
(clean). Both actual merges: "Automatic merge went well", 0 unmerged paths.

## Security invariants — verified

| ID | Invariant | How verified | Result |
|---|---|---|---|
| SI-1 | `5332d54`: `/v1/*` `require_operator` uses the canonical `verify_jwt_token()`; a `scope="operator"` token with no `role` claim is rejected (403), not accepted. `_verify_operator_jwt` and the module JWT constants are gone. | `git diff release:deps.py deps.py` == exactly the `require_admin` additions; import check (`require_operator` source contains `verify_jwt_token(token)`, no `scope_claim`, no `_verify_operator_jwt`, no `JWT_SECRET` attr); `test_v1_auth.py` (5 cases); Step 7 live check `POST /v1/assess` scope-only token -> **403** | PASS |
| SI-2 | `require_admin` gates `/users`: no auth -> 401; operator (non-admin DB row) -> 403; admin JWT without / with wrong `X-S43-Password` -> 401. Reads role from the live DB, not the JWT claim. | `test_users_admin.py` (25 cases); Step 7 live checks (4/4) | PASS |
| SI-3 | Watchtower bridge (`/watchtower/modules`, `/watchtower/check`, `/watchtower/status`) requires operator auth (F-01/F-02); `/watchtower/health`, `/ready`, `/health` stay open with minimal bodies (F-03). Internal Watchtower app has no `/docs` (F-07). Service-token guard on every operational route, 503 fail-closed when unset. | `test_watchtower_service_auth.py` (53), `test_watchtower_bridge_auth.py` (8); Step 7 live checks (5/5: 3x 401 anon, 2x 200 probe) | PASS |
| SI-4 | `e859b61`'s divergent 16-line `core/monitoring/watchtower.py` variant is NOT present; the integrated file is `pass1`'s version (`326acdfd`). | blob compare: staged == `pass1` (`326acdfd`), != `e859b61` (`96c66ddc`) | PASS |
| SI-5 | `:9100` host publication removed from `docker-compose.yml` (source only — not deployed). | `grep` of `docker-compose.yml`: `s43-core` has no `ports:` block; only a commented `127.0.0.1:9100:9100` rollback hint | PASS (static) |
| SI-6 | Firewall compat shim maps to real `FirewallConfig` fields incl. `trusted_proxy_cidrs` (`3f65ca1`). | `test_firewall_trusted_proxy_config.py` (2); file present from release merge, blob `7c981c86` | PASS |
| SI-7 | users router mounted; `/users` is not 404. | Step 7 SI-4; `test_users_admin.py` reachability | PASS |

## Full test suite

Environment:
- OS: Windows 11 Home (win32)
- Python: 3.13.5
- venv: `C:\Users\heero\Sentinel-43-work\.venv-pass1` (fresh, from `requirements.txt` + `pytest`)
- Key package versions: fastapi 0.141.1, starlette 1.6.0, pydantic 2.13.5,
  httpx 0.28.1, pytest 9.1.1, PyJWT 2.13.0, SQLAlchemy 2.0.52,
  asyncpg 0.31.0, argon2-cffi 25.1.0, aiohttp 3.14.3, anyio 4.14.2
- Env for the run: `S43_WATCHTOWER_URL=http://127.0.0.1:59999`,
  `S43_WATCHTOWER_TIMEOUT=0.2` (so the lifespan's watchtower calls fail fast
  instead of hanging on `s43-core` DNS). No other env set — test modules
  self-configure `S43_JWT_*` via module-level `os.environ.setdefault`.

Command:
```
python -m pytest core/tests/ \
  --ignore=core/tests/test_bootstrap.py \
  --ignore=core/tests/test_system_smoke.py -q
```

Result: **206 passed, 0 failed, 0 skipped, 0 xfail, 0 xpass, exit 0**, ~63 s.
5 unique warning locations (197 occurrences), all benign:
- `StarletteDeprecationWarning: 'HTTP_422_UNPROCESSABLE_ENTITY' is deprecated`
  — emitted by fastapi itself and by `core/api/routers/{users,bootstrap}.py`;
  the codebase uses this constant consistently; newly *visible* only because
  the fresh venv resolved starlette 1.6.0. Not a defect.
- `StarletteDeprecationWarning: Using httpx with starlette.testclient ...` —
  test infra, starlette 1.6.0.
- `ImportWarning: core.monitoring ... 'SpartaCore' unavailable ... No module
  named 'core.monitoring.sparta_core'` — pre-existing (file is
  `core/monitoring/Sparta_core.py`, capital S; import expects lowercase).
  Noted in Pass 0. Not touched by this integration.

Per-file:

| File | Tests |
|---|---|
| test_actions_test_inject_auth.py | 6 |
| test_auth_login.py | 16 |
| test_bootstrap_isolated.py | 4 |
| test_firewall_trusted_proxy_config.py | 2 |
| test_health_check_log_filter.py | 25 |
| test_internal_broadcast_auth.py | 5 |
| test_jwt_auth.py | 37 |
| test_policy_gate_smoke.py | 6 |
| test_users_admin.py | 25 |
| test_v1_auth.py | 5 |
| test_watchtower_bridge_auth.py | 8 |
| test_watchtower_service_auth.py | 53 |
| test_ws_auth.py | 14 |
| **total** | **206** |

Each file also passes when run on its own.

Prior sessions' totals ("144 passed" pass1, "105 passed" release) are NOT
added to or compared against this run — this run is the evidence for the
integrated tree, which contains both branches' new test files plus the
user-management and health-filter tests.

## Not run — and why

| File | Reason | Coverage instead |
|---|---|---|
| `core/tests/test_bootstrap.py` | Hits `http://localhost:8000` over real HTTP; would contact the running Compose stack (POSTs to `/bootstrap/admin`); imports `requests` (not in `requirements.txt` since `requirements-test.txt` was deleted at `8d2b80f`). Authorization forbids live-system contact/mutation. | `test_bootstrap_isolated.py` (in-process, 4 tests, PASS) |
| `core/tests/test_system_smoke.py` | Same — live HTTP smoke against `localhost:8000`. | in-process route tests above |

## Known non-blocking issues surfaced during Pass 1

1. Test-ordering fragility (pre-existing, not introduced): several test
   files — including release's `test_v1_auth.py` and the newly-included
   `test_health_check_log_filter.py` — rely on a sibling module's
   `os.environ.setdefault` running during collection to set `S43_JWT_SECRET`
   before `core.api.main` freezes it at import. In the full suite this holds
   (206/206). In some 2-file partial invocations the app-level test in
   `test_health_check_log_filter.py` fails with
   `RuntimeError: S43_WS_REQUIRE_AUTH=true but S43_JWT_SECRET is not
   configured`. Deferred: a `conftest.py` or per-file env fixture.
2. `require_admin` / the `/users` routes return HTTP 500 (not a clean 503)
   when `DATABASE_URL` is unset — the `Depends(get_db_session)` resolution
   raises `RuntimeError` before `require_admin`'s own try/except runs. Same
   behavior as `core/api/routers/bootstrap.py`'s DB-backed routes. Fails
   closed (no access granted). Real deployments set `DATABASE_URL`. Deferred.
3. `core/api/routers/users.py` uses `status.HTTP_422_UNPROCESSABLE_ENTITY`
   (deprecated alias in starlette 1.6). Matches `bootstrap.py`'s existing
   usage. Cosmetic; bulk-rename candidate for a cleanup pass.

## Provenance note — `e859b61` "Agent Host changes for main"

Read-only local git metadata only (no external contact). Formally
UNCONFIRMED. Evidence: raw object has author == committer ==
`Justin Armstrong <86022347+Koklar21@users.noreply.github.com>`, identical
author/committer timestamps (2026-09-01 12:08:18 -0600), no GPG signature,
message "Agent Host changes for main" with no body/trailers. Committer is
the account's `noreply` identity — NOT `GitHub <noreply@github.com>`, which
is what a github.com web edit uses (cf. `8d2b80f`). Reflog records it as a
plain local `commit:` followed by a `git reset` ~6 min later. No repo hooks;
"Agent Host" appears nowhere in tracked files or `.git/config`. Consistent
with an automated coding-agent/host tool committing the working tree locally
under Justin's git identity. The commit object itself is well-formed
(legit parent `8d2b80f`, fsck-clean tree, content == the known union of
prior work verified in Pass 0). No integrity or security problem. Not
pushed; not modified; not used as the integration base.
