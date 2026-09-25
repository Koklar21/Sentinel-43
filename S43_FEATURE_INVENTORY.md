# Sentinel-43 Feature and Capability Inventory — Discovery-Only Audit

## 1. Audit Scope and Constraints

This is a **discovery and classification pass only**. It establishes what Sentinel-43
actually contains and what the current runtime can actually reach, before the owner
decides what to retain, limit, remove, repair, or develop further.

Presence of a source file, class, import, route declaration, configuration key, test
name, or documentation claim is **not** treated as proof that a capability works.

Governing constraints reaffirmed for this audit: Sentinel-43 remains advisory-first,
human-governed, fail-closed where required security evidence is unavailable, separated
between human and service identities, incapable of autonomous enforcement, and limited to
`SHADOW` and `HUMAN_GATED` governance behavior. This audit does not authorize
remediation, activation, deployment, architectural redesign, or restoration of legacy
code. It does not fix findings, generate remediation code, open a PR, merge, deploy, or
proceed to a second phase without explicit owner authorization.

Prohibited actions for this audit are recorded in full in the mission brief and are not
repeated here; none were performed. See §14 unresolved unknowns / final stop statement.

## 2. Provenance Baseline

| Field | Value |
|---|---|
| Repository path | `C:\Users\heero\OneDrive\Documents\GitHub\Olympus_Complete_Dropin\Sentinel-43` |
| Remote URL | `https://github.com/Koklar21/Sentinel-43.git` |
| Current branch | `main` |
| Local HEAD SHA | `5a249e71cc46a6006eb884da9d16066057cf3d25` |
| Freshly fetched `origin/main` SHA | `5a249e71cc46a6006eb884da9d16066057cf3d25` (identical — no divergence) |
| Commit timestamp | `2026-09-17T13:25:03-06:00` |
| Commit subject | `docs(release): record the Heart-activation wave in the rc1 verification report` |
| Working-tree status before this file was created | Clean (`git status --short` empty) |
| Audit start time (UTC) | `2026-09-18T23:32:12Z` |
| Auditor/session identifier | `claude-code-s43-feature-inventory-20260918` |
| Inventory schema version | `1.0` |

**Entry-gate anomaly (recorded, non-blocking):** `git fetch origin --prune` exited `0`
(success — remote-tracking refs updated, `origin/main` confirmed identical to local
`main`), but printed two non-fatal stderr lines while attempting its worktree-admin
cleanup step:
```
error: failed to delete '.git/worktrees/agent-a546802f175b1654a': Permission denied
error: failed to delete '.git/worktrees/Sentinel-43-baseline': Permission denied
```
These are stale `.git/worktrees/` administrative directories from earlier, unrelated
agent/worktree sessions against this same repo, Windows-locked at the filesystem level.
They did not affect ref-fetching and do not constitute a fetch failure under the letter
of the entry-gate rule (exit code 0). Recorded here rather than silently dropped, per the
audit's own evidentiary standard. Not remediated — remediation is out of scope for this
audit.

**Baseline SHA `5a249e71cc46a6006eb884da9d16066057cf3d25` is fixed for the duration of this
audit.** If repository source changes during the audit, that will be recorded and the
audit will stop rather than mixing evidence across revisions.

## 3. Completion Ledger

| # | Subsystem | Status |
|---|---|---|
| 0 | Provenance and entry gate | COMPLETE |
| 1 | API routers and route registration | COMPLETE |
| 2 | Middleware ordering and request processing | COMPLETE |
| 3 | Human authentication and password handling | COMPLETE |
| 4 | Session issuance, refresh, revocation, CSRF, logout | COMPLETE |
| 5 | Bootstrap, administrator, owner, break-glass workflows | COMPLETE |
| 6 | Roles, scopes, permissions, service-identity separation | COMPLETE |
| 7 | WebSocket auth, subscriptions, event delivery, close behavior | COMPLETE |
| 8 | Audit storage, integrity, retrieval, health, failure behavior | COMPLETE |
| 9 | Watchtower client, node, scanning, health, service auth | COMPLETE |
| 10 | Fenrir detection, reporting, hooks, status, failure behavior | COMPLETE |
| 11 | SpartaCore integrity, monitoring, routing, lifecycle wiring | COMPLETE |
| 12 | Yggdrasil components actually present in this repo | COMPLETE |
| 13 | Remote Gateway routes, role tokens, dispatch, audit, persistence | COMPLETE |
| 14 | Dashboard routes, API/WS clients, approval/veto UI, contracts | NOT STARTED |
| 15 | AI assessment, recommendation, planning, model/provider boundaries | NOT STARTED |
| 16 | Governance modes, staging, approval, veto, escalation, budgets, dedup | NOT STARTED |
| 17 | Persistence layers, DBs, SQLite, migrations, schema, restart recovery | NOT STARTED |
| 18 | Redis references and claims vs. live client/service reality | NOT STARTED |
| 19 | Monitoring, metrics, health, readiness, subsystem registry, status | NOT STARTED |
| 20 | Firewall, trusted proxy/host, CORS, origin, TLS-edge, rate limiting | NOT STARTED |
| 21 | External integrations, adapters, callbacks, outbound networking | NOT STARTED |
| 22 | Workers, background tasks, schedulers, replay, shutdown handling | NOT STARTED |
| 23 | Alembic and other migration paths | NOT STARTED |
| 24 | Dockerfiles, Compose, env propagation, secrets, ports, volumes, users | NOT STARTED |
| 25 | Kubernetes bases/overlays, Services, Ingress, NetPolicy, probes, etc. | NOT STARTED |
| 26 | Deployment/rollback tooling, preflight, backup/restore | NOT STARTED |
| 27 | Administrative and operator-facing capabilities | NOT STARTED |
| 28 | Public-facing capabilities and unauthenticated surfaces | NOT STARTED |
| 29 | Dev-only/test-only/compatibility/deprecated/orphaned/legacy code | NOT STARTED |

## 4. Immediate Critical Findings

### CF-001 — Remote Gateway live-dispatch approve/veto accepts a shared service token as a substitute for human authorization

**Discovered:** Subsystem 13, 2026-09-19. **Classification match:** "Service credentials
accepted as human credentials" (Section 5's own named critical-finding category).

**Exact location:** `core/api/routers/remote_gateway.py`. Authentication:
`_resolve_principal()` (lines 1199-1258), called via `_authenticate()` (lines 1261-1317).
Route: `POST /remote-gateway/events/activate`, function `activate_remote_event` (lines
1731-1887). Handlers actually reachable through it today: `APPROVE_DECISION` and
`VETO_DECISION`, registered in `core/api/main.py::_register_remote_dispatch_handlers`
(lines 1955-2046), each calling `_resolve_governance_and_commit_action` (main.py line
781) — the same governance-commit function behind the human-facing `/actions/{id}/approve`
and `/v1/actions/{id}/approve` routes (Subsystem 1, R-004/R-058).

**The gap, precisely:** `_resolve_principal` never imports, calls, or references
`core.api.routers.auth` (the human login/JWT/session module) anywhere in this file — the
*only* principal type it can ever produce is one of three static, long-lived, pre-shared
bearer tokens (`OperatorRole.OWNER`/`ADMIN`/`AUDITOR`, from
`SENTINEL_REMOTE_TOKEN_OWNER`/`_ADMIN`/`_AUDITOR`), explicitly tagged
`IdentityType.SERVICE_REMOTE_GATEWAY` — a **service** identity, per this codebase's own
`core/security_context.py` distinction (Subsystem 6). The request body's `operator_id`
field (attributed as "who approved/vetoed this" in the resulting governance record) is a
free-text string the caller supplies and is **never checked against any real identity,
session, or human directory** — it is only checked for label *self-consistency* against
the token-derived role, not verified as a real person. Once `_authenticate` accepts the
static token, target/role/permission checks pass, and the durable pre-action audit write
succeeds, `_dispatch_remote_event` calls the approve/veto handler **immediately, in the
same request, with no further identity check, no staged-approval record, and no second
party involved.** A holder of the OWNER or ADMIN gateway token can approve or veto any
`STAGED`/`PENDING` governance action end to end, attributing it to any self-declared
`operator_id` string, without ever touching the human login/session system this whole
repository is otherwise built around (Subsystems 3, 4, 6).

**Reachability / liveness — the mitigating factor, stated precisely, not glossed over:**
this path requires **two independent flags, both defaulting to `False`**
(`SENTINEL_REMOTE_GATEWAY_ENABLED`, `SENTINEL_REMOTE_LIVE_DISPATCH_ENABLED`) to be
explicitly set `true`. Neither appears in `.env.example`, `docker-compose.yml`, or any
Kubernetes manifest in this repository — confirmed by a repo-wide grep across every
`.yml`/`.yaml`/`.env.example` file. **This capability is target-gated and disabled in
every deployment profile this repository ships today.** `.env.example` *does* already
scaffold `SENTINEL_REMOTE_TOKEN_OWNER=CHANGE_ME` / `SENTINEL_REMOTE_TOKEN_ADMIN=CHANGE_ME`
placeholders, confirming this is a real, intentionally-built feature meant for eventual
use, not dead/abandoned code — which is exactly why the gap matters despite being
currently switched off.

**Audit/fail-closed behavior:** the mandatory pre-action durable audit write
(`_require_durable_pre_action_audit`) does fail closed with a 503 outside local/dev if
the audit store is unconfigured or the write fails — but this only guarantees an *audit
trail exists*, it enforces nothing about *who* authorized the action. The post-dispatch
record (`_persist_event_record`) is always best-effort in every environment (never blocks
a response).

**Test coverage:** **zero.** No test in this repository constructs a real HTTP request
to any of the 4 Remote Gateway routes (confirmed by repo-wide grep). The one existing test
file for this module (`test_remote_gateway_audit_persistence.py`) calls internal helper
functions directly and its own header comment explicitly states the mandatory pre-action
gate "has no permanent test here by design... verified via a direct, temporary,
non-committed probe instead." The live-dispatch authorization path itself — the subject
of this finding — has no test of any kind, temporary or permanent.

**Confidence:** High (traced directly from source, both the gap and its current
default-off gating; not exploited, triggered, or tested against a live instance).

**Unresolved questions for the owner:** (1) Is this gap intentional — i.e., is the Remote
Gateway meant to be an operator-to-operator trust boundary where a shared role token
*is* considered sufficient authorization by design, rather than a stand-in for a human
session? (2) If not intentional, should `activate_remote_event`'s `APPROVE_DECISION`/
`VETO_DECISION` handlers require a genuine human-session token (or a second, independent
human confirmation) in addition to the gateway role token before committing a governance
decision? (3) Should `operator_id` be resolved against a real identity directory instead
of accepted as free-text attribution?

**Status:** Recorded and saved to disk immediately upon discovery, surfaced in the same
chat turn (per Section 5, step 9), not exploited/enabled/remediated. Both gating flags
confirmed off in every tracked deployment profile — this audit is continuing to the
remaining subsystems rather than halting entirely, since the capability is confirmed
disabled in every inspected (shipped) runtime configuration, but this finding is flagged
for explicit owner attention rather than being left to surface only in the final matrix.

## 5. Feature Inventory (grouped by subsystem)

### Subsystem 1 — API routers and route registration

**Method:** Full route table pulled by direct introspection of the live `core.api.main.app`
object (`for r in app.routes: ...`, run against baseline SHA `5a249e7`) — 72 entries: 70
HTTP routes + 1 WebSocket route + 1 static mount. This introspection is the
composition/wiring evidence for every entry below and is not repeated per row. Per-route
source line numbers, in-body auth calls, config gates, and test references were then
gathered by a dedicated read-only research pass over `core/api/main.py` and every router
module, cross-referenced against `core/tests/`, `browser_tests/` (incl.
`target_acceptance/`), and `dashboard/tests/`.

**Common facts (apply to many entries; not repeated per row unless a route differs):**
- **Auth pattern A ("operator-inline"):** `await _require_operator(request)` called at the
  top of the function body. This is a plain in-body call, not a FastAPI `Depends()` —
  `core.api.main` has zero `Depends(...)` occurrences anywhere. Human operator identity
  (JWT bearer via session), separate from service identities (Subsystem 6).
- **Auth pattern B ("fenrir-service-inline"):** `_require_fenrir_service_token(request)` —
  service identity, not human. Used only by `/internal/events/broadcast` and
  `/watchtower/events`.
- **Auth pattern C ("gateway-inline"):** `_require_gateway_enabled()` +
  `await _authenticate(request, authorization)` — used only by the 4 Remote Gateway
  routes; principal type (human vs. service) determined inside `_authenticate`, reviewed
  in Subsystem 13, not here.
- **Deployment exposure (default, applies unless a row says otherwise):** `docker-compose.yml`
  documents `s43-api` as **not host-published** in the tracked Compose file — reached only
  via `s43-proxy` ("the only host-facing service" per its own comment) or the internal
  Docker network. The Docker-Desktop Kubernetes dev overlay (confirmed live 2026-09-18,
  separate audit pass) additionally exposes the same app directly via a `LoadBalancer`
  Service `s43-api-lb` on `:30433` with **no TLS/proxy in front** — a dev-only exposure
  path, distinct from the hardened Compose edge. Both are local/dev infrastructure; neither
  is a production edge.
- **Persistence (default):** stateless static response, or a read of in-memory `runtime.*`
  process state, with no durable store of its own — called out per row only when a route
  actually touches Postgres, the audit store, or another durable boundary.
- **Test-evidence caveat:** several tests exercise a handler via a **direct Python function
  call** (e.g. `main_module.operator_findings(...)`) rather than a full HTTP round-trip
  through the ASGI app. This proves the handler's internal logic behaves correctly, but not
  that FastAPI's URL routing/method-matching/param-parsing for that exact path is exercised
  by the *same* test — reachability for those routes is instead established independently
  via the live route-table introspection above. Flagged per row as "(function-call, not
  HTTP)" where it applies.
- **Naming collision caveat:** `core/tests/test_watchtower_service_auth.py` tests a
  **separate, standalone FastAPI app** (`core.monitoring.watchtower.app`, the Watchtower
  core service on port 9100) that happens to share several literal path strings
  (`/watchtower/health`, `/watchtower/status`, `/watchtower/modules`, `/watchtower/ready`)
  with bridge routes in `core.api.main`. Those tests do **not** exercise the
  `core.api.main` routes below despite matching path text — called out per row.

| ID | Route | Class | Consequential | Test strength | Confidence |
|---|---|---|---|---|---|
| R-001 | `GET /` | PRESENT BUT UNPROVEN | read-only | none (only a different app's test shares the path) | Med |
| R-002 | `GET /actions` | PROVEN ACTIVE | read-only | integration (real `client.get`, asserts ledger equality) | High |
| R-003 | `POST /actions/test-inject` | DISABLED OR DEV-ONLY | write | behavioral, 6 dedicated tests | High |
| R-004 | `POST /actions/{id}/approve` | PRESENT BUT UNPROVEN | write | none direct (twin `/v1` route tested instead) | Med |
| R-005 | `POST /actions/{id}/veto` | PRESENT BUT UNPROVEN | write | none direct (twin `/v1` route tested instead) | Med |
| R-006 | `GET /api/config` | PRESENT BUT UNPROVEN | read-only | none | Med |
| R-007 | `GET /api/ready` | PRESENT BUT UNPROVEN | read-only | none direct (delegate's canonical path is tested) | Med |
| R-008 | `GET /api/rules` | PRESENT BUT UNPROVEN | read-only | none | Med |
| R-009 | `GET /api/status` | PRESENT BUT UNPROVEN | read-only | none (log-filter classification text only) | Med |
| R-010 | `GET /api/version` | PRESENT BUT UNPROVEN | read-only | none (log-filter classification text only) | Med |
| R-011 | `GET /api/watchtower/health` | PRESENT BUT UNPROVEN | dispatch | none | Med |
| R-012 | `GET /api/watchtower/ready` | PRESENT BUT UNPROVEN | dispatch | none | Med |
| R-013 | `GET /api/watchtower/status` | PRESENT BUT UNPROVEN | dispatch | none direct (delegate's canonical path is tested) | Med |
| R-014 | `GET /audit/health` | PRESENT BUT UNPROVEN | read-only | none | Med |
| R-015 | `POST /auth/login` | PROVEN ACTIVE | write | behavioral + integration, very extensive (7 files, dozens of tests, incl. browser) | High |
| R-016 | `POST /auth/logout` | PROVEN ACTIVE | write | behavioral + browser | High |
| R-017 | `POST /auth/refresh` | PROVEN ACTIVE | write | behavioral + browser | High |
| R-018 | `GET /auth/verify` | PROVEN ACTIVE | read-only | behavioral, 4+ dedicated tests | High |
| R-019 | `POST /bootstrap/admin` | PROVEN ACTIVE | write | behavioral, 2 files + browser fixture | High |
| R-020 | `GET /bootstrap/status` | PROVEN ACTIVE | read-only | behavioral, 2 files + browser fixture | High |
| R-021 | `GET /config/` | PRESENT BUT UNPROVEN | read-only | none | Med |
| R-022 | `GET /config/status` | PRESENT BUT UNPROVEN | read-only | none (log-filter classification text only) | Med |
| R-023 | `GET /core/health` | PRESENT BUT UNPROVEN | read-only | none | Med |
| R-024 | `POST /core/heartbeat` | PRESENT BUT UNPROVEN | dispatch | none | Med |
| R-025 | `GET /core/status` | PRESENT BUT UNPROVEN | read-only | none | Med |
| R-026 | `GET /dashboard` | PROVEN ACTIVE | read-only | behavioral, extensive browser coverage | High |
| R-027 | `GET /dashboard.html` | PRESENT BUT UNPROVEN | read-only | none direct (alias of tested R-026) | Med |
| R-028 | `POST /dependencies/report/{name}/{state}` | PRESENT BUT UNPROVEN | dispatch | none | Med |
| R-029 | `GET /dependencies/status` | PRESENT BUT UNPROVEN | dispatch | none | Med |
| R-030 | `POST /events/proxy` | PRESENT BUT UNPROVEN | write | none | Med |
| R-031 | `GET /fenrir/health` | PRESENT BUT UNPROVEN | read-only | none | Med |
| R-032 | `GET /fenrir/metrics` | PRESENT BUT UNPROVEN | read-only | none | Med |
| R-033 | `GET /fenrir/status` | PRESENT BUT UNPROVEN | read-only | none | Med |
| R-034 | `GET /governance/pending` | PRESENT BUT UNPROVEN | read-only | skip-only live smoke test (no creds in normal CI = no effective evidence) | Low |
| R-035 | `GET /health` | PROVEN ACTIVE | read-only | behavioral, very extensive | High |
| R-036 | `POST /internal/events/broadcast` | PROVEN ACTIVE | write | behavioral (function-call, not HTTP), 4 files | High |
| R-037 | `GET /metrics` | PRESENT BUT UNPROVEN | read-only | none (log-filter classification text only) | Med |
| R-038 | `GET /operator/findings` | PROVEN ACTIVE | read-only | behavioral (function-call, not HTTP), 12 tests | High |
| R-039 | `GET /ready` | PROVEN ACTIVE | read-only | behavioral, explicit config-gate test coverage | High |
| R-040 | `GET /reliability/failed-events` | PRESENT BUT UNPROVEN | read-only | none (docstring mention only) | Med |
| R-041 | `POST /reliability/replay/{event_id}` | PROVEN ACTIVE | dispatch+write | behavioral (function-call, not HTTP), 12 tests | High |
| R-042 | `GET /reliability/status` | PRESENT BUT UNPROVEN | read-only | none | Med |
| R-043 | `GET /remote-gateway/audit/{correlation_id}` | DISABLED OR DEV-ONLY | read-only | none direct | Med |
| R-044 | `POST /remote-gateway/events/activate` | DISABLED OR DEV-ONLY | dispatch+write | none | Med |
| R-045 | `GET /remote-gateway/health` | DISABLED OR DEV-ONLY | read-only | none | Med |
| R-046 | `GET /remote-gateway/targets` | DISABLED OR DEV-ONLY | read-only | none | Med |
| R-047 | `GET /rules/` | PRESENT BUT UNPROVEN | read-only | none | Med |
| R-048 | `GET /rules/status` | PRESENT BUT UNPROVEN | read-only | none (log-filter classification text only) | Med |
| R-049 | `GET /status` | PROVEN ACTIVE | read-only | integration, smoke suite | High |
| R-050 | `GET /system/intercom/status` | PRESENT BUT UNPROVEN | dispatch | none | Med |
| R-051 | `GET /system/routes` | PRESENT BUT UNPROVEN | read-only | skip-only live smoke test (no effective evidence in normal CI) | Low |
| R-052 | `GET /system/status` | PRESENT BUT UNPROVEN | dispatch | skip-only live smoke test (no effective evidence in normal CI) | Low |
| R-053 | `GET /users` | PROVEN ACTIVE | read-only | behavioral + browser, extensive | High |
| R-054 | `POST /users` | PROVEN ACTIVE | write | behavioral, extensive | High |
| R-055 | `PATCH /users/{id}` | PROVEN ACTIVE | write | behavioral, extensive (10 tests) | High |
| R-056 | `POST /users/{id}/password` | PROVEN ACTIVE | write | behavioral, 3 core tests (+ 1 possibly-mismatched browser test, see drift) | High |
| R-057 | `GET /v1/actions` | PROVEN ACTIVE | read-only | behavioral + integration, multi-file | High |
| R-058 | `POST /v1/actions/{id}/approve` | PROVEN ACTIVE | write | behavioral, 4 tests | High |
| R-059 | `POST /v1/actions/{id}/veto` | PROVEN ACTIVE | write | behavioral, 1 test | Med |
| R-060 | `POST /v1/assess` | PROVEN ACTIVE (as an auth-gated 501 stub — see notes) | read-only | behavioral, 7 tests | High |
| R-061 | `GET /vault/stats` | PRESENT BUT UNPROVEN | read-only | none | Med |
| R-062 | `GET /version` | PROVEN ACTIVE | read-only | behavioral, 2 tests | High |
| R-063 | `GET /watchtower/check` | PROVEN ACTIVE | dispatch | behavioral (function-call, not HTTP), 2 tests | Med |
| R-064 | `POST /watchtower/events` | PROVEN ACTIVE | dispatch+write | behavioral (function-call, not HTTP), very extensive | High |
| R-065 | `GET /watchtower/health` | PROVEN ACTIVE | dispatch | behavioral + integration; see naming-collision caveat | High |
| R-066 | `POST /watchtower/heartbeat` | PRESENT BUT UNPROVEN | dispatch | none | Med |
| R-067 | `GET /watchtower/modules` | PROVEN ACTIVE | dispatch | behavioral (function-call, not HTTP); see naming-collision caveat | Med |
| R-068 | `GET /watchtower/ready` | PRESENT BUT UNPROVEN | dispatch | none for this app; see naming-collision caveat | Med |
| R-069 | `POST /watchtower/register` | PRESENT BUT UNPROVEN | dispatch | none | Med |
| R-070 | `GET /watchtower/status` | PROVEN ACTIVE (auth-gate proven; success-path payload less deeply asserted) | dispatch | behavioral, very extensive; see naming-collision caveat | High |
| R-071 | `WS /ws` | PROVEN ACTIVE | write (long-lived connection state) | behavioral, very extensive (20+ tests, incl. browser) | High |
| R-072 | Static mount `/assets` | PROVEN ACTIVE | read-only | behavioral, 1 browser test | Med |

**Per-entry detail (source evidence, config gates, auth, redundancy/drift, owner
decision — fields not already covered by the table above or the Common Facts block):**

- **R-001** `root` — `core/api/main.py:2484`. No config gate. No auth (public). Owner
  decision: none yet (trivial, low risk).
- **R-002** `dashboard_actions` — `core/api/main.py:2542`. Auth pattern A. Owner decision:
  none yet.
- **R-003** `dashboard_test_inject` — `core/api/main.py:2563`. Gate:
  `if not IS_LOCAL_ENV or not TEST_INJECTION_ENABLED: raise 403` (`S43_ENV`/`SENTINEL_ENV` +
  `S43_ENABLE_TEST_INJECTION`, both closed by default — confirmed `S43_ENABLE_TEST_INJECTION:
  "false"` in the live `sentinel43-config` ConfigMap). Disabling is intentional and
  fail-safe. Owner decision: retain as-is (dev-only, well tested, correctly gated).
- **R-004/R-005** `dashboard_approve_action` / `dashboard_veto_action` —
  `core/api/main.py:2587` / `:2616`. Auth pattern A. **Redundancy/drift:** both delegate to
  the same `_resolve_governance_and_commit_action` used by `/v1/actions/{id}/approve|veto`
  (R-058/R-059), which **are** directly tested — these two are not. Two live route surfaces
  converge on one governance-commit function; one surface has direct test coverage, the
  other doesn't. Owner decision: investigate (add direct coverage for the modern-surface
  routes, or consolidate the two surfaces — consolidation is a repair recommendation only,
  not performed here).
- **R-006 – R-013** (`/api/*` compat aliases) — all pure delegates (`return await
  <canonical_fn>(...)`) to already-covered canonical routes. **Redundancy/drift:** this is
  an intentional compatibility layer (name implies "legacy client shim"), not accidental
  duplication — canonical implementation is the non-`/api/`-prefixed route in every case;
  cited evidence: each alias body is a one-line delegate. Owner decision: retain but limit
  (confirm which external clients still need the `/api/*` shim; each alias otherwise adds
  an untested surface for identical logic).
- **R-014** `audit_health` — `core/api/routers/audit.py:28`. No auth, no gate. Trivial
  static reply. Owner decision: none yet.
- **R-015 – R-018** (auth core) — see `core/api/routers/auth.py:1486/1783/1593/1870`.
  Full detail deferred to Subsystem 3/4 (this row only records route-level facts).
- **R-019/R-020** (bootstrap) — `core/api/routers/bootstrap.py:164/144`, both use real
  FastAPI `Depends(get_db_session)`. Full detail deferred to Subsystem 5.
- **R-021 – R-025, R-047, R-048** — plain operator-gated status/config reads with zero
  test evidence found anywhere in the repo. Owner decision: investigate (cheapest possible
  fix is a smoke-test parametrize addition — not performed here, recommendation only).
- **R-026/R-027** `serve_dashboard` / `serve_dashboard_html` — `core/api/main.py:2389/2396`.
  Gate: file-existence check (`os.path.isfile(DASHBOARD_HTML)` → 404), not an env flag.
  R-027 is a one-line delegate to R-026.
- **R-028/R-029** — `core/api/main.py:4164/4140`. Auth pattern A; both dispatch to the
  external Watchtower service with no test coverage of the failure path (Watchtower
  unreachable). Owner decision: investigate.
- **R-030** `ingest_proxy_event` — `core/api/main.py:3206`. Write is in-memory WS fan-out
  only (`_broadcast_dashboard_event`), no durable audit record of an authenticated
  operator's arbitrary proxy-event payload. Owner decision: investigate (a write path with
  zero test coverage and no durable trail, even though it does require operator auth).
- **R-031 – R-033** (Fenrir status/metrics/health) — `core/api/main.py:4352/4363/4344`, all
  read `_fenrir_snapshot()` (in-process `runtime.fenrir_instance` or a static disabled
  dict). No test coverage found for any of the three.
- **R-034** `governance_pending_reviews` — `core/api/main.py:2645`. The only existing test
  (`test_live_protected_route_rejects_missing_token`) is a live-target smoke test that
  **skips without live credentials** — in an ordinary CI run this provides no effective
  evidence at all, positive or negative, for this route's actual listing behavior. Owner
  decision: investigate — this is the human-facing pending-governance-review list and has
  no meaningful test coverage.
- **R-036** `internal_broadcast_event` — `core/api/main.py:3136`. Auth pattern B. Explicit
  payload-content gate (`body.event_type.startswith("fenrir.")` → 403), not an env flag.
  Confirmed by test to NOT call `_notify_monitoring` (intentional split from R-064).
- **R-039** `ready` — `core/api/main.py:2414`. Explicit gate:
  `if _env_bool("S43_WATCHTOWER_REQUIRED", False): ... unreachable → 503`. Fail-closed by
  design when the flag is set; open (skips the check) when unset — the flag itself is the
  documented, intentional control.
- **R-041** `reliability_replay` — `core/api/main.py:3753`. Auth pattern A. Extensive
  fail-closed behavioral coverage (404 unknown, 422 invalid id, 503 layer unavailable, 409
  already-replayed/in-progress/reconciliation-required, non-2xx on Watchtower
  rejection/unavailability) — one of the best-evidenced consequential routes in the app.
- **R-043 – R-046** (Remote Gateway) — gated by `SENTINEL_REMOTE_GATEWAY_ENABLED`
  (`_require_gateway_enabled()`, `core/api/routers/remote_gateway.py:1475`), confirmed
  default-closed. R-044 additionally requires `SENTINEL_REMOTE_LIVE_DISPATCH_ENABLED` for
  live (non-dry-run) dispatch, plus a mandatory `_require_durable_pre_action_audit(...)`
  pre-check in non-local environments. **This is the single most consequential route
  family in the app (external dispatch) — full governance-gate determination is deferred
  to Subsystem 13 rather than decided here**, since that requires reading `_authenticate`'s
  principal resolution in full. Not classified as an immediate critical finding at this
  evidence level: it is disabled by default at two independent layers and has a mandatory
  audit pre-check; flagged high-priority investigate pending Subsystem 13.
- **R-053 – R-056** (users admin) — `core/api/routers/users.py`. Router-level
  `dependencies=[Depends(require_admin)]` plus, on R-055 specifically, a **second,
  route-level** `Depends(require_admin)` used only so the handler can read the caller's own
  username for the self-deactivation/self-demotion guard — not redundant, a deliberate
  extra binding. **Redundancy/drift:** `browser_tests/target_acceptance/
  test_target_admin_mutation.py::test_password_reset_revokes_the_targets_sessions` calls
  R-056 with `PATCH` and body field `password`, while the real route is `POST` with body
  field `new_password` (per `ResetPasswordRequest`) — worth the owner's attention as a
  possible test/contract drift, not fixed here.
- **R-057 – R-059** (`/v1/actions*`) — `core/api/routers/routers.py`, router-level
  `Depends(require_operator)` plus a local `Depends(dep_request_id)` on every route
  (X-Request-ID validation/generation, `routers.py:109`). R-058/R-059 delegate to the same
  `_resolve_governance_and_commit_action` as R-004/R-005 — see that redundancy note.
- **R-060** `assess` — `core/api/routers/routers.py:227`, a plain `def` (not `async def`).
  **Unconditionally raises HTTP 501** — no code path returns a real assessment. **Drift
  finding:** the route name and path (`/v1/assess`, "ThreatAssessmentIn") strongly imply a
  live AI/threat-assessment capability; the actual implementation is a permanently-stubbed
  501 behind real operator auth. Its test suite (7 tests, well evidenced) proves the *stub*
  behaves correctly and consistently — it does not and cannot prove an assessment
  capability, because none exists at this route. Cross-reference: Subsystem 15 must
  establish whether any *other* code path performs real AI assessment; this route is not
  it. Owner decision: investigate/clarify intent (is this a placeholder for planned work,
  or should the route be removed/renamed to stop implying a capability that doesn't exist).
- **R-061** `dashboard_vault_stats` — `core/api/main.py:2551`. Body contains a **hardcoded
  literal** `"durable_vault": False` (not derived from any env/state read) — this field
  will report `False` forever regardless of actual system state. Flagged as a stub-shaped
  hardcoding worth the owner's attention, not fixed here.
- **R-063 – R-070** (Watchtower bridge routes) — all `core/api/main.py`, all Auth pattern A
  except R-064 (pattern B). All are `dispatch` (call out to the separate Watchtower service
  via `_watchtower_request`/helpers) — none of these routes' tests assert what happens when
  the real outbound call fails except via the dedicated reliability/replay path (R-041) and
  R-064's own dedicated suite; R-063/R-066/R-069's failure behavior is otherwise
  unevidenced.
- **R-071** `dashboard_websocket` — `core/api/main.py:2690`. Gate:
  `if WS_REQUIRE_AUTH:` (`S43_WS_REQUIRE_AUTH`, confirmed `"true"` in the live
  `sentinel43-config` ConfigMap) plus an origin allowlist check against
  `S43_ALLOWED_ORIGINS`. Mutates in-process `runtime.ws_clients`/`client.channels` — a
  long-lived connection is itself the "write."
- **R-072** static `/assets` mount — `core/api/main.py:2381-2385`, conditionally mounted
  only `if os.path.isdir(DASHBOARD_ASSETS_DIR)` (a filesystem check, not an env flag).

**Subsystem status:** COMPLETE
**Entries added:** 72 (R-001–R-072)
**Files inspected:** `core/api/main.py`; `core/api/routers/audit.py`, `auth.py`,
`bootstrap.py`, `users.py`, `routers.py`, `remote_gateway.py`
**Existing tests inspected:** `core/tests/test_v1_legacy_disposition.py`,
`test_actions_test_inject_auth.py`, `test_health_check_log_filter.py`,
`test_auth_login.py`, `test_login_throttle.py`, `test_break_glass_pg.py`,
`test_auth_session_pg.py`, `test_bootstrap.py`, `test_bootstrap_isolated.py`,
`test_users_admin.py`, `test_system_smoke.py`, `test_app_route_registration.py`,
`test_schema_version_pg.py`, `test_security_headers.py`, `test_operator_findings.py`,
`test_monitoring_manager_recent_events.py`, `test_event_reliability.py`,
`test_replay_route_auth.py`, `test_remote_gateway_audit_persistence.py`,
`test_internal_broadcast_auth.py`, `test_fenrir_monitoring_integration.py`,
`test_service_identity_separation.py`, `test_security_context_and_envelope.py`,
`test_jwt_auth.py`, `test_v1_auth.py`, `test_watchtower_bridge_auth.py`,
`test_watchtower_service_auth.py`, `test_ws_auth.py`, `test_ws_session_pg.py`;
`browser_tests/test_session_flow.py`, `browser_tests/conftest.py`,
`browser_tests/target_acceptance/test_target_authenticated.py`,
`test_target_admin_mutation.py`, `test_target_readonly.py`.
**Commands run:** live route-table introspection (`python -c "import core.api.main..."`,
72 routes enumerated); no HTTP requests, no writes, no test execution.
**Immediate findings:** none rising to Section 5's immediate-critical-finding bar at this
evidence level. Highest-priority items carried forward: R-004/R-005 (untested
consequential-action twin of a tested route), R-043–R-046 (Remote Gateway, deferred to
Subsystem 13 for a full human-gate determination), R-060 (`/v1/assess` is a permanent
stub, not an assessment capability), R-061 (hardcoded `durable_vault: False`).
**Unresolved questions:** whether `_authenticate()` in `remote_gateway.py` can resolve a
*service* principal (not just human) sufficient to trigger `/remote-gateway/events/activate`
without a distinct human-approval step — deferred to Subsystem 13.
**UTC completion timestamp:** 2026-09-18T23:58:00Z
**Next subsystem:** 2 — Middleware ordering and request processing

### Subsystem 2 — Middleware ordering and request processing

**Verified execution order.** Confirmed against the actually-installed Starlette source
(`Starlette.add_middleware`/`build_middleware_stack`, read directly, not from memory) —
`add_middleware` inserts each new middleware at index 0 of `user_middleware`, and
`build_middleware_stack` wraps `reversed([ServerErrorMiddleware] + user_middleware +
[ExceptionMiddleware])`. `core/api/main.py` registers, in this order:
`CORSMiddleware` (line 2297) → `SentinelFirewall` (line 2320, inside a try/except) →
`SecurityHeadersMiddleware` (line 2341) → `TrustedHostGuard` (line 2342). Working through
the algorithm gives the **actual request-processing order** (outermost/first to
innermost/last): `ServerErrorMiddleware → TrustedHostGuard → SecurityHeadersMiddleware →
SentinelFirewall → CORSMiddleware → ExceptionMiddleware → router`. Concretely: a bad Host
header is rejected by `TrustedHostGuard` before the firewall ever sees the request; a
CORS preflight (`OPTIONS`) request passes through `TrustedHostGuard`, response-header
injection, and the full `SentinelFirewall` screening/rate-limit pipeline **before**
`CORSMiddleware` gets a chance to short-circuit it — i.e., an attacker sending OPTIONS
floods still consumes firewall rate-limit budget, which is the intended fail-safe
direction (CORS is a browser-trust convenience layer, not a security boundary, so it
correctly sits innermost of the four).

| ID | Feature | Class | Config gate | Failure behavior |
|---|---|---|---|---|
| M-001 | `CORSMiddleware` | PROVEN ACTIVE | origins from `S43_ALLOWED_ORIGINS` | framework default (permissive on same-origin, rejects disallowed origins per CORS spec) |
| M-002 | `SentinelFirewall` (IP/path/header/rate-limit pipeline) | PROVEN ACTIVE | `S43_FIREWALL_ENABLED` (default `true`); many sub-thresholds, see below | **fail-open if disabled via config; fail-closed (raises, blocks app start outside local) if construction fails outside local env; fails OPEN (logs, continues with no firewall) if construction fails inside local/test env** |
| M-003 | `SecurityHeadersMiddleware` | PROVEN ACTIVE | `S43_HSTS_FORCE`/`S43_HSTS_DISABLE`/`S43_HSTS_MAX_AGE`/`S43_CONTENT_SECURITY_POLICY` | malformed env value raises `RuntimeError` **on the first request that hits it** (not at startup — no caching), which propagates to `ServerErrorMiddleware` as a 500 |
| M-004 | `TrustedHostGuard` | PROVEN ACTIVE | `S43_TRUSTED_HOSTS` (empty = **no check at all, fail-open**); `*` forbidden outside local | rejects with plain `400 {"error":"invalid_host"}`; same "re-validated every request, no startup fail-fast" pattern as M-003 |
| M-005 | `dep_request_id` (per-route X-Request-ID validate/generate, `/v1/*` only) | PROVEN ACTIVE | none (always active on `/v1/*`) | fail-open: an unsafe/malformed `X-Request-ID` is logged and silently replaced with a fresh UUID, request proceeds |

**Source evidence:** `core/api/main.py:2297-2342`; `core/api/middleware/security_headers.py`
(full file read, 486 lines); `core/api/middleware/sentinel_firewall_middleware.py` (full
file read, 1212 lines); `core/api/routers/routers.py:109-125`.

**M-002 detail (SentinelFirewall), the richest control in the stack:**
- Pipeline order inside one request: scope-type check → header-parse → client-IP
  resolution (direct peer, or `X-Forwarded-For` only from a configured trusted-proxy CIDR,
  rightmost-untrusted-hop selection) → IP allow/block-list → blocked path
  prefix/substring screen (`/.git`, `/.env`, `/wp-admin`, path-traversal patterns, etc. —
  11 prefixes + 7 substrings, all in the constructor's dataclass defaults, not
  externally configurable) → header-budget (32KB default) + duplicate-Content-Length
  rejection → Content-Length size cap (10MB default) → **traffic-class rate limiting**.
- **Traffic-class rate limiting is genuinely well-designed:** five independent in-memory
  sliding-window limiters, one per `TrafficClass` (`PUBLIC` 300/60s — this is the one that
  gates `/health`/`/ready` too, confirmed in the earlier load-test work this session;
  `INTERNAL_FENRIR` 600/60s for `/internal/*` and `/watchtower/events`; `SPARTA_NODE`
  600/60s for `/node/*`; `REMOTE_GATEWAY` 120/60s for `/remote-gateway/*`; `WEBSOCKET`
  60/60s), each keyed independently per client IP **within its own class**, so a
  malfunctioning internal producer cannot starve operator/public traffic. Behaviorally
  confirmed by `core/tests/test_security_context_and_envelope.py::
  test_exhausted_internal_budget_does_not_starve_operator_traffic` and
  `test_traffic_is_classified_by_route`.
- **Architectural limit (carried forward to Subsystems 20 and 25):** the rate limiter and
  IP-block state are plain in-process Python dicts/deques — **not shared across
  processes**. Running more than one API worker/replica would silently multiply the
  effective rate limit (each process gets its own independent budget) and fragment
  IP-block/rate-limit state per replica. This is consistent with the project's own
  recorded "1-replica/1-worker" constraint from prior hardening passes — this audit did
  not discover a new problem here, but did independently re-derive and confirm *why* that
  constraint exists from the current source, which the prior note did not itself cite.
- **Fail-open surface:** `S43_FIREWALL_ENABLED=false` bypasses the entire pipeline (IP
  block, path block, header budget, rate limiting — all of it) with a single flag. This is
  a legitimate, intentional escape hatch (e.g. for isolated test harnesses — this session's
  own load-test work relied on the firewall staying *on* and simply diversified source
  IPs, not on this flag), not a bug, but it is a single point of total control-bypass worth
  the owner knowing about explicitly.
- **Registration-failure behavior is itself directly tested** — `core/tests/
  test_firewall_config_hardening.py::test_registration_failure_is_fatal_outside_local` and
  `::test_registration_failure_degrades_in_local_env` confirm the exact fail-closed/fail-open
  split at `main.py:2325-2334` is intentional and behaviorally verified, not merely present.
- **A related, lower-layer control exists outside the application:** `core/tests/
  test_firewall_config_hardening.py::test_uvicorn_proxy_pin_beats_forwarded_allow_ips_env`
  and `::test_deployment_files_pin_forwarded_allow_ips` indicate uvicorn's own
  `--proxy-headers`/`--forwarded-allow-ips` flags are pinned in the deployment files and
  interact with this same trusted-proxy trust chain at the ASGI-server layer, below
  `SentinelFirewall` itself. Full deployment-file citation deferred to Subsystem 24.

**M-003/M-004 detail:**
- `SecurityHeadersMiddleware` adds 6 static hardening headers unconditionally
  (`nosniff`/`DENY`/`no-referrer`/COOP/CORP/permissions-policy) and conditionally emits
  HSTS (never in local env unless `S43_HSTS_FORCE`) and an operator-supplied CSP. It never
  rejects a request — response-shaping only.
- `TrustedHostGuard` is the only one of the four that can 400-reject based on the Host
  header. **Its own fail-open condition is explicit and by design:** an empty
  `S43_TRUSTED_HOSTS` disables the check entirely — confirmed by
  `test_no_trusted_hosts_means_no_host_check`. It exempts exactly 7 literal paths from the
  host check (`/health`, `/ready`, `/watchtower/health`, `/watchtower/ready`, `/api/ready`,
  `/api/watchtower/health`, `/api/watchtower/ready`) — note this list is **not** identical
  to the health-check-log-filter's path set nor to `/status`/`/api/status` — a deliberately
  narrow, separately-maintained probe allowlist, confirmed by
  `test_trusted_host_guard_rejects_bad_host_but_exempts_probes`.

**Redundancy/drift:**
- `SecurityHeadersMiddleware` and `SentinelFirewall` **can both be configured to add the
  same security headers** (`SentinelFirewall.add_security_headers`, default `False`, with
  an explicit source comment "Keep false when SecurityHeadersMiddleware is mounted
  separately"). Current default configuration correctly avoids double-adding; this is a
  latent footgun if someone ever flips `S43_FIREWALL_ADD_SECURITY_HEADERS=true` without
  realizing `SecurityHeadersMiddleware` already runs — not a bug today, a configuration
  trap for the future. No env var currently sets this flag in `docker-compose.yml`,
  `loadtest.env`, or the live K8s `sentinel43-config` ConfigMap (confirmed absent from all
  three in earlier sessions this audit draws on).
- Both M-003 and M-004 re-read and re-validate their environment variables **on every
  single request** rather than once at startup (no `lru_cache` on the boolean/int readers,
  unlike `_parse_proxy_networks` which is cached). A misconfigured env value therefore
  doesn't fail fast at deploy time — it fails on the first real request, as a 500. Owner
  decision: investigate (cheap fix: validate once at import/startup time; not performed
  here).

**Test-evidence strength:** behavioral + integration for all 5 entries — `core/tests/
test_security_headers.py` (9 tests), `test_firewall_trusted_proxy_config.py` (2),
`test_firewall_proxy_trust.py` (19, extensive XFF-spoofing/trust-chain coverage),
`test_firewall_config_hardening.py` (17, incl. the registration fail-open/closed tests),
`test_security_context_and_envelope.py` (traffic-classification + budget-isolation tests).
This is, by a wide margin, the best-tested subsystem encountered so far in this audit.

**Owner decision matrix for this subsystem:** retain as-is (M-001, M-002 core pipeline,
M-004); investigate (per-request env re-validation in M-003/M-004; the
dormant `add_security_headers` double-header trap in M-002).

**Subsystem status:** COMPLETE
**Entries added:** 5 (M-001–M-005)
**Files inspected:** `core/api/main.py:2280-2350`; `core/api/middleware/security_headers.py`
(full); `core/api/middleware/sentinel_firewall_middleware.py` (full);
`core/api/routers/routers.py:100-126`; installed `starlette/applications.py` source (for
verified ordering semantics).
**Existing tests inspected (names only, not executed):** `test_security_headers.py`,
`test_firewall_trusted_proxy_config.py`, `test_firewall_proxy_trust.py`,
`test_firewall_config_hardening.py`, `test_security_context_and_envelope.py`.
**Commands run:** `python -c "import starlette, inspect; ..."` (read-only source
introspection of the installed framework; no requests, no writes, no test execution).
**Immediate findings:** none rising to the immediate-critical-finding bar. Two
already-flagged-in-code fail-open conditions (`S43_FIREWALL_ENABLED=false`; empty
`S43_TRUSTED_HOSTS`) are intentional, documented, and behaviorally tested, not silent
defects.
**Unresolved questions:** none blocking; the per-request env re-validation pattern (M-003/
M-004) is a repair recommendation, not an open question.
**UTC completion timestamp:** 2026-09-19T00:24:00Z
**Next subsystem:** 3 — Human authentication and password handling

### Subsystem 3 — Human authentication and password handling

**Source evidence:** `core/auth/users.py` (full file, 843 lines); `core/api/routers/auth.py`
lines 103-804 (throttle, break-glass, credential validation — JWT/session issuance in
lines 804+ deferred to Subsystem 4); `core/auth/deps.py` (full file, 56 lines).

| ID | Feature | Class | Consequential | Test strength | Confidence |
|---|---|---|---|---|---|
| H-001 | Argon2id password hashing (`hash_password`/`verify_password` + async wrappers) | PROVEN ACTIVE | write (hash) / read-only (verify) | behavioral, `test_password_verification.py` (18 tests) | High |
| H-002 | Argon2id hash strict-format validator (`is_valid_argon2id_hash`) | PROVEN ACTIVE | read-only | behavioral, `test_operator_hash_validation.py` (8 tests) | High |
| H-003 | DB-backed credential check with timing-attack equalization (`authenticate_user`) | PROVEN ACTIVE | read-only (+ separate `record_login` write) | behavioral, dedicated timing-miss test | High |
| H-004 | Per-username login-failure throttle/lockout (`_login_check_throttled`/`_login_record_failure`/`_login_clear`) | PROVEN ACTIVE | write (in-memory only) | behavioral, `test_login_throttle.py` (5 tests) | High |
| H-005 | Break-glass env-operator authentication (`_env_operator_allowed`/`_validate_env_credentials`) | PROVEN ACTIVE | read-only | behavioral, `test_break_glass_pg.py` (9 tests) | High |
| H-006 | Standalone password reverification (`reverify_password`) | PROVEN ACTIVE | read-only | behavioral, 3 of the 9 break-glass tests target this specifically | High |
| H-007 | First-admin creation concurrency invariant (`create_first_admin` + `_pg_advisory_xact_lock`) | PARTIALLY WIRED (Postgres only — see finding) | write | behavioral, `test_bootstrap.py`/`test_bootstrap_isolated.py` | Med |

**H-001/H-002 detail:** Explicit, non-default Argon2id parameters (`time_cost=3`,
`memory_cost=64 MiB`, `parallelism=4`, `hash_len=32`, `salt_len=16`) — the module's own
comment states this is deliberate ("Do not inherit library defaults silently"). Hashing
and verification both run through `asyncio.to_thread` so the (CPU-bound) Argon2 work
never blocks the event loop — behaviorally confirmed by
`test_hashing_does_not_block_the_event_loop`, not just asserted in a comment.
`is_valid_argon2id_hash` is a strict-format gate (regex + `extract_parameters` bounds
check on memory/time/parallelism/salt-length/hash-length) used specifically to validate
the **configured** `S43_OPERATOR_PASSWORD_HASH` break-glass secret before it is ever
compared against — confirmed real via `test_malformed_shape_valid_hash_refuses_nonlocal_startup`
(a malformed configured hash is fatal at first use outside local/test) vs.
`test_unconfigured_operator_hash_does_not_itself_block_startup` (simply *absent* is fine —
break-glass is then just unavailable, not a startup blocker).

**H-003 detail — timing-attack mitigation is real, not cosmetic:** `authenticate_user`
always calls `verify_password_async` even when the username doesn't exist or the account
is inactive — against a fixed `_DUMMY_HASH` built from the exact same configured
`PasswordHasher`, so an unknown-username lookup and a wrong-password attempt both pay the
same Argon2 cost. Confirmed behaviorally exercised (not just present) by
`test_authenticate_user_timing_miss_vs_wrong_password`.

**H-004 detail:** In-memory only (`_LOGIN_FAILURES: dict[str, deque]`, module-level,
guarded by a plain `threading.Lock`), keyed by **lowercased username**, not IP — a
distinct axis from `SentinelFirewall`'s IP-keyed rate limiting (Subsystem 2). Same
architectural caveat as the firewall's limiter: **per-process state, not shared across
replicas** — carried forward to Subsystems 20/25 alongside the firewall finding, same root
cause, different subsystem. Bounded to 4096 tracked usernames with stale/oldest eviction.
Config (`S43_LOGIN_MAX_FAILURES`/`S43_LOGIN_FAIL_WINDOW_SECONDS`/`S43_LOGIN_LOCKOUT_SECONDS`)
is strictly validated (raises) outside local env, lenient defaults inside it — same pattern
used throughout this codebase for env parsing.

**H-005/H-006 detail — break-glass is fail-closed by default, with a deliberate,
auditable override:**
- `_env_operator_allowed()` returns `True` only when: `S43_BREAK_GLASS_ARMED=true` is
  explicitly set (checked first, short-circuits without ever touching the DB); **or** no
  database is configured at all (`get_sessionmaker()` raises `RuntimeError` → pure-dev
  convenience); **or** zero active admins currently exist (bootstrap window). If the DB
  *is* configured but the live check itself throws (DB unreachable), the function
  explicitly logs `"denying break-glass"` and returns `False` — **fails closed**, not
  open, on infrastructure failure. The only way to keep human access during a real DB
  outage is the explicit, separately-set `S43_BREAK_GLASS_ARMED` flag — an intentional,
  auditable operator decision, not an automatic fallback.
- Both `_validate_env_credentials` and the DB path use `secrets.compare_digest` on
  SHA-256 digests for the username comparison and the real Argon2 verifier for the
  password — no plain `==` comparison anywhere in this path.
- `reverify_password` (used elsewhere to gate password-reverified operator actions — the
  `X-S43-Password` header pattern referenced across the route audit in Subsystem 1) shares
  the identical fail-closed-unless-armed structure with `_validate_credentials`, confirmed
  by 3 dedicated tests covering the DB-unreachable/armed/wrong-password permutations.

**H-007 finding — the first-admin race-condition lock is Postgres-only:**
`_pg_advisory_xact_lock` checks `session.get_bind().dialect.name` and is a **silent no-op
on any non-`"postgresql"` dialect**, including `sqlite+aiosqlite` (a supported
`DATABASE_URL` scheme per `users.py`'s own `_database_url()` validator). This means the
"only one first-admin can ever be created, even under concurrent bootstrap requests"
invariant is enforced at the database layer only when Postgres is the backend; under
SQLite it relies entirely on the absence of real concurrent writers (true in the current
single-worker/single-replica deployment posture, per the Subsystem 2 finding, but not an
independent guarantee of its own). Classified `PARTIALLY WIRED` rather than `PROVEN
ACTIVE`: the intended end-to-end protection exists and one real segment (Postgres) is
fully connected and tested; the SQLite segment is a documented gap, not exercised by any
concurrency test found in this pass. Owner decision: investigate (decide whether SQLite is
still a supported production-adjacent backend for this invariant, or document the
single-writer assumption explicitly).

**Redundancy/drift:**
- `core/auth/deps.py` (`get_db_session`, `require_initialized`) is a **different module**
  from the `core/api/deps/deps.py` referenced by role-gating dependencies
  (`require_operator`/`require_admin`, used by `core/api/routers/users.py` and
  `routers.py` — see Subsystem 1's `Depends(...)` findings). Two same-named `deps.py`
  files in different packages, with genuinely different responsibilities (DB session
  plumbing here vs. role/JWT gating there) — not a bug, but a naming collision worth the
  owner's awareness; full role-gating detail deferred to Subsystem 6.
- `main.py`'s `_require_operator(request)` (inline, used by ~40 routes per Subsystem 1) and
  this subsystem's `authenticate_user`/`_validate_credentials` are **not the same
  function** — `_require_operator` verifies an already-issued JWT/session, while this
  subsystem's functions are what runs *at login time* to issue one in the first place.
  Not redundant, just noting the boundary explicitly so a future reader doesn't conflate
  "authentication" (this subsystem) with "authorization of an existing session"
  (Subsystem 4/6).

**Subsystem status:** COMPLETE
**Entries added:** 7 (H-001–H-007)
**Files inspected:** `core/auth/users.py` (full), `core/auth/deps.py` (full),
`core/api/routers/auth.py:103-804`.
**Existing tests inspected (names only, not executed):** `test_password_verification.py`
(18 tests), `test_operator_hash_validation.py` (8), `test_break_glass_pg.py` (9),
`test_login_throttle.py` (5), `test_generate_secrets_compose_safe_hash.py` (not read in
detail — compose-escaping concern, cross-referenced from this session's own earlier
load-test work rather than re-derived here), `test_bootstrap.py`/`test_bootstrap_isolated.py`
(first-admin creation).
**Commands run:** none beyond file reads and greps; no requests, no writes, no test
execution.
**Immediate findings:** none rising to the immediate-critical-finding bar. Break-glass is
correctly fail-closed by default; the SQLite advisory-lock gap (H-007) is a real but
non-critical finding (no live exploitation path identified — it requires both a
non-Postgres deployment and genuine concurrent bootstrap requests, neither of which is the
current default posture).
**Unresolved questions:** whether SQLite remains an intended supported backend for
`DATABASE_URL` in any target deployment profile (affects how seriously to weigh H-007).
**UTC completion timestamp:** 2026-09-19T01:05:00Z
**Next subsystem:** 4 — Session issuance, refresh, revocation, CSRF, and logout

### Subsystem 4 — Session issuance, refresh, revocation, CSRF, and logout

**Source evidence:** `core/auth/sessions.py` (full file, 1197 lines);
`core/api/routers/auth.py` lines 804-1486 (JWT issuance/verification, legacy-auth
tracking, cookie helpers, origin check) plus the `login`/`refresh`/`logout`/`verify` route
bodies already located in Subsystem 1 (R-015–R-018).

| ID | Feature | Class | Consequential | Test strength | Confidence |
|---|---|---|---|---|---|
| S-001 | JWT issuance (`_issue_token`) — legacy vs. session-bound TTL split | PROVEN ACTIVE | write (mints a token) | behavioral, exercised throughout `test_auth_login.py`/`test_auth_session_pg.py` | High |
| S-002 | JWT verification (`verify_jwt_token`) — algorithm allowlist, required-claims, sid/jti re-validation | PROVEN ACTIVE | read-only | behavioral, `test_auth_login.py` forged-signature/expired/malformed-token tests + `test_ws_auth.py` (WS reuses the same verifier) | High |
| S-003 | Server-side session persistence (`create_session`/`SessionRecord`) | PROVEN ACTIVE (Postgres); PARTIALLY WIRED (SQLite — see finding) | write | behavioral, `test_auth_session_pg.py` | High/Med |
| S-004 | Refresh rotation + one-time-use reuse detection (`rotate_refresh`) | PROVEN ACTIVE | write | behavioral, `test_replay_of_a_rotated_refresh_value_revokes_the_session` + 5 more in `test_auth_session_pg.py` | High |
| S-005 | Session revocation, single and bulk (`revoke_session`/`revoke_all_user_sessions`) | PROVEN ACTIVE | write | behavioral, exercised via admin-disable/password-reset tests (Subsystem 1 R-055/R-056) + `test_auth_session_pg.py` | High |
| S-006 | Logout (`logout_by_refresh`) | PROVEN ACTIVE | write | behavioral, `test_refresh_after_logout_is_401` + browser tests | High |
| S-007 | CSRF double-submit (`generate_csrf_token`/`csrf_tokens_match`) | PROVEN ACTIVE | read-only (check) / write (issuance) | behavioral, `test_refresh_without_csrf_header_is_403` + browser tests | High |
| S-008 | State-changing-request Origin/Referer enforcement (`_check_state_change_origin`) | PROVEN ACTIVE | read-only (gate) | behavioral, `test_login_rejects_disallowed_origin` + browser `test_refresh_requires_csrf_and_an_allowed_origin` | High |
| S-009 | Legacy (non-session-bound) dual-auth-contract acceptance toggle | PROVEN ACTIVE | read-only (gate) | behavioral, `test_reject_legacy_auth_off_default_still_accepts_legacy` / `test_reject_legacy_auth_on_blocks_legacy_v1_and_users_not_the_session` | High |
| S-010 | Expired-session purge (`purge_expired_sessions`) | **LEGACY OR UNREACHABLE** | write (deletes rows) | none — function is fully implemented and exported but never called outside its own module | Med |

**S-001/S-002 detail:** HS256 JWT (algorithm read from config, but `verify_jwt_token`
passes an explicit `algorithms=[...]` allowlist to `pyjwt.decode` — this closes the
classic "alg confusion" class of JWT vulnerability by construction, not by convention).
Required claims are enforced via PyJWT's own `options={"require": [...]}` (`sub`, `exp`,
`iss`, `aud`, `iat`, `nbf`, `role`) — a token missing any of these is rejected before role
or session checks even run. Session-bound tokens (`sid`+`jti` present) get a shorter
`_session_access_ttl()`; tokens without a `sid` (the "legacy" contract) get a separate,
longer `_legacy_access_ttl()` — two different token lifetimes for two different token
shapes, by design.

**S-003/S-004 finding — the SQLite integrity gap from Subsystem 3 (H-007) recurs here,
as a pattern, not a one-off:** `SessionRecord.__table_args__` declares a unique index on
`refresh_hash` guarded by `postgresql_where="revoked_at IS NULL"` — a Postgres **partial**
index. SQLAlchemy silently omits dialect-specific index options like this on non-matching
dialects, so under `sqlite+aiosqlite` there is **no DB-level uniqueness guarantee on
active refresh hashes at all**. Separately, `rotate_refresh`/`revoke_all_user_sessions`
both rely on `.with_for_update()` row locking to make rotation/revocation atomic under
concurrent requests — SQLite's SQLAlchemy dialect does not provide real row-level locking
semantics for this construct the way Postgres does. **This is now a confirmed
cross-cutting pattern** (H-007 in Subsystem 3, repeated here in S-003/S-004): every
concurrency/integrity guarantee in the account and session layer that depends on a
database-level lock or partial index is Postgres-only, and the codebase's own
`DATABASE_URL` validator (`users.py::_database_url`) treats `sqlite+aiosqlite://` as an
equally supported scheme. None of this is exploitable under the current single-
worker/single-replica deployment posture (Subsystem 2 finding), but it is a latent gap the
moment either assumption changes. Owner decision: investigate (single, repo-wide
decision — either formally scope SQLite to "test-only, never a concurrent-write target,"
or add equivalent SQLite-side protections).

**S-004 detail — reuse detection mechanics, confirmed from source, not just the test
name:** `rotate_refresh` matches the presented secret's hash against *either*
`refresh_hash` (current) or `prev_refresh_hash` (one generation back) via a single
locked `SELECT ... FOR UPDATE`. If the match was only via `prev_refresh_hash` (i.e. an
already-rotated-away credential was replayed), the code does **not** silently reject —
it explicitly revokes the entire session (`reason="refresh_reuse"`) before raising
`RefreshReuseError`. This is a real theft-response, not just a rejected request: a stolen
old refresh cookie, if used even once after the legitimate client has already rotated
past it, burns the whole session for both parties, not just the replay attempt.

**S-005 note:** revocation is reused, not reimplemented, by the admin-facing account
mutations already inventoried in Subsystem 1 — `update_account`/`reset_account_password`
(R-055/R-056) call into this same `revoke_all_user_sessions`. One canonical
implementation, multiple call sites — this is the *good* version of the pattern flagged as
a concern elsewhere (contrast with the two separate governance-commit route surfaces in
Subsystem 1, R-004/005 vs R-058/059, which converge on one function but only one surface
is tested).

**S-007/S-008 detail:** Refresh cookie is `HttpOnly`+`SameSite=Strict`+conditionally
`Secure` (`_cookie_secure()`: forced on outside local, opt-in via
`S43_FORCE_SECURE_COOKIES` inside local), scoped to a restricted path. The CSRF cookie is
deliberately **not** `HttpOnly` (JS must read it to echo into the `X-S43-CSRF` header —
the standard double-submit shape) but still `Secure`+`SameSite=Strict`. Comparison is
`hmac.compare_digest`, not `==`. `_check_state_change_origin` requires a matching
`Origin`, then falls back to parsing `Referer`, and **fails closed outside local** if
neither header is present at all on a cookie-authenticated state-changing request — it
does not silently allow a headerless request through in any non-local environment.

**S-009 detail:** `S43_REJECT_LEGACY_AUTH` (strict boolean outside local, default
`False`) is the flag this session's own earlier load-test work discovered has **no
passthrough at all in the tracked `docker-compose.yml`** — confirmed again here from the
application side: the flag exists, is read, and is behaviorally gated (tests for both the
on and off states pass), but a real Compose deployment that doesn't separately inject it
(as this session's disposable override did) silently runs with legacy dual-auth-contract
acceptance **enabled** rather than the safer default the flag implies it should default
toward once explicitly set. `note_legacy_auth`/`legacy_auth_request_total` maintain an
in-memory, per-process (same architectural caveat as Subsystems 2/3) counter of how often
the legacy contract is actually used — worth checking in Subsystem 19 whether this counter
is surfaced anywhere in `/system/status` or is itself unreachable telemetry.

**S-010 finding:** `purge_expired_sessions` is fully implemented, exported in `__all__`,
and has no caller anywhere in the codebase outside its own module — confirmed by a
repo-wide grep for the symbol, which found only a comment in the `0002_sessions.py`
migration file referencing it as the *intended* housekeeping mechanism. **Expired session
rows are never deleted by anything currently wired into the running application** (no
scheduler, worker, or CLI entry point calls this function — confirmed against Subsystem 22
findings so far). This is not a security defect (expired/revoked rows are already
excluded from every live-session query by `is_live()`/`resolve_live_session`'s expiry
check), but it is an unbounded-growth data-hygiene gap in the `sessions` table. Owner
decision: investigate (wire it into whatever scheduler Subsystem 22 finds, or an explicit
CLI/cron entry — not performed here).

**Subsystem status:** COMPLETE
**Entries added:** 10 (S-001–S-010)
**Files inspected:** `core/auth/sessions.py` (full); `core/api/routers/auth.py:804-1486`.
**Existing tests inspected (names only, not executed):** `test_auth_session_pg.py`
(11 tests), `test_auth_login.py` (token-verification subset), `test_ws_auth.py`
(shared-verifier subset), `test_v1_legacy_disposition.py` (legacy-auth-contract subset).
**Commands run:** repo-wide grep for `purge_expired_sessions` (no execution; confirms
unreachability). No requests, no writes, no test execution.
**Immediate findings:** none rising to the immediate-critical-finding bar. S-010 (dead
housekeeping function) and the SQLite integrity-gap pattern (S-003/S-004, echoing H-007)
are both real but non-critical under current deployment posture.
**Unresolved questions:** same SQLite-scope question raised in Subsystem 3 (H-007) —
resolving it there resolves it here too; not re-opened as a separate question.
**UTC completion timestamp:** 2026-09-19T01:42:00Z
**Next subsystem:** 5 — Bootstrap, administrator, owner, and break-glass workflows

### Subsystem 5 — Bootstrap, administrator, owner, and break-glass workflows

**Source evidence:** `core/api/routers/bootstrap.py` (full file, 222 lines);
`core/api/routers/users.py` lines 372-450 (`update_account`'s guards); repo-wide grep for
`LastAdminError` and `owner`.

**Terminology finding, stated up front:** Sentinel-43 has **no distinct human "owner"
role** — `core/auth/users.py::APPROVED_ROLES` is exactly `{"operator", "admin"}`. The only
place `"owner"` exists in this codebase is as one tier of `OperatorRole` in
`core/api/routers/remote_gateway.py` (`OWNER = "owner"`, alongside `admin`/`auditor`), used
for **service/API-token role separation on the Remote Gateway** (env vars
`SENTINEL_REMOTE_TOKEN_OWNER`/`SENTINEL_REMOTE_OWNER_TOKEN`), not for any human account.
Full detail deferred to Subsystem 13. For this subsystem, "administrator" (the `admin`
role) is the highest human tier that exists.

| ID | Feature | Class | Consequential | Test strength | Confidence |
|---|---|---|---|---|---|
| B-001 | Unauthenticated first-run bootstrap (`bootstrap_admin`/`bootstrap_status`) | PROVEN ACTIVE | write | behavioral, see Subsystem 1 R-019/R-020 | High |
| B-002 | First-admin creation invariant (`create_first_admin` + Postgres advisory lock) | PROVEN ACTIVE (Postgres) / PARTIALLY WIRED (SQLite) | write | behavioral; see Subsystem 3 H-007 for the SQLite caveat | High/Med |
| B-003 | Last-active-admin protection on demotion/deactivation (`_would_orphan_admins`, `users.py:425`) | PROVEN ACTIVE | write (blocks a write) | behavioral, `test_cannot_demote_the_last_admin` | High |
| B-004 | Unconditional self-deactivation block (`users.py:393-400`) | PROVEN ACTIVE | write (blocks a write) | behavioral, `test_cannot_deactivate_own_account` | High |
| B-005 | Break-glass env-operator authentication | PROVEN ACTIVE | read-only | see Subsystem 3 H-005/H-006 (full detail there, not repeated) | High |
| B-006 | "Owner" role for human accounts | **ABSENT** | n/a | n/a | High |

**B-002/B-003 detail — same lock, two enforcement points, one invariant:**
`create_first_admin` (bootstrap) and `update_account` (ongoing admin management, when the
mutation `touches_admin_count`) both explicitly take
`_pg_advisory_xact_lock(session, ADMIN_INVARIANT_LOCK_KEY)` before checking/enforcing "at
least one active admin must exist." This is the same literal constant reused across two
call sites for one real invariant — a clean example of the *non*-duplicated version of a
pattern (contrast with Subsystem 1's R-004/005 vs R-058/059, where two call sites
converge on one function but only one has test coverage; here, both call sites are
independently, behaviorally tested). The Postgres-only nature of the lock is the same
finding as H-007 — not repeated in full here.

**B-003/B-004 are two independently-enforced, differently-scoped rules, confirmed
distinct from source, not assumed from test names:** self-deactivation is blocked
**unconditionally** (any admin, targeting their own username, regardless of how many
other admins exist) by a plain equality check with no orphan-check involved. Self-
*demotion* (admin → operator on one's own account) is **not** separately blocked — it
only fails when it would orphan the admin pool, via the shared `_would_orphan_admins`
guard, matching `test_self_demotion_allowed_when_another_admin_exists`. These are
deliberately different postures for two different actions (deactivation is a harder stop
than demotion), not an inconsistency.

**Dead-code finding:** `core/auth/users.py::LastAdminError` is defined, documented, and
exported in `__all__`, but a repo-wide grep found it **never raised or caught anywhere**.
The actual last-admin protection (B-003) is enforced with a plain inline `HTTPException`
in `users.py` (the router), not this exception class. `LastAdminError` is
**LEGACY OR UNREACHABLE** — the behavior it was presumably meant to signal is real and
well-tested (B-003); the class itself is not wired to it. Owner decision: remove after
owner approval (trivial, unused exception class), or wire it in for consistency with
`FirstAdminExistsError`/`UsernameTakenError`, which *are* both actually raised and caught.

**Subsystem status:** COMPLETE
**Entries added:** 6 (B-001–B-006)
**Files inspected:** `core/api/routers/bootstrap.py` (full); `core/api/routers/users.py:
372-450`; `core/api/routers/remote_gateway.py` (grep only, for the `owner` disambiguation).
**Existing tests inspected (names only, not executed):** covered via Subsystem 1's
R-019/R-020 test lists; `test_users_admin.py` (`test_cannot_demote_the_last_admin`,
`test_cannot_deactivate_own_account`, `test_self_demotion_allowed_when_another_admin_exists`).
**Commands run:** repo-wide greps for `LastAdminError` and `owner` (read-only).
**Immediate findings:** none rising to the immediate-critical-finding bar. The
unauthenticated bootstrap window (B-001) is self-closing by design and already covered by
Subsystem 1's evidence — not re-flagged as new here.
**Unresolved questions:** none new; the SQLite/Postgres question from Subsystem 3 (H-007)
applies identically to B-002 and is not re-opened.
**UTC completion timestamp:** 2026-09-19T02:02:00Z
**Next subsystem:** 6 — Roles, scopes, permissions, and service-identity separation

### Subsystem 6 — Roles, scopes, permissions, and service-identity separation

**Source evidence:** `core/api/deps/deps.py` (full file, 728 lines — the canonical
`require_operator`/`require_admin`, resolved here as the answer to Subsystem 3's
open naming-collision question: this is a *third*, genuinely distinct `deps.py`, this one
under `core/api/deps/`, owning role-gating and engine/store dependency injection — not DB
sessions, which live in `core/auth/deps.py`); `core/security_context.py:99-118`
(`IdentityType`); `core/api/main.py:655-673` (`_require_fenrir_service_token`);
`core/api/routers/auth.py:1376-1440` (`resolve_session_subject`).

| ID | Feature | Class | Consequential | Test strength | Confidence |
|---|---|---|---|---|---|
| RS-001 | `require_operator` (canonical human operator gate) | PROVEN ACTIVE | read-only (gate) | behavioral, used by dozens of routes' `Depends()` (Subsystem 1) + auth suite | High |
| RS-002 | `require_admin` (canonical human admin gate, DB-role-checked) | PROVEN ACTIVE | read-only (gate) | behavioral, `test_users_admin.py` | High |
| RS-003 | `IdentityType` enum — human/service separation invariant | PROVEN ACTIVE | n/a (classification primitive) | behavioral, `test_service_identity_separation.py` | High |
| RS-004 | Fenrir service-token authentication (`_require_fenrir_service_token`) | PROVEN ACTIVE | read-only (gate) | behavioral, `test_internal_broadcast_auth.py` + `test_watchtower_bridge_auth.py` | High |
| RS-005 | Cross-service-token rejection (one service's token cannot authenticate as another) | PROVEN ACTIVE | n/a (negative security property) | behavioral, `test_service_identity_separation.py::test_L_sparta_token_rejected_by_fenrir` | High |
| RS-006 | Live per-request session-revocation check for session-bound tokens (`resolve_session_subject`→`resolve_live_session`) | PROVEN ACTIVE | read-only (gate) | behavioral, `test_session_revoked_mid_stream_drops_the_connection` + `test_expired_session_is_rejected` | High |
| RS-007 | Legacy (non-session-bound) per-request password-reverification contract | PROVEN ACTIVE | read-only (gate) | behavioral, extensive (Subsystem 3 H-006, Subsystem 4 S-009) | High |
| RS-008 | Dev-mode engine/store dependency-injection stubs (`DevEngine`/`DevStore`) | DISABLED OR DEV-ONLY | n/a (stub, explicitly non-enforcing) | none found directly (not searched exhaustively this pass) | Med |

**RS-001/RS-002/RS-006/RS-007 — how human authorization actually works, traced end to
end:** every `Depends(require_operator)`/`Depends(require_admin)` (and every main.py
inline `await _require_operator(request)`, which is a *separate*, main.py-local
implementation — see Redundancy/drift below) ultimately calls
`_authenticate_request()` in `core/api/deps/deps.py`, which: (1) requires a
`Bearer` token; (2) verifies its JWT signature/claims via Subsystem 4's `verify_jwt_token`;
(3) calls `resolve_session_subject(claims)`. That function returns `None` **only when the
token carries no `sid`/`jti` at all** (the true legacy shape) — if the token *is*
session-bound but the underlying session is revoked, expired, or its owner is now
inactive, it raises `HTTPException(401, "Session is no longer valid...")` directly, which
is **not caught anywhere in `_authenticate_request`** and propagates straight to the
caller. **This audit specifically checked whether a revoked session-bound token could
fall through to the legacy password-reverification path and successfully re-authenticate
anyway — it cannot; the two paths are mutually exclusive by construction, not by
convention.** Only a token with no `sid` claim at all reaches the legacy branch, which
then requires `legacy_auth_is_rejected()` to be `False` and a correct `X-S43-Password`
header re-verified fresh on every single request.

**RS-004/RS-005 — service identities are a hard, tested separation, not just a naming
convention:** `IdentityType` (`core/security_context.py`) has seven values — one human
(`OPERATOR`), one anonymous, and five distinct service identities
(`SERVICE_API`/`SERVICE_WATCHTOWER`/`SERVICE_FENRIR`/`SERVICE_SPARTA_NODE`/
`SERVICE_REMOTE_GATEWAY`), each with its own shared-secret comparison
(`secrets.compare_digest`, constant-time) against its own dedicated env-configured token.
`test_service_identity_separation.py` directly proves a Sparta node's token is rejected by
the Fenrir verifier and a human operator's JWT is rejected by the Fenrir verifier too —
this audit did not merely find that separate token variables exist, it found a positive
test asserting one type's credential is *rejected* by another type's check, which is
materially stronger evidence than "they use different env var names."

**Redundancy/drift — two independent operator-gate implementations exist:**
`core/api/main.py`'s inline `_require_operator(request)` (used by ~40 routes, per
Subsystem 1) and `core/api/deps/deps.py`'s `require_operator` (used by `/users/*`,
`/v1/*`) are **two separate functions**, not one shared implementation reused via import.
Both ultimately call `verify_jwt_token`/`resolve_session_subject`/`reverify_password` —
this audit did not find them to diverge in observable behavior in anything read so far —
but they are two maintained code paths for the same security-critical decision, in two
different files, and a future fix to one is not guaranteed to reach the other. Owner
decision: investigate/consolidate (verify main.py's inline version and
`core/api/deps/deps.py::require_operator` are byte-for-byte equivalent in behavior, or
have main.py import and reuse the canonical one).

**RS-008 note:** `DevEngine`/`DevStore` are explicitly non-enforcing stubs
(`approve_action`/`veto_action` always return `True` with a code comment stating they
never execute anything external), double-gated behind `config.is_local` (fatal outside
local, per `_ensure_dev_factory_allowed`) **and** their own explicit
`S43_ENABLE_DEV_ENGINE`/`S43_ENABLE_DEV_STORE` flags. Not searched for direct test
coverage in this pass — carried forward as a light unresolved item rather than asserted.

**Subsystem status:** COMPLETE
**Entries added:** 8 (RS-001–RS-008)
**Files inspected:** `core/api/deps/deps.py` (full); `core/security_context.py:99-118`;
`core/api/main.py:655-673`; `core/api/routers/auth.py:1376-1440`.
**Existing tests inspected (names only, not executed):** `test_service_identity_separation.py`,
`test_internal_broadcast_auth.py`, `test_watchtower_bridge_auth.py`, `test_users_admin.py`,
`test_ws_session_pg.py` (`test_session_revoked_mid_stream_drops_the_connection`),
`test_auth_session_pg.py` (`test_expired_session_is_rejected`).
**Commands run:** targeted greps for `require_admin`/`require_operator`/`IdentityType`
definitions (read-only). No requests, no writes, no test execution.
**Immediate findings:** none rising to the immediate-critical-finding bar. The
session-bound-bypass concern this audit specifically went looking for (RS-006) was
checked against source and **not found to exist** — recorded as a verified-absent finding,
not left as an assumption.
**Unresolved questions:** whether `main.py`'s inline `_require_operator` and
`core/api/deps/deps.py::require_operator` are truly behaviorally identical (RS-004
redundancy note) — would require a direct diff/trace, not performed in this pass; whether
`DevEngine`/`DevStore` have any direct test coverage (RS-008).
**UTC completion timestamp:** 2026-09-19T02:35:00Z
**Next subsystem:** 7 — WebSocket authentication, subscriptions, event delivery, close behavior

### Subsystem 7 — WebSocket authentication, subscriptions, event delivery, close behavior

**Source evidence:** `core/api/main.py:2690-3120` (`dashboard_websocket`, full handler
traced end to end); line references for supporting constants: `WS_SESSION_RECHECK_SECONDS`
(242), `CHANNEL_RE` (295), cleanup at 3111-3115. Single unit already inventoried once at
the route level as R-071 (Subsystem 1) — this pass decomposes its internal behavior, which
Section 1's rules explicitly call for ("independently meaningful message channel").

| ID | Feature | Class | Consequential | Test strength | Confidence |
|---|---|---|---|---|---|
| W-001 | Connection capacity limiting (`runtime.ws_capacity` semaphore, 50ms acquire timeout) | PROVEN ACTIVE | read-only (admission control) | none found directly in this pass (not exhaustively searched) | Med |
| W-002 | Pre-accept Origin allowlist check | PROVEN ACTIVE | read-only (gate) | behavioral, `test_ws_rejects_invalid_origin` | High |
| W-003 | Auth handshake: session-bound token or legacy token+password (dual contract, mirrors Subsystem 6 RS-006/RS-007) | PROVEN ACTIVE | read-only (gate) | behavioral, `test_ws_auth.py` (15 tests) + `test_ws_session_pg.py` (5) | High |
| W-004 | Periodic mid-connection session-liveness recheck (`_session_still_valid`, every `WS_SESSION_RECHECK_SECONDS` or on each message) | PROVEN ACTIVE | read-only (gate) | behavioral, `test_session_revoked_mid_stream_drops_the_connection` | High |
| W-005 | Subscribe/unsubscribe channel model with snapshot-on-subscribe for `actions`/`governance` | PROVEN ACTIVE | read-only (subscribe) / dispatch (snapshot reads live state) | none found directly targeting subscribe/unsubscribe behavior itself in this pass | Med |
| W-006 | ping/pong keepalive frame | PROVEN ACTIVE | read-only | none found directly | Med |
| W-007 | Guaranteed client cleanup on disconnect (`finally: runtime.ws_clients.pop(...)`) | PROVEN ACTIVE | write (in-memory state cleanup) | none found directly | Med |

**W-003/W-004 detail — the WebSocket handler reuses Subsystem 6's exact auth primitives,
not a parallel reimplementation:** it imports and calls the same
`verify_jwt_token`/`resolve_session_subject`/`reverify_password`/`legacy_auth_is_rejected`/
`note_legacy_auth` from `core/api/routers/auth.py` used by the HTTP path — this is the
*good* pattern (one canonical set of primitives, two transport-specific callers), in
contrast to the RS-004 finding (two independent implementations of the *same* gate). The
one necessary difference is orchestration shape: HTTP resolves auth once per request via
`_authenticate_request`; the WS handler resolves it once at handshake **and then re-checks
session liveness on a timer for the life of the connection** (`_session_still_valid`,
invoked both on each received message and on every idle-timeout tick) — a real, additional
control HTTP doesn't need because HTTP has no long-lived connection to keep honest.
Confirmed this recheck is the actual mechanism behind
`test_session_revoked_mid_stream_drops_the_connection`, not merely a plausible
explanation for the test's name.

**W-001/W-005 note:** `CHANNEL_RE` (`^[A-Za-z0-9_.:-]{1,64}$`) is a *shape* validator, not
an enumerated channel allowlist — any string matching that pattern is accepted into
`client.channels`, but only `"actions"` and `"governance"` currently trigger a snapshot
push or have any broadcaster targeting them (confirmed `"proxy"` is a third real channel,
used by `/events/proxy`, R-030 in Subsystem 1). Subscribing to an arbitrary
unrecognized channel name is accepted and harmless — it simply never receives traffic.
Not a defect; recorded so a future reader doesn't mistake broad format validation for a
curated channel list.

**Subsystem status:** COMPLETE
**Entries added:** 7 (W-001–W-007)
**Files inspected:** `core/api/main.py:2690-3120` (full handler), plus supporting
constants at lines 242 and 295.
**Existing tests inspected (names only, not executed):** `test_ws_auth.py` (15),
`test_ws_session_pg.py` (5) — both already listed in full under Subsystem 1's R-071 entry,
not repeated here.
**Commands run:** none beyond file reads and greps for supporting constants/cleanup.
**Immediate findings:** none. W-001/W-005/W-006/W-007 have no test evidence found in this
specific pass (distinct from W-002/W-003/W-004, which are heavily tested) — none of the
four are consequential-enough or reachable-without-auth to warrant elevation, but they are
recorded as `Med` confidence rather than `High` precisely because no direct test was
located for them individually.
**Unresolved questions:** whether `runtime.ws_capacity`'s actual configured limit is
tested anywhere (capacity-exhaustion behavior specifically) — not found in this pass, not
exhaustively searched.
**UTC completion timestamp:** 2026-09-19T02:55:00Z
**Next subsystem:** 8 — Audit storage, integrity verification, retrieval, health, failure behavior

### Subsystem 8 — Audit storage, integrity verification, retrieval, health, failure behavior

**Source evidence:** `core/audit/store.py` (full file, 1226 lines); `core/audit/audit.py`
(full file, 235 lines); `core/api/main.py` lines 424, 1309-1334, 1576-1660, 1900-1945,
2136-2163, 2219 (wiring, subsystem declaration, sink usage, shutdown).

| ID | Feature | Class | Consequential | Test strength | Confidence |
|---|---|---|---|---|---|
| AU-001 | `AuditStore` — HMAC-SHA256 hash-chained, WAL+FULL-sync SQLite ledger (`append`/`verify_integrity`/`get_records`) | PRESENT BUT UNPROVEN (core mechanics) | write (append) / read-only (verify, get_records) | import/construction-only for the store's own chain-tamper/anchor-CAS/health-transition mechanics — see finding below | Med |
| AU-002 | Startup initialization + full-chain integrity verification (`_start_audit_store`) | PROVEN ACTIVE | read-only (verify) + write (schema/backfill) | behavioral via the failure-alerting tests (AU-007); not directly via a dedicated startup test found in this pass | Med |
| AU-003 | Audit-store subsystem readiness participation (`SUBSYS_AUDIT`, required when governance enabled or non-local) | PROVEN ACTIVE | read-only | behavioral, via Subsystem 1's `/ready` gate coverage (R-039) — same mechanism, not re-tested separately for this specific subsystem name | Med |
| AU-004 | Built-in best-effort JSONL mirror (`AuditStore._write_jsonl_mirror`) | PROVEN ACTIVE | write | none found directly | Med |
| AU-005 | Standalone `AuditJsonlMirror` class (`core/audit/audit.py`) | **LEGACY OR UNREACHABLE** | n/a | import-only (`test_package_integrity.py` export check) | High |
| AU-006 | `/audit/health` HTTP route | **PROVEN ACTIVE, but misleading** — see finding | read-only | none found | High |
| AU-007 | Integrity-failure → Watchtower alert path | PROVEN ACTIVE | dispatch | behavioral, `test_pr275_corrections.py` (3 tests) | High |

**AU-001 finding — this is some of the most carefully-reasoned code found anywhere in
this audit so far, but its own core mechanics have thin direct test evidence.** The
module's source comments show genuine adversarial engineering: an HMAC chain
(`payload_hmac` over `payload_json + prev_hash`), an anchor row updated only via a
conditional `UPDATE ... WHERE head_hash = ?` (optimistic concurrency — `rowcount != 1`
means a concurrent writer won the race, and this is treated as an integrity error, not
silently retried), a denormalized `component`/`correlation_id` pair kept *outside* the
HMAC chain purely for SQL-side filtering but **independently re-verified against the
authenticated payload on every read** (so directly editing those columns to misattribute
or hide a record is itself detected, not just chain-tampering), and a documented,
deliberate lock-ordering argument for exactly when `last_known_health` is allowed to
flip, so a concurrent `append()`/`verify_integrity()` pair can never let a stale success
overwrite a fresher failure. **Despite this density of defensive reasoning, a repo-wide
search found exactly one test file that even constructs an `AuditStore`**
(`test_pr275_corrections.py`, feeding three Watchtower-alerting tests — AU-007) — **no
dedicated test exercises chain-tamper detection, anchor-mismatch, lookup-metadata-mismatch,
or the append/verify race-avoidance logic the source comments extensively reason about.**
This is a genuine, evidence-backed gap: the *design* is unusually rigorous; the *test
coverage proving that design actually behaves as reasoned* is largely absent. Classified
`PRESENT BUT UNPROVEN` for the store's own mechanics specifically, not `PROVEN ACTIVE`,
per this audit's own standard that import/construction is not behavioral proof — even
though this audit's read of the source gives reasonable confidence the code is correct.
Owner decision: investigate (this is the single highest-value place in the whole audit so
far to add tests, given the gap between design sophistication and verification).

**AU-005 finding — a second, unused JSONL-mirror implementation exists:**
`core/audit/audit.py::AuditJsonlMirror` is a fully separate class (its own `append`/
`read_recent`, own file locking, own byte-size cap) from `AuditStore`'s built-in
`_write_jsonl_mirror` private method (AU-004), which is the one actually invoked from the
live append path. A repo-wide grep for `AuditJsonlMirror` found exactly one reference
outside its own module: a package-export assertion in `test_package_integrity.py` — a
pure import-only check per this audit's own Section 4 taxonomy, not evidence of use.
**`AuditJsonlMirror` is never constructed anywhere in the running application.** Owner
decision: remove after owner approval, or document why two independent JSONL-mirror
implementations should both continue to exist.

**AU-006 finding — the dedicated audit-health route does not reflect the real audit
store's health.** `core/api/routers/audit.py::audit_health` (Subsystem 1's R-014)
unconditionally returns `{"status": "ok", "module": "audit"}` — a hardcoded literal with
no reference to `runtime.audit_store` or `AuditStoreHealth` at all. Meanwhile, this audit
confirmed the *real* signal exists and is wired correctly elsewhere: `audit_store` is a
properly `declare()`d subsystem (`SUBSYS_AUDIT`), marked `required` whenever
`S43_GOVERNANCE_ENABLED=true` or the environment is non-local, which means its true health
**does** participate in `/ready`'s fail-closed computation (Subsystem 1 R-039) and
presumably `/system/status`'s subsystem listing (same mechanism as the `heart` entry seen
throughout this session). So the overall system is not blind to audit-store health — but
an operator or monitoring script that specifically checks `/audit/health`, reasonably
expecting it to mean what its name says, is being told "ok" regardless of whether the
ledger has actually failed integrity verification. Owner decision: repair (have this route
read `runtime.audit_store.last_known_health` instead of returning a literal), or remove
the route to stop implying a check that isn't performed — same class of finding as
Subsystem 1's R-060 (`/v1/assess`, a name implying a capability that isn't there).

**AU-007 detail:** the tested integration path is narrower than "the audit store is
monitored" — specifically, `test_real_hash_mismatch_raises_a_watchtower_alert`,
`test_healthy_integrity_raises_no_alert`, and
`test_unrecognised_integrity_status_is_not_read_as_healthy` confirm that *whatever code
consumes* an `AuditVerificationResult` correctly distinguishes healthy/broken/ambiguous
outcomes before deciding to alert — this is real, valuable behavioral evidence, but it
exercises the alerting consumer's own logic against a constructed result, not the full
path of a genuine corrupted SQLite file being detected by `verify_integrity()` itself.

**Subsystem status:** COMPLETE
**Entries added:** 7 (AU-001–AU-007)
**Files inspected:** `core/audit/store.py` (full), `core/audit/audit.py` (full),
`core/api/main.py` (targeted sections for wiring).
**Existing tests inspected (names only, not executed):** `test_pr275_corrections.py`
(audit-relevant subset: 3 tests), `test_package_integrity.py` (export-only reference),
`test_remote_gateway_audit_persistence.py` (exercises helper functions around persistence,
not `AuditStore` directly — see Subsystem 1 R-043 note), `test_event_reliability.py`
(reference only, not read in full this pass).
**Commands run:** repo-wide greps for `AuditStore(`/`AuditConfig(`/`AuditJsonlMirror`/
`SUBSYS_AUDIT` (read-only). No requests, no writes, no test execution.
**Immediate findings:** none rising to the immediate-critical-finding bar — AU-006 is a
misleading-but-non-bypassing health signal (the real gate is enforced correctly
elsewhere), not a security-control bypass.
**Unresolved questions:** whether `/system/status`'s subsystem listing actually surfaces
the audit store's real health by name (this audit inferred it from the shared
`runtime.subsystems` mechanism seen for `heart` in prior sessions, but did not directly
read `system_status`'s full body in this pass to confirm the `audit_store` entry
specifically appears).
**UTC completion timestamp:** 2026-09-19T03:35:00Z
**Next subsystem:** 9 — Watchtower client, node, scanning, health, and service authentication

### Subsystem 9 — Watchtower client, node, scanning, health, and service authentication

**Source evidence:** `core/monitoring/watchtower.py` (full file, 1591 lines — a separate,
standalone FastAPI app, distinct from `core.api.main`) and `core/monitoring/
watchtower_client.py` (full file, 496 lines — the outbound client `core.api.main` uses to
reach it), both read in full via a dedicated research pass; cross-checked against this
audit's own earlier disambiguation note (Subsystem 1, R-065/067/068/070) that several
`core.api.main` "bridge" routes share literal path strings with this standalone app's own
routes without being the same code.

| ID | Feature | Class | Consequential | Test strength | Confidence |
|---|---|---|---|---|---|
| WT-001 | Watchtower standalone app — 9 guarded + 2 open routes, service-token gate | PROVEN ACTIVE | mixed (see per-route) | behavioral, `test_watchtower_service_auth.py` (18 tests) | High |
| WT-002 | Dual-gated state-change route (`POST /watchtower/state/{state_name}`) | PROVEN ACTIVE | write | behavioral (covered by the same 18-test file) | High |
| WT-003 | "Node/module registration" — in-memory bookkeeping, not an access gate | PROVEN ACTIVE, but see finding | write (in-memory only) | behavioral, `test_module_register_roundtrip_with_token` | High |
| WT-004 | "Scanning" (`WatchtowerNode.scan_event`/`WatchtowerSegment.scan`) — reactive threshold evaluation, not an active scan loop | PROVEN ACTIVE, terminology finding below | read-only (evaluation) | not directly named in the test list gathered; evaluated indirectly via `/watchtower/analyze` tests | Med |
| WT-005 | Outbound client (`watchtower_client.py`) — "never raises," fully classified failure modes | PROVEN ACTIVE | dispatch | behavioral, `test_watchtower_client.py` (17 tests) | High |
| WT-006 | Cross-service-token rejection specifically for Watchtower's verifiers | PROVEN ACTIVE | n/a (negative security property) | behavioral, `test_service_identity_separation.py` (5 Watchtower-specific pairs) | High |
| WT-007 | Stale-entry eviction for registered modules/dependencies | **ABSENT** | n/a | none — confirmed no such code exists | High |
| WT-008 | API docs (`/docs`/`/redoc`/`/openapi.json`) on the Watchtower app | DISABLED (unconditionally, stricter than the main app) | n/a | behavioral, `test_api_docs_are_disabled` | High |

**WT-001/WT-002 detail:** `/watchtower/health` and `/watchtower/ready` are the *only*
unauthenticated routes on this app (explicit source comment: "probe targets for Docker
and Kubernetes"). Every other route requires `Authorization: Bearer <token>` compared via
`secrets.compare_digest` against `S43_WATCHTOWER_SERVICE_TOKEN`, fails closed with 503 if
that env var is unset. `/watchtower/state/{state_name}` additionally requires a *second*,
independent credential — `X-S43-Admin-Token` against `S43_ADMIN_TOKEN`, same
constant-time/fail-closed pattern — the only route on this app with two independent
gates, matching its being the most consequential one (a direct node-state change).

**WT-003/WT-004 — two more instances of this audit's recurring naming-vs-reality
pattern (alongside Subsystem 1's R-060 `/v1/assess` and Subsystem 8's `/audit/health`):**
- "Registration" does not gate anything. `heartbeat_module()` silently **creates** a
  module record on the fly if the presented `module_id` isn't already known — so calling
  `/watchtower/modules/heartbeat` first works identically to calling `/watchtower/modules/
  register` first. The only observable effect of registering is metadata bookkeeping and
  whether `module_snapshot()` later reports that id as "stale" — not authorization.
- "Scanning" is a synchronous, purely reactive evaluation of whatever event dict is
  POSTed to `/watchtower/analyze` (or synthesized internally by register/heartbeat/report
  calls) against 8 static threshold-based segments — there is no polling, no active
  probing of anything, and this file contains no code that pulls data from Fenrir or any
  other producer; producers push events *to* it. Not a defect — this is a legitimate,
  common "detection engine" design — but the word "scanning" on its own could suggest
  active probing, which this audit specifically checked and did not find.

**WT-005/WT-006 detail:** the outbound client's contract is unusually explicit and
well-tested: every failure mode (bad payload, HTTP error, timeout, unreachable host,
oversized/malformed response, misconfigured base URL) is mapped to a specific
`{"error": "watchtower_<kind>", ...}` dict rather than an exception, confirmed by name for
essentially every branch (`test_401_surfaced_as_error_never_raises_never_looks_like_success`,
`test_unreachable_host_surfaced_as_error`, `test_timeout_classified_separately_from_
unreachable`, `test_oversized_response_with_content_length_rejected_without_reading_body`,
etc.) — this is the strongest "failure behavior is proven, not assumed" evidence found
in this audit so far for any dispatch-style component. No retry logic exists anywhere in
this file — a single failed attempt is final; any retry semantics would have to live in
the caller. Cross-service-identity rejection is tested for five separate pairs specific to
Watchtower's own verifiers (human JWT rejected, session-bound human JWT rejected, human
JWT rejected by the *admin*-token check specifically, Sparta's token rejected by
Watchtower, Watchtower's token rejected by Sparta) — the most thoroughly
cross-tested identity-separation evidence found for any one service pair in this audit.

**WT-007 finding — a third instance of the "nothing ever purges this" pattern:**
confirmed by direct grep that `watchtower.py` contains no `asyncio.create_task`, no
scheduler, and no eviction logic of any kind. `self.modules`/`self.dependencies` (both
plain in-memory dicts) grow for the lifetime of the process with no cap and no cleanup —
staleness is computed lazily on read (flagged in API responses) but stale entries are
**never removed**. This is the same shape of finding as Subsystem 4's S-010
(`purge_expired_sessions`, defined but never called) — a third occurrence of "housekeeping
logic that doesn't exist or isn't wired in" across this audit, now clearly a pattern
rather than a coincidence. Low real-world impact here specifically (in-memory-only state,
reset on restart, bounded by how many distinct module/dependency ids ever report in), but
worth the owner tracking as one recurring class of gap rather than three unrelated ones.

**WT-008 note:** Watchtower disables its interactive docs **unconditionally**
(`docs_url=None` etc. with no `is_local`-style branch visible in the constructor call),
which is actually *stricter* than `core.api.main`'s own docs gating (Subsystem 1's
`_DOCS_ENABLED = IS_LOCAL_ENV` — enabled in local/dev). Not a defect; recorded as a
deliberate asymmetry between the two apps' postures, confirmed by
`test_api_docs_are_disabled`.

**Subsystem status:** COMPLETE
**Entries added:** 8 (WT-001–WT-008)
**Files inspected:** `core/monitoring/watchtower.py` (full, 1591 lines);
`core/monitoring/watchtower_client.py` (full, 496 lines).
**Existing tests inspected (names only, not executed):** `test_watchtower_service_auth.py`
(18), `test_watchtower_client.py` (17), `test_watchtower_dependency_freshness.py` (3,
confirms the client-side periodic re-report pattern, not a server-side cleanup),
`test_service_identity_separation.py` (5 Watchtower-specific), plus incidental references
in `test_fenrir_monitoring_integration.py`, `test_event_reliability.py`,
`test_health_check_log_filter.py`, `test_pr275_corrections.py`,
`test_replay_route_auth.py`, `test_system_smoke.py`.
**Commands run:** none beyond file reads/greps performed by the delegated research pass
(read-only). No requests, no writes, no test execution.
**Immediate findings:** none rising to the immediate-critical-finding bar. WT-007 is a
data-hygiene gap in an in-memory-only, restart-reset store, not a security bypass.
**Unresolved questions:** none blocking. The naming-vs-reality pattern (WT-003/WT-004,
alongside R-060 and AU-006) is now flagged three times across this audit — worth a single
consolidated mention in the final report rather than treating each as independent.
**UTC completion timestamp:** 2026-09-19T04:10:00Z
**Next subsystem:** 10 — Fenrir detection, reporting, hooks, status, and failure behavior

### Subsystem 10 — Fenrir detection, reporting, hooks, status, and failure behavior

**Source evidence:** `core/detection/feniri_hunter.py` (full file, 1668 lines — filename
typo confirmed real, propagated consistently across every importer) and
`core/security/fenrir_auth.py` (full file, 281 lines), both read in full via a dedicated
research pass; wiring confirmed in `core/api/main.py` (`_start_fenrir`, lines 1515-1571;
`runtime.fenrir_instance` declared line 429).

**Correction to this audit's own prior assumption:** an earlier session's memory
referenced `S43_FENRIR_MAX_HONEYPOT_EVENTS` and described Fenrir in honeypot terms. This
pass searched the entire repository for `HONEYPOT`/`MAX_HONEYPOT` and found **zero
matches anywhere**. Fenrir is not a honeypot and has no deception/lure logic. It is a
statistical anomaly layer on top of an existing rule/threshold detector
(`SentinelThreatDetector`) plus a reporter — confirmed directly from the module's own
docstring and code, not inferred. Recorded here explicitly per this audit's own Section 8
standard ("historical handoffs citing nonexistent paths... unsupported claims") rather
than silently carrying the earlier, incorrect characterization forward.

| ID | Feature | Class | Consequential | Test strength | Confidence |
|---|---|---|---|---|---|
| FE-001 | `FenrirHunter` — background anomaly-detection/reporting loop (`hunting_loop`, real `asyncio.Task`) | PROVEN ACTIVE | dispatch (advisory only, see finding) | behavioral (`test_fenrir_broadcast_uses_the_enforced_fenrir_namespace`) + integration (Subsystem 1's `test_fenrir_monitoring_integration.py`) | High |
| FE-002 | `FenrirAnomalyLayer` — bounded, per-identity, decaying statistical baseline (Welford online algorithm) | PROVEN ACTIVE | read-only (scoring) | none found directly targeting this class in isolation | Med |
| FE-003 | Dual outbound reporting (Watchtower URL + API broadcast URL, concurrent) with enforced `fenrir.*` namespace | PROVEN ACTIVE | dispatch | behavioral, tested at **both ends** of the contract (Fenrir's own broadcast shape and the API's inbound guard) | High |
| FE-004 | Optional advisory hand-off to Heart (`_observe_with_heart`) — staging only, never blocking Fenrir's own reporting | PROVEN ACTIVE | dispatch (staging, not enforcement) | none found directly in this pass; cross-referenced to Subsystem 16 | Med |
| FE-005 | Startup wiring, required-vs-degraded failure posture (`_start_fenrir`, `S43_FENRIR_REQUIRED`) | PROVEN ACTIVE | n/a (lifecycle) | behavioral via `test_subsystem_lifecycle.py`'s generic registry contract tests (uses `"fenrir"` as the example subsystem, not hunter-specific) | Med |
| FE-006 | `fenrir_auth.py` — principal/scope/role authorization helper library | **LEGACY OR UNREACHABLE** | n/a | import/contract-only (`test_fenrir_auth_exposes_its_canonical_contract`) | High |
| FE-007 | Standalone health server (`/health`, `/ready` on Fenrir's own aiohttp app, non-embedded mode only) | PRESENT BUT UNPROVEN | read-only | none found directly | Med |

**FE-001/FE-004 detail — genuinely, verifiably advisory-only, not just by policy:** the
module's own docstring states in plain terms what it does *not* do: "block traffic /
change firewall state / approve or veto actions / execute remediation / mutate governance
state." This audit's source read confirms no code path contradicts that — every branch
either scores, transitions Fenrir's own internal state enum, POSTs a finding, or hands an
assessment to an *optional* `Heart.observe()` call that is explicitly documented as
staging-only and never blocking or gating Fenrir's own reporting even if the Heart call
fails. This is the same "advisory-first, human-gated" invariant the whole repo is built
around, independently re-confirmed here from a different subsystem's source rather than
assumed from the project's stated architecture.

**FE-003 detail — the enforced-namespace contract has a real regression history and is
tested at both producer and consumer:** `process_finding()` POSTs
`{"event_type": "fenrir.finding", ...}` (dot-separated) specifically because
`/internal/events/broadcast` on `core.api.main` (Subsystem 1 R-036) 403s anything outside
the `fenrir.*` namespace — an inline comment in `feniri_hunter.py` records that the
previous, underscore form (`"fenrir_finding"`) was rejected by every call in production
history. `test_monitoring_event_pipeline.py::test_fenrir_broadcast_uses_the_enforced_
fenrir_namespace` constructs a real `FenrirHunter`, calls `process_finding()`, and asserts
the outbound shape; its sibling test inspects `main.internal_broadcast_event`'s own source
for the matching guard — a genuine bidirectional regression test for a real historical
defect, not a one-sided assumption.

**FE-006 finding — a designed-but-unwired authorization library:** `fenrir_auth.py` is a
complete, self-consistent principal/scope/role model (`FenrirPrincipal`,
`require_fenrir_scope`, `require_fenrir_role`, `extract_bearer_token`) whose own docstring
explicitly disclaims owning authentication or reading any environment variable — it is
meant to sit *downstream* of the canonical auth layer, authorizing an already-authenticated
identity for Fenrir-specific operations. A repo-wide grep found it imported nowhere except
its own module and one existence-check test confirming its exported symbol contract
(`test_fenrir_auth_exposes_its_canonical_contract`, which itself documents that this
module was restored after a predecessor at `core/s34_auth/` was deleted). **No route,
handler, or the hunter itself calls any of its functions.** Unlike Subsystem 5's dead
`LastAdminError` (a symptom of an inline reimplementation elsewhere), this looks like a
genuinely unfinished integration — a real authorization surface built and contract-tested,
but never actually wired to anything that grants or checks a Fenrir-specific scope/role
today. Owner decision: investigate (is there a planned caller for this, or should it be
removed/documented as reserved-for-future-use).

**Subsystem status:** COMPLETE
**Entries added:** 7 (FE-001–FE-007)
**Files inspected:** `core/detection/feniri_hunter.py` (full, 1668 lines);
`core/security/fenrir_auth.py` (full, 281 lines); `core/api/main.py:429,1515-1571,1857-1868,
2065-2074,4302-4323` (wiring/status route).
**Existing tests inspected (names only, not executed):** `test_monitoring_event_pipeline.py`
(2 Fenrir-relevant), `test_nervous_system.py` (1 structurally Fenrir-relevant, others use
"Fenrir" only as example fixture data), `test_subsystem_lifecycle.py` (4, generic registry
contract using "fenrir" as example name), `test_package_integrity.py` (1, contract-only for
`fenrir_auth`); `test_fenrir_monitoring_integration.py`/`test_internal_broadcast_auth.py`
already covered in Subsystem 1.
**Commands run:** none beyond the delegated research pass's file reads/greps (read-only).
No requests, no writes, no test execution.
**Immediate findings:** none rising to the immediate-critical-finding bar. FE-006 is an
unused-but-benign authorization library, not a bypass of an existing control.
**Unresolved questions:** whether FE-006 has a planned integration point not yet built;
whether FE-002's anomaly-scoring math itself has any direct unit test (not found in this
pass, not exhaustively searched beyond the four files named above).
**UTC completion timestamp:** 2026-09-19T04:55:00Z
**Next subsystem:** 11 — SpartaCore integrity, monitoring, routing, and lifecycle wiring

### Subsystem 11 — SpartaCore integrity, monitoring, routing, and lifecycle wiring

**Source evidence:** `core/monitoring/sparta_core.py` (full file, 1264 lines) via a
dedicated research pass; wiring confirmed in `core/api/main.py` (router mount lines
2345-2367, `_start_sparta()` lines 1435-1512, task scheduling line 1493-1495).

**Correction to this audit's own carried-forward memory, checked directly against
current source rather than trusted:** an earlier audit note claimed "no
`S43_SPARTA_ENABLED` guard exists" and "fail-closed 401 w/o `S43_SPARTA_NODE_TOKEN`."
**Both are now confirmed stale.** The guard exists in two independent places today —
`core/api/main.py:2349` (`if _env_bool("S43_SPARTA_ENABLED", False):`, wrapping the entire
router-mount block) and `_start_sparta()`'s own check at line 1436 (wrapping instance
construction) — and the unconfigured-token case yields **503**
("Node API token not configured..."), not 401; 401 is reserved specifically for a
present-but-wrong credential once the token *is* configured. This audit's own persistent
memory file has been corrected to reflect this (see note after this subsystem's entry).

| ID | Feature | Class | Consequential | Test strength | Confidence |
|---|---|---|---|---|---|
| SP-001 | File-integrity watchdog (`SpartaCore.check_integrity`, SHA-256 vs. operator-configured digests) | PROVEN ACTIVE | read-only (detection) + write (event log) | behavioral, `test_pr275_corrections.py` (5+ tests) | High |
| SP-002 | Async watchdog loop (`SpartaCore.run`, scheduled by `main.py` as `asyncio.create_task`) | PROVEN ACTIVE | n/a (lifecycle) | not directly tested as a running loop in this pass (tests call `check_integrity()` directly) | Med |
| SP-003 | `/node` mesh API (`create_node_router` — health/status/events/auth/register/heartbeat/unlock) | PROVEN ACTIVE, gated (see below) | read-only (health/status/events) / write (auth/register/heartbeat/unlock) | behavioral, `test_service_identity_separation.py::TestSpartaNodeBoundary` (7+ tests) | High |
| SP-004 | Two-layer fail-closed gating: absent entirely if disabled, 503 if enabled-but-unconfigured | PROVEN ACTIVE | read-only (gate) | behavioral, confirmed by direct calls to `_require_node_token` in both test files | High |
| SP-005 | Cross-service-token rejection specific to Sparta's verifier | PROVEN ACTIVE | n/a (negative security property) | behavioral, 6 dedicated cross-identity tests | High |
| SP-006 | `/node/unlock` → `acknowledge_recovery` — clears only SpartaCore's own state flag | PROVEN ACTIVE | write (self-scoped only) | behavioral, confirmed by docstring + `test_monitoring_fault_does_not_change_sparta_state` | High |
| SP-007 | `TrafficClass.SPARTA_NODE` firewall rate-limit bucket (`/node/` prefix, 600/60s) | PROVEN ACTIVE | n/a (already inventoried as part of Subsystem 2's M-002) | behavioral, Subsystem 2 evidence | High |

**SP-001/SP-004 detail:** `watched_files` (path→expected-SHA-256 map) is built entirely
from operator-supplied `S43_SPARTA_HASH_<name>` env vars in `main.py::_start_sparta` — if
none are set, `watched_files` is empty and startup **refuses to start Sparta at all**
(`_refuse_unconfigured`), not "starts and watches nothing silently." Hash comparison uses
`secrets.compare_digest` (constant-time), and an unreadable watched file is itself a
distinct, logged `"FileUnavailable"` event, separate from a genuine hash mismatch
(`"TamperDetected"`), which flips the reported state to `COMPROMISED`. The router-mount
and instance-construction gates are independent and both fail closed to 503 (never a
silent allow) if the node token is missing — confirmed by tracing both
`RuntimeSpartaProxy.__getattr__`'s `RuntimeError`-on-`None` path and
`_require_node_token`'s own direct 503 check.

**SP-006 note — same "advisory scoped to itself" pattern as Fenrir (Subsystem 10):**
SpartaCore's only "write" capability that could sound consequential
(`/node/unlock`) is documented, and confirmed by test, to change **only SpartaCore's own**
`COMPROMISED`→`OPERATIONAL` state flag — "It does not alter firewall, auth, routing, or
any other subsystem" (source docstring, quoted directly). This is the third subsystem in
a row (Watchtower's alerting, Fenrir's staging-only hand-off, now this) where this audit
independently verified an "advisory only" claim against actual code rather than accepting
the module's own docstring at face value.

**Test-coverage note, in contrast with Subsystem 8's AuditStore finding:** unlike the
audit store, SpartaCore's security-relevant logic (the node-auth boundary, cross-identity
rejection, monitoring-fault isolation) has genuine, dedicated behavioral tests —
`test_service_identity_separation.py::TestSpartaNodeBoundary`/
`TestSpartaTokenCannotSatisfyOtherIdentities`/`TestSpartaPublicHealthDoesNotLeak` and
several tests in `test_pr275_corrections.py` construct real `SpartaCore` instances and
call its real methods, not just import/construct it. No dedicated `test_sparta_core.py`
file exists, but the coverage is real, not merely incidental name-matching (contrast with
`test_operator_findings.py`/`test_monitoring_manager_recent_events.py`, which use
`"SpartaCore"` only as fixture-data source strings, not real code).

**Subsystem status:** COMPLETE
**Entries added:** 7 (SP-001–SP-007)
**Files inspected:** `core/monitoring/sparta_core.py` (full, 1264 lines);
`core/api/main.py:1435-1512,2345-2367` (wiring).
**Existing tests inspected (names only, not executed):** `test_service_identity_separation.py`
(SpartaCore-specific subset: ~14 tests across 3 test classes), `test_pr275_corrections.py`
(SpartaCore-specific subset: ~8 tests), `test_package_integrity.py` (1, lazy-export
check), `test_security_context_and_envelope.py` (SpartaCore-specific subset: 3).
**Commands run:** none beyond the delegated research pass's file reads/greps (read-only).
No requests, no writes, no test execution.
**Immediate findings:** none rising to the immediate-critical-finding bar.
**Unresolved questions:** none blocking. Correction applied to persistent memory (see
below) rather than left as an open question.
**UTC completion timestamp:** 2026-09-19T05:30:00Z
**Next subsystem:** 12 — Yggdrasil components actually present in this repository

### Subsystem 12 — Yggdrasil components actually present in this repository

**Source evidence:** repo-wide case-insensitive grep for `yggdrasil` across every file
type (not just `.py`).

| ID | Feature | Class | Confidence |
|---|---|---|---|
| YG-001 | Any "Yggdrasil"-named component | **ABSENT** | High |

**Finding:** zero occurrences of "yggdrasil" (case-insensitive) exist anywhere in this
repository, in any file type — no Python module, class, route, config key, doc, or test.
The only match found is this inventory file's own copy of the mission brief's subsystem
list. Per the mission's own explicit instruction for this subsystem ("do not import
concept-only external designs"), this is recorded as a clean `ABSENT` rather than
speculating about what such a component might be — there is nothing in this codebase to
audit under this name.

**Subsystem status:** COMPLETE
**Entries added:** 1 (YG-001)
**Files inspected:** none (repo-wide grep only).
**Existing tests inspected:** none exist to inspect.
**Commands run:** repo-wide case-insensitive grep for `yggdrasil` (read-only, two passes —
`.py` files first, then all files).
**Immediate findings:** none.
**Unresolved questions:** none.
**UTC completion timestamp:** 2026-09-19T05:33:00Z
**Next subsystem:** 13 — Remote Gateway routes, role tokens, dispatch, audit prerequisites, and persistence

### Subsystem 13 — Remote Gateway routes, role tokens, dispatch, audit prerequisites, and persistence

**Source evidence:** `core/api/routers/remote_gateway.py` (full file, 2032 lines — the
largest single file read in this audit) via a dedicated research pass, specifically
targeted at resolving Subsystem 1's deferred question. **This subsystem's headline result
is CF-001 above** — see that entry for the full human-gate analysis; this section covers
the remaining subsystem-required facts.

| ID | Feature | Class | Consequential | Test strength | Confidence |
|---|---|---|---|---|---|
| RG-001 | Role-token authentication (`_resolve_principal`, 3 static bearer tokens, no human JWT path) | PROVEN ACTIVE | read-only (gate) | none via HTTP; unit-level only, and not for the auth function itself directly (see CF-001) | High |
| RG-002 | `POST /remote-gateway/events/activate` — the live/dry-run dispatch route | PROVEN ACTIVE, see CF-001 | write + dispatch | **zero HTTP-level test coverage** (confirmed by repo-wide grep) | High |
| RG-003 | Static, hardcoded target registry (`REGISTERED_TARGETS`) — exactly one entry, no runtime mutation | PRESENT BUT UNPROVEN | n/a | none found | High |
| RG-004 | In-process dispatch mechanism — `/node`-style network dispatch does NOT occur; dispatch means calling a registered in-process handler | PROVEN ACTIVE | dispatch (in-process only) | unit-level (`test_remote_gateway_audit_persistence.py`) | High |
| RG-005 | Mandatory pre-action durable audit gate, non-local-only fail-closed | PROVEN ACTIVE | read-only (gate) + write | unit-level only; explicitly documented by its own test file as having "no permanent test" for this specific gate | Med |
| RG-006 | Best-effort post-dispatch audit record + non-durable in-memory `EVENT_BUFFER` | PROVEN ACTIVE | write | behavioral, `test_remote_gateway_audit_persistence.py` (5 tests) | High |
| RG-007 | `GET /remote-gateway/audit/{correlation_id}` — role-scoped record visibility (`_AUDIT_VISIBLE_ROLES`) | PRESENT BUT UNPROVEN | read-only | none via HTTP | Med |
| RG-008 | Only 2 of 6 `RemoteEventType`s have any registered dispatch handler; the other 4 always 501 | PRESENT BUT UNPROVEN (unimplemented, not broken) | n/a | n/a | High |

**RG-001/RG-004 — the "Remote Gateway" does not talk to any remote system at all.**
Despite its name, `_dispatch_remote_event` performs zero outbound network I/O — it looks
up a Python async callable from an in-process registry populated at startup
(`register_dispatch_handler`, called only twice, for `APPROVE_DECISION`/`VETO_DECISION`)
and awaits it directly. There is exactly one hardcoded "target" (`REGISTERED_TARGETS =
{"local-sentinel": ...}`), with no route or mechanism to add another at runtime — adding
a real second target would require an in-process code change, not a configuration change.
This is a materially different architecture than the name and route paths
(`/remote-gateway/targets`, `body.target_id`) would suggest to a reader expecting genuine
remote/external dispatch.

**RG-008 detail:** `FORCE_HEALTH_CHECK`, `FORCE_SYNC`, `ROTATE_REMOTE_TOKEN`, and
`REQUEST_DIAGNOSTIC_SNAPSHOT` are all real `RemoteEventType` values with real
role-permission entries in `ROLE_EVENT_POLICY`, but none has a registered handler
anywhere in the codebase — activating any of them today returns HTTP 501, not because of
a missing gate but because the feature is simply unimplemented. Only the two governance
actions (approve/veto — see CF-001) are actually wired to do something.

**Redundancy/drift:** none found distinct from CF-001 itself. The role-visibility scoping
on `GET /audit/{correlation_id}` (RG-007) is a real, separate access-control layer from
the write-side authorization gap in CF-001 — reading records is scoped by role; writing
(approving/vetoing) is not scoped by anything beyond "holds a valid token for a role
whose policy includes the event type."

**Subsystem status:** COMPLETE
**Entries added:** 8 (RG-001–RG-008) + 1 immediate critical finding (CF-001, recorded in
Section 4)
**Files inspected:** `core/api/routers/remote_gateway.py` (full, 2032 lines);
`core/api/main.py:1955-2046,2223` (dispatch-handler registration);
`.env.example`/`docker-compose.yml`/k8s manifests (grep only, for CF-001's gating check).
**Existing tests inspected (names only, not executed):** `test_remote_gateway_audit_
persistence.py` (5, all unit-level/direct-function-call, no HTTP); confirmed via
repo-wide grep that no other test file references this module's routes, `OperatorRole`,
or `REGISTERED_TARGETS`.
**Commands run:** repo-wide greps for env-var gating and test coverage (read-only). No
requests, no writes, no test execution, no route ever called.
**Immediate findings:** **CF-001**, recorded above and in Section 4, surfaced in this same
turn per Section 5.
**Unresolved questions:** the three owner-facing questions listed inside CF-001.
**UTC completion timestamp:** 2026-09-19T06:20:00Z
**Next subsystem:** 14 — Dashboard routes, API clients, WebSocket clients, approval/veto interfaces, backend-contract dependencies

## 6. Redundancy and Drift Findings

_Populated incrementally as subsystems are completed._

## 7. Governance and Consequential-Action Findings

_Populated incrementally as subsystems are completed._

## 8. Security-Boundary Findings

_Populated incrementally as subsystems are completed._

## 9. Deployment/Runtime Findings

_Populated incrementally as subsystems are completed._

## 10. Potential IP-Review Candidates

_Populated incrementally as subsystems are completed._

## 11. Classification Totals

_Computed after all subsystems reach COMPLETE._

## 12. Owner-Decision Matrix

_Computed after all subsystems reach COMPLETE._

## 13. Unresolved Unknowns

_Aggregated after all subsystems reach COMPLETE._

## 14. Final Stop Statement

_Audit in progress — not yet reached._
