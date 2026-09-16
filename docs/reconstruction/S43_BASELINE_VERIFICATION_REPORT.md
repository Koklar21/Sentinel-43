# Sentinel-43 — Post-Reconstruction Baseline Verification Report

Relocated from the repository root to `docs/reconstruction/` (content
unchanged) after a direct commit deleted it from root without archiving it
first, leaving `core/api/routers/routers.py` and `core/tests/test_v1_auth.py`
citing a document that no longer existed. Historical verification evidence
is archived, not removed — those two references still point at this file's
"Section I, Defect 4", which is preserved below exactly as originally
recorded.

Mode: VERIFY FIRST / MINIMAL FIX ONLY / NO ARCHITECTURAL REWORK
Scope: ordinary-operation baseline only. No chaos, load, stress, soak, or failure-injection testing was performed.

**Status: all four defects below (1-4) are now FIXED.** Sections A-K below are the original live baseline-verification pass, preserved as-recorded (its own defect statuses at the time are left as originally written for the historical record). Section L records the follow-up remediation pass that closed Defects 3 and 4, which the original pass had left BLOCKED/architectural.

## A. Provenance

- Branch verified: `main`
- HEAD at verification: `aadf5c36fa629f2f995250e5e4315737e842af1f` (fast-forwarded from local main's prior `a45499358f50a1e6d1fabde8e21bfb1445a399cd` to `origin/main`)
- `origin/main`: `aadf5c36fa629f2f995250e5e4315737e842af1f` — identical to HEAD, no divergence
- Working tree at verification start: clean (`nothing to commit, working tree clean`)
- Working tree at verification end: 2 modified files (`core/api/main.py`, `core/cli/generate_secrets.py`) — the two minimal fixes documented in Section I; no other files touched
- Reconstruction confirmed present: PR #276 ("bring Kubernetes into runtime parity" + the full event-reliability/Fenrir-monitoring integration work, 19 commits, `fddc44a..aadf5c3`) is merged into `main`. Verified via `git log a454993..aadf5c3` (19 matching commit messages) and GitHub API (`pulls/276`: `state: closed, merged: true, merge_commit_sha: aadf5c3...`).
- A stale git-worktree administrative entry (`.git/worktrees/Sentinel-43-baseline`) produces a harmless "Permission denied" line on `git fetch`/`git checkout`; it does not affect fetch/checkout correctness (exit code 0, refs updated correctly both times) and was not touched, per the instruction not to modify unrelated state.

## B. Runtime Topology Observed

Single canonical composition root: `core/api/main.py::lifespan()`, building one `RuntimeState` instance (`runtime = RuntimeState()`) with an ordered, fail-closed startup sequence:

1. `_validate_security_config()` / `bootstrap_expectations()`
2. `_configure_watchtower_client()` (injects the canonical Watchtower HTTP client config)
3. `_declare_subsystems()` — registers every subsystem (monitoring, watchtower, sparta, fenrir, audit, governance, reliability) up front so none is silently absent, each with an explicit `required=` policy read from environment
4. `_start_monitoring_manager()` — builds one **embedded** `WatchtowerNode` + `MonitoringManager` (node_id defaults to `sentinel43-api`), registered via `set_monitoring_manager()`
5. `_start_sparta()` — SpartaCore file-integrity watchdog, via the single canonical factory `core.monitoring.build_sparta_core()` (explicitly documented in-code as the one composition path — a duplicate path was previously removed)
6. `_start_fenrir()` — `FenrirHunter`, embedded-mode, reports back through the API's own bridge routes
7. `_start_audit_store()` — the authoritative HMAC-chained `AuditStore` (SQLite, WAL, `synchronous=FULL`, hash-chained anchor); hard-required whenever governance is enabled or the environment is non-local
8. `_start_reliability()` — `EventReliabilityManager` (idempotency ledger, bounded retry, dead-letter store), audit-sink wired to the same authoritative `AuditStore` — no second pseudo-audit log
9. `_start_governance()` — `SystemOrchestrator` via `core.governance.build_orchestrator_from_settings()`; mode is read from `S43_GOVERNANCE_DEFAULT_MODE`/`S43_DEFAULT_MODE` but validated/clamped inside `core.governance.composition` to `SHADOW | HUMAN_GATED` only — **ACTIVE (autonomous) mode does not exist as a reachable value from this composition root**
10. `_register_remote_dispatch_handlers()` — remote-gateway APPROVE/VETO handlers, both routed through `_resolve_governance_and_commit_action()` (human-gated commit path, no direct execution)
11. Watchtower registration + heartbeat + one dependency report, then an `asyncio.create_task` heartbeat loop
12. `yield` → on exit, `_shutdown_runtime()` runs in `finally`, unconditionally

A second, independent Watchtower service exists: `core.monitoring.watchtower:app`, run standalone in the `s43-core` container (`node_id=sentinel43-watchtower`). The API's `/watchtower/health`, `/watchtower/ready`, `/watchtower/status`, `/watchtower/modules` routes are **bridge/proxy routes** to this separate process, used for registration/heartbeat/dependency bookkeeping — they are **not** the same object as the embedded monitoring node that Sparta/Fenrir actually feed (see Section I, Defect 3, for the operational consequence of this).

Docker Compose topology (`docker-compose.yml`): `s43-db` (Postgres 16.3) → `s43-migrate` (Alembic, run-once) → `s43-core` (standalone Watchtower) → `s43-api` (main app, healthchecked) → `s43-proxy` (nginx TLS terminator, only host-published service). This is the intended and exercised local deployment path.

Static composition audit (file/module level): no stale compatibility shims, duplicate registries, or parallel implementations were found in the live composition graph.
- `core/api/middleware/sentinel_firewall_middleware.py` (real ASGI middleware) vs. `core/middleware/sentinel_firewall.py` (thin canonical-export/env-parsing wrapper, explicitly documented as replacing a prior import-time monkey-patch) — legitimate layering, single registration site (`app.add_middleware(SentinelFirewall, ...)`, once).
- `core/scripts/generate_secrets.py` (40-line launcher) vs. `core/cli/generate_secrets.py` (952-line canonical implementation) — legitimate thin wrapper, not drift.
- A nested, tracked-but-orphaned `Sentinel-43/` directory containing four historical rewrites (`Sentienal_Nexus.py`, `Sentienal_core.py`, `Shadow_mode.py`, `sentinel_AI_escalation.py`) has **zero references** from `core/`, `dashboard/`, or `scripts/` (confirmed by grep). Dead, inert, not imported anywhere. Documented as debt (Section J), not removed — no instruction was given to delete it and doing so is outside this pass's scope.
- `core/monitoring/rules.py` / `adapters.py`: reconfirmed still dead (consistent with the prior Core-Composition pass's finding); no new references introduced by the reconstruction.

## C. Endpoint Matrix

Full inventory pulled from the live app's own OpenAPI schema (73 paths / 74 operations) rather than documentation. Representative subset actually exercised:

| Method | Path | Auth class | Expected | Observed | Result |
|---|---|---|---|---|---|
| GET | /health | none (public) | 200 coarse | 200 `{"status":"ok",...}` | PASS |
| GET | /ready | none (public) | 200 coarse | 200 `{"status":"ready",...}` | PASS |
| GET | /status, /version, /api/* compat | none (public) | 200 coarse | 200, no internal detail | PASS |
| GET | /audit/health | none (public) | 200 coarse | 200 `{"status":"ok","module":"audit"}` | PASS |
| GET | /watchtower/health | none (public, bridged) | 200 | 200, `reachable:true` | PASS |
| GET | /watchtower/ready | none (public, bridged) | 200 once dependency freshness is fixed | 200 (post-fix; was 503 pre-fix — see Defect 1) | PASS (after fix) |
| GET | /core/health, /node/health | none (public) | 200 coarse | 200 | PASS |
| GET | /fenrir/health | requires auth | 401 anonymous | 401 `Authentication required` | EXPECTED-DENY |
| GET | /remote-gateway/health | — | 503 (unconfigured) | 503 `Remote gateway is disabled.` | EXPECTED-DENY (no remote-gateway tokens configured in this baseline) |
| GET | /users, /actions, /reliability/status, /reliability/failed-events, /v1/actions, /governance/pending, /node/status, /system/status, /watchtower/status, /watchtower/modules, /core/status, /fenrir/status, /config/status, /dependencies/status, /vault/stats, /system/intercom/status | operator/admin | 401 anonymous | 401 (all) | PASS |
| POST | /auth/login | none, Origin-checked | 422 empty body, 403 disallowed Origin, 401 bad credentials, 200 correct credentials | all matched | PASS |
| GET | /auth/verify | Bearer JWT | 200 with valid token | 200, correct subject/role/expiry | PASS |
| GET | /users (Bearer + X-S43-Password, role=operator) | admin only | 403 | 403 `Admin role required` | EXPECTED-DENY (correct role separation) |
| GET | /reliability/status, /system/status, /governance/pending (Bearer + X-S43-Password, role=operator) | operator | 200 | 200, full correct state | PASS |
| POST | /watchtower/events (Fenrir service token, `fenrir.*` type) | service | 200, delivered | 200, `DELIVERED`, then `DUPLICATE` on resend | PASS |
| POST | /actions/test-inject | operator, feature-flagged | 403/blocked when `S43_ENABLE_TEST_INJECTION=false` | `{"detail":"test injection is disabled"}` | EXPECTED-DENY |
| GET | /actions (canonical, non-legacy) | operator | 200 `[]` | 200 `[]` | PASS |
| GET | /v1/actions | operator | 200 (documented, listed route) | **500 Internal Server Error** | **FAIL — see Defect 4** |
| POST | /v1/assess | operator | 200/4xx | **500 Internal Server Error** | **FAIL — see Defect 4** |
| POST | /node/unlock (Sparta service token) | service, human-gated | 200 only after a clean re-check | 200, correctly required a clean scan first | PASS |

## D. Component Health Matrix

| Component | Configured | Lifecycle state | Dependency health | Functional verification | Result |
|---|---|---|---|---|---|
| API composition root | yes | started, single instance | n/a | full lifespan ran startup→ready→shutdown→restart cleanly | PASS |
| Embedded MonitoringManager | yes | ACTIVE | n/a | proven to score a real CRITICAL alert (Section E) | PASS |
| Standalone Watchtower (`s43-core`) | yes | ACTIVE | dependency-freshness bug found and fixed (Defect 1) | registration + heartbeat succeed; `/ready` now stays 200 continuously | PASS (after fix) |
| SpartaCore (file-integrity watchdog) | yes, 3 watched files | OPERATIONAL ↔ COMPROMISED (state machine exercised both ways) | n/a | full tamper→detect→restore→operator-unlock cycle proven live (Section E) | PASS |
| FenrirHunter | yes, embedded | HUNTING | reports through API bridge with its own service token | representative finding delivered end-to-end (Section E) | PASS |
| Authoritative AuditStore | yes (`S43_AUDIT_HMAC_KEY` set) | ACTIVE, HMAC chain verified at startup | n/a | 2 real rows written and read back for one representative event, correct unique-ID semantics | PASS |
| Event reliability layer | yes | ACTIVE | audit sink wired | idempotency (duplicate correctly refused), delivery success, metrics counters all correct | PASS |
| SystemOrchestrator (governance) | yes, `S43_GOVERNANCE_ENABLED=true` | ACTIVE, mode=HUMAN_GATED | audit store required and present | test-injection correctly fail-closed; no autonomous action path reachable | PASS |
| Remote gateway | not configured (no tokens set) | disabled | n/a | fails closed 503, not anonymous accept | EXPECTED-DENY (config-dependent) |
| Legacy `/v1/*` action surface | no (`SENTINEL_STORE_FACTORY` never configured anywhere in the deployment) | n/a | n/a | 500 on every route in this family, unconditionally, out of the box | **FAIL — Defect 4, BLOCKED** |
| Postgres, nginx proxy | yes | healthy | n/a | proxy needed a one-time local dev TLS cert generation (documented, expected first-run step, not a defect) | PASS |

## E. End-to-End Event Evidence

**Fenrir → reliability → embedded monitoring → audit (representative finding):**
- Ingress: `POST /watchtower/events`, Fenrir service token, `event_type=fenrir.finding`, `kind=security`, `severity=HIGH`, `threat_kind=baseline_verification_probe`, `source_ip`, `indicators`, `confidence=0.87`
- Correlation identifier: `baseline-e2e-1789178097` (producer-supplied `event_id`, preserved end-to-end)
- Processing path observed: firewall/Host validation → `_require_fenrir_service_token` → `_delivery_envelope` → `_reject_analysis_loop` (no loop) → `reliability.deliver()` → embedded `_notify_monitoring()` with sanitized finding fields → bridged delivery to the standalone Watchtower's `/watchtower/analyze`
- Result: `{"state":"DELIVERED","attempts":1,"status_code":200}`; `/reliability/status` showed `events_accepted:1, delivery_success:1` immediately after
- Duplicate-safety proof: resubmitting the identical `event_id` returned `{"state":"DUPLICATE","attempts":0,"reason":"duplicate_event_id"}` — zero re-delivery, exactly the PR #276 review-fix behavior, now proven against a real running stack rather than only unit tests
- Audit evidence: two distinct rows in the authoritative SQLite `audit_log` table, `subject_event_id=baseline-e2e-1789178097` on both, each with its **own unique** row `event_id` (`1bff291c-...` for DELIVERED, `6cf2d200-...` for DUPLICATE) — confirms the audit-ID-collision fix from the prior review pass holds under a real deployment, not just tests

**SpartaCore integrity compromise → embedded monitoring → node-state degradation → human-gated recovery (representative orchestration flow):**
- A watched file (`core/audit/store.py`, on-disk, not the loaded module) was deliberately modified inside the running container
- Within one check cycle (≤30s), `/node/status` (Sparta service token) showed `state: COMPROMISED, tamper_count: 1` (then 2 on a second confirmed cycle)
- Orchestration evidence: the embedded WatchtowerNode's own log emitted `Watchtower state changed: ACTIVE -> DEGRADED` at the same moment — proving SpartaCore's finding actually reached and changed the state of the embedded MonitoringManager/WatchtowerNode, not merely that the objects are wired. This was independently confirmed by direct code-path testing (constructing a fresh `WatchtowerNode` + `MonitoringManager` + `WatchtowerNodeScanner` with the same config and replaying the identical event): `alert_count=1`, `severity=CRITICAL`, `reason="Integrity compromise detected"`, tower `SE:LOGGING_AUDIT`.
- The file was restored to its expected hash; SpartaCore's state did **not** auto-clear from COMPROMISED (by design — `check_integrity()` only auto-recovers from `INITIALIZING`/`DEGRADED`, never from `COMPROMISED`)
- `POST /node/unlock` (Sparta service token, with `operator` + `reason` fields) was required to clear it: `{"status":"unlocked","state":"OPERATIONAL"}`, then confirmed via `/node/status`
- Recovery evidence: `Watchtower state changed: DEGRADED -> ACTIVE` / `"recovered DEGRADED -> ACTIVE after 3 consecutive clean scans"` logged once clean scans resumed
- This demonstrates a complete, correctly human-gated detect→alert→(no auto-heal)→operator-acknowledged-recovery cycle — not merely "module imported."
- See Defect 3 for the one real gap this test surfaced: this entire embedded-node state transition is visible only in container logs, not through any HTTP status endpoint or dashboard broadcast.

## F. Security/Governance Baseline

- **Identity separation**: confirmed. A valid Bearer JWT for the break-glass operator identity (`role=operator`) was correctly refused `Admin role required` (403) on `/users`; a service token (Sparta) could not be used on operator/admin routes and vice versa; Fenrir's service token is scoped to `fenrir.*` event types only.
- **Authentication baseline**: anonymous requests to every protected route tested returned 401 (never a silent 200). Malformed/wrong-username/wrong-password login attempts returned 401/403 as appropriate, never 500. Non-ASCII/malformed input was not specifically fuzzed (out of scope for this pass) but no crash was observed in any input tried.
- **Step-up authentication discovered, verified as intentional, not a defect**: routes reached via the break-glass (non-session-bound) operator token additionally require the legacy `X-S43-Password` header for reverification (`resolve_session_subject()` returns `None` for a non-DB-backed session, `reverify_password()` is then required) — a deliberate anti-theft measure for a token that has no revocable session record. DB-backed accounts (`session_bound: true`) do not carry this friction. Documented, not changed.
- **Fail-closed configuration**: `/remote-gateway/*` answers 503 (not anonymous-accept) with no tokens configured; Sparta and Fenrir both refuse to start "half-alive" if their respective tokens/config are missing (`_refuse_unconfigured`), rather than starting and silently dropping everything.
- **No localhost/Docker-network trust bypass**: `S43_TRUSTED_HOSTS` and `S43_TRUSTED_PROXIES` are both explicit allowlists; the kind-smoke CI job (separate, pre-existing evidence) already proved `TrustedHostGuard` rejects an untrusted `Host` header even from inside the Docker network.
- **Human-gate / no autonomous enforcement**: `SystemOrchestrator` mode is HUMAN_GATED (ACTIVE mode is not a reachable value from the composition root — enforced in `core.governance.composition`, unchanged and re-verified). `/actions/test-inject` correctly refuses when `S43_ENABLE_TEST_INJECTION=false` (the documented, must-never-be-true-in-production default). Remote-gateway APPROVE/VETO handlers both route through `_resolve_governance_and_commit_action()`, never a direct action executor. SpartaCore's COMPROMISED state requires an explicit human/operator `/node/unlock` call with `operator` + `reason` fields recorded — it does **not** self-heal, by design. No autonomous action of any kind was observed or is reachable in this configuration.

## G. Observability Baseline

Measured on the idle/lightly-exercised stack via `docker stats --no-stream` and direct `curl` timing (method noted per row — this is a baseline reference, not a performance benchmark):

| Metric | Method | Value |
|---|---|---|
| API container CPU | `docker stats` | 0.18% |
| API container memory | `docker stats` | 76.4 MiB / 7.6 GiB limit (0.98%) |
| Watchtower (s43-core) CPU/mem | `docker stats` | 0.15% / 36.0 MiB |
| Postgres CPU/mem | `docker stats` | 0.00% / 41.9 MiB |
| nginx proxy CPU/mem | `docker stats` | 0.00% / 15.3 MiB |
| `/health` latency (10 samples, via nginx→API) | `curl -w %{time_total}` | 7.4–28.2 ms |
| Open file descriptors, API process | `/proc/1/fd` count in container | 14 (stable across the session) |
| Event throughput | reliability metrics counters | `events_received/accepted/delivery_success` all incremented exactly once per representative event sent; `events_duplicate` correctly 0 (duplicate is refused before that counter, by design — see `events_accepted` staying at 1) |
| Dropped/rejected events | `/reliability/status`, `/watchtower/status` | 0 across the whole session |
| Component lifecycle states | `/system/status` | all 7 declared subsystems ACTIVE at steady state |

No metric was invented; anything not listed here (queue depth, DB connection-pool occupancy) was not available through any endpoint or tool exercised in this pass and is not reported.

## H. Shutdown / Restart Result

Graceful `docker compose stop s43-api` produced, in order, from the container's own log: `Shutting down` → `Waiting for application shutdown` → `Fenrir shutdown requested` → `Fenrir state: HUNTING -> DORMANT` → embedded `Watchtower state changed: ACTIVE -> STOPPED` (`"WatchtowerNode stopped cleanly (STOPPED -- no further events accepted)"`) → `Application shutdown complete` → `Finished server process`. No exceptions, no orphaned task warnings, no component reported FAILED as a result of shutdown itself.

A single clean restart (`docker compose start s43-api`) returned the stack to its exact baseline state with no manual repair: `/health` → 200, `/ready` → 200, SpartaCore → `OPERATIONAL` with a clean 0 tamper count (fresh check against the correct hash), all 7 subsystems ACTIVE again.

## I. Defects Found

**Defect 1 — Watchtower `/ready` permanently contradicts `/health` after ~60s of ordinary operation (FIXED)**
- Severity: High (baseline-blocking — the exact "readiness collapses to a false signal" failure mode this pass exists to catch)
- Evidence: fresh stack, `/watchtower/health` → `reachable:true` continuously; `/watchtower/ready` → `reachable:false` (HTTP 503, body `{"status":"not_ready"}`) after roughly one minute of otherwise uneventful operation, and stayed that way indefinitely.
- Root cause: `core/api/main.py::lifespan()` reports the API as a Watchtower "dependency" exactly once, at startup (`report_dependency_to_watchtower("sentinel-43-api", ...)`). Watchtower's own readiness (`core/monitoring/watchtower.py::readiness_from_snapshots`) requires zero `stale_dependencies`, with a default `dependency_stale_seconds=60`. The periodic `_async_heartbeat_loop` (every 15s by default) already refreshes the *module* heartbeat but never refreshed this *dependency* report, so the one-time report always aged out during perfectly ordinary operation.
- Fix performed: `_async_heartbeat_loop` (`core/api/main.py`) now also calls `report_dependency_to_watchtower("sentinel-43-api", "online", {...})` on the same successful cycle it already uses for the module heartbeat, keeping the dependency record fresh by the same mechanism and cadence already used for the module record. One function, no new abstraction, no config change, no architecture change.
- Verification: rebuilt and redeployed; polled `/watchtower/ready` every 10s for 120s (twice the stale threshold) — stayed HTTP 200 the entire time. Also independently confirmed via `/system/status`'s embedded watchtower detail: `stale_dependencies: []`, dependency `last_report_ts` continuously current.

**Defect 2 — `S43_OPERATOR_PASSWORD_HASH` is silently corrupted by Docker Compose's own `.env` interpolation (FIXED)**
- Severity: High (baseline-blocking for any first-time setup following the documented instructions — 100% reproduction rate, not an edge case)
- Evidence: generated an operator password hash exactly as documented (`core/scripts/generate_secrets.py --password-hash`, itself a thin launcher for the real implementation in `core/cli/generate_secrets.py`), pasted the printed `S43_OPERATOR_PASSWORD_HASH=$argon2id$v=19$...` line into `.env` verbatim. Every login attempt then failed `503 Break-glass credentials are not configured correctly`. `docker exec ... printenv S43_OPERATOR_PASSWORD_HASH` showed the value with every `$...` segment stripped out.
- Root cause: Docker Compose's `.env`-file loader performs its own `$VAR`/`${VAR}` interpolation over `.env` file contents (this is documented Compose behavior, not a Sentinel-43 bug in itself) — a literal `$` must be written as `$$` to survive. An Argon2id hash always contains 4+ literal `$` delimiters by format, so this corrupts on every single real deployment that follows the project's own generation instructions, with no warning anywhere.
- Fix performed: `core/cli/generate_secrets.py::password_hash_flow()` now prints the value with every `$` doubled (`digest.replace("$", "$$")`), plus a one-line stderr note explaining why, so a direct copy-paste into `.env` survives Compose's interpolation intact. This is the only place in the codebase that ever emits a `$`-bearing secret for `.env` use (verified: no other `write_env_file`-managed secret ever contains `$`, since `secrets.token_urlsafe`/`token_hex` never produce one).
- Verification: regenerated, confirmed the escaped value round-trips through `docker compose --env-file` back into the container as the exact original, valid Argon2id hash (`docker exec ... printenv` showed the correct unescaped hash); logged in successfully end-to-end with a real JWT issued.

**Defect 3 — SpartaCore/Fenrir findings reaching the embedded MonitoringManager have no operator-facing observability (CONFIRMED, NOT FIXED — architectural, reported per Fix Policy §11)**
- Severity: Medium-High for a human-governed system, but not baseline-blocking under ordinary (no-tamper) operation, so left unfixed per the "if it requires architectural redesign, report BLOCKED" instruction.
- Evidence: `MonitoringManager` is constructed in `_start_monitoring_manager()` with no `telemetry_sink` (`MonitoringManager(WatchtowerNodeScanner(node))`), so every internal `_emit()` call (including `{"kind":"monitoring","status":"alerts_generated",...}`) is a guaranteed no-op (`_emit`: `if sink is None: return`). No HTTP route anywhere calls the embedded manager's own `get_status()`. The only externally-visible Watchtower status routes (`/watchtower/health`, `/ready`, `/status`, `/modules`) all bridge to the **separate, standalone** `s43-core` Watchtower service, which Sparta/Fenrir never feed. The state transition the embedded node makes on a real CRITICAL finding (proven in Section E: `ACTIVE -> DEGRADED`, later auto-recovering to `ACTIVE`) is visible **only** in raw container logs — not via any API response, dashboard WebSocket broadcast, or audit entry.
- Root cause is architectural: bridging the embedded `MonitoringManager`'s synchronous `_emit()` telemetry callback into the existing async dashboard-broadcast/audit infrastructure requires a sync→async bridging design decision (which sink, what rate limiting, audit vs. dashboard vs. both) that goes beyond a minimal, single-function correction.
- Recommendation (not implemented): wire a `telemetry_sink` into the `MonitoringManager(...)` construction in `_start_monitoring_manager()` that forwards `alerts_generated` events to the existing `_broadcast_dashboard_event()` path and/or the authoritative audit sink already used by the reliability layer — reusing existing infrastructure rather than building a new one. This is a design decision for the maintainer, not something this pass should decide unilaterally.

**Defect 4 — The entire `/v1/*` legacy action-compat route family 500s unconditionally in every standard deployment (CONFIRMED, NOT FIXED — architectural, BLOCKED)**
- Severity: Medium (a documented, publicly-listed route family is completely non-functional out of the box; not baseline-blocking for the canonical, non-legacy equivalents, which work correctly)
- Evidence: `GET /v1/actions` and `POST /v1/assess`, with valid operator credentials, both returned `500 Internal Server Error`. Traceback: `core.api.deps.deps.DependencyResolutionError: Store is using development factory 'core.api.deps:dev_store_factory', but S43_ENABLE_DEV_STORE=true is not set`. The canonical, non-legacy equivalent (`GET /actions`) returned a correct `200 []` with identical credentials in the same session, confirming this is isolated to the `/v1/*` compat surface's own dependency wiring, not a general auth/DB problem.
- Root cause: `core/api/deps/config.py` resolves the "Store" dependency from `SENTINEL_STORE_FACTORY` (env var), defaulting to `core.api.deps:dev_store_factory` — an in-memory development-only implementation that explicitly refuses to run unless `S43_ENABLE_DEV_STORE=true`. `SENTINEL_STORE_FACTORY` is never referenced anywhere in `docker-compose.yml` or `.env.example`, and grepping the entire tree found no second, production-grade implementation of `StoreProtocol` anywhere outside `dev_store_factory` itself. This is not a missing wire — a real Store implementation appears never to have been written.
- Why not fixed: writing (or selecting) a production `StoreProtocol` implementation, or deciding this legacy surface should instead be deprecated/removed in favor of the working `/actions` family, are both genuine architectural/product decisions outside "smallest justified correction." Reported as BLOCKED per Fix Policy §11.

## J. Architectural Debt Observed (documented, not touched)

- Nested, tracked, fully-orphaned `Sentinel-43/` directory (4 historical rewrite files, zero live references) — safe to delete whenever a cleanup pass is authorized, but not this pass's call.
- `core/monitoring/rules.py` / `adapters.py` — reconfirmed dead, unchanged since the prior Core-Composition-Firewall audit.
- The dual "Watchtower" naming (embedded per-API node vs. standalone `s43-core` service) is a genuine source of confusion during operational triage (this report's own investigation into Defect 3 initially went down the wrong path for exactly this reason) — worth a naming or documentation pass, not a functional defect.
- `/v1/*` legacy action-compat surface (Defect 4) — recommend an explicit maintainer decision: implement a real Store, or deprecate/remove the route family.
- MonitoringManager's telemetry sink gap (Defect 3) — recommend wiring it to existing dashboard/audit infrastructure in a future, properly-scoped pass.

## K. Final Verdict

**BASELINE VERIFIED WITH NON-BLOCKING DEBT**

Justification against the stated success criteria:
- Intended stack starts normally: yes (Section B, H)
- Required components reach correct lifecycle states: yes, all 7 declared subsystems ACTIVE at steady state (Section D)
- Health/readiness endpoints correspond to actual runtime health: yes, **after** fixing Defect 1, which was a genuine baseline-blocking discrepancy found and corrected in this pass
- Protected endpoints enforce expected authentication boundaries: yes (Section C, F) — no anonymous-access or identity-confusion failure found anywhere
- Representative legitimate traffic traverses the real system: yes (Section E) — a real Fenrir-shaped finding was delivered, deduplicated correctly, and audited correctly, live
- SpartaCore demonstrably orchestrates at least one representative flow: yes (Section E) — a real file-tamper was detected, scored CRITICAL by the embedded MonitoringManager/WatchtowerNode, changed that node's live state, and required an explicit human-gated unlock to clear — proven both live and via independent isolated repro of the scoring logic
- Persistence/audit behavior is correct where applicable: yes (Section E) — unique per-row audit IDs, correct `subject_event_id` linkage, verified against a real SQLite file, not mocks
- Human approval/governance boundaries remain intact: yes (Section F) — ACTIVE/autonomous mode unreachable, test-injection fail-closed, SpartaCore recovery requires an explicit operator call
- No unexpected autonomous enforcement occurs: confirmed, none observed or reachable
- Graceful shutdown succeeds: yes (Section H)
- Clean restart succeeds: yes (Section H), no manual repair needed
- No unresolved baseline-blocking defect remains: **true** — the two baseline-blocking defects found (readiness staleness, Compose `.env` `$`-corruption of the operator hash) were both fixed and re-verified live; the two remaining defects (Sections I.3, I.4) are real but do not block ordinary baseline operation and are correctly scoped as BLOCKED/architectural rather than patched under this pass's minimal-fix mandate.

This is a baseline-verification-only result. Load, chaos, failure-injection, soak, and stress testing were explicitly out of scope for this pass and were not performed.

## L. Post-Merge Remediation (follow-up pass)

Branch: `fix/post-merge-baseline-remediation`, created from `origin/main` at `aadf5c36fa629f2f995250e5e4315737e842af1f` (identical to the HEAD this report was originally verified against — no drift). PR #276 itself was not touched; this is a new, separate PR against `main`.

Four items were completed. Items 1-2 land the fixes already proven live in Sections I.1/I.2 above (re-verified, not re-invented); items 3-4 close the two defects the original pass had left BLOCKED.

**1. Watchtower readiness freshness (Defect 1) — landed, re-verified**
Same fix as Section I.1 (`_async_heartbeat_loop` now re-reports the `sentinel-43-api` dependency on every successful cycle). 3 new tests (`core/tests/test_watchtower_dependency_freshness.py`) pin: a healthy cycle refreshes the dependency report with the same identity/details shape as the original startup call; a failed heartbeat never fabricates one; the refresh runs on every successful cycle, not only the first.

**2. Compose-safe operator hash (Defect 2) — landed, re-verified**
Same fix as Section I.2 (`password_hash_flow()` doubles every `$` before printing). 4 new tests (`core/tests/test_generate_secrets_compose_safe_hash.py`) prove: the printed value is never itself a valid Argon2id hash (so escaping is provably not a no-op); un-escaping it (Compose's own `$$`→`$` transform) recovers the exact original hash, which still verifies the original password and rejects a wrong one; the round trip is stable across multiple independently-salted hashes; a password mismatch never reaches the escaping step at all.

**3. Operator findings surface (Defect 3) — now FIXED, no longer BLOCKED**
The original pass correctly identified that wiring `MonitoringManager`'s telemetry into the dashboard/audit path required a sync→async bridging decision beyond a one-line fix, and declined to make that call unilaterally. Re-examined with a narrower, already-existing primitive: `WatchtowerNode` already maintains a bounded, synchronous, in-memory recent-events view (`recent_event_snapshot()`) for exactly this purpose — no sync/async bridge, no telemetry sink, and no new store was needed at all; only a read-side passthrough.

- **Canonical finding source**: `WatchtowerNode.recent_events` (existing bounded deque, sized by `S43_WATCHTOWER_MAX_EVENTS`), reached via a new passthrough `WatchtowerNodeScanner.recent_event_snapshot()` and `MonitoringManager.recent_events()` (`core/monitoring/manager.py`). No second findings database, event bus, or monitoring subsystem was created.
- **Endpoint added**: `GET /operator/findings` (`core/api/main.py`), query params `limit` (clamped to 500), `source`, `severity`, `event_type`, `subsystem`, `since` (epoch seconds or ISO-8601).
- **Auth model**: `_require_operator(request)` — the identical guard every other operator route uses. No new auth scheme. Anonymous and unauthorized-human callers rejected; an unavailable `MonitoringManager` reports a clean 503, not a crash.
- **Fields exposed**: identity/provenance (`id`, `event_id`, `kind`, `event_type`, `source`, `source_identity`, `correlation_id`, `parent_event_id`, `created_at`, `ingested_at`), finding content (`severity`, `threat_kind`, `source_ip`, `indicators`, `confidence`, `secrets_exposed`, `privilege_escalation`, `unsigned_artifact`, `debug_mode_enabled`, `integrity_status`), and the tower's own alert/decision output (`alerts`, `coordinator_decision`, `source_event_id`) — plus a derived `subsystem` label (from `source_identity`, e.g. `service:fenrir` → `fenrir`) so an operator can tell producers apart at a glance.
- **Fields deliberately withheld**: everything not named above — an explicit allowlist (`_FINDING_ALLOWED_FIELDS`), so a service token, `Authorization` header, or unexamined raw producer field can never ride through. Verified by a test that includes a fake `authorization`/`service_token` key on a raw finding and asserts neither ever appears in the response.
- **Fenrir visibility proof**: `core/tests/test_monitoring_manager_recent_events.py` and `core/tests/test_operator_findings.py` push a Fenrir-shaped security event through the real `MonitoringManager`/`WatchtowerNode` and through the route, asserting `severity`/`threat_kind`/`confidence` all survive and `subsystem == "fenrir"`.
- **SpartaCore visibility proof**: the same two files push a Sparta-shaped integrity-compromise event and assert the resulting entries include both the raw `integrity_status: "compromised"` event and the `watchtower_alerts` entry it produces (`severity: CRITICAL`, `tower_type: LOGGING_AUDIT`) — the identical alert shape Section E's live tamper test produced, now operator-retrievable rather than log-only.
- **Dashboard/client changes**: one new canonical client, `dashboard/services/findings_client.py`, mirroring `reliability_client.py`'s exact shape (client-side limit validation, an explicit field-display allowlist, `describe_failure()` distinguishing auth/authorization/unavailable rather than a blanket "server offline", fails closed to an empty/unavailable view on any non-ok or malformed response). No second dashboard backend. No approve/enforce/remediate/schedule entry point exists on the client — verified by a test asserting no such name appears in its public API. This is visibility only, exactly as instructed.

**4. `/v1/*` legacy route disposition (Defect 4) — now FIXED, no longer BLOCKED**
Full inventory (`core/api/routers/routers.py`, all behind `Depends(require_operator)` — the same canonical JWT verifier as the rest of the API, confirmed still intact and unweakened):

| Route | Purpose | Prior state | Disposition | Replacement used |
|---|---|---|---|---|
| `GET /v1/actions` | list actions | 500 (dead `StoreProtocol`) | **REPLACE** | `core.api.main._list_actions()` — the same in-memory ledger `GET /actions` reads |
| `POST /v1/actions/{id}/approve` | approve a staged action | 500 (dead `EngineProtocol`+`StoreProtocol`) | **REPLACE** | `core.api.main._resolve_governance_and_commit_action(approved=True, ...)` — same path `POST /actions/{id}/approve` uses |
| `POST /v1/actions/{id}/veto` | veto a staged/pending action | 500 (dead `EngineProtocol`+`StoreProtocol`) | **REPLACE** | same function, `approved=False` |
| `POST /v1/assess` | post an arbitrary payload for threat assessment | 500 (dead `EngineProtocol`) | **DEPRECATE** | none — no modern equivalent exists; explicit `501 Not Implemented` |

No route was silently REMOVED, and no fake `Store`/`Engine` was built to stop the 500s: the two REPLACE routes bypass the dead abstraction entirely in favor of the backend that already exists; the DEPRECATE route reports its own non-implementation honestly rather than pretending to work. `core.api.deps`'s `EngineProtocol`/`StoreProtocol`/`get_engine`/`get_store` machinery is left in place (removing it outright is a separate decision, noted in the debt list below) but is no longer referenced by any route.

- **Replacements verified**: `core/tests/test_v1_legacy_disposition.py` (11 tests) runs against a full app boot with **neither** `S43_ENABLE_DEV_STORE` **nor** `S43_ENABLE_DEV_ENGINE` set — the exact condition that produced the 500 originally. A real staged action is listed, approved, and vetoed through `/v1/*`, and each result is cross-checked against `GET /actions` seeing the identical committed ledger state. Action-id mismatch still 400s and unknown-action-id still 404s without touching the ledger. `/v1/assess`'s 501 is proven unaffected by arming the old `S43_ENABLE_DEV_ENGINE` flag, confirming the dependency is gone, not just bypassed.
- **Governance/security preserved on surviving routes**: `require_operator` unchanged (still 401s anonymous callers); the commit path is the identical `_resolve_governance_and_commit_action` the modern routes use, so governance decision-gating (`HUMAN_GATED`, decision-id resolution, 409 on an invalid state transition) applies identically — nothing here bypasses approval or introduces autonomous execution.
- **Existing test updated, not silently left broken**: `test_v1_auth.py::test_v1_accepts_valid_token_and_password` previously armed `S43_ENABLE_DEV_ENGINE=true` and asserted 200 on `/v1/assess` — direct evidence the route never worked without that flag. Updated to assert the route's own deliberate 501 with a properly authenticated caller, which is what "the auth boundary works, and the route it protects behaves as designed" now means for a deprecated endpoint. The file's actual subject (the JWT/password auth boundary) is unchanged and still fully asserted.
- **No unexplained 500 remains**: confirmed by the full regression run (Section L.6).

**5. Report preserved and extended**
This section was added to the existing `S43_BASELINE_VERIFICATION_REPORT.md` rather than replacing it — Sections A-K above are the original, unedited verification record.

**6. Verification performed for this remediation pass**

*Focused tests* (new, run individually per area before the combined run): `test_watchtower_dependency_freshness.py` (3), `test_generate_secrets_compose_safe_hash.py` (4), `test_operator_findings.py` (12), `test_monitoring_manager_recent_events.py` (5), `test_findings_client.py` (13), `test_v1_legacy_disposition.py` (11), plus the pre-existing `test_v1_auth.py` and `test_auth_session_pg.py` re-run to confirm no regression from the `/v1/*` rewiring. All passed.

*Live Compose re-acceptance* (fresh build off this branch, `docker compose -p s43remediation`, Sparta + Governance both enabled, matching the original pass's configuration):
- Migration ran to completion cleanly; `s43-api` reported `(healthy)` on first attempt.
- `GET /health` → 200, `GET /watchtower/ready` → 200, sampled every 10s for 120s (twice the default staleness threshold) — **stayed 200 the entire window**, confirming Defect 1's fix under a fresh build.
- Operator login proven via the *actual fixed code path*: ran `python -m core.cli.generate_secrets --password-hash` inside the built image (not a manual re-implementation), captured its printed, `$$`-escaped output, wrote it into `.env`, confirmed via `docker compose config` that Compose's own resolved config still shows it escaped (Compose's own round-trip representation), then via `docker exec ... printenv S43_OPERATOR_PASSWORD_HASH` confirmed the **container's actual environment received the exact original, unescaped, valid Argon2id hash** — and logged in successfully (`200`, real JWT issued) using that password.
- `GET /operator/findings` (operator-authenticated) → `200 {"count":0,...}` on a clean stack; anonymous → `401`.
- Posted one Fenrir-shaped finding (`severity=HIGH`, `threat_kind=remediation_probe`, `confidence=0.8`, `indicators=["marker-a"]`) to `/watchtower/events` → `200 DELIVERED`.
- Deliberately tampered a watched file inside the container; within one check cycle `/node/status` showed `COMPROMISED`, and `GET /operator/findings` **simultaneously showed all of**: the Fenrir finding (`subsystem: "fenrir"`, full content intact), the raw Sparta `integrity_status: "compromised"` log entry (`subsystem: "sparta-node"`), and the resulting `watchtower_alerts` entry (`severity: CRITICAL`, `reason: "Integrity compromise detected"`, `coordinator_decision.classification: CRITICAL_SYSTEM_RISK`) — the first time this information has been operator-retrievable through the API rather than log-only.
- Restored the file, confirmed the digest matched the expected hash, called `POST /node/unlock` → `{"status":"unlocked","state":"OPERATIONAL"}`, confirmed via `/node/status`.
- `GET /v1/actions` → `200` (was `500`); `POST /v1/assess` → `501` with `S43_V1_ASSESS_DEPRECATED` (was `500`) — both confirmed with `S43_ENABLE_DEV_STORE`/`S43_ENABLE_DEV_ENGINE` **absent** from the container's actual environment (`docker exec ... printenv` on both returned nothing), i.e. the exact condition that produced the original 500s.
- `docker compose stop s43-api` → clean shutdown log sequence (`Fenrir HUNTING -> DORMANT`, embedded `Watchtower DEGRADED -> STOPPED`, `WatchtowerNode stopped cleanly`, `Application shutdown complete`), no exceptions.
- `docker compose start s43-api` → `/health` 200, `/watchtower/ready` 200, SpartaCore back to a clean `OPERATIONAL`/0-tamper state with no manual repair.
- Stack torn down (`down -v`) and images removed afterward; no residual containers, volumes, or images left behind.

*Full regression*: `pytest core/tests/ dashboard/tests/` — **998 passed, 103 skipped, 1 xfailed, 0 failed** (609.5s). 0 failures.

*Not tested in this pass*: load, chaos, soak, or stress conditions (unchanged scope boundary from the original pass); the standalone `s43-core` Watchtower service was not re-exercised beyond what Section L.1's targeted tests and the live acceptance above cover, since its own behavior did not change.

## M. Architectural Debt — Updated

Superseding the equivalent entries in Section J:
- `/v1/*` legacy action-compat surface: **resolved** (Section L.4) — no longer debt.
- MonitoringManager operator visibility: **resolved** (Section L.3) via the existing `recent_event_snapshot()` primitive — no longer debt.
- Remaining, unchanged from Section J: the orphaned nested `Sentinel-43/` directory; `core/monitoring/rules.py`/`adapters.py` (dead); the dual "Watchtower" naming (embedded vs. standalone) — still a real source of operator/triage confusion, still not a functional defect, still recommended for a future naming/documentation pass.
- New, minor: `core.api.deps`'s `EngineProtocol`/`StoreProtocol`/`get_engine`/`get_store`/`DevEngine`/`DevStore` machinery is now unreferenced by any route. Left in place deliberately (removing a dependency-injection extension point outright is a separate decision from disposing the routes that used to depend on it), but a future pass should decide whether to keep it as a documented extension point or remove it.

## N. Revised Final Verdict

**BASELINE VERIFIED.** All four defects identified during the original live verification pass (Section I) are now fixed and re-verified: two (readiness freshness, Compose-safe secrets) were already proven live in the original pass and are now landed on a proper branch with regression tests; two (operator findings visibility, `/v1/*` legacy routes) that the original pass correctly declined to fix unilaterally have since been resolved using existing canonical primitives, without a second event bus, a second monitoring subsystem, a fake Store, or any weakening of authentication, governance, or human-gating. No unresolved baseline-blocking defect remains.
