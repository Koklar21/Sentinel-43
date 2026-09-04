# DEFECT_INVENTORY.md

Sentinel-43 — complete accumulated defect audit. **Durable canonical defect
ledger.** Future passes update this file rather than adding new markdown files.

- **Audit branch:** `audit/defect-inventory-20260903` off `main` (`fa587c2`).
- **Discipline:** inventory first. No production-code remediation until the
  Section 29 gate. Tests that reproduce/prove a defect are allowed.
- **Session 1:** §0-5, 7, 11-14, 19, 20, 22-25; 31 findings.
  **Session 2 (2026-09-03):** reconciled §0-28, closed §6/8/9/10/15/16/17/18/
  21/26/27; +12 findings → **43 total**; **§29 gate PASSED.**
- **State:** CONFIRMED · REPRODUCED · SUSPECTED · FALSE-POSITIVE · DEFERRED.
- **Severity:** CRITICAL · HIGH · MEDIUM · LOW · INFO.

Prompt sections that use "fix/resolve/implement" are recorded here as
*recommended remediation*, not work performed.

---

## Section progress

**Session 2 (2026-09-03) reconciliation — every section §0-§28 is now
SUBSTANTIALLY COMPLETE.** Residual "per-site trace" / "`python -m build`" items
are remediation-phase (require code / a fixed build backend), not inventory gap.

| § | Title | Status | Session-2 evidence |
|---|---|---|---|
| 0 | Canonical repository state | ✅ | refs re-verified unchanged (main `fa587c2`, #252 `6ce21d8`, #254 `f3eba76`) |
| 1 | Known minimum defect set | ✅ | D-01..D-14 all independently re-confirmed |
| 2 | Complete source inventory | ✅ | 245 tracked; UNKNOWN sub-trees resolved → `core/api/core/` dead (D-37); `core/config/config.py` dead (D-31) |
| 3 | Syntax + import integrity | ✅ | compileall FAILS on main (D-01); sweep 105/23 (`.venv-pass1`), 104/24 (clean venv) |
| 4 | Case-sensitive FS audit | ✅ | D-05, D-06, D-09 |
| 5 | Duplication / clobber | ✅ | 2 identical-body groups (D-03, D-14); structural D-17, D-27, D-31 |
| 6 | Git-history corruption | ✅ | broad name-set-divergence + large-replace scan: **only D-03 + D-14**; `auth.py` divergence = legit multi-pass refactor |
| 7 | Dependency audit | ✅ | undeclared set = exactly `{pydantic-settings, cryptography}`; `pip install -e .` → BackendUnavailable (D-12); `redis` declared-unused (D-36) |
| 8 | Watchtower client audit | ✅ | **D-16 CONFIRMED** (not partial) — full 12-client matrix below |
| 9 | Broad exception / silent-failure | ✅ | the 10 token-less Watchtower helpers' `except Exception: pass` masking 401 + the lazy-loader = the concrete MASKING findings; whole-repo per-site sweep = remediation-phase |
| 10 | Authn / authz matrix | ✅ | existing suites + PR #254 Sparta pass cover the grid; gap = `remote_gateway` role-token matrix untested (D-40) |
| 11 | Sparta /node audit | ✅ | PR #254 pass (D-06, D-23, D-24) |
| 12 | Governance correctness | ✅ | D-35 root cause; regression-test design below |
| 13 | Firewall canonicalization | ✅ | **D-27 corrected** — one impl + a `setattr` monkey-patch shim, not two impls; consolidation plan below |
| 14 | Network / service discovery | ✅ | D-15; lifespan bg-task cleanup verified OK |
| 15 | Public endpoint inventory | ✅ | 63 paths; groups classified; `/system/*` `/vault/stats` `/config/*` flagged for per-route trace; D-33, D-34 |
| 16 | CORS / host / proxy / TLS | ✅ | exact-origin ✅, cookies Secure/HttpOnly/SameSite=Strict ✅, CSRF double-submit ✅, HSTS gated-on-https ✅; **D-39** WS Origin check skipped when header absent |
| 17 | DB / transaction audit | ✅ | disposable PG: `alembic upgrade head` clean, single head; **86 pg-tests pass**; 1 non-portable test (D-38) |
| 18 | Identity data model (P3-8) | ✅ | **REPRODUCED on disposable PG** — `Justin`/`justin`/`"  justin  "` + `a@b.com`/`A@B.COM` all coexist; `0004` query validated |
| 19 | Rate limiting | ✅ | D-29; path B recommended |
| 20 | Documentation reference integrity | ✅ | full broken-ref list below (+ **D-41** 2 missing `docs/security/*.md`) |
| 21 | Config contract audit | ✅ | 74 env vars read vs 56 in `.env.example`; D-26 = ORPHANED CONTRACT; **D-42** auth-relevant vars undocumented |
| 22 | Packaging / license metadata | ✅ | D-12, D-18; SPDX inconsistent (INFO); `python -m build` = remediation-phase |
| 23 | Remote gateway completeness | ✅ | full event-type inventory below; D-30 UNSUPPORTED-BY-DESIGN |
| 24 | Dead / unused service audit | ✅ | Redis OBSOLETE-or-FUTURE (D-32); all other services have live consumers |
| 25 | Static security scan | ✅ | one `CERT_NONE` (D-22 FALSE-POSITIVE); **NO live secret**; deeper categories classified below |
| 26 | Resource / concurrency | ✅ | lifespan tasks cancelled w/ 5s timeout; `ThreadPoolExecutor` bounded; WS loop `finally`; blocking `urllib` telemetry (2s timeout, bounded) — INFO |
| 27 | Complete test inventory | ✅ | map below; **D-40** governance/detection/real-AuditStore have no behavioral tests |
| 28 | Required validation | ✅ | compileall, both sweeps, dup sweep, clean-venv, `pip install -e .`, alembic graph, 86 pg-tests, 63-route enum, governance smoketest — all run; full CI battery = PR #252/#254 green runs |

---

## MASTER FINDINGS TABLE

Legend for "PR": which open PR (if any) already remediates the finding.
`—` = not addressed by either open PR.

| ID | Sev | State | Short | File(s) | PR |
|---|---|---|---|---|---|
| D-01 | HIGH | CONFIRMED | `core/config/__init__.py:8` `=from .settings…` SyntaxError → `compileall` fails on `main`, `core.config` + `governance_smoketest` unimportable | `core/config/__init__.py` | **#254** |
| D-02 | HIGH | CONFIRMED | `pydantic-settings` imported by `core/config/{settings,config}.py`, never declared → `core.config` unimportable on a clean install | `requirements.txt` | **#254** |
| D-03 | HIGH | CONFIRMED | `core/audit/store.py` byte-identical to `core/guards/velocity.py` (clobbered by commit `d46d756`); `AuditStore`/`AuditConfig` gone → `core.governance.orchestrator` unimportable since 2026-06-17 | `core/audit/store.py` | **#254** |
| D-04 | HIGH | CONFIRMED | `core/api/middleware/fenrir.py` imports `core.security.fenrir_auth` — deleted with `core/s34_auth/` by PR #253; module dead | `core/security/fenrir_auth.py` (missing) | **#254** |
| D-05 | HIGH | CONFIRMED | `core/detection/Sentinel_threat_types.py` capitalised; every consumer imports lowercase → all of `core.detection.*` unimportable (case-sensitive import check) | `core/detection/` | **#254** |
| D-06 | MEDIUM | CONFIRMED | `core/monitoring/Sparta_core.py` capitalised; lazy loader looks for `.sparta_core` → `from core.monitoring import SpartaCore` silently fails; `/node` router never registered | `core/monitoring/` | **#254** |
| D-07 | MEDIUM | CONFIRMED | `core/detection/feniri_hunter.py` + `core/monitoring/event_types.py` `from sentinel_43_ai.detection.…` — phantom package that never existed | those 2 files | **#254** |
| D-08 | MEDIUM | CONFIRMED | `core/monitoring/__init__.py` lazy-loader: `_JORM_MODULE_CANDIDATES=("core.audit.jormungandr",)` (file is `core/monitoring/jormungandr.py`); `_WINDOW_STORE_CANDIDATES` 2nd entry phantom `sentinel_43_ai.detection.window_store` | `core/monitoring/__init__.py` | **#254** |
| D-09 | MEDIUM | CONFIRMED | `core/runtime.py:49` `from Core.logging_init import get_logger` — capitalised package → `core.runtime` unimportable on case-sensitive FS | `core/runtime.py` | **#254** |
| D-10 | MEDIUM | CONFIRMED | `core/guards/exceptions/expectations.py` never existed; `__init__.py`, `validators.py`, `bootstrap.py` import `BaseExpectation` / `get_default_expectations` / `get_{basic,hardened,sentinel43}_expectations` from it → whole package unimportable | `core/guards/exceptions/` | **#254** |
| D-11 | MEDIUM | CONFIRMED | `dashboard/state/{audit,health,remote,watchtower}_state.py` missing the module-level singleton (`audit_state = AuditState()` …) that `dashboard/state/__init__.py` imports; only `dashboard_state.py` has one → all `dashboard.state.*` unimportable | `dashboard/state/` | **#254** |
| D-12 | LOW | CONFIRMED | `pyproject.toml` `build-backend = "setuptools.backends.legacy:build"` — not a real backend name → `pip install -e .` never worked; no package-discovery config | `pyproject.toml` | **#254** |
| D-13 | MEDIUM | CONFIRMED | `cryptography` imported 4× by `core/monitoring/jormungandr.py`, never declared → `core.monitoring.jormungandr` unimportable on a clean install | `requirements.txt` | **#254** |
| D-14 | LOW | CONFIRMED | `core/api/middleware/request_context.py` byte-identical to `core/middleware/request_context.py`; neither imported | those 2 files | **#254** (`74d2ea9`) |
| D-15 | MEDIUM | CONFIRMED | **13 modules default `S43_WATCHTOWER_URL` to `http://s43-watchtower:9100` — a service that does not exist in the current topology.** Canonical is `s43-core:9100` (only `core/api/main.py` + `core/monitoring/rules.py` have it right). Compose + k8s override the env so prod is masked; standalone-dev / tests / partial deployments misroute all telemetry. Also = 13 independent copies of the same `os.getenv` + `_watchtower_request` helper (copy-paste drift class). | `core/api/config/config.py`, `core/api/deps/__init__.py`, `core/api/deps/deps.py`, `core/config/settings.py`, `core/logging_init.py`, `core/monitoring/{event_types,manager}.py`, `core/guards/exceptions/{bootstrap,contracts,exceptions,registry}.py`, `core/runtime.py` | — |
| D-16 | MEDIUM | SUSPECTED | Several Watchtower client helpers send **no `Authorization: Bearer <S43_WATCHTOWER_SERVICE_TOKEN>`** (`core/api/deps/deps.py`, `core/api/config/config.py`, `core/config/settings.py`, `core/logging_init.py`, `core/monitoring/event_types.py`, `core/guards/exceptions/{registry,contracts,exceptions}.py`). Need per-route verification: which hit token-protected operational routes vs open telemetry-ingest, and whether the helper inspects the response (401/403/503 → silent "success" = defect). | as listed | — |
| D-17 | MEDIUM | CONFIRMED | `core/api/deps/__init__.py` (485 lines) contains a **full second implementation** of the Config dataclass + engine/store factory + `_watchtower_request`, then `from .deps import require_admin, require_operator` **twice**, shadowing its own local `require_admin`/`require_operator`. Canonical = `core/api/deps/deps.py` (728 lines). Same drift class as D-03/D-14. Consumers (`routers.py`, tests) `from core.api.deps import …` and get a mix. | `core/api/deps/__init__.py` vs `deps.py` | — |
| D-18 | INFO | CONFIRMED | `LICENSE.md` referenced by 8 files (`Notice:5`, `core/api/deps/__init__.py` header, +6). Repo has `LICENSE` (no extension). | 8 files | — |
| D-19 | LOW | CONFIRMED | Live deployment/migration files reference deleted docs: `docker-compose.yml:258` → `AUTH_SESSION_BETA.md`; `migrations/versions/0002_sessions.py:8` → `SESSION_MODEL_PASS5A.md`. | those 2 | partial: #252 fixes the `HANDOFF_BETA.md`/`BETA_EXECUTION.md` companion list |
| D-20 | INFO | CONFIRMED | ~15 code comments cite deleted `*_PASS4.md` / `PASS3_VALIDATION.md` / `HANDOFF_PASS5AM.md` / `RELEASE_FINDINGS.md` as "recorded in X" (`core/auth/*`, `core/api/routers/*`, `core/monitoring/watchtower.py`). Design-rationale citations only; not misleading about behaviour. PR #253/#254 deliberately left this class. | many | — |
| D-21 | LOW | CONFIRMED | Kept docs cross-reference deleted siblings: `MIGRATION_ARCHITECTURE_PASS5AM.md` (8/99/208) & `MIGRATION_BASELINE_PASS5AM.md` (7/186) → `PASS5AM_VALIDATION.md` / `HANDOFF_PASS5AM.md` / `SESSION_MODEL_PASS5A.md`; `DEPLOYMENT_RUNBOOK.md` (5/44) → `RELEASE_HARDENING_PLAN.md` / `VALIDATION_REPORT.md`. | those docs | — |
| D-22 | INFO | FALSE-POSITIVE | `core/api/middleware/fenrir.py:403-404` `ctx.check_hostname=False` / `ssl.CERT_NONE` — **properly dev-gated**: `_create_ssl_context` raises `RuntimeError` (fail-closed, `logger.critical`) if `verify_tls=False` outside `S43_ENV∈{dev,development,local}`. Not a defect. (Module itself is currently dead — see D-04.) | `core/api/middleware/fenrir.py` | n/a |
| D-23 | MEDIUM | CONFIRMED | `core/api/main.py` registered the SpartaCore `/node` router **unconditionally** (no `S43_SPARTA_ENABLED` guard, unlike the sibling watchdog block) — once D-06 is fixed this activates the router in every deployment. | `core/api/main.py` | **#254** (`426f0e0` — now gated behind `S43_SPARTA_ENABLED`) |
| D-24 | LOW | CONFIRMED | `_require_node_token` treated a whitespace-only `S43_SPARTA_NODE_TOKEN` as configured → 401 instead of the intended 503. Fail-closed either way. | `core/monitoring/sparta_core.py` | **#254** (`426f0e0`) |
| D-25 | DEFERRED | CONFIRMED | Governance: `governance_smoketest.py` — "HUMAN_GATED requested, decision reported mode=None". Decision object does not carry the effective governance mode. Product/contract decision. | `core/governance/orchestrator.py` (+ policy gate) | — (explicitly out of scope for #252/#254) |
| D-26 | DEFERRED | CONFIRMED | `SENTINEL_LOG_SALT` — required by `generate_secrets.py` + `deploy_preflight.py`, **no runtime reader** after PR #253 deleted `Shadow_mode.py`/`sentinel_ai_escalation.py`. Config-contract decision. | `core/cli/generate_secrets.py`, `scripts/deploy_preflight.py`, `.env.example` | — |
| D-27 | MEDIUM | CONFIRMED (corrected §2) | **`FirewallConfig.from_env()` exists only as an import-time `setattr` monkey-patch.** ONE impl (`core/api/middleware/sentinel_firewall_middleware.py`, no `from_env`); `core/middleware/sentinel_firewall.py` imports it and `setattr`s `from_env` on. `core/api/main.py` uses the patched path; `core/api/middleware/__init__.py` re-exports the raw class → `.from_env()` from there = `AttributeError`. Import-order-fragile security-config loader. Consolidation plan in §13. | `core/middleware/sentinel_firewall.py`, `core/api/middleware/sentinel_firewall_middleware.py`, `core/middleware/__init__.py` | — |
| D-28 | DEFERRED | KNOWN | F-TLS-1: no real-target edge-TLS validation. | deploy | #252 (tooling), not closable without a named target |
| D-29 | DEFERRED | KNOWN | Multi-replica login throttle is per-process; `overlays/beta` ships 2 replicas. | `core/api` throttle | #252 preflight now checks 1-replica/1-worker; shared limiter is a separate change |
| D-30 | INFO | RESOLVED-CLASSIFICATION | Remote-gateway `ROTATE_REMOTE_TOKEN` → **501, by design and honest.** `remote_gateway.py` comments: "returns 501 instead of falsely reporting success", "remains 501 until a key-rotation subsystem is [built]", "`_dispatch_remote_event` raises `NotImplementedError`". **UNSUPPORTED-BY-DESIGN, not a beta blocker** — it fails loudly, not silently. Good pattern. | `core/api/routers/remote_gateway.py` | n/a |
| D-32 | MEDIUM | CONFIRMED | **Redis deployed but unused.** `docker-compose.yml` ships `s43-redis`; k8s ships it; `REDIS_PASSWORD` / `REDIS_URL` are "required secrets" in `generate_secrets.py` + `deploy_preflight.py`. **The only Redis reference in `core/` is `redis_url` in the stale unused `core/config/config.py` (D-31).** No `import redis`, no client, no runtime use. Attack surface + resource + a 2nd orphan secret (cf. D-26). Classify: obsolete, OR intentional-future (D-29's shared limiter would use it) — needs an owner call. | `docker-compose.yml`, `deploy/kubernetes/*`, `core/cli/generate_secrets.py`, `scripts/deploy_preflight.py` | — |
| D-33 | MEDIUM | CONFIRMED | **`/docs` `/redoc` `/openapi.json` are served HTTP 200 unauthenticated by the app** (FastAPI defaults; verified via TestClient). The nginx proxy / k8s ingress proxy `/` wholesale (no path filter). PR #252's `deploy_preflight --phase verify` *asserts these return 401/403/404 on a real target* — **but nothing in the app or the edge actually blocks them.** Either set `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)` in non-local, or add an edge deny, or the preflight check is unsatisfiable. Overlaps the "public docs exposure = owner decision" item but is now a concrete inconsistency. | `core/api/main.py` (FastAPI ctor), proxy, `scripts/deploy_preflight.py` | partial: #252 added the (currently unsatisfiable) check |
| D-34 | LOW | CONFIRMED | Duplicate FastAPI operation IDs — `UserWarning: Duplicate Operation ID health_health_get` at import (`core/api/routers/routers.py`). Route groups are multiply-mounted: `/watchtower/health` **and** `/api/watchtower/health`; `/actions/*` **and** `/v1/actions/*`; 7+ distinct `*/health` and 7+ `*/status` paths. Bloats the API surface + breaks generated clients. Needs a route-map review (§15). | `core/api/routers/routers.py`, `core/api/main.py` | — |
| D-35 | MEDIUM | CONFIRMED (root cause) | **Governance mode not on the Decision contract.** `Decision` dataclass fields = `status, score, reason, decision_id` — **no `mode`**. `process_transaction` computes `effective_mode` and passes it to `PolicyContext.mode` / `metadata["effective_mode"]` (policy eval uses it) but the returned `Decision` doesn't surface it → `governance_smoketest.py::_decision_mode` always `None`. Concrete form of **D-25**. Contract fix (record): add `mode: str` to `Decision`, populate from `effective_mode`; `_resolve_mode` already logs ignored overrides → no silent downgrade. Regression-test design below. | `core/governance/orchestrator.py`, `core/scripts/governance_smoketest.py` | — |
| D-36 | LOW | CONFIRMED | `requirements.txt` declares `redis>=6.4.0`; **no `core/` module imports `redis`**. Declared-unused. Same root as D-32. | `requirements.txt` | — |
| D-37 | MEDIUM | CONFIRMED | **`core/api/core/` is a dead sub-tree.** `config.py` (a 4th `Settings` class), `logging.py`, `runtime.py` — internally consistent, but **nothing outside `core/api/core/` imports `core.api.core.*`** (verified). ~400 LOC. `main.py:1874` comment already notes "core/api/core… neither of which is [used]". Drift risk + a 4th competing config. | `core/api/core/{config,logging,runtime}.py` | — |
| D-38 | LOW | CONFIRMED | `core/tests/test_backup_restore_pg.py` hardcodes `docker exec -i <container> pg_dump -U s43t -d s43t` instead of parsing user/db from `S43_TEST_PG_DSN`. Passes only when the disposable PG is named exactly `s43t` (CI's). Non-portable test, not a product defect — but it means the backup/restore path is unverified outside CI's exact naming. | `core/tests/test_backup_restore_pg.py` | — |
| D-39 | LOW | CONFIRMED | `core/api/main.py:1121` WS Origin check is `if _ALLOWED_ORIGINS and origin and origin not in _ALLOWED_ORIGINS` — **skipped entirely when the `Origin` header is absent** (non-browser clients). Defence-in-depth only (WS still requires a valid token frame), so LOW, but a non-browser client evades the Origin gate. | `core/api/main.py` | — |
| D-40 | MEDIUM | CONFIRMED | **Governance / detection / real-AuditStore contract layers have no behavioral tests.** `core/governance/orchestrator.py` (0), `core/detection/sentinel_threat_detector.py` (0), `core/detection/feniri_hunter.py` (0), `core/monitoring/jormungandr.py` (0), `core/monitoring/manager.py` (0), `core/guards/velocity.py` (0), `core/api/routers/remote_gateway.py` (0), the **real** `AuditStore` (the "11 refs" on main are name-collisions with the clobbered velocity code). This is the coverage hole that let D-03 (AuditStore clobber) and D-35 (governance mode) persist unnoticed. PR #254's `test_package_integrity.py` adds import + min-symbol + real-`AuditStore` construct/append coverage — partial. Behavioral coverage of governance + detection = remediation-phase. | `core/tests/` | partial: #254 `test_package_integrity.py` |
| D-41 | LOW | CONFIRMED | References to **two `docs/security/*.md` files that do not exist**: `endpoint_access_matrix.md` (referenced by `test_actions_test_inject_auth.py:27`, `deploy/kubernetes/README.md:315`, `overlays/beta/ingress.yaml:13`) and `internal_service_auth.md` (`deploy/kubernetes/base/secret.example.yaml:50`). Only `docs/security/trusted_proxy_handling.md` exists. Ironically these are exactly the docs §15 + §8 of this audit would produce. | those 4 files | — |
| D-42 | LOW | CONFIRMED | **Auth-relevant env vars undocumented in `.env.example` / compose / k8s:** `S43_ADMIN_TOKEN` (gates `/watchtower/state/*` via `_require_admin_token`; unset → that route is permanently 401 = dead), `GHOST_DEVICE_HASH_SECRET`, `S43_SESSION_HASH_PEPPER` (optional session-hash HMAC), `S43_SCHEMA_CREATE_ALL` / `S43_SCHEMA_VERSION_CHECK` (deployment overrides), `S43_CONTENT_SECURITY_POLICY`. Operators cannot configure what is not documented. | `.env.example`, `docker-compose.yml`, `deploy/kubernetes/` | — |

---

## Section 0 — Canonical repository state ✅

| item | value |
|---|---|
| `main` SHA | `fa587c2c8dc990ea64fc23695d2caa949a5f6b36` (PR #253 merge) |
| PR #252 | `beta/post-merge-verification-20260903` @ `6ce21d8` → `main`; open; mergeable |
| PR #254 | `fix/post-cleanup-config-validation-20260903` @ `f3eba76` → `main`; open; mergeable |
| Open issues | 0 · Open PRs | #252, #254 |
| `git fsck --full` | clean (dangling objects only) |
| PR #252 ∩ PR #254 changed files | **∅ zero overlap** |
| Worktrees | 1 · Working tree | clean |
| Tracked files | 245 |

**PR reconciliation (§31):** #252 and #254 change disjoint files → a combined
tree is a clean union, no conflict. Recommended order per §30:
**#254 first** (repository-integrity), then **#252** (deploy tooling).

---

## Section 1 — Known minimum defect set: verification ✅

Every PR #254 "known repair" item **independently re-confirmed** on `main` via
the §3 import sweep and §5 hash sweep — see D-01…D-14. All 13 are real; none
was a mis-description. PR #252's tooling defects were verified during that PR's
own REV passes (recorded in its thread; deploy_preflight rewrite + tests).

New confirmations from the prompt's "repository consistency findings":
- stale deleted-doc references → **D-19, D-20, D-21** (CONFIRMED).
- `LICENSE.md` vs `LICENSE` → **D-18** (CONFIRMED).
- Watchtower default `s43-watchtower:9100` vs `s43-core:9100` → **D-15**
  (CONFIRMED — worse than described: 13 files, not "some").
- `core/api/deps/__init__.py` duplicates a large impl → **D-17** (CONFIRMED).
- internal Watchtower clients missing the service token → **D-16** (SUSPECTED,
  per-route verification pending).

---

## Section 3 — Syntax + import integrity ✅ (evidence)

Environment: `.venv-pass1` (has `pydantic-settings` + `cryptography` installed
from the PR #254 work, so D-02/D-13 do **not** surface here — they surface only
on a clean `requirements.txt` install, see §7).

- `python -m compileall browser_tests/ core/ dashboard/ migrations/ scripts/`
  on `main` → **FAILS**, exit 1, `SyntaxError` at `core/config/__init__.py:8`
  (D-01).
- Import sweep (robust, walk-error-tolerant) of every non-test module under
  `core/ dashboard/ migrations/`: **105 OK / 23 BROKEN** on `main`.
  The 23 collapse to **9 distinct root causes** = D-01, D-03, D-04, D-05,
  D-09, D-10, D-11 (+ D-06/D-08 which don't fail `core.monitoring`'s own
  import but break `from core.monitoring import SpartaCore`).
- With PR #254 applied (verified in that pass): **124 → 123 OK / 0 BROKEN**
  (123 after `request_context` dedup).
- No circular-import failures found. No "hidden behind broad except"
  import failures found in the sweep (the broad-except audit is §9).
- 124 is a historical baseline, not a target — the real current-tree count
  after #254 + this audit's test additions is what §28 will record.

---

## Section 4 — Case-sensitive filesystem audit ✅

Repo has `core.ignorecase=true` (Windows). Two case-only defects on `main`:
- **D-05** `core/detection/Sentinel_threat_types.py` (siblings are lowercase).
- **D-06** `core/monitoring/Sparta_core.py` (siblings are lowercase; lazy
  loader expects `.sparta_core`).
- **D-09** `core/runtime.py` `from Core.logging_init` — capitalised *package*
  reference (not a file), same class.

No trailing-space filenames on `main` (PR #253 removed
`core/monitoring/Sentinel_firewall .py`). No duplicate names differing only by
case among tracked files. Windows import success for D-05/D-06/D-09 would
**not** occur on Linux — Python's `FileFinder` enforces case on both, which is
exactly why the sweep catches them on Windows too.

**Remediation (recorded, not done):** `git mv --force` the two files to
lowercase (PR #254 does this: `sentinel_threat_types.py`, `sparta_core.py`),
fix the one package-name string in `core/runtime.py`.

---

## Section 5 — Duplication / clobber detection ✅

Header-stripped body-hash sweep, 175 `.py` files on `main`. **2 identical-body
groups**, both known:
- `core/audit/store.py` == `core/guards/velocity.py` → **D-03** (clobber).
- `core/middleware/request_context.py` == `core/api/middleware/request_context.py`
  → **D-14** (dead duplicate).

Near-identical (>0.85, same top-level name set): only the same two pairs.

Deeper structural review of the prompt's named suspects:
- `core/api/deps/__init__.py` vs `deps.py` → **D-17** (large partial
  duplicate + self-shadowing re-imports).
- `core/middleware/` vs `core/api/middleware/` firewall → **D-27** (competing
  non-identical implementations, documented TODO).
- Config modules: `core/config/` (settings.py + config.py — **two parallel
  `Settings` classes**, only `settings.py` is wired via `__init__.py`;
  `config.py` is a stale parallel), `core/api/config/` (`ApiConfig`,
  separate, the one the app uses), `core/api/core/config.py` (a third —
  resolved §2 — `core.api.core` is dead, D-37). → **D-31**.

| D-31 | MEDIUM | SUSPECTED | Three+ parallel config modules: `core/config/{settings,config}.py` (two `Settings` classes; `config.py` unused parallel), `core/api/config/config.py` (`ApiConfig` — the live one), `core/api/core/config.py` (third). Needs canonical determination. | those | — |

---

## Section 6 — Git-history corruption audit ✅

Two scans this session:
1. **Large single-file replacement** (>100 added, >60 deleted, >55% of the
   file replaced) across `core/**/*.py` history → only `core/s34_auth/*`
   commits (June 2026) — a **deleted** module, irrelevant.
2. **Full class/def name-set divergence** — for every current `core/` module
   >1.5 KB, compared its top-level `class`/`def` name-set to its ~30th-oldest
   revision. **One flag:** `core/api/routers/auth.py` (overlap 0.11) — but the
   shared names (`LoginRequest`, `LoginResponse`, `VerifyResponse`) + the
   commit log (`Refactor auth.py for clarity`, `Refactor JWT verification`,
   `Refactor JWT handling and add service token`) confirm it is a
   **legitimate multi-pass auth redesign**, not a clobber. EXPECTED REFACTOR.

**Verdict: D-03 (`d46d756` AuditStore→velocity) and D-14 (`request_context`
relocation) are the COMPLETE set of history-corruption findings.** No other
module's content diverged from its filename/purpose. `d46d756~1:core/audit/store.py`
has the real `AuditConfig`/`AuditStore` (`sqlite_path`/`jsonl_path`/`signing_key`/
`append()`) — matches `orchestrator.py` — evidence-based restore target confirmed
(PR #254 does exactly this).

---

## Section 7 — Dependency audit ✅

Import-derived vs declared (`requirements.txt`):
- **Undeclared, imported:** `pydantic_settings` (D-02), `cryptography` (D-13).
- **Declared, apparently unused at runtime:** _pending full check_ — candidates
  to verify: none obvious; `redis` (see §24 — is Redis actually used?).
- `pyproject.toml` `[project]` lists **no** runtime deps (comment "Add your
  actual runtime dependencies here") — deps live only in `requirements.txt`.
  So `pip install -e .` installs the package with zero dependencies (D-12
  also blocks the build entirely with the bad backend name).

**DONE (clean venv `.venv-audit`, `requirements.txt` + `pytest requests pyyaml` only):**
- Import sweep: **104 OK / 24 BROKEN** (vs `.venv-pass1`'s 105/23 — the one
  extra is `core.monitoring.jormungandr: No module named 'cryptography'` =
  D-13). The **complete undeclared-dependency set is `{pydantic-settings,
  cryptography}`** — no others. (`pydantic-settings` doesn't show as a distinct
  `ModuleNotFoundError` only because `core.config` dies on D-01's SyntaxError
  first; the source `from pydantic_settings import …` in
  `core/config/{settings,config}.py` is verified undeclared.)
- `pip install -e .` → **`BackendUnavailable: Cannot import
  'setuptools.backends.legacy'`** — D-12 REPRODUCED; editable install is
  entirely broken on `main`.
- No declared-but-unused runtime dependency found (spot-check). Redis: see
  D-32 — `redis>=6.4.0` is declared but **no `core/` module imports it**.

**Remediation-phase (after D-12 fix):** `python -m build` (wheel + sdist) after D-12 fix; Dockerfile
`python:3.13-alpine` musllinux-wheel check for `cryptography` (PR #254 CI
already proved the image builds — re-note).

**D-36 (LOW, CONFIRMED):** `requirements.txt` declares `redis>=6.4.0` but no
runtime code imports `redis`. Declared-unused. (Same root as D-32.)

---

## Section 8 — Watchtower internal client audit ✅

**Server side is CORRECT.** `core/monitoring/watchtower.py::_require_service_token`
fails closed: 503 if `S43_WATCHTOWER_SERVICE_TOKEN` unset, 401 for missing/wrong
Bearer, constant-time compare, token never echoed. Routes:
`/watchtower/health` + `/watchtower/ready` = **unauthenticated** (probes only);
`/status /modules /modules/register /modules/heartbeat /dependencies
/dependencies/report /events/recent /analyze` = **`Depends(_require_service_token)`**;
`/state/{name}` additionally needs `X-S43-Admin-Token` (`S43_ADMIN_TOKEN`, D-42).

**Client matrix — 12 helpers, 10 broken (D-16 CONFIRMED):**

| helper | routes hit | Bearer token? | inspects response? | on non-2xx |
|---|---|---|---|---|
| `core/api/main.py::_watchtower_request` | register / report / analyze / heartbeat | **YES** (`S43_WATCHTOWER_SERVICE_TOKEN`) | yes → returns result | logged |
| `core/monitoring/manager.py::_watchtower_request` | register / report / analyze | **YES** (l.95-97) | `result = …` | `except Exception:` |
| `core/api/deps/deps.py` | register / report / analyze | **NO** | no | `except Exception:` |
| `core/api/deps/__init__.py` | register / report / analyze | **NO** | no | `except Exception:` |
| `core/api/config/config.py` | register / report / analyze | **NO** | no | `except Exception:` |
| `core/config/settings.py` | register / report / analyze | **NO** | no | `except Exception:` |
| `core/guards/exceptions/registry.py` | register / report / analyze | **NO** | captures `result` (unused) | `except Exception:` |
| `core/guards/exceptions/bootstrap.py` | register / report / analyze | **NO** | ? | `except Exception:` |
| `core/guards/exceptions/exceptions.py` | analyze | **NO** | no | `except Exception: pass` |
| `core/guards/exceptions/contracts.py` | analyze | **NO** | no | `except Exception: pass` |
| `core/logging_init.py::_watchtower_report` | dependencies/report | **NO** | no | `except Exception: pass` |
| `core/monitoring/event_types.py` | analyze | **NO** | no | `except Exception:` |

**D-16 mechanism:** these 10 POST to `_require_service_token`-protected routes
with **no `Authorization` header** → Watchtower returns **401** →
`urllib.request.urlopen` raises `HTTPError` → the surrounding
`except Exception:` (`pass` in the guards/logging/event_types cases) swallows it
→ **the caller believes the report was delivered. It never reaches Watchtower.**
The lost telemetry: expectation/contract failures (guards/exceptions),
invalid-log-level events (`logging_init`), event-normalisation reports
(`event_types`), and the deps/config module registrations. Only `main.py`'s
bridge and `manager.py` actually work.

The `_require_service_token` docstring itself lists only "the API bridge…,
FenrirHunter, and the s34_auth reporter" as callers — the guards / logging /
event-types clients were added later (or copy-pasted from a token-less
template) and never wired to the token.

**D-15 + D-16 shared remediation (record only):** one canonical
`core/monitoring/watchtower_client.py` with (a) default `http://s43-core:9100`,
(b) `Authorization: Bearer os.getenv("S43_WATCHTOWER_SERVICE_TOKEN")`,
(c) an explicit `resp.status` check with a **bounded / rate-limited** WARNING
log on non-2xx (never flood — a `logging.LoggerAdapter` with a suppress window,
or a once-per-N-minutes guard). Replace all 12 call sites. Add an integration
test (disposable Watchtower): a report with an absent/wrong token is rejected
**and the caller logs it** — not a silent success.

---

## Section 9 — Broad exception / silent-failure audit ✅

~180 `except Exception` / bare `except` across `core/` (densest:
`core/api/main.py` 17, `core/monitoring/manager.py` 9, `routers/routers.py` 7).
A whole-repo per-site classification is remediation-phase; the two **concrete
MASKING findings** are recorded:

1. **The 10 token-less Watchtower helpers (D-16 / §8).** `except Exception:`
   (`pass` in the guards/logging/event_types cases) wraps
   `urllib.request.urlopen`, which raises `HTTPError` on the 401 that
   Watchtower returns → the auth failure is invisible and the caller acts as
   if the report succeeded. **MASKING ERROR.**
2. **`core/monitoring/__init__.py` lazy loader** (`_import_first`,
   `_load_*_export`) catches `(ImportError, AttributeError)` and only
   `warnings.warn`s — not even a log line. This is *how D-06 & D-08 hid*:
   `from core.monitoring import SpartaCore` silently `AttributeError`s;
   `main.py`'s own `try/except` logs a one-line warning; everything else looks
   fine. **MASKING ERROR** for anything that must load.

**Recommended remediation (record only):**
- For lazy exports that are *required when a flag is on* (`SpartaCore` /
  `create_node_router` under `S43_SPARTA_ENABLED`; `MonitoringManager`
  always) → escalate the swallow to a hard `ImportError` naming the file +
  missing attr. Keep the soft path for genuinely-optional betas (jormungandr,
  window_store). PR #254's `test_package_integrity.py` import-sweep is the
  durable guard.
- For the Watchtower helpers → §8 Batch B (a client that checks `resp.status`
  and logs non-2xx with a bounded rate).
- `core/api/main.py` lifespan `except Exception: logger.error(...)` blocks for
  optional subsystems (Sparta/Fenrir/remote-gateway) — **acceptable
  fail-soft** (they log, they're behind flags), but the log should say
  *which* subsystem and be at WARNING not swallowed.

---

## Section 11 — Sparta /node audit ✅

Completed in the PR #254 hardening pass. Recorded findings **D-06, D-23,
D-24**. Full route matrix, service-identity separation proof, secret-handling
review, fail-closed proof, deployment-exposure analysis, and 40+ regression
tests are in PR #254 (`f3eba76`) and its description. Summary:
- 7 routes under `/node` (health public+coarse; status/events/auth/register/
  heartbeat/unlock require `Bearer S43_SPARTA_NODE_TOKEN`).
- Auth = `secrets.compare_digest` only — no `verify_jwt_token`, no human/other-
  service credential path (proven both directions).
- Missing/blank token → 503; wrong → 401; lockout → 429. Never anonymous.
- Router now gated behind `S43_SPARTA_ENABLED` (default false everywhere).
- Edge-reachable when enabled (same as all routes — no edge path filtering by
  design); no manifest change needed.

---

## Section 13 — Firewall canonicalization ✅ (D-27 corrected + consolidation plan)

**There is only ONE implementation.** `core/api/middleware/sentinel_firewall_middleware.py`
(735 LOC) defines `BlockReason`, `FirewallConfig`, `FirewallDecision`,
`_RateLimiter`, `SentinelFirewall`. It has **no `FirewallConfig.from_env()`**.

`core/middleware/sentinel_firewall.py` (229 LOC) is **not a rival impl** — it
does `from core.api.middleware.sentinel_firewall_middleware import
(SentinelFirewall, FirewallConfig, BlockReason)` and then
`setattr(FirewallConfig, "from_env", classmethod(_firewall_config_from_env))`.
It **monkey-patches `from_env` onto the real class at import time.**

- `core/api/main.py:989` → `from core.middleware import SentinelFirewall,
  FirewallConfig` → gets the patched `FirewallConfig` (has `from_env`).
- `core/api/middleware/__init__.py` → `from .sentinel_firewall_middleware
  import …` → gets the **raw** `FirewallConfig` **without `from_env`**.

**D-27 (corrected):** `FirewallConfig.from_env()` — a security-critical config
loader — exists only as a runtime `setattr` side-effect of importing
`core.middleware`. Import-order-fragile; any caller reaching `FirewallConfig`
via `core.api.middleware` and calling `.from_env()` gets `AttributeError`.
`core/middleware/__init__.py`'s docstring ("relocated stale copy that lost
from_env, caused a production outage") is itself now stale — there's no second
copy, there's a patch. Test coverage: `test_firewall_config_hardening.py`,
`test_firewall_trusted_proxy_config.py`, `test_firewall_proxy_trust.py` (all
exercise the patched path).

### Exact consolidation plan (remediation-phase, NOT this session)

**Commit 1 — move `from_env` into the class.**
- FILES: `core/api/middleware/sentinel_firewall_middleware.py` (add
  `@classmethod def from_env(cls)` to `FirewallConfig`, body = the current
  `_firewall_config_from_env` + `_build_config_kwargs` + the five `_env_*`
  helpers, moved verbatim from `core/middleware/sentinel_firewall.py`).
- PURPOSE: `from_env` becomes a real method, available from **both** import
  paths.
- TESTS: `test_firewall_config_hardening.py`, `test_firewall_trusted_proxy_config.py`,
  `test_firewall_proxy_trust.py` pass unchanged; **new** test:
  `FirewallConfig.from_env()` works when imported from `core.api.middleware`
  (not just `core.middleware`) and produces a `FirewallConfig` **field-for-field
  identical** to the pre-change patched result (assert `dataclasses.asdict`
  equality for a fixed env set).
- SECURITY: none if the identity assertion holds. `from_env` logic byte-moved.
- ROLLBACK: revert commit 1; the shim still works.

**Commit 2 — reduce the shim.**
- FILES: `core/middleware/sentinel_firewall.py` → 4 lines:
  `from core.api.middleware.sentinel_firewall_middleware import BlockReason,
  FirewallConfig, SentinelFirewall` + `__all__ = [...]`. Delete `_env_*`,
  `_build_config_kwargs`, `_firewall_config_from_env`, the `setattr`, the
  double `hasattr` guard.
- FILES: `core/middleware/__init__.py` → drop the prefer/fallback/hard-fail
  ladder; plain `from .sentinel_firewall import BlockReason, FirewallConfig,
  SentinelFirewall` + `__all__`. Keep the "why two locations exist" comment
  trimmed to one line.
- PURPOSE: single source of truth; `core.middleware` and `core.api.middleware`
  are now equivalent thin views.
- TESTS: all firewall tests + `test_app_route_registration.py` (firewall
  registers) + `import core.api.main` (l.566, l.989 both resolve).
- SECURITY: none.
- ROLLBACK: revert commit 2.

`core/api/main.py` is **not touched** in either commit.

---

## Section 14 — Network / service discovery audit ✅

- **D-15** (Watchtower host default) — the headline finding.
- `dashboard/config.py` + `dashboard/services/*` default to
  `http://localhost:8000` / `localhost:8000` WS — correct for the dashboard's
  split-origin dev model; the SPA served by the API is same-origin (PR #252's
  `dashboard/assets/js` work). Classify: acceptable (dashboard app ≠ served
  SPA). INFO.
- `core/api/routers/auth.py:812-813` default CORS/redirect origins include
  `http://localhost:5500` / `127.0.0.1:8000` — dev defaults, overridden by
  `S43_ALLOWED_ORIGINS` in non-local (PR #254's config work + `_validate_
  security_config` refuses plaintext non-loopback origins in non-local). OK.
- `core/api/middleware/fenrir.py:134` `http://postgres:5432` — stale service
  name (`postgres` vs `s43-db`); module is dead (D-04) so INFO, but fix when
  D-04's module is revived.
- `core/detection/feniri_hunter.py:365` `S43_FENRIR_WATCHTOWER_URL` default
  `http://s43-api:8000/watchtower/events` — a *different* route shape than the
  other clients; verify it's intentional (Fenrir posts events via the API
  bridge, not direct to Watchtower). SUSPECTED-OK.

Canonical discovery rule recommendation: single `S43_WATCHTOWER_URL` env,
single default `http://s43-core:9100`, single helper module. Test standalone
+ Compose + k8s.

---

## Section 15 — Public endpoint inventory ✅

**Authoritative enumeration via `TestClient` + OpenAPI: 63 documented paths.**
Full list captured in the audit run. Route-group structure:

| group | notes |
|---|---|
| probes | `/health` `/ready` `/api/ready` `/core/health` `/watchtower/health` `/watchtower/ready` `/fenrir/health` `/remote-gateway/health` `/audit/health` — **9 health/ready endpoints** (D-34) |
| auth (human) | `/auth/login` `/auth/refresh` `/auth/logout` `/auth/verify` |
| bootstrap | `/bootstrap/status` (public) `/bootstrap/admin` (once) |
| admin | `/users` `GET,POST`, `/users/{id}` `PATCH`, `/users/{id}/password` `POST` |
| operator `/v1` | `/v1/actions` `/v1/actions/{id}/approve|veto` `/v1/assess` |
| legacy actions | `/actions` `/actions/test-inject` `/actions/{id}/approve|veto` — **duplicate of `/v1/actions/*`** (D-34) |
| watchtower | `/watchtower/{check,events,heartbeat,modules,register,status,health,ready}` + `/api/watchtower/{health,ready,status}` — **double-mounted** (D-34) |
| fenrir | `/internal/events/broadcast` (service token), `/fenrir/{health,metrics,status}` |
| remote gateway | `/remote-gateway/{targets,health}` `/remote-gateway/events/activate` `/remote-gateway/audit/{cid}` |
| system/debug | `/system/routes` `/system/status` `/system/intercom/status` `/status` `/version` `/api/version` `/api/config` `/config/` `/config/status` `/vault/stats` `/rules/` `/rules/status` `/api/rules` `/governance/pending` `/dependencies/status` `/dependencies/report/{name}/{state}` `/core/{status,heartbeat}` |
| events | `/events/proxy` |
| metrics | `/metrics` |
| ws | `/ws` |
| docs | `/docs` `/redoc` `/openapi.json` → **HTTP 200 unauthenticated** → **D-33** |

**Remediation-phase (Batch C4):** per-route AUTH classification (PUBLIC-PROBE
/ HUMAN / ADMIN / SERVICE / INTERNAL / DEV) by tracing each router's
`dependencies=`, published as `docs/security/endpoint_access_matrix.md`
(D-41). Priority: `/system/routes`, `/system/status`, `/vault/stats`,
`/config/`, `/api/config` — a route-listing / config / vault-stats endpoint
that is not clearly SERVICE/ADMIN-gated would be a defect; each must be
traced and pinned by a test.

New findings: **D-33** (docs exposure vs preflight expectation), **D-34**
(route duplication / operation-id collision).

---

## Section 19 — Rate limiting ✅

- **Login throttle** (`core/auth/users.py` per-username lockout, env-tunable
  `S43_LOGIN_MAX_FAILURES`/`_FAIL_WINDOW_SECONDS`/`_LOCKOUT_SECONDS`) —
  **in-process** (a module-level dict). Per-worker, per-replica. → **D-29**.
- **Sparta `/node` auth-failure lockout** (`sparta_core.py`
  `_record_auth_failure` → `_blocked_clients`) — in-process, per-instance.
  Acceptable: Sparta is single-instance and the lockout is defence-in-depth on
  top of a constant-time secret compare.
- **Firewall** `max_content_length_bytes` / `max_total_header_bytes` — per
  request, stateless. OK.
- No Redis-backed or DB-backed limiter anywhere.

**Recommended remediation path for D-29 (record only):** for controlled beta,
option **B** — enforce and validate exactly one API replica + one worker as
the explicit supported config (PR #252's `deploy_preflight --phase verify`
already checks this). A shared limiter (option A) is a larger change deferred
until a confirmed multi-replica requirement.
`overlays/beta` currently ships **2** replicas + a PDB → must be overridden to
1, or the doubled rate limit accepted, until then. Do **not** claim
multi-replica throttle protection.

---

## Section 20 — Documentation reference integrity ✅

- **D-18** `LICENSE.md` (8 refs) — repo has `LICENSE`.
- **D-19** `docker-compose.yml:258` → `AUTH_SESSION_BETA.md` (deleted);
  `migrations/versions/0002_sessions.py:8` → `SESSION_MODEL_PASS5A.md`
  (deleted). Both in files that ship.
- **D-20** ~15 code comments → deleted `*_PASS*.md` / `RELEASE_FINDINGS.md`.
- **D-21** kept docs (`MIGRATION_*_PASS5AM.md`, `DEPLOYMENT_RUNBOOK.md`)
  cross-ref deleted siblings.
- `HANDOFF_BETA.md` / `BETA_EXECUTION.md` companion lists → **PR #252 already
  fixes these** (its `6ce21d8` reworked the companion list + §K).
- `README.md`, `Notice`, `COMMERCIAL_LICENSE.md` — `Notice:5` has the
  `LICENSE.md` ref (D-18); otherwise clean on a spot-check (full pass pending).

**Recommended remediation (record only):** global `LICENSE.md`→`LICENSE`
(or add a `LICENSE.md` that points to `LICENSE` — pick one); drop/rephrase the
two shipping-file refs (D-19); leave D-20 (matches PR #253/#254 policy) unless
a comment is actively misleading; fix D-21 pointer lines in the kept docs.

---

## Section 21 — Config contract audit ✅

**74 distinct env vars read by `core/`; 56 declared in `.env.example`.** The
gap is mostly cosmetic (`S43_*_MODULE_ID`, `S43_*_VERSION` telemetry labels —
harmless). Substantive findings:

- **D-26 — `SENTINEL_LOG_SALT` = ORPHANED CONTRACT (final).** Generated by
  `generate_secrets.py`, in `.env.example:87`, `docker-compose.yml:125,263`,
  k8s `secret.example.yaml:43` + `k8s.yml:312`, `deploy/kubernetes/README.md:55`,
  `deploy_preflight.py` REQUIRED_SECRETS, `HANDOFF_BETA.md:172` — **zero
  runtime readers** (`Shadow_mode.py`/`sentinel_ai_escalation.py`, its historical
  consumers, deleted by PR #253). `generate_secrets.py:122` label still says
  "required in production by sentinel_ai_escalation.py". Remediation (record):
  either remove it from generator/preflight/`.env.example`/compose/k8s/docs,
  **or** mark it `# FUTURE (log pseudonymisation)` and stop calling it
  "required". Do NOT remove this session.
- **D-15** — `S43_WATCHTOWER_URL` 13 divergent defaults (`s43-watchtower` vs
  `s43-core`).
- **D-42 — undocumented auth-relevant vars:** `S43_ADMIN_TOKEN` (→ `/watchtower/state/*`
  is dead without it), `GHOST_DEVICE_HASH_SECRET`, `S43_SESSION_HASH_PEPPER`,
  `S43_SCHEMA_CREATE_ALL`, `S43_SCHEMA_VERSION_CHECK`, `S43_CONTENT_SECURITY_POLICY`.
- **D-32** — `REDIS_PASSWORD` / `REDIS_URL` are a second orphaned-secret pair.
- `S43_ENV` vs `SENTINEL_ENV` — genuine dual contract; `S43_ENV` read by Fenrir
  / Sparta / Watchtower, `SENTINEL_ENV` by the rest. PR #254 corrected the
  `.env.example` comment. Keep both; document the split.
- No env var is read with a *wrong* type/parse that would crash — the `_env_*`
  helpers all have defaults.

---

## Section 16 — CORS / host / proxy / TLS ✅

| control | finding |
|---|---|
| exact origin matching | `_ALLOWED_ORIGINS` is a `frozenset`; CORS `allow_origins=sorted(...)` (Starlette exact match); WS check `origin not in _ALLOWED_ORIGINS`. **✅ exact, no substring/prefix.** |
| non-local plaintext origin | `core/api/main.py:345-360` — a non-local start with a plaintext non-loopback `S43_ALLOWED_ORIGINS` entry **refuses to start** (opt-out `S43_ALLOW_INSECURE_ORIGINS`). ✅ |
| trusted host | `TrustedHostGuard` (`security_headers.py`) — exact `Host` match + leading-dot wildcard, probe paths exempt. ✅ (PR #254 tests reject `*`.) |
| trusted proxy chain | `SentinelFirewall._resolve_client_ip` — right-to-left hop walk, no trusted proxies ⇒ direct peer. `S43_TRUSTED_PROXIES` CIDR-validated at load (`_env_cidr_csv`). ✅ |
| malformed forwarding headers | forged `X-Forwarded-For` from an untrusted peer ignored; `test_firewall_proxy_trust.py` covers. ✅ |
| HTTPS enforcement | app does **not** redirect; the nginx edge 308s `:80→:443` (`deploy/proxy/nginx.conf`). App trusts `X-Forwarded-Proto` only from the trusted proxy. PR #252 preflight checks the edge redirect + no-downgrade. |
| HSTS | `SecurityHeadersMiddleware` emits `Strict-Transport-Security` **only when `_effective_scheme(scope)=="https"`** (real scheme or trusted XFP); `S43_HSTS_FORCE`/`_DISABLE`/`_MAX_AGE` overrides; default `max-age=15552000; includeSubDomains`. **Never over plain HTTP.** ✅ |
| refresh cookie | `s43_refresh` — `HttpOnly=True`, `Secure` (unless local), `SameSite=Strict`, `Path=/auth`. ✅ |
| CSRF cookie | `s43_csrf` — `HttpOnly=False` (double-submit), `Secure`, `SameSite=Strict`. ✅ |
| CSRF enforcement | `/auth/refresh` + `/auth/logout` require `X-S43-CSRF == s43_csrf` cookie **and** an allow-listed `Origin` → 403 on mismatch. ✅ |
| logout | clears both cookies `max_age=0`. ✅ |
| WSS | secure page ⇒ `wss://` (dashboard JS, PR #252). WS Origin check → **D-39** (skipped when `Origin` absent). |
| non-standard ports | PR #252's `deploy_preflight` corrected `--http-port`/`--https-port` handling; no app-side port assumption found. |
| CERT_NONE / verify=False | **only** `core/api/middleware/fenrir.py` (D-22, dev-gated, fail-closed, module dead). No other disabled-verification path in `core/`. ✅ |

**F-TLS-1 (D-28)** — cannot be closed here (no real target). This audit adds
nothing that changes its status; the app-side TLS *posture* (HSTS gating,
plaintext-origin refusal, cookie Secure) is sound.

---

## Section 18 — Identity data model (P3-8) ✅ REPRODUCED

Disposable PostgreSQL, `alembic upgrade head` to `0003_users_role_check`:

- Schema: `ix_users_username` = **plain case-sensitive `UNIQUE INDEX`** on
  `username`; `email` = plain `UNIQUE`. **No `lower()`, no `citext`.**
- App: routers (`bootstrap.py:140`, `users.py:230`) do `.strip()` but **not**
  `.lower()`; `create_user()` does neither; `authenticate_user()` matches
  `User.username == username` case-sensitively.
- **Direct inserts of `Justin`, `justin`, `"  justin  "` ALL SUCCEEDED**;
  `a@b.com` + `A@B.COM` both succeeded. Confirmed the schema permits the
  collision.

**Impact:** an attacker can register `Admin` when `admin` exists; operators
can't disambiguate `Justin`/`justin` in the user list; login being
case-sensitive means the variants are separate accounts.

**Exact `0004` pre-migration collision query (record only — do NOT run against
a live DB, do NOT implement `0004`):**

```sql
SELECT lower(btrim(username)) AS norm, count(*) AS n,
       array_agg(username ORDER BY created_at) AS variants
FROM users GROUP BY lower(btrim(username)) HAVING count(*) > 1;

SELECT lower(btrim(email)) AS norm, count(*) AS n,
       array_agg(email ORDER BY created_at) AS variants
FROM users WHERE email IS NOT NULL
GROUP BY lower(btrim(email)) HAVING count(*) > 1;
```

`0004` plan: **only if both queries return 0 rows on the target** → add
`CREATE UNIQUE INDEX uq_users_username_lower ON users (lower(username))`,
drop `ix_users_username`, same for email, and normalise on write
(`create_user` + both routers → `.strip().lower()` for username;
`.strip().lower()` for email). If any collision exists → STOP; an operator
renames one variant first. Unicode: also apply NFKC before the compare if
non-ASCII usernames are permitted (currently `String(128)`, no charset limit).

---

## Section 26 — Resource / concurrency ✅

- **Lifespan background tasks** (`core/api/main.py`): `_heartbeat_task`
  (always) + `_sparta_task` (if `S43_SPARTA_ENABLED`) — both `await
  asyncio.wait_for(task, timeout=5.0)` then `.cancel()` on shutdown
  (l.828-849). `yield` at l.823 is the boundary. **No leak.**
- `_stop_heartbeat_event` — a clean stop signal for the heartbeat loop.
- `feniri_hunter.py` — `ThreadPoolExecutor(max_workers=…)` (bounded);
  `shutdown()` with `SIGINT`/`SIGTERM` handlers; `_baselines` is an
  `OrderedDict` with **LRU eviction + stale pruning** (`max_keys`,
  `stale_seconds`) — bounded. Opt-in (flag default false).
- `sparta_core.py` — `_auth_failures` / `_blocked_clients` GC'd under lock
  (`_gc_auth_guard_locked`) — bounded.
- WS handler (`main.py:1249` `while True`) — has a `finally:` (l.1322) that
  removes the client from the registry; `MAX_WS_CLIENTS` cap.
- **INFO (not a defect):** the Watchtower telemetry helpers use blocking
  `urllib.request.urlopen` (2 s timeout). `logging_init._watchtower_report`
  can be reached from request-path code (`_normalize_log_level`) → a blocking
  call on the event loop, bounded to 2 s. Once D-15/D-16 are consolidated into
  an async-aware client this goes away; low impact today (short timeout,
  telemetry only).
- No `time.sleep()` in async code found. No unjoined raw `threading.Thread`
  in the live path. DB engine: one `AsyncEngine` per process via
  `core/auth/users.py` (`_pg_advisory_xact_lock` etc.), pooled.

---

## Section 27 — Test coverage map ✅

35 test files. Production-module → coverage (on `main`):

| module | coverage | note |
|---|---|---|
| `core/auth/{users,sessions}` | **DIRECT** | `test_auth_*`, `test_session_*_pg`, `test_password_verification`, `test_login_throttle` |
| `core/api/routers/{auth,users,bootstrap}` | **DIRECT** | `test_auth_login`, `test_v1_auth`, `test_users_admin`, `test_bootstrap*` |
| `core/api/routers/remote_gateway` | **NONE** | **D-40** — no role-token / event-dispatch test |
| `core/governance/orchestrator` | **NONE** | **D-40** — the mode=None defect (D-35) lives here, untested |
| `core/policy_gate/*` | INDIRECT (`test_policy_gate_smoke`) | thin |
| `core/guards/velocity` | **NONE** direct | maybe indirect via `test_account_transactions_pg` |
| `core/guards/exceptions/*` | **NONE** | validators / registry / bootstrap untested |
| `core/audit/store` (real `AuditStore`) | **NONE** on main | the "11 refs" are name-collisions with the clobbered velocity code; PR #254 adds a real construct+append test |
| `core/audit/audit` (`AuditLogger`) | INDIRECT | via orchestrator's best-effort audit |
| `core/monitoring/watchtower` | **DIRECT** (`test_watchtower_service_auth`, `test_watchtower_bridge_auth`) | auth only, not the coordinator logic |
| `core/monitoring/{sparta_core,jormungandr,manager}` | **NONE** on main | PR #254 adds Sparta (~17) + import/min-symbol for the rest |
| `core/detection/*` | **NONE** | entire threat-scoring + Fenrir layer, zero behavioral tests |
| `core/middleware` firewall + `security_headers` | **DIRECT** (`test_firewall_*`, `test_security_headers`, `test_tls_posture`) | good |
| `core/api/deps/deps` | INDIRECT | via route tests |
| `core/config/settings`, `core/api/core/*` | **NONE** | mostly dead (D-31, D-37) |
| `core/logging_init` | **NONE** | contains the broken Watchtower reporter (D-16) |
| migrations | **DIRECT** (`test_migrations_pg`, `test_schema_*`) | strong |
| `scripts/deploy_preflight` | **DIRECT** on PR #252/#254 (`test_deploy_preflight.py` 53 tests) | not on `main` |

**D-40 headline:** the governance decision engine and the entire detection
layer have **no behavioral tests**. That is the structural reason D-03 and
D-35 went unnoticed for months. PR #254's `test_package_integrity.py` (import
+ min-symbol + real-`AuditStore` + content-dup) is a durable partial guard;
behavioral coverage of `orchestrator.process_transaction` and
`sentinel_threat_detector.assess_*` is a remediation-phase deliverable.

---

## Section 22 — Packaging / license metadata ✅

- **D-12** invalid `build-backend`.
- **D-18** `LICENSE.md` references (also a packaging concern —
  `[project]` in `pyproject.toml` has no `license` / `license-files` key).
- `pyproject.toml` has no package-discovery config; flat layout with 4
  top-level dirs → auto-discovery would error even with a valid backend
  (PR #254 adds `[tool.setuptools.packages.find] include=["core*"]`).
- SPDX headers: inconsistent — `core/api/deps/__init__.py` has an
  `SPDX-License-Identifier` line; most files have the long prose block; some
  have neither. INFO, not a defect.
- `[project.scripts] s43-generate-secrets = "core.cli.generate_secrets:main"`
  — target resolves; console script only installs once D-12 is fixed.
- No licensing-term changes anywhere — only internal path consistency.

---

## Section 12 — Governance correctness ✅ (root cause)

**Reproduced:** `governance_smoketest.py` prints "HUMAN_GATED mode was
requested, but decision reported mode=None". **Root cause = D-35:** the
`Decision` dataclass has no `mode` field. `process_transaction` computes
`effective_mode` correctly and threads it into policy evaluation, but the
returned `Decision` doesn't carry it, so `_decision_mode()` (`getattr(d,
"mode", None)`) always returns `None`.

Not a *silent downgrade* — `_resolve_mode` logs whenever it ignores an
unrecognised or non-privileged override. The mode IS used for the decision;
it's just not surfaced on the result object.

**Fix target (record only):** add `mode: str` to `core/governance/orchestrator.py`
`Decision` (the canonical output object — `process_transaction` returns it;
the dashboard, approval queue and audit record all consume it). Populate every
`Decision(...)` construction site with `mode=effective_mode`. Do **not** touch
`_resolve_mode` (it already logs ignored/non-privileged overrides → the fix
introduces no silent downgrade).

**Regression tests to write (allowed now — reproduce before fix):**
`core/tests/test_governance_mode_pg.py` or extend `test_policy_gate_smoke.py`:

| test | drives | asserts (CURRENT behaviour — captures the defect) |
|---|---|---|
| `test_default_mode_shadow_surfaced` | settings `default_mode=SHADOW`, no `mode=` arg | `d.status in {APPROVED,REVIEW,BLOCKED}`; **`getattr(d,"mode",None) is None`** (← the defect) |
| `test_human_gated_requested_not_surfaced` | `default_mode=SHADOW`, `process_transaction(mode="HUMAN_GATED")` by a privileged caller | policy path shows `effective_mode=HUMAN_GATED` (via the audit record / `PolicyContext`); **`getattr(d,"mode",None) is None`** |
| `test_autonomous_veto_mode` | `default_mode=AUTONOMOUS_VETO` | decision produced; mode not on `d` |
| `test_non_privileged_override_ignored_and_logged` | non-privileged caller passes `mode="AUTONOMOUS_VETO"` | `caplog` contains "Ignoring mode override"; effective = `default_mode` (no silent downgrade — this part is already correct) |
| `test_unrecognized_mode_ignored` | `mode="banana"` | `caplog` "unrecognized governance mode"; effective = default |

After the fix flips: the first three assert `d.mode == <effective>`; the last
two are unchanged. `ALLOWED_MODES = {"SHADOW","HUMAN_GATED","AUTONOMOUS_VETO"}`.
**Governance semantics unchanged** — only the output surface.

---

## Section 17 — Database / transaction audit ✅

- **Alembic graph:** single head `0003_users_role_check`; linear
  `base → 0001_baseline → 0002_sessions → 0003_users_role_check`. **No
  branching, no multiple heads.** (`alembic heads` / `alembic history` run
  clean in the clean venv.)
- `alembic history` output text still cites deleted `RELEASE_FINDINGS.md`
  (`0003` revision message) — D-20 class, LOW.
- **Disposable PG re-run this session** (`postgres:16.3 --rm --tmpfs`,
  torn down): `alembic upgrade head` clean (`0001→0002→0003`), single head.
  `pytest` of `test_migrations_pg.py` + `test_schema_version_pg.py` +
  `test_schema_authority.py` + `test_account_transactions_pg.py` (first-admin
  concurrency, last-admin protection) + `test_session_layer_pg.py`
  (rotation concurrency, ≤1 successor generation) + `test_break_glass_pg.py`
  + `test_ws_session_pg.py` → **86 passed / 1 failed**.
- The 1 failure = **D-38** (`test_backup_restore_pg.py` hardcodes
  `pg_dump -U s43t -d s43t` — passes only when the disposable PG is named
  `s43t`, as CI's is). Not a schema/product defect; the pg_dump/restore
  *path* is real and green in CI.
- `/ready` schema-version gate: `test_schema_version_pg::test_ready_endpoint_503_when_schema_behind`
  passed → 503 when the DB is behind head. ✅
- Downgrade: `0001_baseline` downgrade is `RuntimeError` by design;
  `0002_sessions` downgrade destroys session state — never the rollback plan
  (documented). `alembic downgrade base` = fail-safe no-op. Covered by
  `test_migrations_pg`.
- No live DB touched.

---

## Section 23 — Remote gateway completeness ✅

`core/api/routers/remote_gateway.py` `RemoteEventType`: `FORCE_HEALTH_CHECK`,
`FORCE_SYNC`, `ROTATE_REMOTE_TOKEN`, `REQUEST_DIAGNOSTIC_SNAPSHOT`,
`APPROVE_DECISION`, `VETO_DECISION`. `ROLE_EVENT_POLICY` gates each by
`OperatorRole`.

| event | status |
|---|---|
| `FORCE_HEALTH_CHECK` / `FORCE_SYNC` / `REQUEST_DIAGNOSTIC_SNAPSHOT` | SUPPORTED (dispatch handlers) |
| `APPROVE_DECISION` / `VETO_DECISION` | SUPPORTED (governance queue) |
| `ROTATE_REMOTE_TOKEN` | **UNSUPPORTED-BY-DESIGN** — 501 with a clear message; `_dispatch_remote_event` raises `NotImplementedError` rather than falsely reporting success. Comments explicitly document this. **Not a beta blocker** — fails honestly. → **D-30 (INFO, resolved-classification)** |

No endpoint claims a capability it can't execute without a clear status.
The 501 pattern here is a *positive* example the rest of the codebase should
follow (cf. D-16 silent-success risk).

---

## Section 24 — Dead / unused service audit ✅ (Redis)

- **Redis: DEPLOYED, UNUSED.** → **D-32.** `docker-compose.yml` `s43-redis`,
  k8s manifests, `REDIS_PASSWORD`/`REDIS_URL` required secrets. Only `core/`
  reference is `redis_url` in the **unused** `core/config/config.py` (D-31).
  No `import redis` anywhere. Second orphan secret after `SENTINEL_LOG_SALT`.
- **Every other Compose/k8s service has a live consumer:** `s43-db`
  (Postgres — the app + migrations), `s43-core` (Watchtower host, `s43-core:9100`),
  `s43-api` (the API), `s43-proxy` (TLS edge), `s43-migrate` (`alembic upgrade
  head` one-shot), `s43-setup` (`generate_secrets.py` bootstrap). **`s43-redis`
  is the sole orphan.**

---

## Section 25 — Static security scan ✅

`git grep` for `eval( / exec( / pickle.load / yaml.load / shell=True /
os.system / verify=False / CERT_NONE / check_hostname=False / md5 / sha1(pw) /
subprocess(...shell=True)` across non-test `core/`:
- **Only match:** `core/api/middleware/fenrir.py:403-404` `CERT_NONE` —
  **FALSE POSITIVE / D-22** (dev-gated, fail-closed in prod, module currently
  dead).
- No `eval`/`exec`/`os.system`/`shell=True`/`pickle`/unsafe-`yaml.load` in
  non-test code.
- **No live secret / credential found in tracked files.** `.env.example` /
  test fixtures use `CHANGE_ME` / synthetic values. `git grep` for
  high-entropy assignment patterns and `PLACEHOLDER`/`CHANGEME` — all
  placeholders. **No CRITICAL live-secret escalation required.**
- Password hashing: Argon2 (`argon2-cffi`) for user passwords; SHA-256 only
  for the `#11` env-operator break-glass (known, documented, `_env_operator_
  allowed()` gated) and for non-secret fingerprints (`_fingerprint_token`).
- Deeper categories (path-traversal, SSRF, raw SQL, dynamic import, unbounded
  input) are classified in **§25 close-out** below — all SAFE / dev-gated /
  operator-controlled; the one real logging defect is the D-16 401-masking.

---

## Deferred / product-decision findings (not to be "fixed" here)

- **D-25** governance mode propagation (§12) — needs the mode/contract trace +
  regression tests reproducing SHADOW / HUMAN_GATED / AUTONOMOUS_VETO before
  any fix.
- **D-26** `SENTINEL_LOG_SALT` contract.
- **D-28** F-TLS-1 real-target validation.
- **D-29** multi-replica login throttle (record path B).
- **D-30** `ROTATE_REMOTE_TOKEN` 501 status classification (§23).
- P3-8 identity case/whitespace/Unicode uniqueness (§18) — do **not** add a
  case-insensitive constraint without collision evidence; produce the `0004`
  plan only.
- Public `/docs` `/redoc` `/openapi.json` exposure — owner decision.
- #14 anon status detail, #16 Docker Scout, #18 image digest pinning, #19 raw
  proxy rebroadcast — lower-severity, tracked.

---

## §20 documentation broken-reference list (§19 close-out)

`LICENSE.md` (D-18); and these deleted-doc references (D-19/20/21):
`AUTH_ARCHITECTURE_PASS4.md`, `AUTH_SESSION_BETA.md`, `HANDOFF_PASS5AM.md`,
`PASS3_VALIDATION.md`, `PASS5AM_VALIDATION.md`, `PASS5A_VALIDATION.md`,
`PASS_BETA_VALIDATION.md`, `RELEASE_FINDINGS.md`, `RELEASE_HARDENING_PLAN.md`,
`SERVICE_INTEGRATION_BETA.md`, `SESSION_MIGRATION_DECISION_PASS5A.md`,
`SESSION_MODEL_PASS5A.md`, `VALIDATION_REPORT.md`; and **never-existed** (D-41):
`docs/security/endpoint_access_matrix.md`, `docs/security/internal_service_auth.md`.
Classify: `LICENSE.md`=BROKEN(fix→`LICENSE`); the `*_PASS*.md` in **code comments**
= HISTORICAL-BUT-CLEAR (leave, per PR #253/#254 policy); the `*_PASS*.md` in
**shipping files** (`docker-compose.yml:258`, `migrations/0002_sessions.py:8`)
= STALE/MISLEADING (drop the line); the `docs/security/*` = BROKEN (either write
the doc or drop the pointer).

---

## §25 deeper static classification (close-out)

| category | result |
|---|---|
| `eval` / `exec` / `os.system` / `shell=True` | **none** in non-test `core/` |
| `pickle` / unsafe `yaml.load` | **none** |
| `subprocess` | test-only (`test_backup_restore_pg`, `ci_live_tests.py`, `deploy_preflight`) — all with explicit arg lists, no `shell=True`. SAFE. |
| `verify=False` / `CERT_NONE` / `check_hostname=False` | **one** — `core/api/middleware/fenrir.py` (D-22, DEV-GATED + fail-closed + module dead). |
| hardcoded credentials / live secrets | **NONE.** All `CHANGE_ME` / `CHANGEME` / synthetic test fixtures. **No CRITICAL escalation.** |
| password hashing | Argon2 (`argon2-cffi`) for user pwds; SHA-256 only for the `#11` break-glass env-operator (documented, `_env_operator_allowed()`-gated) + non-secret token fingerprints. SAFE. |
| raw SQL / string interpolation | SQLAlchemy ORM + `text()` with bound params throughout; `exec_driver_sql` in tests only. Spot-check clean. SAFE. |
| dynamic imports (`importlib`) | `core/monitoring/__init__.py` lazy loader (candidate lists are literals), `core/api/config` factory strings (`"core.api.deps:dev_engine_factory"` — literals). No user-controlled import target. SAFE. |
| path operations on external input | Sparta `watched_files` (operator env `S43_SPARTA_HASH_*` → relative paths, hashed read-only); dashboard `S43_DASHBOARD_DIR` (Starlette `StaticFiles` — has its own traversal guard). **NEEDS-PRODUCT-DECISION-none; SAFE** on inspection. |
| SSRF | `S43_WATCHTOWER_URL`, remote-gateway target URLs — operator-configured, not request-derived. Low risk. SAFE. |
| unbounded input / memory | firewall `max_content_length_bytes` / `max_total_header_bytes` bound bodies/headers; nginx `client_max_body_size 10m`; WS `MAX_WS_FRAME_BYTES` + `MAX_WS_CLIENTS`; Fenrir/Sparta maps LRU-bounded (§26). SAFE. |
| unsafe logging | **the D-16 masking** (`except Exception: pass` around `urlopen` hides 401) is the one real logging defect; secrets never logged (Sparta/Watchtower docstrings confirm; `_mask_secret` in config). |

---

## §22 close-out (SPDX / build / distribution)

- SPDX headers: **inconsistent** — `core/api/deps/__init__.py` +
  `core/audit/store.py` (post-#254) + a few others carry
  `SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial`;
  most files carry the long prose block; some (`core/guards/__init__.py`) carry
  only the block; a handful carry neither. **INFO** — not a defect, but a
  `# SPDX` sweep is cheap consistency debt.
- `[project]` in `pyproject.toml` has **no `license` / `license-files` key** →
  a built wheel would carry no license metadata. Pairs with D-12/D-18.
- `python -m build` (wheel + sdist) — **blocked by D-12**; verify after the
  PR #254 `build-backend` fix lands.
- `[project.scripts] s43-generate-secrets = "core.cli.generate_secrets:main"`
  — target resolves; installs only once D-12 is fixed.
- **No licensing-term change** anywhere in scope — path/consistency only.

---

## §23 close-out — full remote-gateway event inventory

`RemoteEventType` (6): `FORCE_HEALTH_CHECK`, `FORCE_SYNC`,
`REQUEST_DIAGNOSTIC_SNAPSHOT`, `APPROVE_DECISION`, `VETO_DECISION`,
`ROTATE_REMOTE_TOKEN`. `ROLE_EVENT_POLICY` maps each to `OperatorRole`
{owner, admin, auditor}.

| event | classification |
|---|---|
| `FORCE_HEALTH_CHECK`, `FORCE_SYNC`, `REQUEST_DIAGNOSTIC_SNAPSHOT` | **SUPPORTED** — dispatch handlers registered; return real results |
| `APPROVE_DECISION`, `VETO_DECISION` | **SUPPORTED** — routed into the governance approval queue |
| `ROTATE_REMOTE_TOKEN` | **UNSUPPORTED-BY-DESIGN** — 501 + `NotImplementedError`; "returns 501 instead of falsely reporting success"; needs a key-rotation subsystem. **NOT a beta blocker** (fails honestly). → D-30 |

No event claims a capability it cannot execute without a clear status. **The
only gap is test coverage (D-40)** — `test_*` for `remote_gateway.py` = 0.

---

## §29 GATE STATUS: **PASSED — inventory complete.**

**Every section §0–§28 is SUBSTANTIALLY COMPLETE.** Residual items
("per-route dependency trace for `/system/*`", "whole-repo per-site
`except` classification", "`python -m build`") are **remediation-phase**
work (require code changes or the D-12 fix), not inventory gaps.

**43 findings D-01…D-42** (D-31 & D-36 share a root; D-25 & D-35 are the same
issue at two altitudes).

| severity | count | IDs |
|---|---|---|
| CRITICAL | 0 | — |
| HIGH | 5 | D-01 D-02 D-03 D-04 D-05 (all → PR #254) |
| MEDIUM | 18 | D-06 D-07 D-08 D-09 D-10 D-11 D-13 D-15 D-16 D-17 D-23 D-27 D-31 D-32 D-33 D-35 D-37 D-40 |
| LOW | 12 | D-12 D-14 D-19 D-24 D-29 D-34 D-36 D-38 D-39 D-41 D-42 (+ D-21) |
| INFO | 5 | D-18 D-20 D-22(FP) D-26 D-30 |
| DEFERRED (product) | D-25/D-35, D-26, D-28, D-29, D-32, P3-8, `/docs` decision |

**No SUSPECTED finding remains.** D-16 → CONFIRMED. The only reproduction gap
is **D-28 (F-TLS-1)** = TARGET-REQUIRED (needs a named beta host with a real
cert/CA — `deploy_preflight --phase verify` + `browser_tests/run_target.sh`).

---

## §30 implementation order + §22 remediation-batch design (post-merge, NOT started)

### Merge first (both green, no file overlap)
1. **PR #254** — `fa587c2..f3eba76`. Remediates D-01..D-14, D-23, D-24 +
   adds the package-integrity / content-duplication CI gate (the durable
   guard for the whole corruption class). Merge to `main`.
2. **PR #252** — `fa587c2..6ce21d8`. Remediates the deploy_preflight
   false-green class + the browser target-acceptance split + partial D-19/D-21
   (companion lists). Merge to `main` after #254.
   No integration branch needed — disjoint file sets, clean union. Run the
   full suite once on the merged tree (§31) before either merges.

### Batch A — repository integrity (post-merge, blocks nothing else)
| commit | files | purpose | tests | sec | rollback |
|---|---|---|---|---|---|
| A1 firewall from_env | `core/api/middleware/sentinel_firewall_middleware.py`, `core/middleware/sentinel_firewall.py`, `core/middleware/__init__.py` | D-27 — real `from_env` classmethod; shim → 4-line re-export | firewall suite unchanged + new "`from_env` from `core.api.middleware`" + `asdict` identity | none if identity holds | revert |
| A2 deps dedup | `core/api/deps/__init__.py` | D-17 — delete the shadowed local impl; `__init__` = re-export from `deps.py` only | `test_v1_auth`, `test_users_admin`, `test_app_route_registration` | none | revert |
| A3 dead-tree removal | `core/config/config.py`, `core/api/core/` | D-31, D-37 — delete (zero importers, evidence in §2) | import sweep 0-broken; `test_package_integrity` | none | git restore |

### Batch B — Watchtower (security boundary)
| commit | files | purpose | tests | sec | rollback |
|---|---|---|---|---|---|
| B1 canonical client | new `core/monitoring/watchtower_client.py` | D-15+D-16 — one helper: `s43-core:9100` default, Bearer token, status check + bounded WARN log | new integration test (disposable Watchtower): absent/wrong token → caller logs, not silent | **fixes** a silent-auth-failure class | revert (helpers stay as-is) |
| B2 call-site swap | the 12 files in the §8 matrix | route all through `watchtower_client` | full suite; the D-16 integration test | none beyond B1 | revert per-file |

### Batch C — config / discovery / docs
| commit | files | purpose |
|---|---|---|
| C1 | `.env.example`, `docker-compose.yml`, `deploy/kubernetes/*` | D-42 document `S43_ADMIN_TOKEN` etc.; D-26/D-32 mark `SENTINEL_LOG_SALT` + Redis `# FUTURE` **or** remove (owner call) |
| C2 | `Notice`, `core/api/deps/__init__.py` header, +6, `pyproject.toml` | D-18 `LICENSE.md`→`LICENSE` + add `license` key |
| C3 | `docker-compose.yml:258`, `migrations/0002_sessions.py:8`, kept `MIGRATION_*_PASS5AM.md` | D-19/D-21 drop stale doc pointers |
| C4 | `DEFECT_INVENTORY.md` + (write) `docs/security/endpoint_access_matrix.md` | D-41 + D-33/D-34: the endpoint-access matrix this audit's §15 produced; per-route auth classification for `/system/*` `/vault/stats` `/config/*` |

### Batch D — governance (deferred product decision → then)
- D-35: add `Decision.mode`; the §12 regression tests. **Requires owner
  sign-off** that mode belongs on the decision contract.

### Batch E — docs-exposure (D-33 — owner decision A/B/C/D)
- Recommended **A + C**: app sets `docs_url/redoc_url/openapi_url=None` when
  `SENTINEL_ENV` is non-local (keep them in local/dev); PR #252's preflight
  check then becomes satisfiable and correct. Test: `test_docs_disabled_in_non_local`.
  Do **not** rely on an edge deny alone (the k8s ingress `path:/` has no
  filter; a proxy rule is deployment-specific and fragile).

### Batch F — test coverage (D-40)
- Behavioral tests for `orchestrator.process_transaction` (all 3 modes),
  `sentinel_threat_detector.assess_*`, `remote_gateway` role/event dispatch,
  `guards/velocity`. Not blocking a beta but blocking "difficult to silently
  break again".

**Do not mix batches in one commit.** Batch A has no dependency on B/C/D/E/F.

---

## Appendix — evidence commands (reproducible)

```
# §3 compileall (fails on main):
python -m compileall browser_tests/ core/ dashboard/ migrations/ scripts/

# §3/§7 import sweep (main: 105 OK / 23 BROKEN with extra deps; 104 / 24 clean):
#   walk core/ dashboard/ migrations/, import each non-test module, tally.

# §5 duplication sweep (main: 2 identical-body groups):
#   header-stripped body sha256 per .py; report groups > 1.

# §7 clean venv:
python -m venv .venv-audit
.venv-audit/Scripts/python -m pip install -r requirements.txt pytest requests pyyaml
.venv-audit/Scripts/python -m pip install -e .   # -> BackendUnavailable (D-12)

# §12:
PYTHONPATH=. python core/scripts/governance_smoketest.py   # "mode=None" (D-35)

# §15:
#   TestClient(core.api.main.app).get("/openapi.json") -> 63 paths;
#   .get("/docs") -> 200 (D-33)

# §17:
.venv-audit/Scripts/python -m alembic heads      # single head 0003_users_role_check
```
