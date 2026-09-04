# DEFECT_INVENTORY.md

Sentinel-43 — complete accumulated defect audit. **Durable canonical defect
ledger.** Future passes update this file rather than adding new markdown files.

- **Audit branch:** `audit/defect-inventory-20260903` off `main` (`fa587c2`).
- **Discipline:** inventory first. No production-code remediation until the
  Section 29 gate. Tests that reproduce/prove a defect are allowed now.
- **Written incrementally.** Resume from the last section marked ✅ below,
  re-verifying if new evidence conflicts.
- **State:** CONFIRMED · REPRODUCED · SUSPECTED · FALSE-POSITIVE · DEFERRED.
- **Severity:** CRITICAL · HIGH · MEDIUM · LOW · INFO.

Prompt sections that use "fix/resolve/implement" are recorded here as
*recommended remediation*, not work performed.

---

## Section progress

| § | Title | Status |
|---|---|---|
| 0 | Canonical repository state | ✅ |
| 1 | Known minimum defect set — verification | ✅ |
| 2 | Complete source inventory | 🟡 partial (counts + UNKNOWN spot-checks) |
| 3 | Python syntax + import integrity | ✅ (evidence captured) |
| 4 | Case-sensitive filesystem audit | ✅ |
| 5 | Duplication / clobber detection | ✅ |
| 6 | Git-history corruption audit | 🟡 partial (AuditStore + request_context traced; broad scan PENDING) |
| 7 | Dependency audit | ✅ (clean-venv sweep + `pip install -e .` reproduced; wheel build PENDING) |
| 8 | Watchtower internal client audit | 🟡 partial (URL + auth-header inventory done; per-route reachability + integration test PENDING) |
| 9 | Broad exception / silent failure audit | 🟡 partial (counts + lazy-loader root cause; per-site classification PENDING) |
| 10 | Authn / authz audit | 🟡 partial (existing suite + §11 + §25; full matrix PENDING) |
| 11 | Sparta /node audit | ✅ (completed in the PR #254 hardening pass; recorded here) |
| 12 | Governance correctness | ✅ (root cause found; regression test is remediation-phase) |
| 13 | Firewall canonicalization | ✅ (canonical identified; consolidation is remediation) |
| 14 | Network / service discovery audit | ✅ |
| 15 | Public endpoint inventory | 🟡 partial (63 paths enumerated; per-route auth classification PENDING) |
| 16 | CORS / host / proxy / TLS audit | 🟡 partial (leans on PR #252 tooling semantics; docs-exposure gap found) |
| 17 | Database / transaction audit | 🟡 partial (single head confirmed; full disposable-PG re-run PENDING) |
| 18 | Identity data model (P3-8) | ☐ PENDING (needs data / migration plan) |
| 19 | Rate limiting | ✅ |
| 20 | Documentation reference integrity | ✅ |
| 21 | Config contract audit | 🟡 partial (orphans found; full env-var matrix PENDING) |
| 22 | Packaging / license metadata | ✅ |
| 23 | Remote gateway completeness | ✅ |
| 24 | Dead / unused service audit (Redis etc.) | ✅ (Redis = orphan; other services PENDING) |
| 25 | Static security scan | ✅ |
| 26 | Resource / concurrency audit | ☐ PENDING |
| 27 | Complete test inventory | ☐ PENDING |
| 28 | Required validation | 🟡 partial (compileall + import sweep + dup + clean-venv done; suite/browser/PG/k8s PENDING) |

**NEXT SESSION:** resume at §6 (broad history scan), §8 (Watchtower per-route
reachability + integration test), §9 (classify every broad-except), §10 (full
matrix — mostly proven, formalise), §15 (per-route auth classification), §16
(TLS/cookie/CSRF), §17 (disposable-PG re-run), §18 (P3-8 plan), §21 (env-var
matrix), §26 (concurrency), §27 (test↔module map), §28 (full validation).

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
| D-27 | MEDIUM | CONFIRMED | Two physical firewall implementations: `core/middleware/sentinel_firewall.py` (**canonical** — has `FirewallConfig.from_env()`; the shim in `core/middleware/__init__.py` prefers it and hard-fails if it lacks `from_env`) vs `core/api/middleware/sentinel_firewall_middleware.py` (relocated copy, known stale once, imported by `core/api/middleware/__init__.py`). `core/middleware/__init__.py`'s own docstring documents a production outage this caused and a TODO to reconcile. **Not identical** (so §5's hash sweep doesn't flag it) — genuine competing implementations. | both firewall files | — |
| D-28 | DEFERRED | KNOWN | F-TLS-1: no real-target edge-TLS validation. | deploy | #252 (tooling), not closable without a named target |
| D-29 | DEFERRED | KNOWN | Multi-replica login throttle is per-process; `overlays/beta` ships 2 replicas. | `core/api` throttle | #252 preflight now checks 1-replica/1-worker; shared limiter is a separate change |
| D-30 | INFO | RESOLVED-CLASSIFICATION | Remote-gateway `ROTATE_REMOTE_TOKEN` → **501, by design and honest.** `remote_gateway.py` comments: "returns 501 instead of falsely reporting success", "remains 501 until a key-rotation subsystem is [built]", "`_dispatch_remote_event` raises `NotImplementedError`". **UNSUPPORTED-BY-DESIGN, not a beta blocker** — it fails loudly, not silently. Good pattern. | `core/api/routers/remote_gateway.py` | n/a |
| D-32 | MEDIUM | CONFIRMED | **Redis deployed but unused.** `docker-compose.yml` ships `s43-redis`; k8s ships it; `REDIS_PASSWORD` / `REDIS_URL` are "required secrets" in `generate_secrets.py` + `deploy_preflight.py`. **The only Redis reference in `core/` is `redis_url` in the stale unused `core/config/config.py` (D-31).** No `import redis`, no client, no runtime use. Attack surface + resource + a 2nd orphan secret (cf. D-26). Classify: obsolete, OR intentional-future (D-29's shared limiter would use it) — needs an owner call. | `docker-compose.yml`, `deploy/kubernetes/*`, `core/cli/generate_secrets.py`, `scripts/deploy_preflight.py` | — |
| D-33 | MEDIUM | CONFIRMED | **`/docs` `/redoc` `/openapi.json` are served HTTP 200 unauthenticated by the app** (FastAPI defaults; verified via TestClient). The nginx proxy / k8s ingress proxy `/` wholesale (no path filter). PR #252's `deploy_preflight --phase verify` *asserts these return 401/403/404 on a real target* — **but nothing in the app or the edge actually blocks them.** Either set `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)` in non-local, or add an edge deny, or the preflight check is unsatisfiable. Overlaps the "public docs exposure = owner decision" item but is now a concrete inconsistency. | `core/api/main.py` (FastAPI ctor), proxy, `scripts/deploy_preflight.py` | partial: #252 added the (currently unsatisfiable) check |
| D-34 | LOW | CONFIRMED | Duplicate FastAPI operation IDs — `UserWarning: Duplicate Operation ID health_health_get` at import (`core/api/routers/routers.py`). Route groups are multiply-mounted: `/watchtower/health` **and** `/api/watchtower/health`; `/actions/*` **and** `/v1/actions/*`; 7+ distinct `*/health` and 7+ `*/status` paths. Bloats the API surface + breaks generated clients. Needs a route-map review (§15). | `core/api/routers/routers.py`, `core/api/main.py` | — |
| D-35 | MEDIUM | CONFIRMED (root cause) | **Governance mode not on the Decision contract.** `core/governance/orchestrator.py` `Decision` dataclass fields = `status, score, reason, decision_id` — **no `mode`**. `process_transaction` computes `effective_mode = self._resolve_mode(...)` and passes it to `PolicyContext.mode` / `metadata["effective_mode"]` (so policy eval uses it) but the returned `Decision` doesn't surface it → `governance_smoketest.py::_decision_mode` (`getattr(decision,"mode",None)`) is always `None`. This is the concrete form of **D-25**. Recommended contract (record only): add `mode: str = ""` to `Decision`, populate from `effective_mode`; `_resolve_mode` already logs when it ignores an override, so no silent downgrade. Governance-semantics-adjacent → stays deferred; regression test (reproducing SHADOW/HUMAN_GATED/AUTONOMOUS_VETO + the `mode=None`) is the allowed inventory-phase work. | `core/governance/orchestrator.py`, `core/scripts/governance_smoketest.py` | — |

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
  needs classification, §2 PENDING). → tracked under **D-31 (SUSPECTED)**.

| D-31 | MEDIUM | SUSPECTED | Three+ parallel config modules: `core/config/{settings,config}.py` (two `Settings` classes; `config.py` unused parallel), `core/api/config/config.py` (`ApiConfig` — the live one), `core/api/core/config.py` (third). Needs canonical determination. | those | — |

---

## Section 6 — Git-history corruption audit 🟡

Traced:
- **D-03**: commit `d46d756` "Refactor AuditStore to use VelocityConfig"
  replaced the entire `core/audit/store.py` with content byte-identical to
  `core/guards/velocity.py`. `d46d756~1:core/audit/store.py` still has the
  real `AuditConfig`/`AuditStore` (`sqlite_path`, `jsonl_path`, `signing_key`,
  `append()`) — matches `orchestrator.py`'s usage exactly. Evidence-based
  restore target confirmed.
- **D-14**: `core/middleware/request_context.py` (`11d3e1a`) is a copy of the
  older `core/api/middleware/request_context.py` (`a9e3e3a`→`e27c812`);
  relocation not finished.

**PENDING:** systematic scan for other "module changed into unrelated code"
commits — walk large-delta commits where the file's `class`/`def` name set
changes completely; compare each critical module (`core/auth/*`,
`core/api/routers/*`, `core/middleware/*`, `core/governance/*`) against a
meaningful historical revision.

---

## Section 7 — Dependency audit 🟡

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

**PENDING:** `python -m build` (wheel + sdist) after D-12 fix; Dockerfile
`python:3.13-alpine` musllinux-wheel check for `cryptography` (PR #254 CI
already proved the image builds — re-note).

**D-36 (LOW, CONFIRMED):** `requirements.txt` declares `redis>=6.4.0` but no
runtime code imports `redis`. Declared-unused. (Same root as D-32.)

---

## Section 8 — Watchtower internal client audit 🟡

**URL default inventory (§14 overlap):** see **D-15**. Canonical rule should
be: one shared helper (e.g. `core/monitoring/watchtower_client.py` or reuse
`core.api.config`), default `http://s43-core:9100`, single `os.getenv`.
`docker-compose.yml:226` and `deploy/kubernetes/base/configmap.yaml:20`
already set `S43_WATCHTOWER_URL=http://s43-core:9100` — so prod is masked, dev
/ tests / partial deploys are not.

**Auth header inventory:** `core/api/main.py` and `core/monitoring/manager.py`
reference `S43_WATCHTOWER_SERVICE_TOKEN`. **No token reference** in the
`_watchtower_request` helpers of: `core/api/deps/deps.py`,
`core/api/config/config.py`, `core/config/settings.py`, `core/logging_init.py`,
`core/monitoring/event_types.py`, `core/guards/exceptions/{registry,contracts,exceptions}.py`
→ **D-16**.

**PENDING:** for every one of the ~13 client call sites record
FILE/CALLER/DEFAULT-URL/ROUTE/AUTH?/TOKEN-SOURCE/TIMEOUT/FAILURE-BEHAVIOR/
RESULT-CHECKED?/LOGGING. Determine which routes each hits, cross-reference
`core/monitoring/watchtower.py`'s router auth (`_require_service_token` on
operational routes; open ingest routes). Add an integration test that a report
with a bad/absent token is **rejected** and the caller observes it (not a
silent success).

---

## Section 9 — Broad exception / silent failure audit 🟡

Counts (`git grep`): ~180 `except Exception` occurrences across `core/`.
**PENDING** per-occurrence classification (EXPECTED FAIL-SOFT / BEST-EFFORT
TELEMETRY / FAIL-CLOSED / BUG / MASKING / UNKNOWN). Priority targets:
- `core/api/main.py` lifespan blocks (Sparta/Fenrir/remote-gateway startup) —
  currently `except Exception: logger.error(...)` and continue. Classify:
  acceptable fail-soft for optional subsystems vs masking a real
  misconfiguration.
- Watchtower client helpers (do they swallow 4xx/5xx? — ties to D-16).
- `core/monitoring/__init__.py` `_import_first` / `_warn_missing` — lazy
  loader swallows `ImportError`/`AttributeError` and only `warnings.warn`s.
  This is *how D-06/D-08 hid*. Recommend: for **required** lazy exports
  (`SpartaCore` when `S43_SPARTA_ENABLED`, `MonitoringManager`), escalate to
  a hard error; keep soft only for genuinely optional ones.

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

## Section 13 — Firewall canonicalization ✅

**Canonical:** `core/middleware/sentinel_firewall.py` — it is the one with
`FirewallConfig.from_env()`; `core/middleware/__init__.py` prefers it, warns
loudly on fallback, and hard-fails at import if the loaded `FirewallConfig`
lacks `from_env()`.
**Relocated copy:** `core/api/middleware/sentinel_firewall_middleware.py` —
imported by `core/api/middleware/__init__.py`; documented as "known stale
once"; `core/api/main.py` registers the firewall via
`from core.api.middleware import SentinelFirewall, FirewallConfig` → so **the
app currently runs the relocated copy**, not the canonical one.

→ **D-27.** Recommended end state (remediation, not done): one implementation
in `core/middleware/sentinel_firewall.py`; `core/api/middleware/` keeps only a
thin re-export shim; `core/api/main.py` unchanged. Reconcile any behaviour
delta between the two first (diff them; run
`test_firewall_config_hardening.py` + `test_firewall_trusted_proxy_config.py`
+ `test_firewall_proxy_trust.py` as the baseline — **run now to establish
baseline, do not consolidate in this phase**).

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

## Section 15 — Public endpoint inventory 🟡

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

**PENDING:** per-route AUTH classification (PUBLIC-PROBE / HUMAN / ADMIN /
SERVICE / INTERNAL / DEV / UNKNOWN) by tracing each router's `dependencies=`.
The `/system/routes`, `/system/status`, `/vault/stats`, `/config/`,
`/api/config` group needs particular attention — a route-listing / config /
vault-stats endpoint that is not clearly SERVICE/ADMIN-gated is a defect.
UNKNOWN until each is traced.

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

## Section 21 — Config contract audit 🟡

**PENDING** full env-var inventory (reader/writer/default/required-envs/secret?/
validation/documented?/compose?/k8s?/orphan?).
Confirmed so far:
- **D-26** `SENTINEL_LOG_SALT` — orphaned (no reader post-#253).
- **D-15** `S43_WATCHTOWER_URL` — 13 divergent defaults.
- `S43_SPARTA_ENABLED` / `S43_SPARTA_NODE_TOKEN` / `S43_SPARTA_TOKEN_SECRET` —
  documented, in `.env.example`, compose, k8s; `/node` now gated (D-23).
- `S43_ENV` vs `SENTINEL_ENV` — dual contract; `S43_ENV` read by Fenrir /
  Sparta / Watchtower, `SENTINEL_ENV` elsewhere (PR #254 corrected the
  `.env.example` comment that mis-attributed it to deleted `s34_auth.py`).

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

**Recommended contract (record only, do NOT implement this phase):** add
`mode: str = ""` to `Decision`; populate from `effective_mode`. **Inventory-
phase work allowed:** a regression test that drives `SHADOW` / `HUMAN_GATED`
/ `AUTONOMOUS_VETO` through `process_transaction` and asserts current
behaviour (incl. `getattr(Decision, "mode", None) is None`), so the defect is
provably captured before it is fixed.

`ALLOWED_MODES = {"SHADOW", "HUMAN_GATED", "AUTONOMOUS_VETO"}`.

---

## Section 17 — Database / transaction audit 🟡

- **Alembic graph:** single head `0003_users_role_check`; linear
  `base → 0001_baseline → 0002_sessions → 0003_users_role_check`. **No
  branching, no multiple heads.** (`alembic heads` / `alembic history` run
  clean in the clean venv.)
- `alembic history` output text still cites deleted `RELEASE_FINDINGS.md`
  (`0003` revision message) — D-20 class, LOW.
- **PENDING (needs disposable PostgreSQL):** fresh-DB migrate, pre-Alembic
  adoption (`alembic stamp 0001_baseline`), drift refusal, upgrade→downgrade→
  re-upgrade, `/ready` schema-version gate, `pg_dump`/restore, session-
  rotation concurrency (≤1 successor generation), first-admin concurrency,
  last-admin protection. **These are covered by `core/tests/test_migrations_pg.py`,
  `test_schema_version_pg.py`, `test_schema_authority.py`,
  `test_auth_session_pg.py`, `test_account_transactions_pg.py`,
  `test_backup_restore_pg.py` in the `pg-tests` CI job** (PR #252 thread:
  "89 pg tests, 0 skipped, green"). Re-run against a fresh disposable PG is a
  §28 task.
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
- **PENDING:** classify every other Compose/k8s service (`s43-db`, `s43-core`,
  `s43-migrate`, `s43-api`, `s43-proxy`, `s43-setup`) for a live consumer —
  `s43-core` (Watchtower host), `s43-db` (Postgres), `s43-api`, `s43-proxy`,
  `s43-migrate`, `s43-setup` are all clearly used; only `s43-redis` is the
  orphan. Likely complete but marked 🟡 pending the formal per-service check.

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
- **PENDING (deeper §25):** path-traversal on any filesystem-path input
  (Sparta `watched_files`, dashboard static serving `S43_DASHBOARD_DIR`),
  SSRF on `S43_WATCHTOWER_URL` / remote-gateway URLs (operator-controlled,
  low risk), SQL string interpolation (SQLAlchemy ORM used throughout —
  spot-check clean), unbounded queues/maps (→ §26).

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

## Implementation order (§30) — for the post-gate phase, NOT started

1. Repository corruption / broken imports → **PR #254 already covers
   D-01..D-14, D-23, D-24.** Remaining new: D-15, D-17, D-27, D-31.
2. Security boundary → D-16 (Watchtower token), D-27 (firewall consolidation),
   verify D-22 stays gated.
3. False-green tooling → **PR #252 covers the deploy_preflight class.**
4. Authn/service-identity → §10 full matrix (mostly already proven), D-16.
5. Governance → D-25 (after the §12 trace + regression tests).
6. Migration/data → §17 re-run, D-18? no — §18 P3-8 plan.
7. Deployment/TLS → D-28.
8. Config/service-discovery → D-15, D-26, §21 full pass.
9. Docs/reference integrity → D-18, D-19, D-21.
10. Debt that creates future drift → D-17, D-27, D-31, the 13× Watchtower
    helper duplication, D-15's copy-paste class; **the package-integrity +
    content-duplication CI gate from PR #254 is the guardrail — ensure it
    lands.**

---

## Section 9 — Broad exception audit 🟡 (root cause captured)

~180 `except Exception` / bare `except` across `core/`; densest in
`core/api/main.py` (17), `core/monitoring/manager.py` (9),
`core/api/routers/routers.py` (7).

**Key structural finding:** `core/monitoring/__init__.py`'s lazy loader
(`_import_first`, `_load_*_export`) catches `(ImportError, AttributeError)`
and only `warnings.warn`s (`_warn_missing`) — **not even a log line**. This is
precisely the mechanism that let **D-06** (`SpartaCore` case mismatch) and
**D-08** (wrong jormungandr candidate path) sit undetected: `from
core.monitoring import SpartaCore` silently `AttributeError`s, `main.py`'s own
`try/except` logs a one-line warning, and everything else looks fine.

**Recommended remediation (record only):** for lazy exports that are
*required when their feature flag is on* (`SpartaCore`/`create_node_router`
when `S43_SPARTA_ENABLED`, `MonitoringManager` always), escalate the swallow
to a hard `ImportError` naming the file and missing attr. Keep the soft path
only for genuinely optional betas (jormungandr, window_store). Pair with the
PR #254 package-integrity test that now import-sweeps every module — that
test is the durable guard for this class.

**PENDING:** per-site classification of the remaining ~180 (EXPECTED-FAIL-SOFT
/ BEST-EFFORT-TELEMETRY / FAIL-CLOSED / BUG / MASKING / UNKNOWN), priority on
`core/api/main.py` lifespan + the Watchtower client helpers (D-16 tie-in).

---

## §29 GATE STATUS: **NOT PASSED.**

Inventory ≈ **75% complete**. **36 findings** (D-01…D-36).

Sections still 🟡/☐: 6 (broad history scan), 8 (Watchtower per-route +
integration test), 9 (per-site classification), 10 (formal matrix), 15
(per-route auth classification), 16 (cookie/CSRF/WS-origin/redirect detail),
17 (disposable-PG re-run), 18 (P3-8 collision plan + `0004` draft), 21
(full env-var matrix), 26 (concurrency/leak audit), 27 (test↔module map), 28
(full validation battery).

**No broad remediation may begin** until every section is ✅ and the progress
table shows no ☐/🟡. Per §30, when the gate opens: **PR #254 already
remediates D-01..D-14, D-23, D-24** (repository-corruption + Sparta class) and
**PR #252 the deploy-tooling class** — land those first; the genuinely new
remediation backlog is D-15, D-16, D-17, D-27, D-31, D-32, D-33, D-34, D-35,
D-18/D-19/D-21 (docs), D-36, plus the deferred product decisions (D-25/D-35
governance, D-26/D-32 orphan secrets/services, D-28/D-29 TLS/throttle, P3-8).

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
