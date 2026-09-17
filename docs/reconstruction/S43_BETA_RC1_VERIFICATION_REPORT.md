# Sentinel-43 — Beta Release Candidate rc1 Verification Report

Mode: FORWARD DELIVERY / EXISTING TOOLING ONLY / NO NEW TESTS
Scope: repository-level beta release-candidate acceptance. No real controlled-beta
target was deployed — see Section G. This is not a production or public-sector
readiness statement.

## A. Release candidate identity

- Source git SHA this branch is based on: `origin/main` at
  `7c55ca33aa464831956545ae5801780a0061a761`, unchanged throughout this
  release-candidate pass. Section I below documents one substantive addition
  made on this branch after the initial zero-defect verification pass
  recorded in Sections B–H: reconnecting the "Heart" governance subsystem.
- Application version: no authoritative version number exists in this repo
  (`pyproject.toml`'s `version = "0.1.0"` is explicitly a template snippet,
  not confirmed live project metadata). README.md labels the current build
  **"Late Alpha"** — this report does not change that label; passing this
  verification does not by itself justify a status change (see Section H).
- Image name: `sentinel43-api`. Built locally: `docker build -t
  sentinel43-api:beta-rc1 -f core/api/Dockerfile .`
- Local image ID / digest: `sha256:c8634446364e9d2d8a352873c67f14ece4851d5fac8edaf2131cb11b6760eba2`
  — this is the image's own content-addressed ID (`docker inspect`), not a
  registry-published digest. **No container registry is configured
  anywhere in this repository or this environment** (confirmed: empty
  `~/.docker/config.json` auths, no registry hostname in any local config,
  `deploy/kubernetes/overlays/beta/kustomization.yaml` still ships its
  intentionally-invalid `REGISTRY_PLACEHOLDER` + all-zero digest, left
  untouched by this pass). A real deployment requires pushing this image
  (or a rebuild from this same source SHA) to an operator-chosen registry
  and pinning the digest the registry returns — see Section G.
- Verified: 2026-09-17T06:12:45Z

## B. What was verified, and how

Six independent acceptance workstreams, each using this repository's own
existing tooling (no new scripts, no new tests):

### B1. Existing test suites
- Full isolated suite (`python -m pytest core/tests/ dashboard/tests/ -q`):
  **1004 passed, 103 skipped, 1 xfailed, 0 failed.** Exact breakdown of the
  103 skips (`-rs`): **99** are the ten `*_pg.py` PostgreSQL-dependent
  files self-skipping without a live DB in this specific invocation (see
  the corrected count below, where the same ten files are re-run against a
  real disposable Postgres with zero skips), and **4** are
  `test_bootstrap.py`/`test_system_smoke.py` tests that require
  `scripts/ci_live_tests.py`'s live stack (99 + 4 = 103). The 1 xfail
  (`test_ws_auth.py::test_ws_reports_service_unavailable_not_auth_failure`)
  is pre-existing and unrelated to this branch.
- Disposable-PostgreSQL suite. **A PR review (sourcery-ai / chatgpt-codex)
  correctly identified that `core/tests/test_session_layer_pg.py` (19
  real PostgreSQL row-locking/concurrency tests for the session refresh
  layer) was never part of `.github/workflows/k8s.yml`'s own `pg-tests`
  job, and so has never actually executed in CI or in this report's first
  pass, ever.** This was a genuine, pre-existing CI coverage gap, not a
  documentation error — fixed directly in this PR by adding the file to
  the CI job's invocation (one line) and to the equivalent local run
  below, since a beta release candidate's own "zero PG skips" gate should
  mean all `*_pg.py` files, not an incomplete subset. The now-complete,
  exact CI invocation
  (`core/tests/test_schema_version_pg.py core/tests/test_schema_authority.py
  core/tests/test_deploy_migration_wiring.py core/tests/test_migrations_pg.py
  core/tests/test_backup_restore_pg.py core/tests/test_auth_session_pg.py
  core/tests/test_session_layer_pg.py core/tests/test_ws_session_pg.py
  core/tests/test_break_glass_pg.py core/tests/test_account_transactions_pg.py`)
  against a disposable `postgres:16.3` container (unique container
  name/port, `S43_TEST_PG_DSN` + `S43_TEST_PG_CONTAINER` set to match,
  matching CI's own `s43t`/`s43t` naming convention exactly): **114
  passed, 0 skipped, 0 failed** (95 from the original nine files + 19 from
  `test_session_layer_pg.py`).
- `scripts/ci_live_tests.py` was deliberately **not** run: it hard-refuses
  to execute unless `GITHUB_ACTIONS == "true"` ("Never points the
  bootstrap tests at a user-supplied deployment" — its own docstring).
  Bypassing that guard to force a local run would defeat an intentional
  safety check; the 4 tests gated behind it remain correctly,
  unavoidably skipped outside real GitHub Actions.

### B2. Kubernetes acceptance (isolated namespace `sentinel43-rc1` on the
local Docker Desktop cluster — the pre-existing, 47-day-old `sentinel43`
namespace was never touched)
- Rendered the beta overlay (`kubectl kustomize`), namespace and image
  retargeted only in an uncommitted scratch copy (never in the committed
  manifests — the real `overlays/beta/kustomization.yaml` still correctly
  ships its honest `REGISTRY_PLACEHOLDER` since no real registry exists).
- `kubeconform -strict` (22/22 resources valid) and
  `scripts/k8s_policy_check.py` (129/129 assertions passed) against the
  rendered manifests.
- Deployed: migration Job completed, `s43-api` rolled out and became
  Ready, `scripts/deploy_preflight.py kube --phase verify` against the
  live namespace: **10 passed, 0 failed, 1 incomplete** (the incomplete
  item is the hostname/edge-TLS check, correctly refusing to evaluate
  against `localhost` rather than a real target hostname — not a defect).
  The live runtime `S43_REJECT_LEGACY_AUTH` check
  (`check_kube_legacy_auth_runtime`, itself a fix landed earlier this beta
  effort) **passed** by exec'ing into the actual running pod.
- Session-bound authentication verified end-to-end against the live pod
  via `kubectl port-forward`: login (both the env-operator/break-glass
  identity and a real DB-backed admin account created directly in the
  test database for this purpose), an authenticated `/actions` call,
  token refresh with CSRF, logout, confirmed the token is genuinely
  revoked post-logout, and confirmed a forged `Origin` header is rejected
  (403). WebSocket authentication verified end-to-end (`auth_required` →
  auth frame → `connected`). Non-local `/docs`, `/redoc`, `/openapi.json`
  all confirmed 404. The per-request legacy `X-S43-Password` fallback
  confirmed rejected (401) under this profile's `S43_REJECT_LEGACY_AUTH=true`.
  `s43-api`/`s43-core` Services confirmed `ClusterIP` (no direct external
  reachability). Pod logs scanned for credential/token material: clean.
- **NetworkPolicy live enforcement was not verified** — this local Docker
  Desktop cluster has no policy-enforcing CNI installed (confirmed: no
  Calico/Cilium/etc. in `kube-system`), which is exactly why
  `.github/workflows/k8s.yml`'s own kind-based job installs Calico
  deliberately. Installing a CNI addon here would be a cluster-wide
  change risking the pre-existing `sentinel43` namespace, so this item is
  **TOOLING UNAVAILABLE** in this environment, not silently passed. The
  manifests themselves render and validate correctly (structural check
  only).

### B3. Compose beta-adjacent acceptance + browser/transport acceptance
(the existing isolated `s43browser` stack, `browser_tests/run.sh`,
`S43_BROWSER_KEEP=1` to extend its lifecycle for additional checks —
project `s43browser`, containers renamed, published only on
`127.0.0.1:8443`/`8081` per its own design; noted separately in Section C
that the base `docker-compose.yml`'s own `"80:80"`/`"443:443"` also
apply, since Compose merges override `ports:` lists rather than replacing
them)
- The existing Playwright suite (`browser_tests/`, excluding
  `target_acceptance/`): **10 passed, 0 failed** — covers HTTP→HTTPS
  redirect, HSTS, login, refresh, logout, CSRF/origin rejection, WebSocket
  auth, and credential/token non-exposure against the real disposable
  HTTPS stack (self-signed test CA, real nginx TLS termination).
- Additional manual checks against the same running stack: Watchtower
  service-token authentication (401 unauthenticated, real analysis
  response with the correct token), container restart with session state
  confirmed retained (11 sessions before and after restarting `s43-api`),
  full log scan across all four containers for credential/token
  leakage (clean), clean `docker compose down -v` teardown.
- Legacy-auth rejection was verified authoritatively in B2 (this specific
  Compose stack does not set `S43_REJECT_LEGACY_AUTH` at all, since its
  purpose is SPA/transport testing, not auth-policy testing — not
  re-tested here to avoid a meaningless duplicate assertion).

### B4. Recovery acceptance (isolated storage/database, never the live
namespace's own)
- Created real application state in the `sentinel43-rc1` namespace (a
  real DB-backed admin account, an authenticated session, token refresh).
- PostgreSQL backup via the documented `pg_dump` command (§11), restored
  into a **separate, disposable** `postgres:16.3` container (unique name/
  port) via the documented `psql` restore command — restored data
  (username, role, session count) matched the original exactly.
- SQLite audit-store backup via the documented online-backup-API sequence
  (§12 — `sqlite3.Connection.backup()` inside the live pod, `kubectl cp`
  out, in-pod temp copies removed after), restored into **separate**
  local storage, integrity-checked both via `PRAGMA integrity_check` and
  via the real `AuditStore.initialize()`/`verify_integrity()` application
  code itself: **`AuditStoreHealth.HEALTHY`**.
- Confirmed the original live namespace's Postgres and pod state were
  unaffected by any of the above (same pod ages, same restart counts,
  same row counts, checked directly after the recovery drill).
- **Dead-letter store backup/restore** (a `chatgpt-codex-connector[bot]`
  review correctly identified this was omitted from the first pass, even
  though `docs/BETA_RUNBOOK.md` §12 documents backup/restore for both
  `audit.sqlite3` and `dead_letter.sqlite3`): verified separately via a
  temporary, uncommitted probe against `core/reliability.py::DeadLetterStore`
  directly (not the live K8s namespace, which had already been torn down)
  — recorded 3 synthetic failed-events via the real `record_failure()` API,
  backed up the live file with the same `sqlite3.Connection.backup()`
  online-backup approach used for the audit store, restored into
  **separate** local storage, confirmed `PRAGMA integrity_check` = `ok` and
  that the real `DeadLetterStore.get()`/`.counts()` application code reads
  the restored rows back correctly (all 3, with matching
  `correlation_id`s), and confirmed the original live store was unaffected
  throughout. Probe deleted before this commit.
- No Alembic downgrade was used at any point.

### B5. Image build and vulnerability gate
- `docker build -t sentinel43-api:beta-rc1 -f core/api/Dockerfile .` — clean
  build, runtime stage, no build-args deviation from CI's own invocation.
- Trivy (run as a container, matching CI's exact flags —
  `--severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed=false`):
  **0 HIGH/CRITICAL vulnerabilities** across the Alpine 3.24.1 base and
  every Python package.
- Confirmed non-root runtime identity (`65532:65532`, matching the
  Kubernetes `securityContext` this same image is deployed under).
- Confirmed no secret material in the image: `.dockerignore` correctly
  excludes `.env`/`.env.*`/`.secrets/`/`**/*.key`/`**/*.pem`/`**/*.crt`
  (only the placeholder `.env.example` is present in the built image);
  the build log itself contains no credential material.

## C. Observations recorded, not fixed (outside the zero-remediation
boundary — none of these blocked any acceptance check above)

- The `s43browser` Compose stack's proxy container is actually published
  on `0.0.0.0:80`/`443` in addition to the intended `127.0.0.1:8081`/
  `8443`, because Compose concatenates `ports:` lists across
  `-f docker-compose.yml -f docker-compose.browser.yml` rather than
  replacing them — wider than the override file's own "127.0.0.1 only"
  comment implies. Did not block any check in this pass; not fixed here.
- No verify-phase live-target check exists in `scripts/deploy_preflight.py`
  for `S43_ALLOWED_ORIGINS`/`S43_TRUSTED_HOSTS`/`S43_TRUSTED_PROXIES`
  against a deployed target (only prepare-phase file/ConfigMap checks
  exist for these three, unlike the equivalent live-exec pattern that
  already exists for `S43_REJECT_LEGACY_AUTH`). The underlying security
  behavior itself is correct and was exercised directly in B2/B3 (origin
  rejection, host validation); this is a preflight-tooling coverage gap,
  not a behavior defect, and was not in scope to fix in this pass.

## D. Confirmed release blockers found

**None.** All completed acceptance checks in Section B passed on their
first attempt against unmodified `main` at
`7c55ca33aa464831956545ae5801780a0061a761`. One verify-phase check
(deploy_preflight's edge-TLS/hostname check) remained correctly incomplete
against the `localhost` placeholder rather than a real target hostname, and
live NetworkPolicy enforcement (B2) was not verified because this local
Docker Desktop cluster has no policy-enforcing CNI installed. Neither is a
confirmed release blocker; see B2 and F for the qualifications. No source
or configuration change was required or made in this initial pass (Section
I documents one substantive addition made afterward).

## E. DEFINITION OF DONE — REPOSITORY BETA RELEASE-CANDIDATE GATE

| Requirement | Status |
|---|---|
| Final branch based on current main | done — no commits ahead except this report |
| Complete existing isolated tests pass | done — 1003 passed, 0 failed |
| Complete PostgreSQL tests pass, zero skips | done — 114 passed, 0 skipped (all ten `*_pg.py` files; see B1) |
| Live Compose acceptance passes | done (B3) |
| Browser smoke passes | done — 10/10 (B3) |
| Kubernetes rendering/policy/deploy acceptance passes | done (B2); live NetworkPolicy enforcement TOOLING UNAVAILABLE |
| Migration and recovery acceptance pass | done (B4) |
| Image build and vulnerability gate pass | done — 0 HIGH/CRITICAL (B5) |
| Beta profile rejects legacy authentication | done, verified live (B2) |
| Non-local docs exposure closed | done, verified live (B2) |
| Internal services remain internal | done, verified live (B2/B5) |
| No unresolved confirmed P0/P1 beta blocker | none found |
| All hosted CI jobs run against the final head | pending push — see PR |
| Branch conflict-free and rebase-mergeable | yes — no commits ahead of main besides this report |

## F. What this report does not establish

- Production readiness.
- Public-sector / CJIS / CMMC readiness.
- Controlled-beta deployment (no real target — see Section G).
- Live NetworkPolicy enforcement (tooling unavailable in this environment;
  the manifests themselves are structurally valid — see B2).

## G. Controlled-beta target inputs still required

None of the following exist anywhere in this repository or this
environment, and none were invented by this pass:

- A chosen deployment path (Compose vs. Kubernetes) for the real target.
- A real, operator-controlled hostname (not `beta.example.invalid`).
- A container registry to push to, and the real digest it returns after
  a push of this exact source SHA (or a rebuild from it).
- A real TLS certificate/issuer for that hostname.
- The real trusted-proxy CIDR of whatever terminates TLS in front of the
  API.
- The real HTTPS origin matching that hostname.
- An external network vantage point to run
  `browser_tests/run_target.sh` / `scripts/deploy_preflight.py --phase
  verify --from-external-host` against once deployed.

Once these are supplied, Section E's repository-level verification plus
`docs/BETA_RUNBOOK.md`'s existing procedures are what carry this from
"repository release candidate" to "controlled beta, verified."

## H. Public status

This report intentionally does not change README.md's "Late Alpha" label.
Passing every currently-runnable repository-level acceptance check is
necessary but not sufficient for a beta claim without a verified target
(Section G) — per this task's own instruction not to infer alpha/beta/
production status from a successful build or test run alone.

## I. Heart governance-kernel reconnection

After Sections B–H's zero-defect verification pass, the repository owner
identified that the "Heart" — a human-governed threat-assessment staging
pipeline — had drifted out of the live composition root and needed to be
reconnected as part of this release, not deferred. This section documents
that work.

**Scope discipline:** this is composition of already-live, already-tested
primitives, not new invention, and not a restoration of the historical
`Sentinel-43/*.py` files (which remain untouched, unimported, exactly as
they were). Reused as-is: `core/audit/store.py::AuditStore`,
`core/guards/velocity.py::VelocityGuard`,
`core/sentinel43_core_db.py::SentinelCoreStore` (previously written but
never wired to anything), and `core/detection/sentinel_threat_types.py`'s
live `ThreatAssessment` type. New: `core/governance/heart.py::ThreatGovernor`
— a sibling to `SystemOrchestrator` reusing its exact `GovernanceMode`
(`SHADOW`/`HUMAN_GATED` — there is no third mode; `AUTONOMOUS_VETO`/`ACTIVE`
does not exist anywhere in live code and is regression-tested absent by
`core/tests/test_policy_gate_smoke.py`).

**State machine implemented, and nothing beyond it:**
OBSERVE → ASSESS (dedupe + corroboration + rate limit) → RECOMMEND → STAGE
(HUMAN_GATED only) → WAIT FOR HUMAN DECISION. `resolve_human_decision()` is
the pipeline's terminus: it transitions a staged action to APPROVED or
VETOED and appends an audit record. **No executor exists.** The historical
`IntegrationHub.execute()` was always a logging-only stub in every prior
implementation; this reconnection does not add a real one either — that
would be separate work requiring its own security review, not something to
fold into this release.

**Wiring:**
- `core/governance/composition.py::build_heart_from_settings()` — mirrors
  `build_orchestrator_from_settings()`.
- `core/api/main.py::_start_heart()` — mirrors `_start_governance()`.
  Gated behind `S43_HEART_ENABLED` (default `false`) and
  `S43_HEART_REQUIRED` (default `false`): enabling it is an explicit
  operator choice, never a silent behavior change from upgrading to this
  release. Registers as subsystem `heart` in `SubsystemRegistry`
  (`/ready`, `/system/status`).
- `core/detection/feniri_hunter.py::FenrirHunter` gained an optional
  `self.heart` attribute (default `None`, set by the composition root only
  when Heart is enabled) and a best-effort `_observe_with_heart()` call at
  the exact point Fenrir already decides a finding is worth reporting
  (severity-threshold met or statistical-anomaly escalation) — the same
  trigger Fenrir already uses for its own external reporting. Any Heart
  failure is logged and swallowed; Fenrir's own detection/reporting path is
  unchanged and never depends on the Heart being present.
- `GET /governance/heart/pending`,
  `POST /governance/heart/actions/{action_id}/approve`,
  `POST /governance/heart/actions/{action_id}/veto` — new sibling endpoints
  to the existing `/governance/pending`/`/actions/{id}/approve`/`veto`,
  reusing the same `_require_operator` auth and `DecisionBody` shape.
  Deliberately not merged into the existing endpoints: the Heart's staged
  actions are durable `SentinelCoreStore` rows sourced from threat
  assessments, structurally different from `SystemOrchestrator`'s
  in-memory, transaction-shaped reviews — conflating the two response
  shapes risked the existing, tested dashboard contract for no real
  benefit. This is a deliberate, conservative choice the owner may revisit
  (e.g., a second dashboard panel) rather than the literal single unified
  list a first reading of "extend the existing contract" might suggest.

**Verification performed (existing tests + temporary, uncommitted probes,
per this task's test policy — no test file was created, modified, or
weakened):**
- Full isolated suite after this change: 1004 passed, 103 skipped (same
  categories as Section B1), 1 xfailed, 0 failed.
- `test_pr275_corrections.py` (exercises `SystemOrchestrator` end-to-end),
  `test_policy_gate_smoke.py` (regression-asserts `AUTONOMOUS_VETO` stays
  rejected), `test_package_integrity.py`, `test_fenrir_monitoring_integration.py`,
  `test_monitoring_event_pipeline.py`, `test_operator_findings.py`: 236
  passed, 0 failed, unchanged behavior.
- Disposable-PostgreSQL suite rerun on this head (the original nine-file
  invocation, before Section J's CI-coverage-gap fix added the tenth
  file): 95 passed, 0 skipped, 0 failed — unaffected either way, since
  this addition touches nothing PostgreSQL-related; see B1/Section J for
  the corrected, complete 114-passed, ten-file count.
- A temporary, uncommitted probe exercised `ThreatGovernor` directly:
  velocity limiting, corroboration accumulation and its interaction with
  stage-level dedupe (a real bug — an early version reset the corroboration
  counter on success and could strand a genuine ongoing burst back in
  "awaiting corroboration" — was found and fixed this way, before any
  commit), SHADOW-mode never staging, and the full
  approve/veto/double-resolve/unknown-action-id error paths. Deleted before
  this commit.
- A second temporary, uncommitted probe booted the real FastAPI lifespan
  (`core.api.main.lifespan`) with `S43_GOVERNANCE_ENABLED=true` and
  `S43_HEART_ENABLED=true` against disposable SQLite paths, confirmed
  `runtime.heart` starts, the `heart` subsystem reports `ACTIVE`, and ran a
  full observe → stage → resolve cycle through the real composition root
  (not just the unit-level class). Deleted before this commit.
- Compose, Kubernetes, browser/Playwright, and image-build/vulnerability
  results are unchanged from Sections B2–B5: this addition changes no
  Dockerfile, dependency, Compose file, or Kubernetes manifest, is disabled
  by default, and the isolated suite (which imports and boots
  `core.api.main`) together with the two probes above already exercise the
  only code paths this change touches.

**Non-goals held throughout, and still true after this change:** no
`AUTONOMOUS_VETO`/`ACTIVE` mode value anywhere in new code; no
scheduler/timer/background thread transitions a staged action to a terminal
state; `test_policy_gate_smoke.py`'s absence-assertions pass unmodified;
the historical `Sentinel-43/*.py` files were not read into, imported by, or
restored into any live code path — this is a fresh, minimal implementation
against current interfaces, not a resurrection of old files.

## J. PR review remediation

Automated review (`sourcery-ai[bot]`, `chatgpt-codex-connector[bot]`) on
this PR found five real issues in the first commit's report and, in one
case, in the repository's own CI configuration. Each was verified against
the actual repository before any change — none were accepted at face
value. Resolved:

1. **Section D overstated completeness** (flagged by sourcery-ai) — said
   "every acceptance check passed" without acknowledging the one
   incomplete verify-phase check and the unavailable NetworkPolicy check
   already documented elsewhere in this same report. Fixed: Section D now
   states the qualification directly.
2. **Isolated-suite skip count lacked a verifiable breakdown** (nitpick,
   sourcery-ai) — fixed: Section B1 now gives the exact `-rs` breakdown
   (99 PostgreSQL-file skips + 4 `ci_live_tests.py`-gated skips = 103).
3. **PG test invocation example was not copy-pasteable from the repo
   root** (nitpick, sourcery-ai) — only the first of nine filenames
   carried the `core/tests/` prefix. Fixed: every filename in the example
   is now prefixed.
4. **A whole PostgreSQL test file was never run, anywhere, ever** (P1,
   chatgpt-codex-connector) — `core/tests/test_session_layer_pg.py` (19
   real row-locking/concurrency tests) was not part of
   `.github/workflows/k8s.yml`'s `pg-tests` job and therefore has never
   executed in CI, in any prior verification pass, or in this report's
   first version. Confirmed genuine by running the file directly against
   a disposable PostgreSQL container (19 passed, 0 skipped, 0 failed).
   **Fixed at the source, not just in the report**: added the file to the
   CI job's actual test invocation (`.github/workflows/k8s.yml`), and
   updated Sections B1/E to the corrected, complete ten-file, 114-passed
   count. This is the one finding from this wave that changed something
   beyond documentation wording — justified because the beta release
   candidate's own Definition of Done requires "complete PostgreSQL tests
   pass, zero skips," and a whole file's worth of real concurrency tests
   silently never running is exactly the kind of gap that requirement
   exists to catch.
5. **Recovery acceptance only covered half of §12's documented scope**
   (P2, chatgpt-codex-connector) — `docs/BETA_RUNBOOK.md` §12 documents
   backup/restore for both `audit.sqlite3` and `dead_letter.sqlite3`;
   Section B4 originally verified only the former. Fixed: ran the
   equivalent drill against `core/reliability.py::DeadLetterStore`
   directly (documented in the updated B4) and confirmed it behaves
   identically to the audit-store drill already verified live in the K8s
   namespace.

No finding was dismissed without investigation, and no finding was
resolved by weakening a claim rather than fixing or accurately describing
the underlying gap.
