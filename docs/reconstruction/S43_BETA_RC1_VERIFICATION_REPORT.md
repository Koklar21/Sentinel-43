# Sentinel-43 — Beta Release Candidate rc1 Verification Report

Mode: FORWARD DELIVERY / EXISTING TOOLING ONLY / NO NEW TESTS
Scope: repository-level beta release-candidate acceptance. No real controlled-beta
target was deployed — see Section G. This is not a production or public-sector
readiness statement.

> **Historical report notice (2026-09-30):** This file preserves the point-in-time RC1 verification record from September 2026. References below to the README being **"Late Alpha"** describe the repository status at the time of that verification and are not the current project status. The authoritative current README classifies the repository as a **Controlled Beta Candidate**; a specific deployment still requires the target-evidence gates in `docs/BETA_RUNBOOK.md` before it is an accepted controlled-beta target.

## A. Release candidate identity

- Source git SHA this branch is based on: `origin/main` at
  `7c55ca33aa464831956545ae5801780a0061a761`, unchanged throughout the
  original verification pass (Sections B–H, 2026-09-17). That pass made no
  source or configuration change. Sections I–K document substantive source,
  CI and configuration changes made on this branch AFTER that pass: reconnecting
  the "Heart" governance subsystem, one CI workflow fix, and making the Heart
  fail-closed and usable in the beta profile. Sections B–H are point-in-time
  evidence tied to the SHA above; the merged post-RC state is recorded in
  Section L.
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
  Calico/Cilium/etc. in `kube-system`), which is why
  `.github/workflows/k8s.yml`'s own kind-based job installs Calico
  deliberately (that job runs a positive smoke with the policies applied; it
  does not run the negative connectivity test — see Section M). Installing a CNI addon here would be a cluster-wide
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
| Final branch based on current main | point-in-time (2026-09-17): done, the only commit ahead was this report. Superseded by Section L (later commits, rebase-merged) |
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
| All hosted CI jobs run against the final head | point-in-time (2026-09-17, before push): pending. Post-merge outcome: see Section L |
| Branch conflict-free and rebase-mergeable | point-in-time (2026-09-17): yes, at that moment the only commit ahead of main was this report. Superseded — the branch later gained the Section I–K commits and was rebase-merged (Section L) |

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
(`SHADOW`/`HUMAN_GATED` — there is no third mode). `AUTONOMOUS_VETO`/`ACTIVE`
does not exist anywhere in the live `core/` runtime path and is
regression-tested absent there by `core/tests/test_policy_gate_smoke.py`.
Historical, quarantined prototypes under `Sentinel-43/` still contain those
concepts; they are preserved as design history, are not imported or executed
by any live code, and are excluded from application images (see Section L).

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
  Gated behind `S43_HEART_ENABLED` (code default `false`; the beta overlay
  sets it `true`) and `S43_HEART_REQUIRED`. As first written in this section
  `S43_HEART_REQUIRED` defaulted to `false`; Section K corrected that, and the
  current code default is `true` (`core/api/main.py`, matching
  `S43_GOVERNANCE_REQUIRED`), so an enabled Heart that fails blocks `/ready`.
  Enabling the Heart is an explicit operator choice, never a silent behavior
  change from upgrading to this release. Registers as subsystem `heart` in `SubsystemRegistry`
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
  results are unchanged from Sections B2–B5 as of this section's own commit
  (point-in-time; later sections did change CI and beta configuration): this
  addition changes no Dockerfile, dependency, Compose file, or Kubernetes
  manifest, is disabled
  by default, and the isolated suite (which imports and boots
  `core.api.main`) together with the two probes above already exercise the
  only code paths this change touches.

**Non-goals held throughout, and still true after this change:** no
`AUTONOMOUS_VETO`/`ACTIVE` mode value anywhere in new code or the live
runtime path; no
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

## K. Making the Heart beat

Section I connected the Heart to the composition root; this section closes
the gap between "imported and constructed" and actually beating: staged,
observable, fail-closed, and usable in the beta profile. The owner's own
review of Section I's initial cut identified five concrete defects, all
independently re-verified before any fix:

1. **A second, Heart-only action queue.** The endpoints Section I added
   (`/governance/heart/pending`, `.../approve`, `.../veto`) operated on
   `SentinelCoreStore` directly, entirely separate from the canonical
   `/actions`/`/actions/{id}/approve`/`/actions/{id}/veto` system every
   dashboard client, WebSocket consumer, and existing test already expects.
   **Fixed**: those three endpoints are removed. A Heart recommendation is
   now mirrored into the exact same `runtime.action_store` the dashboard
   already reads (via a new `ActionSink` the Heart calls synchronously,
   bridged onto the event loop with `asyncio.run_coroutine_threadsafe`
   since `ThreatGovernor.observe()` runs in a worker thread), tagged
   `action_type: "HEART_RECOMMENDATION"` — a real regression surfaced and
   fixed during this same wave's own test run: an earlier draft used the
   pre-existing generic `"THREAT_ACTION"` default
   (`_create_synthetic_action()`, `dashboard.js`) as the discriminator,
   which collided with unrelated existing synthetic/dashboard actions and
   silently misrouted their approve/veto calls into the Heart, breaking
   `core/tests/test_v1_legacy_disposition.py`'s two governance-path tests.
   `_resolve_governance_and_commit_action` now branches on the
   collision-free tag to resolve through `ThreatGovernor` instead of
   `SystemOrchestrator` — the existing `/actions/{id}/approve`/`veto`
   routes need no changes at all. `SentinelCoreStore` remains the durable
   source of truth (it survives a restart; the in-memory canonical store
   does not); the mirror is a best-effort view of that truth, not a second
   one. Verified end-to-end via a temporary probe: a real `observe()` call
   produced an action visible in `GET /actions`, approvable/vetoable only
   through the canonical routes, with the durable `SentinelCoreStore`
   status agreeing after resolution and after a full process restart; the
   full isolated suite (including the two previously-broken
   `test_v1_legacy_disposition.py` tests) re-ran clean afterward.
2. **`S43_HEART_ENABLED` was absent from every beta configuration.** Not
   set in the Kubernetes beta overlay, the Compose environment passthrough,
   or `.env.example`, and not checked by `deploy_preflight.py` in either
   phase. **Fixed**: added to
   `deploy/kubernetes/overlays/beta/configmap-patch.yaml`,
   `docker-compose.yml`'s environment passthrough (default `false`, so
   local dev is unaffected), and `.env.example`. `deploy_preflight.py`
   gained a prepare-phase check (fails a beta/non-local target that
   doesn't explicitly set it `true`, for both Compose and Kubernetes) and
   a verify-phase check that execs into the live container/every
   non-terminating pod and reads the effective value the running process
   actually has — refactored the existing legacy-auth runtime-check's
   pod-iteration logic into a shared, parameterized helper rather than
   duplicating ~90 lines of hardened JSON-parsing for a second variable.
   Reuses the existing `_is_explicitly_true` boolean parser; no new one
   was written. Verified: rendered the beta overlay
   (`kubectl kustomize` → `S43_HEART_ENABLED: "true"` present), 129/129
   `k8s_policy_check.py` assertions and 22/22 kubeconform resources still
   pass; rendered `docker compose config` with the var set and confirmed
   it resolves into the container's environment; `core/tests/test_deploy_preflight.py`
   (64 tests, unchanged) still passes.
3. **`S43_HEART_REQUIRED` defaulted to `false`, unlike governance's `true`.**
   A beta profile that turned the Heart on would not have made a failed
   Heart block `/ready` — an operator could deploy with a broken Heart and
   the target would still report ready. **Fixed**: default now matches
   `S43_GOVERNANCE_REQUIRED`'s own precedent exactly (`true`). Verified via
   a temporary probe that forced a real Heart startup failure (an
   unwritable SQLite parent path): `/ready` returned 503 with
   `"blocking": ["heart"]`, while `/health` (liveness) correctly stayed
   200 -- the process keeps running and diagnosable rather than
   crash-looping, a deliberate difference from `_start_governance()`'s own
   raise-on-required-failure (crashing here would take detection,
   Watchtower, the dashboard, and auth down with it, when only
   Heart-governed staging actually needs to stop). The Heart also now
   self-reports health via an injected callback
   (`on_health_change`, reused by both the Fenrir-ingestion path and the
   HTTP approve/veto path) so a later runtime failure -- not just a
   startup one -- flips `/ready` closed too, and a subsequent success
   self-heals it, the same way Watchtower's own reachability flag does.
4. **Audit-append failure during staging was a soft return, not a hard
   failure.** The original `observe()` could report `status="STAGED"`
   even when the durable audit record for that stage failed to append --
   violating "no consequential staging without audit" outright. **Fixed**:
   staging now compensates (transitions the row to `EXPIRED`) and raises
   on audit failure instead of returning a decision that misrepresents
   what happened; `resolve_human_decision()` got the equivalent fix
   (reverts an unaudited decision back to `PENDING` and raises). Verified
   by the same temporary `ThreatGovernor`-level probe used in Section I,
   extended to assert the exception now propagates instead of returning a
   soft "STAGED"/"AUDIT_APPEND_FAILED" value.
5. **Fenrir's Heart hook could lose the fact that governance staging
   never happened.** `heart is None` returned silently with no metric, no
   log, nothing distinguishing "legitimately disabled" from "should be
   staging but isn't." **Fixed**: added `heart_unavailable` and
   `heart_observe_failed` counters to Fenrir's existing `metrics` dict,
   and a log-once-until-recovered warning (never per-finding, so it can't
   flood logs) when the Heart is unavailable. Raw detection/reporting
   remain completely unaffected either way -- a Heart failure is never
   reinterpreted as "no threat." Verified via a temporary probe that ran a
   real `FenrirHunter` (its actual `SentinelThreatDetector`, fed 30
   synthetic login-failure events) with `.heart` wired to a real,
   running `ThreatGovernor`: the resulting finding reached the canonical
   action store with zero `heart_unavailable`/`heart_observe_failed`
   counts, proving the whole path -- detection to canonical dashboard
   action -- beats end to end, not just the Heart in isolation.

Also fixed in passing, found while generating Heart action ids for the
canonical store: `observe()` built ids with bare `str(uuid4())`
(lowercase, hyphenated), which does not match the canonical store's own
`ACTION_ID_RE` (`^[A-Z0-9_-]{1,64}$`) -- every Heart-staged action would
have 404'd against `/actions/{id}/approve`. Ids are now
`f"HEART-{uuid4().hex.upper()}"`, used as the single id for both the
canonical mirror and the durable `SentinelCoreStore` row (one id per
recommendation, not a mapping to keep in sync between two stores).

**Verification performed on this wave** (existing suites + temporary,
uncommitted probes per this task's test policy -- no test file was
created, modified, or weakened): full isolated suite and the disposable-
PostgreSQL suite (both re-run after this wave's changes, results in the
Final Report); the full targeted regression set from Section I
(`test_pr275_corrections.py`, `test_policy_gate_smoke.py`,
`test_package_integrity.py`, `test_fenrir_monitoring_integration.py`,
`test_monitoring_event_pipeline.py`, `test_operator_findings.py`) plus
`test_actions_test_inject_auth.py` and `test_jwt_auth.py` (the existing
tests closest to the approve/veto/auth paths this wave changed): 280
passed, 0 failed; `core/tests/test_deploy_preflight.py`: 64 passed, 0
failed. Two temporary probes exercised the full real stack through a real
FastAPI lifespan and `TestClient` (real JWT-based operator auth, real
`ThreatGovernor`, real `SentinelCoreStore`, a real restart) and a real
`FenrirHunter` instance; both were deleted before this wave's commits, per
the same test policy honored throughout this task.

**Non-goals held, unchanged from Section I:** still no `AUTONOMOUS_VETO`/
`ACTIVE` mode in the live runtime path (historical quarantined prototypes
excepted — Section L), still no scheduler/timer/background thread that
transitions a staged action to a terminal state on its own, still no real
enforcement executor, still no historical `Sentinel-43/*.py` file read
into or restored into any live path.

## L. Post-merge reconciliation (2026-09-19)

This section supersedes the pre-merge wording in Sections A, E, I and K where
they differ, and records the repository's state after merge. Historical test
counts elsewhere in this report are evidence tied to the exact source SHA that
was verified at the time; they were not re-run or rewritten here.

**Merge record.** PR #287 was merged into `main` by REBASE AND MERGE. A rebase
merge rewrites commit SHAs, so the PR commits and the resulting `main` commits
are different objects with identical content:

| Item | SHA |
|---|---|
| Final tested PR #287 head (`release/beta-rc1-20260917`) | `54d911bf2ccbaceab339ca7d4c4f3b38719de14f` |
| Resulting `main` head after the rebase-merge | `5a249e71cc46a6006eb884da9d16066057cf3d25` |
| Git tree of both (`git rev-parse <sha>^{tree}`) | `b9c6431251347283a3a8d514a8fc30ba294e6d2d` |

The PR-head tree and the merged-`main` tree are identical, so every file is
blob-identical between the tested PR head and merged `main` (verified with
`git rev-parse` on both trees and an empty `git diff --stat`).

**Heart.** The live Heart is `core/governance/heart.py`. The beta overlay sets
`S43_HEART_ENABLED=true`; `S43_HEART_REQUIRED` defaults to `true` in code, so
when enabled a failed Heart blocks `/ready` while `/health` stays up.

**Historical prototypes.** The nested `Sentinel-43/` directory is preserved
unchanged as design history. It is not imported, launched or shipped by any
live path: it is excluded from application images by `.dockerignore` and
documented as non-runtime in `Sentinel-43/README.md`. It contains
`ACTIVE`/`AUTONOMOUS_VETO` concepts, which are prohibited from the live
runtime. The accurate statement is therefore: no `ACTIVE`/`AUTONOMOUS_VETO`
mode exists in the live `core/` runtime path; historical quarantined
prototypes still contain those concepts but are neither shipped nor executed.

**WebSocket.** An unavailable authentication/session backend now closes the
socket with code 1011 (server error) and reason `service_unavailable`
(previously code 1011, reason `auth_service_unavailable`, whose text matched
the dashboard's `auth|token|password|credential|session|login` heuristic and
so could be classified as a client authentication failure). Code 1011 is
retained deliberately: the dashboard reconnects with backoff after 1011 but
never after 1008. Genuine credential/session failures keep code 1008 and their
existing reasons. Every outage path still fails closed: the socket is closed
before the client is registered or any event is delivered.

The one xfailed test described in Section B1 as pre-existing
(`core/tests/test_ws_auth.py::test_ws_reports_service_unavailable_not_auth_failure`)
was resolved by correcting that existing test, not by adding one. It had pinned
close code 1008 for this outage, which would have suppressed dashboard
reconnect after a transient outage; it now asserts code 1011 with reason
`service_unavailable`, and its obsolete `xfail` marker was removed. It now
PASSES as an ordinary test with all of its other assertions unchanged. The
Section B1 counts remain evidence for the SHA they were run against.

**Readiness tiers — distinct, and none is established by this report:**

| Tier | Status |
|---|---|
| Repository beta release candidate | Repository-level acceptance recorded in Sections B–K |
| Controlled-beta target verification | NOT DONE — no named target (Section G) |
| Production readiness | NOT ESTABLISHED |
| Public-sector readiness | NOT ESTABLISHED |

README.md continues to classify the public project as "Late Alpha"; this
report does not change that label.

## M. Controlled-beta handoff reconciliation (2026-09-19)

Dated reconciliation after PR #288 merged. Nothing here re-runs or rewrites the
results above; it records what is now verified, what was discovered about the
target, and what is still missing. **No deployment, registry publish, live
migration, secret rotation, or readiness promotion occurred.**

**Merged baseline.** `main` = `7194bb0aee737ff1f6ff79ad9b06b71e63bebd9d`. The
tested PR #288 head `3fed0799ee98ce2e0d1511906b5fa3f2b89e178d` and `main` have
the identical git tree `4600c4591844faed89e7ef6d128b7137efde3eb4`
(`git rev-parse <sha>^{tree}` on both; empty two-commit `git diff --stat`), so
CI evidence for the PR head applies to `main`'s content. Hosted CI passed all
six jobs on the PR head (pull_request run 35457777806) and again on `main`
(push run 35457863248, `7194bb0`): manifests, pytest, disposable-PostgreSQL
pytest, image build + Trivy, kind smoke deploy, Playwright SPA smoke.

**What CI does and does not prove.** Hosted CI proves the repository release
candidate against a *disposable* stack and cluster. It is not target
verification. In particular, the `kind smoke deploy` job installs Calico and
runs a positive smoke (rollout, `/ready`, posture assertions, health/bootstrap
over the Host header); it does not test that forbidden connections are refused.
Negative NetworkPolicy connectivity (`docs/BETA_RUNBOOK.md` §20) has not been
run in CI and must be run on the real target.

**Test-isolation defect (reproduced, fixed).** `core/tests/test_auth_login.py`
errored when run after `core/tests/test_ws_auth.py`
(`pytest core/tests/test_ws_auth.py core/tests/test_auth_login.py`: 15 passed,
1 error, `S43_WS_REQUIRE_AUTH=true but S43_JWT_SECRET is not configured`), while
the reverse order and the full default-order suite passed. Cause:
`test_ws_auth.teardown_module` restores variables that were unset when it was
imported by popping them and reloading `core.api.main`, which removed the values
`test_auth_login` had set once at import time. Fixed with a `setup_module` hook
in the existing `test_auth_login.py` that re-applies its own environment and
reloads `main` (the pattern `test_ws_auth.py` already uses). No assertion, test
case, skip or production code changed; both orders now pass (31 passed).

**Target discovery (read-only; no secret values read or printed).** No
controlled-beta target is defined anywhere discoverable:

| Input | Finding |
|---|---|
| Deployment path | Not chosen. Local Kubernetes context is only `docker-desktop` (a development cluster with no NetworkPolicy-enforcing CNI); the local Compose stack is a development stack (`SENTINEL_ENV=development`, localhost origins). |
| Hostname / DNS | None. Only placeholders (`beta.example.invalid`) and the disposable browser-test name `s43.beta.test:8443` (`.env.browser`, test-only). |
| TLS | None. The Compose proxy's certificate is a self-signed `CN=localhost` development certificate (gitignored). No cert-manager `ClusterIssuer` is known. |
| Registry | Not chosen. Docker Hub and `dhi.io` have stored logins on this machine, but neither was selected for Sentinel-43; the overlay still ships `REGISTRY_PLACEHOLDER` with an all-zero digest. GHCR could not be inspected (token lacks `read:packages`). |
| Allowed origin / trusted hosts / trusted-proxy CIDR | Placeholders (`https://beta.example.invalid`, `beta.example.invalid,s43-api`, empty CIDR). No real ingress or proxy network is known. |
| External verification vantage | None identified. |
| GitHub-side | No environments, variables, secret names, deployments or homepage are configured for the repository. |

`python scripts/deploy_preflight.py kube --phase prepare` against the repository
as shipped: 2 passed, 0 failed, **3 incomplete** (hostname, immutable image
identity, kube context/namespace) — `PREPARE INCOMPLETE`, not a pass. Placeholder
values are not evidence.

**Deployment sequence prepared for operator review (nothing executed).**
Constraints carried unchanged: single replica with `Recreate`, session-only
authentication (`S43_REJECT_LEGACY_AUTH=true`), mandatory durable audit,
Heart enabled and required (`S43_HEART_ENABLED=true`, `S43_HEART_REQUIRED`
default true), Remote Gateway disabled.

| # | Step (runbook §) | Status |
|---|---|---|
| 0 | Operator supplies the target inputs listed above | BLOCKED — inputs missing |
| 1 | Pin the source revision (`main` at or after `7194bb0`); build from a clean `git archive` of that exact commit with the OCI revision label set to it (§8) | READY — not executed |
| 2 | Push to the chosen registry; read the returned digest; verify it resolves from the registry itself; pin `repo@sha256:<digest>` in the overlay (§8) | BLOCKED — no registry |
| 3 | Generate secrets and the Argon2id operator hash, kept out of Git (§4, §5) | READY — operator action, values never committed |
| 4 | Replace the three `CHANGEME` values (trusted hosts, allowed origin, trusted-proxy CIDR); select real TLS (§13, §14) | BLOCKED — hostname, TLS, CIDR |
| 5 | `deploy_preflight.py <compose\|kube> --phase prepare` with real inputs; must pass with no incomplete mandatory check (§15) | INCOMPLETE — 3 incomplete as shipped |
| 6 | Run the migration Job/service first; wait for the schema-version gate (`/ready` 503 until at head) before serving traffic (§9, §10) | READY — live migration not authorized in this phase |
| 7 | Apply; confirm one replica/`Recreate`, Heart subsystem active, legacy auth rejected, audit store healthy (§16) | BLOCKED — depends on 2, 4 |
| 8 | `deploy_preflight.py ... --phase verify --from-external-host` from an outside vantage (TLS chain and hostname, HSTS, docs closed, internal ports unreachable) (§15) | BLOCKED — target and vantage missing |
| 9 | `browser_tests/run_target.sh` read-only edge suite, then authenticated suite with designated operator credential file (never bootstrap; admin-mutation opt-in only with throwaway accounts) (§17) | BLOCKED — target and accounts missing |
| 10 | Negative NetworkPolicy connectivity on the real cluster's CNI (§20) — Kubernetes path only | BLOCKED — no cluster; CI Calico is not this proof |
| 11 | Backups before first user, restore drill on scratch storage, rollback = previous pinned digest with a `Recreate` outage (§11, §12, §19) | READY as procedure; destructive recovery not authorized in this phase |
| 12 | Retain evidence: commit SHA + digest, preflight outputs for both phases, netpol output, acceptance output, secret-rotation date, backup timestamps (§21) | Pending steps above |

**Readiness.** Repository beta release candidate: recorded above (Sections B–L).
Controlled-beta target verification: NOT DONE. Production and public-sector
readiness: NOT ESTABLISHED. README's "Late Alpha" label is unchanged.
