# Sentinel-43 — Beta Release Candidate rc1 Verification Report

Mode: FORWARD DELIVERY / EXISTING TOOLING ONLY / NO NEW TESTS
Scope: repository-level beta release-candidate acceptance. No real controlled-beta
target was deployed — see Section G. This is not a production or public-sector
readiness statement.

## A. Release candidate identity

- Source git SHA (branch `release/beta-rc1-20260917`, based directly on
  `origin/main` with no additional commits — every acceptance check below
  passed against main as-is, so no source change was required): `7c55ca33aa464831956545ae5801780a0061a761`
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
  **1003 passed, 103 skipped, 1 xfailed, 0 failed.** The 103 skips are the
  `*_pg.py` PostgreSQL-dependent files self-skipping without a live DB in
  this specific invocation (see B2, where the same files are re-run
  against a real disposable Postgres with zero skips) plus 4 tests in
  `test_bootstrap.py`/`test_system_smoke.py` that require
  `scripts/ci_live_tests.py`'s live stack. The 1 xfail
  (`test_ws_auth.py::test_ws_reports_service_unavailable_not_auth_failure`)
  is pre-existing and unrelated to this branch.
- Disposable-PostgreSQL suite, the exact CI invocation
  (`core/tests/test_schema_version_pg.py test_schema_authority.py
  test_deploy_migration_wiring.py test_migrations_pg.py
  test_backup_restore_pg.py test_auth_session_pg.py test_ws_session_pg.py
  test_break_glass_pg.py test_account_transactions_pg.py`) against a
  disposable `postgres:16.3` container (unique container name/port,
  `S43_TEST_PG_DSN` + `S43_TEST_PG_CONTAINER` set to match, matching CI's
  own `s43t`/`s43t` naming convention exactly): **95 passed, 0 skipped, 0
  failed.**
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

**None.** Every acceptance check in Section B passed on its first attempt
against unmodified `main` at `7c55ca33aa464831956545ae5801780a0061a761`.
No source or configuration change was required or made.

## E. DEFINITION OF DONE — REPOSITORY BETA RELEASE-CANDIDATE GATE

| Requirement | Status |
|---|---|
| Final branch based on current main | done — no commits ahead except this report |
| Complete existing isolated tests pass | done — 1003 passed, 0 failed |
| Complete PostgreSQL tests pass, zero skips | done — 95 passed, 0 skipped |
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
