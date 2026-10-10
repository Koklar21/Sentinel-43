# Public beta reopening evidence gate

This is an operator-facing evidence checklist for reopening access to the **source repository**. It supplements [the controlled beta runbook](../BETA_RUNBOOK.md); it does not establish production readiness or authorize Internet exposure of a running instance.

**Do not weaken detection or governance to make this gate pass.** Keep Sigma-compatible deterministic detection, eBPF telemetry where supported, agent-sequence correlation, behavioral/anomaly evidence, Fenrir, Watchtower, Heart, and the single `Sentinel43RuntimeAuthority` boundary intact. Detectors remain evidence producers only; no autonomous quarantine, blocking, policy changes, or bypass of human gates. An unsupported sensor is reported as unsupported, not silently represented as passing.

## 1. Release-critical PRs and CI

- Verify the target commit on `main` includes the reviewed Compose bootstrap test isolation (PR #453) and ACME ignore protection (PR #454).
- Inspect **all required checks for the current release commit**, including Kubernetes manifest validation, disposable PostgreSQL, core pytest, zero-skip acceptance, Kind, Playwright, and image vulnerability scan. Do not infer a green `main` from one green local pytest command or from an older PR.
- Record commit SHA, each job URL, conclusion, and required reviewer approval. A failed, skipped, absent, or unobserved required job is **not a pass**. Do not bypass branch protections or merge unreviewed fixes.
- Use the existing `scripts/acceptance_campaign.py` and `acceptance/suites.json` inventory to collect full acceptance evidence. Its disposable Postgres helper uses the name `s43-accept-pg`: **before running**, confirm that name is not already used by a container that must be preserved. Never point destructive tests at the live beta database.
- Re-run the existing detection and governance suites after any release-critical code changes. Do not remove test cases, weaken assertions, suppress skipped-test reporting, or replace mandatory jobs with documentation.

## 2. Repository and Git history secret hygiene

Run from the actual checkout. Commands below list *paths* and statuses, not secret contents:

```powershell
git status --short
git ls-files deploy/proxy/certs
git ls-files | Select-String -Pattern '(^|/)(\.env(\.|$)|account\.conf$|http\.header$|.*\.(pem|key|p12|pfx)$)'
```

- Verify all local ACME artifacts are ignored, including `deploy/proxy/certs/account.conf`, `http.header`, `ca/`, and domain `*_ecc/` directories. Ignore rules do **not** remove already-tracked files or history.
- Run an approved **whole-history** secret scanner locally or in trusted CI before changing repository visibility. Review findings without pasting secret values into issues, logs, PRs, or chat. If a real credential is found, keep the repo private, revoke/rotate the affected credential using the documented coordinated workflow, and remediate history as appropriate before public access.
- Do not use `git add .` around local certificate or secret state. Do not run `docker compose config` without considering that resolved output may expose environment values.

## 3. Rotation and backend verification evidence

Record the operator-observed live coordinated rotation separately from full credential validation:

- Observed: Docker services remained available; backend dependencies, Watchtower, and heartbeat endpoints returned HTTP 200 after rotation.
- Still verify, without printing tokens: new authentication/session flow succeeds; old credentials are rejected where rotation is expected to invalidate them; service-to-service authentication continues; audit integrity and governed Heart/Watchtower decisions remain correct; detection evidence still reaches the canonical authority.
- `/health` is liveness and `/ready` is dependency readiness. HTTP 200 alone is **not** proof of secret propagation, complete audit correctness, or preserved detection coverage.
- No second rotation is required merely to repeat this evidence. Never run `--full-reset` on a live stateful beta.

## 4. Remaining acceptance and network limitations

- A previous broad local pytest run reported **1,338 passed, 1 failed, 123 skipped**. The single Compose test failure was addressed by PR #453 and its focused suite passed locally; the broad suite has **not** thereby become a verified zero-skip pass.
- Previous targeted suites reported **78 passed** (Sigma/authority/Heart) and **44 passed** (eBPF/agent sequence/anomaly/router telemetry). These are useful historical evidence, not a substitute for current-commit CI or the full acceptance inventory.
- Spectrum router restrictions prevented an external mobile-data/WAN verification. Local HTTPS `curl -k` checks do **not** validate certificate trust or public reachability. Never claim external TLS/ingress passed without testing from an authorized external network.
- Public visibility of source code is separate from Internet exposure of a running instance. Keep the instance private until the runbook's external-access, TLS, authentication, and firewall gates pass.
- Before switching source visibility to public, independently verify repository history hygiene, required approvals, release commit CI, and the acceptance disposition. If any required gate is unresolved, keep visibility private and record the blocker rather than lowering the standard.

## Evidence record (fill with verified data only)

| Gate | Evidence / link | Result |
| --- | --- | --- |
| Release commit and human review | Pending | Unverified |
| Current commit required CI and zero-skip acceptance | Pending | Unverified |
| Detection/governance regression on release commit | Pending | Unverified |
| Whole-history secret scan and tracked-file review | Pending | Unverified |
| Live rotation: observed availability | Operator backend observations, Oct 9 2026 | Observed; credential propagation not verified |
| External WAN/TLS for running instance | Spectrum router blocked test | Not verified; separate from source publication |

Do not fill a pending result with PASS based on a plan, a missing workflow run, or a successful HTTP liveness response.
