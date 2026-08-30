# Sentinel-43 — Beta Production Hardening Plan

**Read this file at the start of every phase.** It exists specifically so that context loss (compaction, session restart) does not cause drift from the original objective.

**Note on file survival:** earlier versions of this document (and its 3 siblings) were lost twice from disk with no corresponding git history — once via an unattributed `git stash`, once with no stash entry at all, in a repo that lives inside an actively-synced OneDrive folder. As of this revision, these documents are committed to git on every update, not left as untracked files, specifically to survive whatever is causing that.

## Non-negotiable invariant

> Deterministic. Advisory. Never Autonomous.

Confirmed as pre-existing, documented architecture (`README.md:13`), not newly imposed. No phase of this plan may give the core engine autonomous enforcement capability. Governance and explicit human approval remain mandatory for operational actions.

## Concurrent-session note

This effort ran as two parallel Claude sessions on the same repo: `sentinel-43-b8` (this one — auth/`deps.py`/firewall-config regression + shared docs) and `sentinel-43-9d` (Watchtower exposure/auth, an independently-numbered "Pass" structure). Both are recorded in `RELEASE_FINDINGS.md`. `sentinel-43-9d`'s branch is `pass1/watchtower-exposure`, complete and standing down as of this revision. This session's branch is `release/beta-production-hardening`, now in a **separate git worktree** (`../Sentinel-43-hardening-b8`) after discovering the two sessions were sharing one working directory's HEAD.

## Branch / recovery state

- Working branch: `release/beta-production-hardening` (worktree `../Sentinel-43-hardening-b8`), created from `origin/main` @ `4e281bc41566097899e0b5161d911e9a34aa9de7`
- Recovery tag: `pre-beta-hardening-20260830` → `4e281bc41566097899e0b5161d911e9a34aa9de7`
- Peer branch: `pass1/watchtower-exposure`, 5 commits, not pushed
- Neither branch has been pushed. No PR opened. Nothing merged to `main`.

## Phase status (this session's lane)

| Phase | Description | Status |
|---|---|---|
| 0 | Establish reality and recovery points | **Done** |
| 1 | Complete repository audit | **Substantially done** — see `RELEASE_FINDINGS.md` (19 confirmed + 6 more + 7 from peer's live probes) |
| 2 (Watchtower) | Owned by `sentinel-43-9d` | **Done on their branch** — 5 commits, 144 tests passing, live-verified; not merged |
| 3 (API auth redesign) | `deps.py` JWT role-bypass closed now; full plaintext-password-removal redesign (finding #10) NOT started | **Partially done** — see commit `5332d54` |
| 4 (Trusted-proxy/firewall) | Firewall config field-mapping fixed | **Done** — commit `3f65ca1` |
| 5 (Bootstrap race) | Not started | Not started |
| 6 (Info exposure) | Not started (this session's lane — API's own `/config/status`, `/docs`, compat aliases) | Not started |
| 7 (Docker hardening) | Non-root Dockerfile fix | **Partially done** — commit `c7a7502` (image only; Compose-side mkdir+chown note deferred to avoid colliding with peer's in-flight `docker-compose.yml` edit) |
| 8 (Kubernetes hardening) | Not started this session | Not started |
| 9 (Dependency/supply-chain) | Not started | Not started |
| 10 (CI release gates) | Not started | Not started |
| 11 (Cleanup) | Inventory only, no deletions | See `CLEANUP_INVENTORY.md` |
| 12 (Local validation) | Full suite run against final committed state | See `VALIDATION_REPORT.md` |
| 13 (Commit/PR structure) | 5 commits made on this branch, dependency-ordered | Done for this lane's scope |
| 14 (Production deployment prep) | **Blocked** | No production Docker/K8s target exists — only `docker-desktop` kube-context available |
| 15/16 (Deployment/acceptance) | Blocked (depends on 14) | Blocked |

## Commits on `release/beta-production-hardening` (this session)

1. `5332d54` `fix(auth): close /v1 JWT role-check bypass in deps.py`
2. `3f65ca1` `fix(firewall): map compat shim to real FirewallConfig fields`
3. `6cf7e97` `fix(auth): stop rewriting last_login_at on every password re-verification`
4. `c7a7502` `build(docker): run non-root with correct volume ownership`
5. `0eb4941` `test: recover auth/bootstrap regression coverage`

All validated: `python -m pytest core/tests/ -q` → see `VALIDATION_REPORT.md` for exact counts.

## Phase 14 blocker (unchanged)

Only kube-context available on this machine is `docker-desktop` (local single-node dev cluster). No production Docker host or Kubernetes context identified anywhere in the repo or environment. **Phases 14-16 do not proceed without the owner explicitly naming a real production target.**

## Required documents

- `RELEASE_HARDENING_PLAN.md` — this file
- `RELEASE_FINDINGS.md` — audit findings, confirm/refute of prior review, both sessions' work merged
- `CLEANUP_INVENTORY.md` — obsolete-artifact inventory before any deletion
- `VALIDATION_REPORT.md` — exact commands run and their exit status
- `DEPLOYMENT_RUNBOOK.md` — what deployment procedure actually exists and is tested today
- `ROLLBACK_RUNBOOK.md` — how to undo each stage of this work

None of these documents assert compliance or certification.
