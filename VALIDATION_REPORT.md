# Sentinel-43 — Validation Report

Exact commands and outcomes only.

## Phase 0 — reality and recovery points (2026-08-30)

| Command | Result |
|---|---|
| `git rev-parse HEAD` (before branching) | `4e281bc41566097899e0b5161d911e9a34aa9de7` — matched `origin/main` and the reviewed commit |
| `kubectl config get-contexts` | `docker-desktop` only — no production target |
| `git tag pre-beta-hardening-20260830 HEAD` | created |
| `git checkout -b release/beta-production-hardening origin/main` | succeeded |

## Phase 1 — audit

19/19 prior findings confirmed + 6 more (A1-A6) + 7 from a concurrent peer session's live probes (F-01..F-07). Full detail and evidence: `RELEASE_FINDINGS.md`.

## This session's fixes — validation

Recovered non-`deps.py` fixes from a git stash (`stash@{1}` at time of recovery — index shifted mid-session due to an unattributed `GitHub_Desktop` auto-stash, see notes below); redid the `deps.py` fix from scratch (not present in the stash).

| Command | Result |
|---|---|
| `python -m pytest core/tests/ -q` (after recovering stash files + redoing `deps.py`, before final commit split) | `105 passed, 4 skipped, 1 warning in 360.92s` |
| `python -m pytest core/tests/ -q` (re-run against final committed state, commits `5332d54`..`0eb4941`) | `105 passed, 4 skipped, 1 warning in 361.19s` — identical result, confirms the commit-splitting (reset+restage) didn't change file content |
| Live DB credential fix: `ALTER ROLE s43 WITH PASSWORD ...` then `curl :8000/bootstrap/status` | `200 {"initialized":true}` (was `500`/`InvalidPasswordError` before) |

No failures in either run. 4 skips are pre-existing/expected (not investigated further in this pass).

## Peer session (`sentinel-43-9d`, branch `pass1/watchtower-exposure`) — reported, not independently re-run by this session

- Full suite: `144 passed, 4 skipped` (per their report)
- Live-verified against the running Compose stack: host can no longer reach `:9100`; Watchtower operational/mutation routes require the service token (401 without, 200 with); `/health`+`/ready` stay open; API-bridge `/watchtower/modules` and `/watchtower/check` now require auth (were anonymous 200); Fenrir→Watchtower reporting path fixed and verified end-to-end.

This session did not re-run their suite directly — recorded as their claim, not this session's own verification. If merging both branches, re-run the full suite against the merged tree before treating both as jointly validated.

## Environment instability observed during this pass

Multiple background/foreground commands (a `git status --short`, at least one `pytest` background job) either hung past their normal duration or returned with substantially delayed completion notifications during this session, coincident with recurring unattributed file loss (planning docs vanishing from disk twice with no corresponding git or stash trail) and an unattributed branch-HEAD change in a peer session's working directory. Repo lives inside an actively-synced OneDrive folder; suspected but not confirmed root cause. Recommendation: pause OneDrive sync on this folder for the remainder of active work, and commit working documents immediately rather than leaving them untracked (adopted mid-session, see commit `e9dec5d` onward).

## Phases 2-13 outside this session's lane, Phases 14-16 — not attempted

See `RELEASE_HARDENING_PLAN.md` for phase-by-phase status. No production Docker host or Kubernetes context identified — Phase 14 blocked pending owner input, unchanged from earlier in this effort.
