# Sentinel-43 — Cleanup Inventory

Populated before any deletion, per Phase 11 rules. No deletions have been performed in this pass.

## Remote branches

- **244** remote branches match `origin/Koklar21-patch-*` (GitHub web "edit this file" per-commit branch pattern).
- Merge status against `origin/main`: **1 merged** (`Koklar21-patch-1`), **243 not merged**.
- `origin/pass1/watchtower-exposure` also exists on the remote, pointing at `4e281bc` (identical to `main`), dated 2026-08-16 — predates both of today's sessions by two weeks. Not attributable to either session (verified via reflog: `update by push`, shared across worktrees, and the commit date itself). Worth asking the repo owner directly what this was.

| Item | Tracked | Decision | Reason | Recovery |
|---|---|---|---|---|
| `origin/Koklar21-patch-1` | remote branch | **Candidate for deletion** | Fully merged into `origin/main`, adds no unique history | Record tip SHA before deleting |
| `origin/Koklar21-patch-2` … `-996447` (243 branches) | remote branch | **NOT deleted — retain pending triage** | Not merged; deletion rules forbid removing an unmerged branch. Likely root cause of the Aug-30 regression this pass fixed — a merge from one of these plausibly overwrote local uncommitted work before it existed as a documented stash. | N/A |
| `origin/pass1/watchtower-exposure` (pre-existing, Aug 16) | remote branch | **Do not touch** | Unknown provenance, predates this effort | Ask repo owner |

## Local generated artifacts

| Path | Tracked | Reason obsolete | Decision |
|---|---|---|---|
| `.pytest_cache/`, `__pycache__/` | untracked, gitignored | Regenerate automatically | Safe to delete anytime; not deleted |
| `.env.bak.20260810143708` | untracked | Superseded by two rotations since | Retain — no destructive action on secret-bearing files without separate explicit confirmation |
| `.env.bak.20260830100315` | untracked | Active rollback point for the current `.env` (contains the password needed to reverse the Aug 30 rotation) | **Retain — do not delete** |
| `.env.old` | untracked | Skeleton/early-format env file, 2026-06-13 | Low-risk deletion candidate; not deleted without explicit confirmation |

## Tracked source-tree oddities

| Item | Tracked | Reason obsolete | Decision |
|---|---|---|---|
| `core/monitoring/Sentinel_firewall .py` (trailing space in filename) | tracked | 1061 lines of pre-relocation firewall code, unreferenced by any import (`git log`: last touched `d97df19`, "Upgrade SentinelFirewall to v1.2.0") | **Recommend delete**, fully recoverable via `git show d97df19:"core/monitoring/Sentinel_firewall .py"` — not deleted in this pass pending confirmation |
| `docker-compose.yml`'s `s43-setup.entrypoint: scripts/generate_secrets.py` | tracked | References a nonexistent path; real file is `core/scripts/generate_secrets.py` | Defect, not a cleanup item — tracked as a fix, not deletion |
| `docs/security/trusted_proxy_handling.md` | **restored** in commit `3f65ca1` | Was deleted from `main` (`f3baa57`); recovered from the stash and recommitted as part of the firewall fix | Resolved — no longer a cleanup item |

## Docker/session state (as of this pass)

- Live Compose stack running: `s43_api`, `s43_core`, `s43_postgres`, `s43_redis` — all healthy after the DB credential-drift fix (`ALTER ROLE s43 WITH PASSWORD ...`, applied and verified against the live API in this session).
- `.tools/kind.exe`, `.tools/kubeconform.exe` — retained, actively used, gitignored.

## Deletions actually performed in this pass

**None.**
