# Sentinel-43 — Rollback Runbook

How to undo each stage of this hardening pass. Nothing here has been exercised end-to-end against a real production target (none exists yet — see `RELEASE_HARDENING_PLAN.md`'s Phase 14 blocker). What's below is verified for the local/Compose stage; the Kubernetes rollback commands are standard `kubectl` procedure, not yet live-tested against this repo's manifests in this pass.

## 1. Git — this session's commits

Nothing has been pushed or merged. To fully discard this session's work and return to the reviewed baseline:

```bash
git -C ../Sentinel-43-hardening-b8 checkout release/beta-production-hardening
git -C ../Sentinel-43-hardening-b8 reset --hard 4e281bc41566097899e0b5161d911e9a34aa9de7
```

Or, to keep the branch but abandon it entirely and return to the tagged baseline:

```bash
git checkout pre-beta-hardening-20260830
```

The tag `pre-beta-hardening-20260830` and `origin/main` both point at `4e281bc41566097899e0b5161d911e9a34aa9de7` — this is the recovery anchor for everything in this effort.

To undo one specific commit rather than the whole branch, `git revert <sha>` (not `reset`) so the undo itself is auditable:

| Commit | Fix | Revert command |
|---|---|---|
| `5332d54` | deps.py JWT bypass fix | `git revert 5332d54` |
| `3f65ca1` | firewall config mapping | `git revert 3f65ca1` |
| `6cf7e97` | last_login_at write fix | `git revert 6cf7e97` |
| `c7a7502` | non-root Dockerfile | `git revert c7a7502` |

Reverting `c7a7502` restores root execution — only do this if the non-root image breaks something unexpected, and treat it as a temporary measure, not a resolution.

## 2. Secrets

`.env` was rotated on 2026-08-30. Pre-rotation backup: `.env.bak.20260830100315` (also `.env.bak.20260810143708` from an earlier, now doubly-superseded rotation). To roll back the rotation:

```bash
cp .env.bak.20260830100315 .env
# Then reverse the live ALTER ROLE (this session set Postgres to the NEW password):
docker exec -e PGPASSWORD='<new-POSTGRES_PASSWORD-from-current-.env>' s43_postgres \
  psql -U s43 -d s43 -c "ALTER ROLE s43 WITH PASSWORD '<old-POSTGRES_PASSWORD-from-the-backup>';"
```

Do not do this without a concrete reason — the rotation and the DB sync were both deliberate, verified fixes, not experiments.

## 3. Docker Compose (local stack)

```bash
docker compose down
git checkout <baseline-commit-or-tag> -- core/api/Dockerfile docker-compose.yml
docker compose build --no-cache
docker compose up -d
```

Verified this session: `docker compose down` / `up -d` cycles cleanly against the current stack; `/health` and `/bootstrap/status` return 200 after a fresh `up`.

## 4. Kubernetes (untested rollback — no live cluster exercised this pass beyond ephemeral Kind smoke tests)

Standard procedure, not yet re-verified against this branch's manifests:

```bash
kubectl -n sentinel43 rollout undo deployment/s43-api
kubectl -n sentinel43 rollout undo deployment/s43-core
kubectl -n sentinel43 rollout status deployment/s43-api
```

For a Kind smoke-test cluster specifically, rollback is simply teardown:

```bash
kind delete cluster --name s43-test
```

## 5. What "rollback" does not cover

No production Docker host or Kubernetes context has been identified (Phase 14 blocker, unchanged). There is no production revision to roll back to, because nothing in this effort has been deployed to production. This runbook will need a production-specific section added before any real deployment proceeds — do not treat this document as production-rollback-ready.
