# Sentinel-43 — Deployment Runbook

What deployment procedure actually exists and is tested today. No production target has been identified — see "Phase 14 blocker" below before reading this as a production procedure.

## Phase 14 blocker (repeated from `RELEASE_HARDENING_PLAN.md`)

`kubectl config get-contexts` on this machine returns exactly one context: `docker-desktop` (Docker Desktop's bundled local single-node cluster). No production or staging kube-context, no production Docker host reference, exists anywhere in this repo or environment. Per this effort's own governing instructions: *"If the configured target is ambiguous, missing... stop and request clarification."* **This runbook covers local Compose and ephemeral Kind only. Production deployment does not proceed until the owner names a real target.**

## Local Docker Compose (verified this session)

```bash
git checkout release/beta-production-hardening   # or whichever branch has the fixes you want
docker compose build --no-cache
docker compose up -d
docker compose ps                                 # all services should report healthy
curl -fsS http://localhost:8000/health
curl -fsS http://localhost:8000/bootstrap/status
```

Required `.env` variables: see `docker-compose.yml`'s header comment, or run `python core/cli/generate_secrets.py --write .env` (missing keys only) / `--force` (rotate everything) to populate them. After any `POSTGRES_PASSWORD` rotation, if the `s43_pgdata` volume already exists, you must additionally sync the live role:

```bash
docker exec -e PGPASSWORD='<old-password>' s43_postgres \
  psql -U s43 -d s43 -c "ALTER ROLE s43 WITH PASSWORD '<new-password>';"
```

(Verified working in this session — the generator's own `_warn_stale_database_url` tells you to do exactly this.)

## Ephemeral Kind (verified this session, for CI/local validation only — not a production target)

```bash
kind create cluster --config deploy/kubernetes/kind-cluster-config.yaml --wait 120s
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.29.1/manifests/tigera-operator.yaml
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.29.1/manifests/custom-resources.yaml
kubectl -n calico-system wait --for=condition=Ready pods --all --timeout=180s
docker build -t sentinel43-api:ci -f core/api/Dockerfile .
kind load docker-image sentinel43-api:ci --name <cluster-name>
kubectl apply -k deploy/kubernetes/overlays/dev
kubectl -n sentinel43 wait --for=condition=Ready pod -l app=s43-db --timeout=180s
kubectl -n sentinel43 rollout status deployment/s43-api --timeout=180s
kind delete cluster --name <cluster-name>
```

This full sequence was run successfully in an earlier session on this branch's ancestor, including security assertions (`id -u` = 65532, read-only-rootfs write correctly rejected) and the `/health`/`/bootstrap/status` smoke test. It has not been re-run against the exact commits in `release/beta-production-hardening` in this pass — see `VALIDATION_REPORT.md` for what was actually re-verified here.

## Staging / production

Not applicable — no target exists. When one is identified, this section needs, at minimum: exact Docker host or Kubernetes context/cluster/namespace, current deployed image digest, existing ingress/DNS, backup location, and secret source, gathered per Phase 14's checklist before any deploy command is run.
