# Sentinel-43 — Kubernetes Deployment (public-beta)

This is a **public-beta deployment**, not a production-certified one. It
adds Kubernetes as an *additional* deployment path alongside
`docker-compose.yml` — Compose remains the documented default for local
development and is unaffected except for one shared, security-motivated fix
(see "Relationship to Docker Compose" below).

## Prerequisites

| Requirement | Notes |
|---|---|
| Kubernetes | 1.28–1.32 tested (kind's `kindest/node:v1.32.2`; kubeconform validated against 1.30.0 schemas). Older/newer 1.2x versions are likely fine but untested here. |
| A **NetworkPolicy-enforcing CNI** | Required — Postgres/Redis isolation and the whole default-deny posture depend on it. Calico, Cilium, and most managed-cloud CNIs (EKS with the AWS VPC CNI + Calico, GKE's native NetworkPolicy support, AKS with Azure CNI + Calico/Cilium) enforce it. **kind's default CNI (kindnet) and some minimal setups do not** — verify with a real negative test (see "Verifying NetworkPolicy enforcement" below), don't trust `kubectl get networkpolicy` returning objects as proof they're doing anything. |
| Ingress controller (beta overlay only) | ingress-nginx, installed in a namespace literally named `ingress-nginx` (the default for standard install methods). Different namespace name → edit `overlays/beta/networkpolicy-ingress.yaml`'s `namespaceSelector`. |
| cert-manager (beta overlay only) | For the `cert-manager.io/cluster-issuer: letsencrypt-prod` annotation in `overlays/beta/ingress.yaml` to do anything — install it and create that ClusterIssuer (or change the annotation) before applying. |
| A container registry (beta overlay only) | Not provided by this repo. `overlays/beta/kustomization.yaml`'s image digest is a deliberately-invalid placeholder — CI (`.github/workflows/k8s.yml`) is set up to build the image, but pushing to a real registry and pinning the resulting digest is an operator decision (GHCR, ECR, GCR, etc.). |
| `kubectl` + `kustomize` (or `kubectl kustomize`) | `kubectl kustomize` (bundled) is enough to render; the standalone `kustomize` CLI is only needed for `kustomize edit set image` when wiring in a real registry digest. |

## Directory layout

```
deploy/kubernetes/
  base/                    # every security control lives here — shared by every overlay
  overlays/dev/            # local dev on kind/Docker Desktop: locally-built image, no ingress
  overlays/beta/           # ingress+TLS, 2 API replicas + PodDisruptionBudget, registry image
  kind-cluster-config.yaml # disposable test-cluster config (Calico, not kindnet — see below)
```

Nothing under `deploy/kubernetes/` is applied automatically by anything —
every `kubectl apply -k ...` below is explicit and operator-initiated.

## Secret provisioning

`base/secret.example.yaml` documents every key `sentinel43-secrets` needs —
**it is a template only, not in any `kustomization.yaml`'s resources, and
must never be applied as-is** (every value is a `CHANGEME_...` placeholder,
not a usable credential).

Real secrets are created directly with `kubectl`, generated the same way
`docker-compose.yml`'s setup does, and never written to a YAML file on disk:

```bash
# from a populated .env (see .env.example / scripts/generate_secrets.py)
set -a; source .env; set +a
kubectl create namespace sentinel43 --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic sentinel43-secrets -n sentinel43 \
  --from-literal=POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  --from-literal=REDIS_PASSWORD="$REDIS_PASSWORD" \
  --from-literal=DATABASE_URL="postgresql+asyncpg://s43:${POSTGRES_PASSWORD}@s43-db:5432/s43" \
  --from-literal=REDIS_URL="redis://:${REDIS_PASSWORD}@s43-redis:6379/0" \
  --from-literal=S43_JWT_SECRET="$S43_JWT_SECRET" \
  --from-literal=S43_OPERATOR_PASSWORD_HASH="$S43_OPERATOR_PASSWORD_HASH" \
  --from-literal=S43_AUTH_PEPPER="$S43_AUTH_PEPPER" \
  --from-literal=SENTINEL_LOG_SALT="$SENTINEL_LOG_SALT" \
  --from-literal=SENTINEL_REMOTE_TOKEN_OWNER="$SENTINEL_REMOTE_TOKEN_OWNER" \
  --from-literal=SENTINEL_REMOTE_TOKEN_ADMIN="$SENTINEL_REMOTE_TOKEN_ADMIN" \
  --from-literal=SENTINEL_REMOTE_TOKEN_AUDITOR="$SENTINEL_REMOTE_TOKEN_AUDITOR" \
  --from-literal=S43_FENRIR_API_TOKEN="$S43_FENRIR_API_TOKEN"
```

**Secrets-at-rest**: whether this Secret is encrypted at rest in etcd
depends entirely on the cluster, not on anything in this repo — Kubernetes
does not encrypt Secrets by default. Enable
[encryption at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
(an `EncryptionConfiguration` on the API server, or your managed provider's
equivalent — e.g. EKS/GKE/AKS all offer this) before storing real
production secrets. **This is an operator/cluster requirement outside this
repo's control**, not something a manifest can turn on.

**Fail-closed, proven, not assumed**: `core/api/main.py`'s
`_validate_security_config()` refuses to start with an unconfigured
`S43_JWT_SECRET` (or several other required values) — this was directly
exercised in integration testing (see below): a pod started with an empty
`S43_JWT_SECRET` crash-loops with `RuntimeError: S43_WS_REQUIRE_AUTH=true
but S43_JWT_SECRET is not configured` rather than serving traffic
insecurely, and a pod started with the Secret missing entirely never gets
past `CreateContainerConfigError` (Kubernetes' own `envFrom` resolution
fails before the container ever execs).

## Deploy

```bash
# Dev (local kind/Docker Desktop cluster, no registry needed):
docker build -t sentinel43-api:dev -f core/api/Dockerfile .
kind load docker-image sentinel43-api:dev --name <your-cluster>   # skip if using Docker Desktop's cluster
kubectl apply -k deploy/kubernetes/overlays/dev

# Beta (real cluster, after: pushing a pinned image digest into
# overlays/beta/kustomization.yaml, setting overlays/beta/ingress.yaml's
# real hostname, and overlays/beta/configmap-patch.yaml's real
# S43_TRUSTED_PROXIES CIDR):
kubectl apply -k deploy/kubernetes/overlays/beta
```

## Migration process

There is no Alembic (or other) migration system in this repo — schema
creation is `core/auth/users.py`'s `init_models()`
(`SQLAlchemy Base.metadata.create_all()`, idempotent). `base/migration-job.yaml`
wraps that exact function in a single-execution `Job` instead of inventing a
new migration system. **Apply it and wait for `Complete` before the API
Deployment is expected to serve real traffic on a fresh database** — both
`kubectl apply -k` commands above already include it (it's part of `base/`),
but on a fresh cluster you may want to gate it explicitly:

```bash
kubectl apply -k deploy/kubernetes/overlays/dev  # or overlays/beta
kubectl wait --for=condition=Complete job/s43-migration -n sentinel43 --timeout=120s
```

**Observed in integration testing**: the migration Job can fail its first
1-2 attempts with `socket.gaierror: Temporary failure in name resolution`
in the few seconds right after pod creation, self-healing via its
`backoffLimit: 3` on retry. This appears to be a NetworkPolicy-programming
race in Calico (the policy hasn't finished being applied to the pod's
network namespace yet) rather than a DNS or database problem — the
long-running Deployments (api/core) didn't exhibit it, only the Job, which
makes its very first move a database connection attempt with no
in-process retry of its own. The Job's `Complete` condition is what
actually matters and was reached every test run.

## Health verification

```bash
kubectl get pods -n sentinel43
kubectl -n sentinel43 port-forward svc/s43-api 8000:8000
curl http://localhost:8000/health
curl http://localhost:8000/bootstrap/status
```

## Logs and diagnostics

```bash
kubectl logs -n sentinel43 deployment/s43-api
kubectl logs -n sentinel43 deployment/s43-core
kubectl logs -n sentinel43 job/s43-migration
kubectl describe pod -n sentinel43 -l app=s43-api   # events, probe failures
```

## Scaling

Only `s43-api` is designed to run >1 replica (stateless, behind its
Service). `overlays/beta/resources-patch.yaml` sets `replicas: 2` with a
`PodDisruptionBudget` (`minAvailable: 1`) and a soft pod-anti-affinity
preference to spread replicas across nodes. Scale further with:

```bash
kubectl scale deployment/s43-api -n sentinel43 --replicas=4
```

`s43-core`, `s43-db`, and `s43-redis` are single-replica everywhere in this
repo — see "Known limitations" below for why scaling `s43-db`/`s43-redis`
isn't as simple as changing a replica count.

## Backup / restore

Postgres and Redis here are **single-instance StatefulSets with PVCs, not a
managed or HA database** — see "Known limitations." There is no automated
backup CronJob in this repo (it would need an operator-specific object
storage target — S3 bucket, GCS, etc. — that this repo has no way to know
in advance). Manual procedure:

```bash
# Backup
kubectl exec -n sentinel43 s43-db-0 -- pg_dump -U s43 s43 > s43-backup-$(date +%Y%m%d).sql

# Restore (to a fresh/empty database)
kubectl exec -i -n sentinel43 s43-db-0 -- psql -U s43 s43 < s43-backup-YYYYMMDD.sql
```

For Redis (only relevant if you rely on cached state — see "Known
limitations," nothing in `core/` currently uses Redis):

```bash
kubectl exec -n sentinel43 s43-redis-0 -- redis-cli -a "$REDIS_PASSWORD" --rdb /data/dump.rdb
kubectl cp sentinel43/s43-redis-0:/data/dump.rdb ./s43-redis-backup-$(date +%Y%m%d).rdb
```

For real production use, put a proper backup/restore process (pgBackRest,
WAL-G, a managed database's native backups) in front of this — the above is
a manual break-glass procedure, not a backup strategy.

## Upgrade / rollback

Standard Kubernetes rolling update — `s43-api` and `s43-core` use
`maxUnavailable: 0, maxSurge: 1` so a bad rollout never takes down the
currently-serving replica while the new one is starting. **Proven in
integration testing**: deploying a nonexistent image tag left the new pod
stuck in `ErrImageNeverPull`/`ImagePullBackOff` while the old pod kept
serving `/health` successfully throughout; `kubectl rollout undo` recovered
cleanly.

```bash
kubectl rollout status deployment/s43-api -n sentinel43
kubectl rollout undo deployment/s43-api -n sentinel43
```

`s43-db`/`s43-redis` are StatefulSets — upgrading their image version
follows standard Postgres/Redis major-version upgrade caveats (not
Kubernetes-specific); this repo doesn't attempt to automate that.

## Complete removal

```bash
kubectl delete -k deploy/kubernetes/overlays/dev    # or overlays/beta
kubectl delete namespace sentinel43                 # also deletes PVCs — irreversible, confirm backups first
```

## Verifying NetworkPolicy enforcement

Don't trust `kubectl get networkpolicy` returning objects as proof anything
is enforced — some CNIs (kindnet, some minimal installs) accept
NetworkPolicy objects without acting on them. Verify with a real negative
test, PSS-compliant so it isn't rejected outright by the namespace's
`restricted` enforcement label:

```bash
kubectl run netpol-test -n sentinel43 --image=busybox:1.36 --restart=Never \
  --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":65532,"runAsGroup":65532,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"netpol-test","image":"busybox:1.36","command":["sleep","3600"],"securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"privileged":false,"capabilities":{"drop":["ALL"]},"seccompProfile":{"type":"RuntimeDefault"}}}]}}' \
  --command -- sleep 3600
kubectl exec -n sentinel43 netpol-test -- timeout 5 nc -zv s43-db 5432    # must hang/fail
kubectl exec -n sentinel43 netpol-test -- timeout 5 nc -zv s43-redis 6379 # must hang/fail
kubectl delete pod netpol-test -n sentinel43
```

This exact sequence was run against a kind cluster with Calico installed
during development (see "Integration testing evidence" below) — all three
connections hung until the 5s timeout killed them (exit 143), confirming
real enforcement, not just object presence.

## Relationship to Docker Compose

- `core/api/Dockerfile` now runs as a fixed non-root UID/GID (65532) — this
  is the one change shared with Compose, made because Kubernetes' PSS
  `restricted` profile requires it and there's no way to satisfy that only
  for k8s without maintaining two Dockerfiles. Verified not to break Compose
  (rebuilt, ran the full stack, confirmed `/app/logs`'s bind mount and
  `/tmp` are writable as the new non-root user; nothing in the live app
  writes to `/app/sentinel43_state` today — see "Known limitations").
- `core/middleware/sentinel_firewall.py`'s trusted-proxy fix (see
  `docs/security/trusted_proxy_handling.md`) also applies to Compose —
  behavior is unchanged for anyone not setting `S43_TRUSTED_PROXIES`
  (nobody currently does, since it was silently broken before).
- Everything else here is additive. `docker-compose.yml` is untouched and
  remains the documented default for local development.

## Known limitations

- **The firewall's rate limiter is in-process, not Redis-backed.**
  `sentinel_firewall_middleware.py`'s rate limiting is per-pod in-memory
  state. `overlays/beta` runs 2 `s43-api` replicas — rate limits are
  therefore enforced *per replica*, not globally (a client could get up to
  2x the configured limit by landing on both pods). This is a real
  application-level gap, not something this Kubernetes deployment
  introduces or silently works around; fixing it means making the rate
  limiter Redis-backed, which is an application change outside this task's
  scope.
- **Neither `/health`/`/ready` (api) nor `/watchtower/health` (core) verify
  Postgres/Redis connectivity.** `core/api/main.py`'s `dependencies_status()`
  hardcodes both as `"unknown"`. Readiness in this deployment therefore
  means "the process is serving HTTP," not "this pod can currently reach
  the database" — a pre-existing app-level gap, documented rather than
  silently expanded in scope by this deployment.
- **`/watchtower/ready` is intentionally NOT used for any probe on
  `s43-core`**, despite the name suggesting it's the obvious readiness
  check. It measures whether every *other* registered module/dependency
  (e.g. `s43-api`) is actively heartbeating within a staleness window — a
  system-wide convergence signal, not "is this pod healthy." Using it for
  `s43-core`'s own readinessProbe was tried during development and directly
  observed to cause a circular-coupling failure (core reports NotReady
  whenever a client is unhealthy or still starting) — see
  `base/s43-core-deployment.yaml`'s comment for the full explanation. All
  three probes on `s43-core` use `/watchtower/health` instead, which only
  reflects the node's own local state.
- **Postgres and Redis are single-instance StatefulSets, not a managed or
  HA database.** No replication, no automatic failover, no automated
  backups. Real production/public-beta-at-scale use should sit behind a
  managed database service (RDS, Cloud SQL, managed Redis, etc.) or a
  proper HA operator (CloudNativePG, Zalando's postgres-operator, Redis
  Sentinel/Cluster) — this repo's manifests are a functional starting
  point, not a substitute for that.
- **Nothing in `core/` currently connects to Redis.** `REDIS_URL` is wired
  through as config (matching `docker-compose.yml`) but grep confirms no
  live import of a Redis client anywhere in `core/`. It's provisioned for
  parity and forward-compatibility, not because the app depends on it
  today.
- **`/docs`, `/redoc`, `/openapi.json` are public and unauthenticated**
  (FastAPI defaults) on whatever this Ingress exposes — already flagged as
  an open decision in `docs/security/endpoint_access_matrix.md` (finding
  #5) pending the app owner's call; this deployment doesn't resolve it
  either way (see `overlays/beta/ingress.yaml`'s comment).
- **`S43_TRUSTED_PROXIES` ships as an unfillable placeholder in the beta
  overlay** (pod CIDRs vary per cluster/CNI and can't be guessed
  generically) — see `overlays/beta/configmap-patch.yaml`. Left unset, XFF
  is simply never trusted (fail-safe), but the firewall/audit trail will
  attribute every request to the ingress controller's IP until it's set
  correctly for your cluster.
- **CI's Docker Scout step runs unauthenticated** (no `DOCKERHUB_*` repo
  secrets configured) and is `continue-on-error: true` as a result — it
  still reports what it can, but adding real Docker Hub credentials as
  repo secrets (an operator decision) would give it full policy evaluation
  instead of just local CVE listing.
- **The CI workflow's syntax was validated but not executed against a real
  GitHub Actions runner** in this pass (no `act` or equivalent available
  locally) — the equivalent steps were run manually against a local kind
  cluster instead (see "Integration testing evidence"), which is the same
  underlying command sequence the workflow automates.

## Integration testing evidence

Run manually against a disposable `kind` cluster (Calico CNI) during
development of this deployment — not against Docker Desktop's persistent
cluster, and torn down unconditionally afterward:

- Full stack (`s43-db`, `s43-redis`, `s43-core`, `s43-api`) reached `Ready`
  under the `restricted` Pod Security Standard.
- `id` inside every pod confirmed non-root (`65532` for api/core, `999` for
  postgres/redis — their images' own baked-in non-root users).
- `readOnlyRootFilesystem: true` confirmed: writes to `/app` failed with
  `Read-only file system`; `/tmp` writes succeeded.
- Full bootstrap → login → JWT+password-protected route flow worked
  end-to-end through the real Service/Ingress-equivalent network path
  (`kubectl port-forward`), including a correct `401` with no credentials.
- Deleted the Postgres pod mid-test; it rescheduled onto the same PVC and
  the previously-created admin account was still present
  (`/bootstrap/status` still reported `initialized: true`).
- An unauthorized pod (correct PSS-compliant security context, but missing
  the `network/s43-*-client` labels) could not reach Postgres, Redis, or
  the API — all three connection attempts hung until timeout (blocked, not
  refused).
- A pod attempting to run without a compliant `securityContext` was
  rejected outright by the namespace's Pod Security admission
  (`restricted`) before Kubernetes even tried to schedule it.
- Deploying a nonexistent image tag left the bad replica stuck
  (`ErrImageNeverPull`) while the good replica kept serving `/health`
  throughout (zero downtime); `kubectl rollout undo` recovered cleanly.
- Deleting `sentinel43-secrets` entirely and restarting `s43-api` produced
  `CreateContainerConfigError` (Kubernetes-level fail-closed) — the old
  replica kept serving.
- Recreating the Secret with an **empty** `S43_JWT_SECRET` (present but
  invalid, not missing) produced `CrashLoopBackOff` with the app's own
  `RuntimeError: S43_WS_REQUIRE_AUTH=true but S43_JWT_SECRET is not
  configured` (app-level fail-closed) — the old replica kept serving.
- The `s43-core` readiness-probe issue described in "Known limitations"
  was found and fixed during this exact testing process.
