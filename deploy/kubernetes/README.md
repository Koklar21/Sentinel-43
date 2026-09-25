# Sentinel-43 — Kubernetes Deployment (public-beta)

This is a **public-beta deployment**, not a production-certified one. It
adds Kubernetes as an *additional* deployment path alongside
`docker-compose.yml` — Compose remains the documented default for local
development and is unaffected except for one shared, security-motivated fix
(see "Relationship to Docker Compose" below).

**For the full controlled-beta procedure** (secrets, session-only auth,
image/digest pinning, migrations, backup/restore, TLS, NetworkPolicy
verification, evidence to retain, and what beta evidence does and does not
establish) **see [`docs/BETA_RUNBOOK.md`](../../docs/BETA_RUNBOOK.md)** —
this file covers the Kubernetes-specific manifests and prerequisites only.

## Prerequisites

| Requirement | Notes |
|---|---|
| Kubernetes | 1.28–1.32 tested (kind's `kindest/node:v1.32.2`; kubeconform validated against 1.30.0 schemas). Older/newer 1.2x versions are likely fine but untested here. |
| A **NetworkPolicy-enforcing CNI** | Required — Postgres isolation and the whole default-deny posture depend on it. Calico, Cilium, and most managed-cloud CNIs (EKS with the AWS VPC CNI + Calico, GKE's native NetworkPolicy support, AKS with Azure CNI + Calico/Cilium) enforce it. **kind's default CNI (kindnet) and some minimal setups do not** — verify with a real negative test (see "Verifying NetworkPolicy enforcement" below), don't trust `kubectl get networkpolicy` returning objects as proof they're doing anything. |
| Ingress controller (beta overlay only) | ingress-nginx, installed in a namespace literally named `ingress-nginx` (the default for standard install methods). Different namespace name → edit `overlays/beta/networkpolicy-ingress.yaml`'s `namespaceSelector`. |
| cert-manager (beta overlay only) | For the `cert-manager.io/cluster-issuer: letsencrypt-prod` annotation in `overlays/beta/ingress.yaml` to do anything — install it and create that ClusterIssuer (or change the annotation) before applying. |
| A container registry (beta overlay only) | Not provided by this repo. `overlays/beta/kustomization.yaml`'s image digest is a deliberately-invalid placeholder — CI (`.github/workflows/k8s.yml`) is set up to build the image, but pushing to a real registry and pinning the resulting digest is an operator decision (GHCR, ECR, GCR, etc.). |
| `kubectl` + `kustomize` (or `kubectl kustomize`) | `kubectl kustomize` (bundled) is enough to render; the standalone `kustomize` CLI is only needed for `kustomize edit set image` when wiring in a real registry digest. |

## Directory layout

```
deploy/kubernetes/
  base/                    # every security control lives here — shared by every overlay
  overlays/dev/            # local dev on kind/Docker Desktop: locally-built image, no ingress
  overlays/beta/           # ingress+TLS, beta resource sizing, registry image
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
  --from-literal=DATABASE_URL="postgresql+asyncpg://s43:${POSTGRES_PASSWORD}@s43-db:5432/s43" \
  --from-literal=S43_JWT_SECRET="$S43_JWT_SECRET" \
  --from-literal=S43_OPERATOR_PASSWORD_HASH="$S43_OPERATOR_PASSWORD_HASH" \
  --from-literal=S43_AUTH_PEPPER="$S43_AUTH_PEPPER" \
  --from-literal=S43_SESSION_HASH_PEPPER="$S43_SESSION_HASH_PEPPER" \
  --from-literal=S43_AUDIT_HMAC_KEY="$S43_AUDIT_HMAC_KEY" \
  --from-literal=S43_FENRIR_API_TOKEN="$S43_FENRIR_API_TOKEN" \
  --from-literal=S43_WATCHTOWER_SERVICE_TOKEN="$S43_WATCHTOWER_SERVICE_TOKEN"
```

Those nine are the **required** keys — they are exactly the non-optional
keys in `base/secret.example.yaml`, and the API or Watchtower fails closed
without each of them. Two were missing from this command until the
Kubernetes parity pass and are not optional:

| Key | What breaks without it |
| --- | --- |
| `S43_AUDIT_HMAC_KEY` | the authoritative HMAC-chained audit ledger has no key |
| `S43_SESSION_HASH_PEPPER` | the canonical session verifier has no pepper |

Add these **only if you are using the feature they belong to**. Each one is
absent-means-disabled, and each fails closed rather than degrading:

```bash
  # Watchtower administrative routes (s43-core). NOT the service token:
  # that authenticates s43-api as a machine, this authorizes an admin
  # action. Unset => those routes answer 503.
  --from-literal=S43_ADMIN_TOKEN="$S43_ADMIN_TOKEN" \
  # Remote operator gateway (core/api/routers/remote_gateway.py). Each role
  # is independent; an unset role is simply not issued.
  --from-literal=SENTINEL_REMOTE_TOKEN_OWNER="$SENTINEL_REMOTE_TOKEN_OWNER" \
  --from-literal=SENTINEL_REMOTE_TOKEN_ADMIN="$SENTINEL_REMOTE_TOKEN_ADMIN" \
  --from-literal=SENTINEL_REMOTE_TOKEN_AUDITOR="$SENTINEL_REMOTE_TOKEN_AUDITOR" \
  # Only with S43_SPARTA_ENABLED="true" in the ConfigMap. Two distinct
  # credentials; generate them independently.
  --from-literal=S43_SPARTA_NODE_TOKEN="$S43_SPARTA_NODE_TOKEN" \
  --from-literal=S43_SPARTA_TOKEN_SECRET="$S43_SPARTA_TOKEN_SECRET"
```

`REDIS_PASSWORD` / `REDIS_URL` are **no longer provisioned** — there is no
Redis in this deployment (see "No Redis" below). `SENTINEL_LOG_SALT` is not
provisioned either: `core/cli/generate_secrets.py` still generates both, but
no module outside that generator reads either one.

`S43_WATCHTOWER_SERVICE_TOKEN` is read by both `s43-api` and `s43-core` (both
`envFrom` this Secret). The Watchtower core rejects every operational and
mutation route without it and fails closed with 503 if it is unset —
`/watchtower/health` and `/watchtower/ready` (the probe targets) stay open.
It is defence-in-depth alongside `networkpolicy-core.yaml`, which already
restricts `:9100` ingress to `s43-api` only.

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

**Alembic is Sentinel-43's authoritative production schema mechanism**
(`MIGRATION_ARCHITECTURE_PASS5AM.md`). `base/migration-job.yaml` is the single
migration actor: one pod runs `alembic upgrade head`. **Apply it and wait for
`Complete` before the API Deployment is expected to serve real traffic** —
both `kubectl apply -k` commands above already include it (it's part of
`base/`), but you should gate it explicitly on a fresh cluster:

```bash
kubectl apply -k deploy/kubernetes/overlays/dev  # or overlays/beta
kubectl wait --for=condition=Complete job/s43-migration -n sentinel43 --timeout=120s
```

The API pods also refuse traffic on their own until the schema matches: each
`s43-api` pod's **readiness** probe (`GET /ready`) returns `503` while
`alembic_version` is behind / ahead / missing, so a `RollingUpdate` will not
send requests to a replica that is pointed at an un-migrated database (see
`core/auth/schema_version.py`). Liveness (`GET /health`) is unaffected — a
schema mismatch never restarts a pod.

### Fresh vs existing database

| Situation | What to run |
|---|---|
| **Fresh** database (new PVC) | Nothing extra — the Job's `alembic upgrade head` runs `0001_baseline` (creates `users`) then `0002_sessions`. |
| **Existing pre-Alembic** database (a `users` table created by the old `init_models()`/`create_all` path, no `alembic_version`) | Adopt it once, then let the Job run: `kubectl run s43-stamp --rm -it -n sentinel43 --image=<same image> --restart=Never --overrides='{...same securityContext + envFrom the Job uses...}' --command -- alembic stamp 0001_baseline`. `env.py` runs `migrations/baseline.py`'s **semantic** compatibility check first and refuses (exit 1) on any incompatible column/type/nullability/uniqueness — it never blindly stamps. |
| **Incompatible** schema | `alembic` exits non-zero, the Job fails its `backoffLimit`, and you do not proceed to the API Deployment. The failure message names the drifting columns only — no row data, no credentials, no connection string. |

`alembic downgrade` is **never** run automatically. `0001_baseline` has no
supported downgrade (it would drop `users`); `0002_sessions` downgrade drops
`sessions` and **destroys all active session state** — a deliberate manual
`kubectl exec` step, not part of any rollout.

**Observed in earlier integration testing** (still applies to the Job's very
first database contact): the migration Job can fail its first 1-2 attempts
with `socket.gaierror: Temporary failure in name resolution` in the few
seconds right after pod creation, self-healing via its `backoffLimit: 3` on
retry — a NetworkPolicy-programming race in Calico, not a DNS or database
problem. The Job's `Complete` condition is what matters and was reached every
run.

## Health verification

```bash
kubectl get pods -n sentinel43
kubectl -n sentinel43 port-forward svc/s43-api 8000:8000
curl http://localhost:8000/health
curl http://localhost:8000/bootstrap/status
```

`"initialized": false` means no administrator has been claimed yet. Claim
one at once with `docs/BETA_RUNBOOK.md` §16a. Never put the password on a
command line.

## Logs and diagnostics

```bash
kubectl logs -n sentinel43 deployment/s43-api
kubectl logs -n sentinel43 deployment/s43-core
kubectl logs -n sentinel43 job/s43-migration
kubectl describe pod -n sentinel43 -l app=s43-api   # events, probe failures
```

## Scaling

**Every workload here runs exactly one replica, `s43-api` included.** Do not
scale `s43-api` out. This is a property of the application, not a
conservative default, and the manifests enforce it: `replicas: 1` plus
`strategy: Recreate`, so a rollout never overlaps two API pods either.

`s43-api` holds four pieces of state that exist per process and are not
shared between pods:

| State | Where | What a second replica does |
| --- | --- | --- |
| Idempotency ledger | `core/reliability.py` (in-process `OrderedDict`) | each replica has its own; the same `event_id` is processed twice |
| `FenrirHunter` | started per API process | N replicas produce N copies of every finding |
| Sparta watchdog task | started per API process | N concurrent integrity scanners |
| Dashboard WebSocket clients | held per process | a dashboard sees only events that landed on its own replica |

It also could not work mechanically: `s43-api` mounts the ReadWriteOnce PVC
`s43-api-state`, which holds the audit ledger and the dead-letter store, so
a second pod on another node would sit `Pending` on volume attach — and two
processes writing the same SQLite files would risk corrupting them.

An earlier revision of `overlays/beta` set `replicas: 2` with a
`PodDisruptionBudget` and an anti-affinity rule spreading replicas across
nodes. That combination was removed in the Kubernetes parity pass: it
promised horizontal scale the application cannot honour, and the
anti-affinity actively guaranteed the second pod could never attach the
volume.

Making `s43-api` genuinely horizontally scalable is application work, not a
manifest change — a shared idempotency store, a shared broadcast bus, and
leader election for the Fenrir/Sparta singletons. `scripts/k8s_policy_check.py`
fails the build if a manifest sets `replicas != 1`, switches to
`RollingUpdate`, or adds a PodDisruptionBudget selecting `s43-api`, so this
cannot regress silently.

`s43-core` and `s43-db` are single-replica for their own reasons — see
"Known limitations" below for why scaling `s43-db` isn't as simple as
changing a replica count.

## Backup / restore

Postgres here is a **single-instance StatefulSet with a PVC, not a managed
or HA database** — see "Known limitations." There is no automated
backup CronJob in this repo (it would need an operator-specific object
storage target — S3 bucket, GCS, etc. — that this repo has no way to know
in advance). Manual procedure:

```bash
# Backup
kubectl exec -n sentinel43 s43-db-0 -- pg_dump -U s43 s43 > s43-backup-$(date +%Y%m%d).sql

# Restore (to a fresh/empty database)
kubectl exec -i -n sentinel43 s43-db-0 -- psql -U s43 s43 < s43-backup-YYYYMMDD.sql
```

`pg_dump` is **not** a complete backup of this system. Two SQLite databases
live on the `s43-api-state` PVC and are not in Postgres:

```bash
kubectl cp sentinel43/$(kubectl get pod -n sentinel43 -l app=s43-api \
  -o jsonpath='{.items[0].metadata.name}'):/app/sentinel43_state/audit.sqlite3 \
  ./audit-$(date +%Y%m%d).sqlite3
kubectl cp sentinel43/$(kubectl get pod -n sentinel43 -l app=s43-api \
  -o jsonpath='{.items[0].metadata.name}'):/app/sentinel43_state/dead_letter.sqlite3 \
  ./dead-letter-$(date +%Y%m%d).sqlite3
```

`audit.sqlite3` is the authoritative HMAC-chained audit ledger; losing it
loses the tamper-evident record, and restoring a partial copy breaks the
chain. `dead_letter.sqlite3` holds the events that failed delivery and
whether an operator replayed them. Copying a live SQLite file can capture a
torn write — quiesce the pod (scale to 0, copy, scale back to 1) if the
copy needs to be authoritative.

For real production use, put a proper backup/restore process (pgBackRest,
WAL-G, a managed database's native backups) in front of this — the above is
a manual break-glass procedure, not a backup strategy.

## Upgrade / rollback

`s43-core` uses a rolling update (`maxUnavailable: 0, maxSurge: 1`), so a
bad rollout never takes down the serving pod while the new one starts.
**Proven in integration testing**: deploying a nonexistent image tag left
the new pod stuck in `ErrImageNeverPull`/`ImagePullBackOff` while the old
pod kept serving `/health` throughout; `kubectl rollout undo` recovered
cleanly.

`s43-api` uses **`strategy: Recreate`** instead, and therefore has a short
outage on every rollout — the old pod terminates before the new one starts.
That is deliberate: `maxSurge: 1` would briefly run two API pods, which is
exactly the duplicated-singleton state described under "Scaling", and the
second pod could not attach the ReadWriteOnce state PVC anyway. The tradeoff
is a visible gap instead of silent duplicate event processing.

Because of that, an `s43-api` rollback is not covered by a still-serving old
pod — verify the new image elsewhere first, and keep `rollout undo` ready:

```bash
kubectl rollout status deployment/s43-api -n sentinel43
kubectl rollout undo deployment/s43-api -n sentinel43
```

`s43-db` is a StatefulSet — upgrading its image version follows standard
Postgres major-version upgrade caveats (not Kubernetes-specific); this repo
doesn't attempt to automate that.

### Changing configuration

A `ConfigMap` or `Secret` consumed through `envFrom` is read **once, at
container start**. Editing either one changes nothing in a running pod, and
there is no reload signal — `kubectl apply -k ...` on a ConfigMap-only
change looks successful while the old values stay live. Roll the workload
explicitly:

```bash
kubectl rollout restart deployment/s43-api  -n sentinel43
kubectl rollout restart deployment/s43-core -n sentinel43
```

(For `s43-api` this is a Recreate rollout — see the outage note above.)

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
kubectl exec -n sentinel43 netpol-test -- timeout 5 nc -zv s43-db 5432   # must hang/fail
kubectl exec -n sentinel43 netpol-test -- timeout 5 nc -zv s43-core 9100 # must hang/fail
kubectl delete pod netpol-test -n sentinel43
```

This sequence was run against a kind cluster with Calico installed during
development (see "Integration testing evidence" below) — the connections
hung until the 5s timeout killed them (exit 143), confirming real
enforcement, not just object presence. That run also probed `s43-redis:6379`,
which no longer exists (see "No Redis").

## Relationship to Docker Compose

- `core/api/Dockerfile` now runs as a fixed non-root UID/GID (65532) — this
  is the one change shared with Compose, made because Kubernetes' PSS
  `restricted` profile requires it and there's no way to satisfy that only
  for k8s without maintaining two Dockerfiles. Verified not to break Compose
  (rebuilt, ran the full stack, confirmed `/app/logs`'s bind mount and
  `/tmp` are writable as the new non-root user). The claim that once
  followed here — that nothing writes to `/app/sentinel43_state` — is no
  longer true: the audit ledger and the dead-letter store both live there,
  and the directory is `chown`ed to 65532 in the image for that reason.
- `core/middleware/sentinel_firewall.py`'s trusted-proxy fix (see
  `docs/security/trusted_proxy_handling.md`) also applies to Compose —
  behavior is unchanged for anyone not setting `S43_TRUSTED_PROXIES`
  (nobody currently does, since it was silently broken before).
- Everything else here is additive. `docker-compose.yml` is untouched and
  remains the documented default for local development.
- **Environment parity is checked, not assumed.** Every variable
  `docker-compose.yml` passes to `s43-api` is either in `base/configmap.yaml`
  or `base/secret.example.yaml`. Two deliberate divergences:
  `s43-core` gets no `sentinel43_state` mount here (Compose shares one named
  volume between `s43-api` and `s43-core`, but `core/monitoring/watchtower.py`
  opens no file — sharing it in Kubernetes would need ReadWriteMany for no
  reason), and the Sparta integrity baselines
  (`S43_SPARTA_HASH_<PATH>`) are not committed because they are per-image
  hashes, not per-environment configuration.

## Known limitations

- **`s43-api` is a singleton, and several subsystems are why.** The
  in-process rate limiter, the in-process idempotency ledger, the
  per-process Fenrir and Sparta producers, and the per-process WebSocket
  client set all assume one API process. Every manifest here pins
  `replicas: 1` with `strategy: Recreate` accordingly, and
  `scripts/k8s_policy_check.py` enforces it. The consequence to accept:
  `s43-api` has a brief outage during rollouts and during node maintenance,
  and there is no PodDisruptionBudget that can change that (on a 1-replica
  workload `minAvailable: 1` only blocks drains forever). Fixing it is
  application work — shared limiter/ledger state and leader election for the
  producers — see "Scaling".
- **`/health` (liveness) does not verify database connectivity** — by
  design: a DB outage must not make Kubernetes kill every API pod.
  `/ready` (readiness) now **does** connect to Postgres to check the Alembic
  schema revision (`core/auth/schema_version.py`), so a pod that cannot reach
  the database, or is pointed at an un-migrated / wrong-revision one, reports
  `503` and is taken out of the Service's endpoint list until it recovers.
  `/ready` also reflects the subsystem dependency graph: it returns `503`
  while a REQUIRED subsystem (`core/lifecycle.py`) is not `ACTIVE`, so a pod
  whose Watchtower, audit or reliability wiring failed to start never
  receives traffic.
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
- **Postgres is a single-instance StatefulSet, not a managed or HA
  database.** No replication, no automatic failover, no automated backups.
  Real production/public-beta-at-scale use should sit behind a managed
  database service (RDS, Cloud SQL) or a proper HA operator (CloudNativePG,
  Zalando's postgres-operator) — this repo's manifests are a functional
  starting point, not a substitute for that.
- **The audit ledger and dead-letter store are SQLite files on a single
  ReadWriteOnce PVC.** They are backed up by `kubectl cp`, not by
  `pg_dump` (see "Backup / restore"), and they are a second reason
  `s43-api` cannot be scaled out.
- **No Redis.** There is none in this deployment, and there never was one
  that worked. A `s43-redis` StatefulSet, its NetworkPolicy and the
  `network/s43-redis-client` labels were removed in the Kubernetes parity
  pass, for three independent reasons: nothing in `core/` or `dashboard/`
  opens a Redis connection; `docker-compose.yml` runs no Redis service, so
  it was a Kubernetes-only component with no counterpart in the canonical
  runtime; and the StatefulSet named a ServiceAccount (`s43-redis`) that no
  manifest in this tree ever defined, so its pods could not be admitted.
  `scripts/k8s_policy_check.py` now fails any workload that references an
  object the render does not create, so that class of defect cannot ship
  again. `core/cli/generate_secrets.py` still emits `REDIS_PASSWORD` and
  `.env.example` still lists it — both are unused leftovers in application
  tooling, left alone deliberately rather than changed from a deployment
  pass. Redis becomes relevant again only if the rate limiter or the
  idempotency ledger is made shared, and it should be reintroduced by that
  work, with a client in `core/`.

- **`/docs`, `/redoc`, `/openapi.json` are disabled outside local/dev.** The
  application itself now decides this (`core/api/main.py` passes
  `docs_url`/`redoc_url`/`openapi_url` as `None` whenever `SENTINEL_ENV` is
  not one of the local/test values), not the Ingress — so it holds
  regardless of which edge fronts this deployment. Local/dev environments
  keep interactive docs; every other target gets a real 404 for all three
  paths (not merely hidden UI with the JSON schema still served). Verified
  by `scripts/deploy_preflight.py`'s existing `check_docs_exposure()` in
  `verify` mode, which already expected exactly this (401/403/404 = PASS).
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
cluster, and torn down unconditionally afterward.

> **This log describes the manifests as they were at the time of that run,
> and is kept unedited as a record.** The Kubernetes parity pass changed two
> things it depends on, so read these items with that in mind rather than as
> claims about the current manifests:
>
> - **Redis was removed.** Anything below mentioning `s43-redis` describes a
>   workload that no longer exists — and, as it turns out, one whose pods
>   could not have been admitted in the tree as committed, because its
>   ServiceAccount was never defined. Whatever reached `Ready` in that run
>   was not reproducible from these manifests.
> - **`s43-api` is now a `Recreate` singleton.** The three "the old/good
>   replica kept serving" observations below were properties of
>   `replicas: 2` + `RollingUpdate`. They no longer hold: a bad image, a
>   deleted Secret and an invalid `S43_JWT_SECRET` all still fail closed
>   exactly as described — `ErrImageNeverPull`, `CreateContainerConfigError`
>   and `CrashLoopBackOff` respectively — but with a brief API outage
>   instead of zero downtime. The fail-closed behaviour is what that testing
>   established; the zero-downtime part was a consequence of a replica count
>   the application could not actually support.

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
