# Sentinel-43 Controlled Beta Runbook

This is the one authoritative document for deploying and operating a
**controlled beta** of Sentinel-43. It supersedes any other handoff/runbook
notes scattered elsewhere in this repository's history.

## 1. Scope — read this first

**This document describes a controlled beta, not a production or
public-sector deployment.** Sentinel-43 defines three non-inferable
readiness tiers: controlled beta, production, and public-sector readiness.
Completing every step in this runbook, and passing every check it
describes, establishes only the first tier. It does **not** establish
production readiness and does **not** establish public-sector (e.g. CJIS)
readiness — those require separate evidence, separate review, and separate
authorization that this document does not provide and cannot substitute
for.

A controlled beta means: a small, known set of operators/testers, a
non-public or access-limited hostname, real TLS and real secrets (not
placeholders), and the operational discipline in this runbook followed in
full — but still short of the compliance, scale, and support posture
"production" implies.

Sentinel-43 itself remains, in every tier: advisory-first, human-governed,
fail-closed when required security evidence is unavailable, cryptographically
separated between human and service identities, and incapable of autonomous
enforcement. Nothing in this runbook changes any of that.

## 2. Supported deployment paths

Two paths are supported. Pick one; do not mix them for the same instance.

- **Docker Compose** — `docker-compose.yml`, fronted by the `s43-proxy`
  nginx service (the only host-published service; TLS termination, HTTP→HTTPS
  redirect). Suited to a single-host beta.
- **Kubernetes** — `deploy/kubernetes/base` plus the `overlays/beta` overlay
  (`kubectl apply -k deploy/kubernetes/overlays/beta`). Suited to a beta
  running on an existing cluster with its own Ingress controller.

Both paths run the same application image and the same single-replica
constraint (§16).

## 3. Required operator inputs

Before starting, have ready:

- A real hostname you control (not `beta.example.invalid`, the placeholder
  this repo ships).
- A real TLS certificate + key for that hostname (Compose path), or a
  cluster with a working Ingress controller and cert-manager `ClusterIssuer`
  (Kubernetes path, `letsencrypt-prod` is what `overlays/beta/ingress.yaml`
  currently names — change it if you use a different issuer).
- The real CIDR of whatever terminates TLS in front of the API (ingress
  controller pod network, or `127.0.0.1/32` for a same-host reverse proxy)
  — this becomes `S43_TRUSTED_PROXIES`.
- A container registry you can push to (GHCR, ECR, GCR, etc.) — **this repo
  does not provide one or push to one automatically for the beta overlay.**
- 13 generated secret values (§4) — none ship with real values; the
  checked-in examples are placeholders that must not reach a real
  deployment. The break-glass operator hash (§5) is **not** a beta input:
  that login is refused outside local/dev/test.

## 4. Secret generation and rotation

Managed via `core/cli/generate_secrets.py`. It manages 13 keys:
`S43_JWT_SECRET`, `S43_BOOTSTRAP_CLAIM_TOKEN`, `S43_AUTH_PEPPER`, `S43_SESSION_HASH_PEPPER`,
`SENTINEL_LOG_SALT`, `SENTINEL_REMOTE_TOKEN_OWNER`,
`SENTINEL_REMOTE_TOKEN_ADMIN`, `SENTINEL_REMOTE_TOKEN_AUDITOR`,
`S43_FENRIR_API_TOKEN`, `S43_WATCHTOWER_SERVICE_TOKEN`,
`S43_AUDIT_HMAC_KEY`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`.
`DATABASE_URL` is deliberately **not** in this list — set it to your real
Postgres connection string. Neither is `S43_OPERATOR_PASSWORD_HASH`, which
only a local/dev/test stack uses (§5); leave it empty for beta.

```bash
# Generate/add any missing managed secrets into a real .env file
# (creates the file if absent; existing values are preserved)
python -m core.cli.generate_secrets --write .env

# Rotate every managed secret (does NOT touch S43_OPERATOR_PASSWORD_HASH
# or DATABASE_URL)
python -m core.cli.generate_secrets --write .env --force

# Validate an existing .env's managed secrets (missing/placeholder/
# too-short values, exit 1 on any problem)
python -m core.cli.generate_secrets --check .env
```

For Kubernetes, the equivalent values go into the `sentinel43-secrets`
Secret in the `sentinel43` namespace (see `deploy/kubernetes/base/secret.example.yaml`
for the full key list and `deploy/kubernetes/README.md` for the
`kubectl create secret` invocation) — the same 13 keys generated the same
way, applied as a Secret instead of an `.env` file.

`S43_SECRETS_ROTATED_AT` should be updated (ISO-8601 timestamp) whenever
you rotate; `deploy_preflight.py` checks it isn't more than 90 days stale.

## 5. The Argon2id operator hash (local/dev/test only) — and Compose's `$` escaping trap

**Not for beta.** This hash belongs to the break-glass env operator, whose
login is refused outside `SENTINEL_ENV` `development`/`dev`/`local`/`test`
— armed or not, with or without an active admin. Do not provision it for a
beta or production target; if it is set there, it must still be a
well-formed Argon2id hash or the API refuses to start, so leave it empty.
Accounts on a beta target are database accounts (§16a). The rest of this
section applies to local development stacks.

```bash
python -m core.cli.generate_secrets --password-hash
```

This prompts twice (hidden input), hashes with Argon2id, and prints
`S43_OPERATOR_PASSWORD_HASH=<hash>` with every `$` **already doubled**.

**This doubling is not cosmetic — it is required for Compose specifically.**
An Argon2id digest looks like `$argon2id$v=19$m=...$salt$hash`. Compose's
`.env`-file variable interpolation treats a bare `$` as the start of a
variable reference; pasted verbatim into `.env`, every `$` in the hash is
silently swallowed before the container ever sees it, and the API then
fails every break-glass login with "Break-glass credentials are not
configured correctly" — a confusing failure mode if you don't know this is
happening. Use the tool's doubled-`$` output verbatim in `.env`; Compose
undoes the doubling before the value reaches the container. If you set this
value directly in a Kubernetes Secret (not through Compose), do **not**
double the `$` — Kubernetes Secrets have no such interpolation step.

## 6. Session-only beta authentication

Sentinel-43 has two ways a bearer token can authenticate: **session-bound**
(normal login, tied to a live server-side session — no password needed
again) and **legacy/break-glass** (a long-lived token for accounts with no
DB session, re-verified with a password, via `X-S43-Password`, on every
request). The legacy fallback exists for local/dev/test break-glass access
when no DB admin exists yet or when explicitly armed
(`S43_BREAK_GLASS_ARMED=true`) — it is not something a normal
operator/admin account needs, and it does not exist outside local.

**For beta, legacy authentication must be rejected.** The Kubernetes beta
overlay now sets this:

```yaml
# deploy/kubernetes/overlays/beta/configmap-patch.yaml
S43_REJECT_LEGACY_AUTH: "true"
```

For Compose, set `S43_REJECT_LEGACY_AUTH=true` in your `.env` file — the
base `docker-compose.yml` forwards it, and the beta override requires it.
Outside local/dev/test the API **refuses to start** unless the value is
explicitly true: unset, blank, `false` and malformed values all refuse, and
there is no override that accepts legacy authentication. With `true` it is
refused on every request. Only when `SENTINEL_ENV` is
`development`/`dev`/`local`/`test` can legacy authentication be accepted
(the default there). `deploy_preflight.py` (§15) also **fails** a
beta/non-local target unless the value is an explicit `true`.

If a deployment that worked before now stops at startup with a
`S43_REJECT_LEGACY_AUTH` error, add `S43_REJECT_LEGACY_AUTH=true` to its
`.env` (or ConfigMap). Any client that relied on `X-S43-Password` outside
local has to log in for a session instead.

**The break-glass env operator is unavailable outside local/dev/test.**
Its login (`S43_OPERATOR_USERNAME` / `S43_OPERATOR_PASSWORD_HASH`) is
refused there with `401 Invalid credentials` and issues no token — armed or
not, with or without an active admin, with or without a database. The token
it used to issue had no server-side session, so every protected route would
have refused it anyway. The API logs a startup warning when that credential
is configured in a non-local environment. It was never an administrator
recovery path either — it always gets role `operator` and cannot reach
`/users`. There is currently no non-local emergency operator access and no
in-product administrator recovery (§16a).

## 7. Service-token separation

Sentinel-43 keeps human and service identities cryptographically distinct
— never treat one as the other:

- `S43_FENRIR_API_TOKEN` — FenrirHunter's own service identity.
- `S43_WATCHTOWER_SERVICE_TOKEN` — internal service-to-service auth between
  `s43-api` and the standalone Watchtower node (`s43-core`). Distinct from
  the Fenrir token; neither can authenticate as the other.
- `SENTINEL_REMOTE_TOKEN_OWNER` / `_ADMIN` / `_AUDITOR` — Remote Gateway
  role tokens (disabled by default; see §17).
- None of these are ever accepted as a human operator/admin credential, and
  none of the human login flows accept a service token.

A missing `S43_WATCHTOWER_SERVICE_TOKEN` on either `s43-api` or `s43-core`
manifests as Watchtower heartbeats failing with HTTP 503 and `/ready`
reporting `"degraded":["watchtower"]` — this is the service failing
*closed* on a missing credential, not a bug; supply the token to clear it.

## 8. Image build, registry push, digest pinning, and source revision

Build:
```bash
docker build -t sentinel43-api:<tag> -f core/api/Dockerfile .
```

**This repository does not push to any registry and does not pin a digest
automatically for the beta overlay.** `deploy/kubernetes/overlays/beta/kustomization.yaml`
ships an intentionally-invalid placeholder:
```yaml
newName: REGISTRY_PLACEHOLDER/sentinel43-api
digest: sha256:0000000000000000000000000000000000000000000000000000000000000
```
You must push the built image to a real registry you control and pin the
resulting digest yourself. `docker tag`'s destination must be a `repository:tag`
reference — not a digest — so the sequence is tag-then-push-then-pin-the-digest-
you-get-back, not the other way around:
```bash
# 1. Build the local image with a normal tag (already done above; repeated
#    here for the full sequence's own context).
docker build -t sentinel43-api:<tag> -f core/api/Dockerfile .

# 2. Tag it for the selected registry -- a normal repository:tag reference.
docker tag sentinel43-api:<tag> <registry>/sentinel43-api:<tag>

# 3. Push that tag.
docker push <registry>/sentinel43-api:<tag>

# 4. Obtain the immutable digest the registry/push returned (the line
#    starting "<tag>: digest: sha256:..." in docker push's own output;
#    docker inspect also works if you need it again later):
docker inspect --format='{{index .RepoDigests 0}}' <registry>/sentinel43-api:<tag>

# 5. Verify the digest resolves to the image you just pushed, from the
#    registry itself (not just your local Docker cache):
docker pull <registry>/sentinel43-api@sha256:<64-hex-digest-from-step-4>

# 6. Pin that verified digest in the Kubernetes overlay.
cd deploy/kubernetes/overlays/beta
kustomize edit set image sentinel43-api=<registry>/sentinel43-api@sha256:<64-hex-digest>

# 7. Record the source revision alongside the digest (both together, not
#    separately) -- this is part of the evidence retained per §21.
echo "$(git rev-parse HEAD) <registry>/sentinel43-api@sha256:<64-hex-digest>" >> deployed-images.log
```
A CI job that automates this push+pin step for beta does not currently exist
in `.github/workflows/k8s.yml` (it exists only for the disposable `dev`
overlay/kind-smoke path); until one is added, this is a manual operator step.

## 9. Database migration procedure

```bash
kubectl apply -k deploy/kubernetes/overlays/beta   # or overlays/dev
kubectl wait --for=condition=Complete job/s43-migration -n sentinel43 --timeout=120s
```
The migration Job (`deploy/kubernetes/base/migration-job.yaml`) runs
`alembic upgrade head` after a `wait-for-db` initContainer TCP-polls the
database. Kubernetes does **not** make the `s43-api` Deployment wait for
this Job merely because both are applied together — you must explicitly
wait for `condition=Complete` as shown, or rely on the schema readiness
gate (§10) to keep unmigrated pods out of service rather than serving
against a stale schema.

## 10. Schema readiness gate

`GET /ready` calls `schema_report()` and returns HTTP 503 with
`{"status":"not_ready","reason":"schema_version","schema_state":...}`
whenever the schema isn't `OK` (outside local/dev, where mismatches are
reported but don't block). The states you may see, and what to do:

| State | Meaning | Operator action |
|---|---|---|
| `OK` | schema matches expected revision | none |
| `BEHIND` | DB revision is behind expected | run `alembic upgrade head` |
| `AHEAD` | DB revision is unknown to this code | you're running older code against a newer schema — deploy matching code |
| `UNSTAMPED` | app tables exist, no `alembic_version` row | `alembic stamp 0001_baseline` (only after confirming the existing schema actually matches that revision), then `alembic upgrade head` |
| `FRESH` | database not yet initialized by Alembic | `alembic upgrade head` before serving traffic |
| `UNREACHABLE` | could not query the DB | check DB connectivity/credentials |
| `GRAPH_INVALID` | the Alembic revision graph itself is broken | a repository defect — do not paper over it; fix the migration graph |
| `NOT_APPLICABLE` | `DATABASE_URL` not configured | expected only where no Postgres is in use; never blocks |

Kubernetes probes (`s43-api-deployment.yaml`): `startupProbe`/`livenessProbe`
hit `/health` (never touches the DB); `readinessProbe` hits `/ready` — this
is the mechanism that keeps a pod with a bad schema state out of the
Service's endpoints.

## 11. PostgreSQL backup and restore

**Manual break-glass procedure only — there is no automated backup CronJob
in this repository.**
```bash
# Backup
kubectl exec -n sentinel43 s43-db-0 -- pg_dump -U s43 s43 > s43-backup-$(date +%Y%m%d).sql

# Restore, to a fresh/empty database
kubectl exec -i -n sentinel43 s43-db-0 -- psql -U s43 s43 < s43-backup-YYYYMMDD.sql
```
The round-trip (including revoked-session state surviving correctly) is
exercised by `core/tests/test_backup_restore_pg.py` against a disposable
Postgres — that proves the mechanism works, it is not itself an
operator-facing scheduled backup.

## 12. SQLite audit/state volume backup and restore

**Manual break-glass procedure only, like §11 — there is no automated
backup CronJob for this volume either.** This covers the two SQLite
databases on the `s43-api-state` PVC (`audit.sqlite3` — the authoritative
HMAC-chained audit ledger, `S43_AUDIT_SQLITE_PATH` — and
`dead_letter.sqlite3` — failed events awaiting replay,
`S43_DEAD_LETTER_PATH`; see the PVC's own comment in
`deploy/kubernetes/base/s43-api-deployment.yaml`). **This is separate from,
and does not replace, the PostgreSQL backup in §11** — Postgres holds
sessions, targets, and everything else the application does not put on
this volume; both must be backed up.

Do not copy either file directly while `s43-api` is running: SQLite is in
WAL mode here, and a plain file copy of `audit.sqlite3` alongside a
missing or stale `audit.sqlite3-wal` can capture a torn, inconsistent
snapshot. Do not scale `s43-api` to 0 first either — that removes the only
pod that can reach the volume's contents to copy from, and there would be
no pod left for `kubectl cp` to target. Instead, use SQLite's own online
backup API (`sqlite3.Connection.backup()`, part of the Python stdlib
already inside the `s43-api` image — no extra tooling to install) from
*inside* the still-running pod: it produces a consistent snapshot of a
live, WAL-mode database without stopping the writer.

### 12a. Backup (the API keeps running; no downtime)

```bash
NAMESPACE=sentinel43
POD=$(kubectl get pod -n "$NAMESPACE" -l app=s43-api -o jsonpath='{.items[0].metadata.name}')

# Snapshot both databases with the online backup API, into the pod's own
# /tmp (the "tmp" emptyDir volume -- the one writable path outside
# sentinel43_state under readOnlyRootFilesystem: true). Paths are read from
# the pod's own environment (S43_AUDIT_SQLITE_PATH / S43_DEAD_LETTER_PATH),
# never hardcoded, so this stays correct even if an overlay changes them.
# Snapshot files are created 0600 and never contain S43_AUDIT_HMAC_KEY or
# any other secret -- only the ledger rows themselves.
kubectl exec -i -n "$NAMESPACE" "$POD" -c s43-api -- python - <<'PYEOF'
import os, sqlite3, sys

outdir = "/tmp/s43-backup"
os.makedirs(outdir, mode=0o700, exist_ok=True)

sources = {
    "audit": os.environ["S43_AUDIT_SQLITE_PATH"],
    "dead_letter": os.environ["S43_DEAD_LETTER_PATH"],
}

for name, src_path in sources.items():
    dst_path = f"{outdir}/{name}.sqlite3"
    src = sqlite3.connect(src_path)
    dst = sqlite3.connect(dst_path)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    os.chmod(dst_path, 0o600)

    check = sqlite3.connect(dst_path)
    try:
        result = check.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        check.close()
    if result != "ok":
        print(f"INTEGRITY_FAIL {name}: {result}")
        sys.exit(1)
    print(f"OK {name} snapshot at {dst_path}")
PYEOF

# Copy the completed, already-integrity-checked snapshots out -- only after
# the backup above exited 0. Never the live files themselves.
DATE=$(date +%Y%m%d)
kubectl cp "$NAMESPACE/$POD:/tmp/s43-backup/audit.sqlite3" -c s43-api "./audit-$DATE.sqlite3"
kubectl cp "$NAMESPACE/$POD:/tmp/s43-backup/dead_letter.sqlite3" -c s43-api "./dead-letter-$DATE.sqlite3"

# Re-verify the copies that actually landed on the operator's machine --
# confirms the kubectl cp transfer itself didn't corrupt anything.
for f in "./audit-$DATE.sqlite3" "./dead-letter-$DATE.sqlite3"; do
  python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute('PRAGMA integrity_check').fetchone()[0]; c.close(); print(sys.argv[1], r); sys.exit(0 if r=='ok' else 1)" "$f"
done

# Remove the in-pod temporary copies now that the transfer is verified.
kubectl exec -n "$NAMESPACE" "$POD" -c s43-api -- rm -rf /tmp/s43-backup
```

### 12b. Restore (requires downtime — replaces authoritative state)

Restoring means the single `s43-api` pod must stop touching these files
while they are replaced. Scaling the Deployment to 0 removes the only pod
Sentinel-43 runs — by design (§16) — so there is no running `s43-api`
container left to `kubectl exec`/`kubectl cp` into for the restore itself.
Do the file replacement from a separate, temporary, tightly-scoped
maintenance pod that mounts the same PVC instead — the same
`kubectl run --overrides=...` pattern already used for the NetworkPolicy
probe in §20, adapted to mount `s43-api-state` and pinned to the same
image already running (or another explicitly pinned, trusted image; never
`:latest` or a mutable tag).

```bash
NAMESPACE=sentinel43

# 1. Stop the API so nothing else touches sentinel43_state during restore.
kubectl scale deployment/s43-api -n "$NAMESPACE" --replicas=0
kubectl wait --for=delete pod -l app=s43-api -n "$NAMESPACE" --timeout=60s

# 2. Note the currently-deployed, digest-pinned image (per §8) to reuse for
#    the maintenance pod -- do not substitute an unpinned tag.
IMAGE=$(kubectl get deployment/s43-api -n "$NAMESPACE" \
  -o jsonpath='{.spec.template.spec.containers[0].image}')
# IMAGE now looks like <registry>/sentinel43-api@sha256:<64-hex-digest>

# 3. Launch the maintenance pod: same restrictive posture as s43-api itself
#    (runAsUser/Group 65532, no privilege escalation, all capabilities
#    dropped, readOnlyRootFilesystem), the state PVC mounted read-write,
#    no port/Service -- it exposes nothing on the network -- and it just
#    sleeps until this operator deletes it.
kubectl run s43-restore -n "$NAMESPACE" --image="$IMAGE" --restart=Never \
  --overrides='{
    "spec": {
      "automountServiceAccountToken": false,
      "securityContext": {"runAsNonRoot": true, "runAsUser": 65532,
                           "runAsGroup": 65532, "fsGroup": 65532,
                           "seccompProfile": {"type": "RuntimeDefault"}},
      "containers": [{
        "name": "s43-restore",
        "image": "'"$IMAGE"'",
        "envFrom": [{"configMapRef": {"name": "sentinel43-config"}}],
        "securityContext": {"allowPrivilegeEscalation": false,
                             "readOnlyRootFilesystem": true,
                             "privileged": false,
                             "capabilities": {"drop": ["ALL"]},
                             "seccompProfile": {"type": "RuntimeDefault"}},
        "volumeMounts": [{"name": "state", "mountPath": "/app/sentinel43_state"},
                          {"name": "tmp", "mountPath": "/tmp"}]
      }],
      "volumes": [{"name": "state",
                    "persistentVolumeClaim": {"claimName": "s43-api-state"}},
                   {"name": "tmp", "emptyDir": {}}]
    }
  }' --command -- sleep 3600
kubectl wait --for=condition=Ready pod/s43-restore -n "$NAMESPACE" --timeout=60s

# 4. Copy the verified snapshots (from §12a) into the maintenance pod, then
#    integrity-check them again on this volume before touching the active
#    files -- copy failures or a bad backup file must be caught here, not
#    after the active database is already overwritten.
kubectl cp "./audit-$DATE.sqlite3" "$NAMESPACE/s43-restore:/tmp/audit.sqlite3"
kubectl cp "./dead-letter-$DATE.sqlite3" "$NAMESPACE/s43-restore:/tmp/dead_letter.sqlite3"

kubectl exec -i -n "$NAMESPACE" s43-restore -- python - <<'PYEOF'
import os, shutil, sqlite3, sys

# Same envFrom (sentinel43-config) as the real s43-api container, so these
# resolve to the actual configured paths -- never hardcoded here either.
pairs = [
    ("/tmp/audit.sqlite3", os.environ["S43_AUDIT_SQLITE_PATH"]),
    ("/tmp/dead_letter.sqlite3", os.environ["S43_DEAD_LETTER_PATH"]),
]

for snapshot_path, active_path in pairs:
    check = sqlite3.connect(snapshot_path)
    try:
        result = check.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        check.close()
    if result != "ok":
        print(f"INTEGRITY_FAIL {snapshot_path}: {result}")
        sys.exit(1)

    # Replace the active file with the verified snapshot, preserving the
    # UID/GID 65532 ownership and 0600 permissions the running s43-api
    # process (also UID/GID 65532) expects. os.replace() is an atomic
    # rename on the same filesystem -- no partially-written active file.
    tmp_active = active_path + ".restoring"
    shutil.copyfile(snapshot_path, tmp_active)
    os.chown(tmp_active, 65532, 65532)
    os.chmod(tmp_active, 0o600)
    os.replace(tmp_active, active_path)
    for suffix in ("-wal", "-shm"):
        stale = active_path + suffix
        if os.path.exists(stale):
            os.remove(stale)
    print(f"restored {active_path} from {snapshot_path}")
PYEOF

# 5. Remove the maintenance pod -- its job is done, and it must not
#    linger holding the ReadWriteOnce PVC (s43-api could not reschedule
#    while it does).
kubectl delete pod s43-restore -n "$NAMESPACE"

# 6. Restart the API and confirm it comes back healthy against the
#    restored state.
kubectl scale deployment/s43-api -n "$NAMESPACE" --replicas=1
kubectl rollout status deployment/s43-api -n "$NAMESPACE" --timeout=120s
```

After the rollout completes, verify the restore actually worked, not just
that the pod is Running:
- **Audit integrity**: `initialize()` runs a full `verify_integrity()` at
  every `s43-api` startup (`core/audit/store.py`) and refuses to serve if
  the restored ledger's HMAC chain or lookup metadata (§18) doesn't check
  out -- a pod that reaches `Ready` already proves this, but a
  crash-looping pod after this procedure means the restored `audit.sqlite3`
  itself is the problem, not a transient startup race.
- **Readiness**: `curl -fsS https://<hostname>/ready` returns 200 (§10).
- **Authentication**: log in through the dashboard/API as a real operator
  -- confirms the restored state didn't leave auth in a broken
  configuration.
- **Retained records**: `GET /remote-gateway/audit/{correlation_id}` (§18)
  for a `correlation_id` you know was recorded before the incident that
  made this restore necessary, and confirm the expected record is present
  and `authoritative: true` in the response.

## 13. TLS certificate and hostname validation

- **Kubernetes**: `overlays/beta/ingress.yaml` uses
  `cert-manager.io/cluster-issuer: letsencrypt-prod`, forces
  `ssl-redirect: "true"`, sends HSTS (`max-age=15552000`). Replace the
  placeholder host `beta.example.invalid` with your real hostname before
  applying, and confirm your cluster actually has cert-manager and that
  issuer configured — this manifest does not install either.
- **Compose**: `s43-proxy` (nginx) terminates TLS. For real deployment you
  must provide a real certificate/key at `deploy/proxy/certs/s43.crt`/`s43.key`
  (via certbot or your CA) — `deploy/proxy/generate-dev-cert.sh` produces
  only a **self-signed** cert for local testing, never use it for a real
  beta hostname.
- Either path: verify the certificate validates for your real hostname and
  isn't near expiry (`deploy_preflight.py`'s `verify` phase does this —
  §15), and that plain HTTP redirects to HTTPS.

## 14. Trusted host, trusted proxy, and allowed-origin configuration

In `deploy/kubernetes/overlays/beta/configmap-patch.yaml`, currently:
```yaml
S43_TRUSTED_PROXIES: ""    # CHANGEME -> your ingress pod CIDR, e.g. "10.244.0.0/16"
S43_TRUSTED_HOSTS: "beta.example.invalid,s43-api"    # CHANGEME -> <your real host>,s43-api
S43_ALLOWED_ORIGINS: "https://beta.example.invalid"  # CHANGEME -> https://<your host>
S43_TLS_TERMINATED_AT_TRUSTED_EDGE: "true"
```
All three `CHANGEME`-flagged values must be replaced with your real
hostname/CIDR before this is a real beta, not just a rendering exercise.
`S43_TRUSTED_PROXIES` ships **empty**, not a placeholder string — this is
deliberate (a non-CIDR placeholder would raise at startup and fail every
request, not just forwarded-header trust). Empty fails closed safely: no
peer is trusted, `X-Forwarded-For` is never honored, and every request is
attributed to the ingress controller's own IP in the firewall/audit trail
until you set the real CIDR. Never set this broader than the actual
proxy's network (never `0.0.0.0/0`). See `docs/security/trusted_proxy_handling.md`
for the full rationale (its prose about the beta overlay's value was
reconciled with the YAML on 2026-09-19; the YAML remains the source of truth).

`S43_TRUSTED_HOSTS` must keep `s43-api` alongside your real hostname (a
ConfigMap patch replaces the whole value; dropping the in-cluster name
breaks Fenrir's own internal callback, which presents `Host: s43-api:8000`).

## 15. Public endpoint exposure checks

```bash
# Static/config checks, before anything is deployed
python scripts/deploy_preflight.py compose --phase prepare --hostname <host> --https-port 443 --http-port 80 --env-file .env --image <registry>/sentinel43-api@sha256:<digest>

# Live-target checks, once deployed
python scripts/deploy_preflight.py compose --phase verify --hostname <host> --project s43 --env-file .env [--from-external-host]
python scripts/deploy_preflight.py kube --phase verify --context <ctx> --namespace <ns> --hostname <host> [--ca-bundle /path/to/ca.pem]
```
`--phase` is required, no default. `--from-external-host` matters: without
it, the internal-port check (5432/6379/8000/9100 must not be externally
reachable) reports `INCOMPLETE`, not a real pass — you must run it from
outside the target's network for it to mean anything. `check_docs_exposure`
(§ Phase 4 above) expects `/docs`, `/redoc`, `/openapi.json` to answer
401/403/404 — confirms the application-level fix, not just an Ingress
assumption.

## 16. Startup and readiness checks

`/health` is synchronous and never touches the database — liveness only.
`/ready` is the real dependency gate (schema, Watchtower if required,
subsystem registry). Kubernetes probe config
(`deploy/kubernetes/base/s43-api-deployment.yaml`): `startupProbe` and
`livenessProbe` on `/health` (5s/15s period), `readinessProbe` on `/ready`
(10s period, 3-failure threshold).

**This deployment is single-replica-safe only, by design, not by
preference** — the idempotency ledger, Fenrir/SpartaCore producers,
WebSocket broadcast, the rate limiter, and the audit/dead-letter SQLite
files (on a `ReadWriteOnce` PVC) are all process-local or single-writer
state. `s43-api`'s Deployment strategy is `Recreate` (not rolling) to keep
this true even mid-rollout, meaning **every `s43-api` rollout is a short
outage** — this is expected, not a bug. `scripts/k8s_policy_check.py`'s
`check_singleton_workloads()` fails the manifest build if anything sets
`replicas != 1` for `s43-api`, switches its strategy, or adds a
PodDisruptionBudget selecting it.

## 16a. Platform ownership: first administrator claim and admin recovery

**Status: first-admin ownership and emergency admin recovery closed.**
The holder of the deployment secret store authorizes the first claim through
`S43_BOOTSTRAP_CLAIM_TOKEN`; deployment exec authority handles emergency admin
recovery without exposing a privileged network endpoint. What is enforced today:

- **One-time claim.** `POST /bootstrap/admin` creates the first account,
  role `admin`, in an empty account store. Concurrent claims are serialized
  by a PostgreSQL advisory lock (exactly one succeeds, the rest get `409`);
  the claim commits in one transaction, so an interrupted claim leaves
  nothing behind and can be retried. Outside local/test, a backend that
  cannot serialize claims refuses with `503`.
- **Closed for every application path.** Once any account exists,
  `/bootstrap/admin` returns `409` and `/bootstrap/status` reports
  `initialized: true`. Deactivating or demoting every admin, even directly
  in the database, does not reopen it, and the API cannot delete an account.
  It is not yet a separate consumed-bootstrap marker: deleting every account
  row directly in the database reopens the claim. Anyone with that database
  access could already insert an admin row, so treat database write access
  as full control of identity.
- **Deployment-authorized first claim.** Outside local/dev/test,
  `POST /bootstrap/admin` requires the high-entropy
  `S43_BOOTSTRAP_CLAIM_TOKEN` in `X-S43-Bootstrap-Token`. Missing
  configuration refuses with `503`; a missing or incorrect presented token
  refuses with `403`. The token grants no login/session rights and has no
  purpose after the first account exists. Local/dev/test keeps the token
  optional for developer setup.
- **An operator login is not ownership.** The break-glass env operator
  (`S43_OPERATOR_USERNAME` / `S43_OPERATOR_PASSWORD_HASH`) is always role
  `operator`, cannot manage accounts, and outside local its login is refused
  and issues no token (§6).
- **Administrators do not outrank governance.** The `admin` role grants
  account management (`/users`) only. Approving or vetoing a staged action
  requires the server-recorded identity of an authenticated human operator;
  no role skips HUMAN_GATED review. Shared-secret credentials (Remote
  Gateway `OWNER`/`ADMIN`/`AUDITOR` tokens, the Watchtower service and admin
  tokens, the Fenrir token) never yield a human operator identity, and
  governance refuses and audits them as approvers. The authoritative audit
  store (§12) is append-only: no route or role can edit or delete a record.
- **Account mutations are authority-audited.** First-admin claim, account
  creation, role/activation changes, password resets, and session lifecycle
  mutations cross `Sentinel43RuntimeAuthority.identity`, which emits the
  authoritative identity-governance audit record before the mutation.

### Claiming the first administrator (Compose and Kubernetes)

Claim as soon as the stack first reports ready, before sharing the URL. No
default admin account exists and none is created for you. The username,
password, and deployment claim token are read without placing credentials in
the URL or command history. The claim token comes from the same protected
deployment secret source used to provision `S43_BOOTSTRAP_CLAIM_TOKEN`.
Only the HTTP status is printed, because a validation error response would
echo the submitted values.

Set the target first:

- **Compose:** `S43_URL=https://<your host>` — the API is reachable only
  through `s43-proxy`. With the self-signed development certificate, add
  `--cacert deploy/proxy/certs/s43.crt` to the `curl` below; never use `-k`.
- **Kubernetes:** the Ingress URL, `S43_URL=https://<your host>`; or, before
  the Ingress and TLS are live, run
  `kubectl -n sentinel43 port-forward svc/s43-api 8000:8000` in another
  terminal, set `S43_URL=http://127.0.0.1:8000`, and add
  `-H 'Host: s43-api'` to the `curl` below (`s43-api` is in
  `S43_TRUSTED_HOSTS`, §14).

```bash
read -rsp 'deployment claim token: ' S43_BOOTSTRAP_CLAIM_TOKEN; echo
python3 -c '
import getpass, json, sys
sys.stderr.write("first admin username: "); sys.stderr.flush()
user = sys.stdin.readline().strip()
pw = getpass.getpass("password (12+ characters): ")
if len(pw) < 12 or pw != getpass.getpass("repeat password: "):
    sys.exit("password too short or not matching; nothing was sent")
json.dump({"username": user, "password": pw}, sys.stdout)
' | curl -sS -o /dev/null -w '%{http_code}\n' \
      -H 'Content-Type: application/json' \
      -H "X-S43-Bootstrap-Token: $S43_BOOTSTRAP_CLAIM_TOKEN" \
      --data-binary @- "$S43_URL/bootstrap/admin"
unset S43_BOOTSTRAP_CLAIM_TOKEN
```

| Status | Meaning |
|---|---|
| `201` | You are the first administrator. Confirm by signing in to the dashboard with those credentials. |
| `403` | The deployment claim token is missing or incorrect. Nothing was created. |
| `409` on your **first** authorized attempt | Someone else already claimed this deployment. Treat it as compromised: take the stack down, destroy the database volume/PVC, and redeploy. |
| `409` after an attempt that printed no status | The earlier claim may have committed. Sign in with the credentials you chose: success means the claim was yours; failure means treat it as compromised, as above. |
| `503` | The deployment claim secret is not configured, the account store is not PostgreSQL (outside local/test), or the API/database is unavailable. Nothing was created. |
| `422` | The username or password was rejected. Nothing was created. |

Then, signed in as that admin, create the other accounts through `/users`,
including a second active admin, so that one lost credential is not a
lockout.

### Emergency administrator recovery

The normal API cannot orphan the deployment: `PATCH /users` refuses to
deactivate or demote the last active admin, and no admin can deactivate
their own account. A lockout can still happen if credentials are lost or
identity rows are changed directly.

Recovery is intentionally **not an HTTP endpoint**. The deployment operator
uses the exec-only CLI from a trusted host/container context:

```bash
# Docker Compose
docker compose exec s43-api python -m core.cli.recover_admin <username>

# Kubernetes
kubectl exec -n sentinel43 deployment/s43-api -c s43-api -- \
  python -m core.cli.recover_admin <username>
```

The command prompts twice for a new password and never accepts it as a
command-line argument. It targets an existing account only. Recovery:

- requires PostgreSQL advisory locking and refuses weaker backends;
- goes through `Sentinel43RuntimeAuthority.identity`, not direct SQL;
- writes the authoritative identity-governance audit record before mutation;
- restores the selected account to `role=admin` and `is_active=true`;
- replaces its password;
- revokes all of its existing sessions;
- fails closed if authoritative audit initialization/write fails.

Container/host exec is the recovery authority because it already represents
deployment-level control. No network-facing recovery credential or permanent
admin bypass is added. Keep two active administrators anyway; emergency
recovery should remain exceptional.

## 17. Browser and WSS acceptance

Against a **real deployed target** (not the disposable local stack):
```bash
S43_TARGET_BASE_URL=https://<host> ./browser_tests/run_target.sh
```
`S43_TARGET_BASE_URL` must be `https://` (enforced by the script). Optional:
`S43_TARGET_OPERATOR_CRED_FILE` (JSON `{"username","password"}` — without
it, authenticated/WSS-authenticated checks error loudly rather than
silently skipping), `S43_TARGET_CA_BUNDLE`, and admin-mutation opt-ins
(`S43_TARGET_ADMIN_SCOPE=explicit-dedicated-account`,
`S43_TARGET_ADMIN_CRED_FILE`, `S43_TARGET_MUTATION_OPERATOR_CRED_FILE`).
This runner never builds/starts/stops/scales anything and never bootstraps
an admin on your behalf — it only reads and exercises what you point it at.

## 18. Remote Gateway audit requirements

The Remote Gateway is **disabled by default** in every deployment path —
enabling it for beta is a separate, explicit decision, not implied by this
runbook. If you do enable it (`SENTINEL_REMOTE_GATEWAY_ENABLED=true` plus
the three `SENTINEL_REMOTE_TOKEN_*` role tokens):

- A live (non-dry-run) activation now **requires** the authoritative
  AuditStore to durably accept a pre-action record before dispatch, in any
  non-local environment — if `S43_AUDIT_HMAC_KEY` is not configured, or the
  store rejects the write, the activation is refused (503) and nothing is
  dispatched. This means the audit store must be configured (§ secrets,
  `S43_AUDIT_HMAC_KEY`) **before** enabling live dispatch for beta, not
  after.
- Check `GET /remote-gateway/health`'s `audit_write_available` and
  `audit_read_available` fields — both should be `true` before relying on
  live dispatch. `event_buffer_durable` is always `false`; that field
  describes the in-memory operational buffer, not the authoritative ledger.
- Durably-persisted Remote Gateway records remain retrievable via
  `GET /remote-gateway/audit/{correlation_id}` after a restart (merged from
  the authoritative store), not just from the in-memory buffer. The
  response is `{"records": [...], "authoritative": bool}` — `authoritative`
  is `true` only when the durable store was actually consulted. If a
  configured store's read fails, or none is configured outside local/dev,
  the endpoint returns 503 rather than a normal response that could be
  mistaken for a complete (if empty) history.

## 19. Shutdown, restart, rollback, and incident recovery

```bash
# Status / rollback for s43-api (Recreate strategy -- expect a short outage either way)
kubectl rollout status deployment/s43-api -n sentinel43
kubectl rollout undo deployment/s43-api -n sentinel43

# Pick up a ConfigMap/Secret change (envFrom is read once at container
# start; there is no reload signal)
kubectl rollout restart deployment/s43-api  -n sentinel43
kubectl rollout restart deployment/s43-core -n sentinel43

# Full removal (irreversible -- deletes PVCs; confirm backups first)
kubectl delete -k deploy/kubernetes/overlays/beta
kubectl delete namespace sentinel43
```
`s43-core` uses a rolling strategy and has been proven in integration
testing to recover cleanly via `rollout undo` from a bad image tag;
`s43-api`'s `Recreate` strategy means undo still costs a short outage,
which is expected given §16.

## 20. NetworkPolicy enforcement — negative connectivity test

Manifests existing is not proof of enforcement. Run this against the real
cluster:
```bash
kubectl run netpol-test -n sentinel43 --image=busybox:1.36 --restart=Never \
  --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":65532,"runAsGroup":65532,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"netpol-test","image":"busybox:1.36","command":["sleep","3600"],"securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"privileged":false,"capabilities":{"drop":["ALL"]},"seccompProfile":{"type":"RuntimeDefault"}}}]}}' \
  --command -- sleep 3600
kubectl exec -n sentinel43 netpol-test -- timeout 5 nc -zv s43-db 5432    # must hang/fail
kubectl exec -n sentinel43 netpol-test -- timeout 5 nc -zv s43-core 9100  # must hang/fail
kubectl delete pod netpol-test -n sentinel43
```
This is a **manual** procedure — it is not run in CI today.
`scripts/k8s_policy_check.py` only statically checks that NetworkPolicy
objects exist and reference real selectors, and the hosted `kind smoke deploy`
job installs Calico and runs a *positive* smoke (rollout, `/ready`, posture
assertions, health/bootstrap over the Host header) with the policies applied.
Installing Calico and seeing the workload come up is **not** proof that
forbidden connections are refused; no CI job runs the negative connectivity
test above. (A one-time development run against a kind cluster with Calico is
recorded in `deploy/kubernetes/README.md`, not in CI.) Run it against your actual cluster's CNI before trusting the
policies are doing anything — enforcement depends on the CNI, not just the
manifest.

## 21. Evidence to retain

For each beta deployment, keep:

- The git commit SHA the deployed image was built from, and the pushed
  image's digest (§8).
- `deploy_preflight.py`'s full output for both `prepare` and `verify`
  phases, for both the Compose and/or Kubernetes path used.
- The negative NetworkPolicy connectivity test's actual output (§20).
- The `browser_tests/run_target.sh` acceptance run's output (§17).
- The local live-system report from `scripts/S43_System.Tests.ps1` and the
  endurance summary from `scripts/S43_Endurance.Tests.ps1` when those
  checks were used as candidate evidence (§22).
- The final `acceptance_gate.py --mode final-beta` verdict and its complete
  evidence directory for the exact deployed revision (§22).
- The date and value-source of the last secret rotation
  (`S43_SECRETS_ROTATED_AT`).
- Backup timestamps and their storage location (§11, §12).

## 22. Final beta-closure gate

Sentinel-43's repository can be a **Controlled Beta Candidate** without a
specific deployment being accepted as a controlled-beta target. Treat those
as two separate states.

### 22.1 Local candidate verification

For a local/dev stack, use the live harnesses to prove the running system is
coherent before spending time on target deployment evidence:

```powershell
$cred = Get-Credential

pwsh .\scripts\S43_System.Tests.ps1 `
  -ApiUrl https://localhost `
  -Credential $cred `
  -SkipCertificateCheck `
  -ReportPath .\s43-system-report.json

pwsh .\scripts\S43_Endurance.Tests.ps1 `
  -ApiUrl https://localhost `
  -Credential $cred `
  -SkipCertificateCheck `
  -DurationMinutes 120 `
  -IntervalSeconds 60 `
  -FullSweepEvery 5
```

Base Compose publishes only the nginx front door on host ports 80/443; the
API's port 8000 is internal to the Compose network. The commands above therefore
use the real local HTTPS proxy path. `-SkipCertificateCheck` is appropriate
only for this local candidate check when using the repository's self-signed
development certificate. Do not use it against a real beta target; supply and
validate the target's real CA/TLS chain there.

Run the disposable real-browser suite as a separate browser/TLS integration
check:

```powershell
& "C:\Program Files\Git\bin\bash.exe" ./browser_tests/run.sh
```

On non-Windows systems, run `./browser_tests/run.sh` normally.

These checks establish useful **local candidate evidence**: API/readiness,
authenticated route behavior, WebSocket authentication, browser session
behavior, repeated health, and runtime endurance. They do **not** establish
that a real beta target has correct DNS, public/edge TLS, trusted-proxy
configuration, CNI enforcement, or target-specific credentials.

### 22.2 Repository acceptance campaign

The repository's strict evidence gate combines local/disposable work,
target acceptance, and the hosted kind + Calico smoke for the **same exact
revision**. Hosted CI now uploads an `acceptance-kind-smoke` artifact containing
`check-kind-smoke.meta.json`; that record carries the checkout revision and
tree fingerprint used by the strict gate.

First, obtain a successful `acceptance-kind-smoke` artifact from the hosted
Kubernetes workflow for the exact commit you are accepting and extract it
locally. Do not reuse evidence from another commit. Then provide the authorized
target variables required by `browser-target`:

```text
S43_TARGET_BASE_URL
S43_TARGET_OPERATOR_CRED_FILE
S43_TARGET_ADMIN_SCOPE
S43_TARGET_ADMIN_CRED_FILE
S43_TARGET_MUTATION_OPERATOR_CRED_FILE
```

Run the campaign with the extracted hosted evidence:

```bash
python scripts/acceptance_campaign.py --out acceptance_out \
  --kind-smoke-evidence <path-to-extracted-acceptance-kind-smoke>
```

The campaign creates a fresh timestamped evidence directory, records test
inventory before execution, runs every local/disposable required job, runs
`browser-target` against the explicitly authorized target, copies only the
hosted `check-kind-smoke` evidence record into that fresh directory, and
finishes by invoking the strict gate:

```bash
python scripts/acceptance_gate.py verify --out <evidence-directory> --mode final-beta
```

The verifier rejects mixed revisions/tree states, so a kind artifact from a
different checkout cannot satisfy the final gate. If
`--kind-smoke-evidence` is omitted, `check-kind-smoke` is recorded as unmet.
If the complete `S43_TARGET_*` credential set is absent, `browser-target`
is unmet. Both cases deliberately produce `FINAL-BETA ACCEPTANCE FAIL`.

Do not hand-edit an unmet job into a pass or delete it from the manifest simply
to obtain a green verdict.

### 22.3 Target acceptance

Before declaring one specific deployment an accepted **controlled-beta
target**, all target-specific prerequisites in this runbook must be satisfied,
including:

- real hostname/TLS and allowed-origin posture;
- correct trusted-proxy configuration;
- database migration/readiness success;
- backup/restore evidence;
- target browser/WSS acceptance via `browser_tests/run_target.sh`;
- NetworkPolicy negative-connectivity evidence when using Kubernetes;
- immutable image/source provenance for the deployed revision;
- all required acceptance jobs reconciled for the same revision.

The authoritative closure condition is a machine-readable verdict of:

```text
FINAL-BETA ACCEPTANCE PASS
```

from `scripts/acceptance_gate.py --mode final-beta`, with no skipped,
unexecuted, unmet, stale-revision, missing, or failed required job.

A clean local Docker run by itself is not that verdict. Conversely, once the
strict gate passes for the deployed revision and the runbook's target
prerequisites are satisfied, do not keep the project labeled "Late Alpha"
merely out of habit: that target has met the repository's controlled-beta
acceptance definition.

## 23. What this runbook does not establish

Completing this runbook, including the final closure gate in §22, and every
check within it passing, demonstrates a
**controlled beta** is correctly configured and operating as designed. It
does **not** by itself establish:

- **Production readiness** — that requires separate operational,
  performance, and support-posture evidence this runbook does not cover.
- **Public-sector readiness** (e.g. CJIS or equivalent compliance) — that
  requires separate compliance review, evidence, and formal authorization
  entirely outside this document's scope.

Do not represent a controlled beta, however well it passes the checks
above, as satisfying either of those tiers.
