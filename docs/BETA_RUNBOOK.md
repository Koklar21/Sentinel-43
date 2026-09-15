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
- 12 generated secret values (§4) plus a real Argon2id operator password
  hash (§5) — none of these ship with real values; the checked-in examples
  are placeholders that must not reach a real deployment.

## 4. Secret generation and rotation

Managed via `core/cli/generate_secrets.py`. It manages 12 keys:
`S43_JWT_SECRET`, `S43_AUTH_PEPPER`, `S43_SESSION_HASH_PEPPER`,
`SENTINEL_LOG_SALT`, `SENTINEL_REMOTE_TOKEN_OWNER`,
`SENTINEL_REMOTE_TOKEN_ADMIN`, `SENTINEL_REMOTE_TOKEN_AUDITOR`,
`S43_FENRIR_API_TOKEN`, `S43_WATCHTOWER_SERVICE_TOKEN`,
`S43_AUDIT_HMAC_KEY`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`.
`S43_OPERATOR_PASSWORD_HASH` and `DATABASE_URL` are deliberately **not** in
this list — set those manually (§5, and your real Postgres connection
string).

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
`kubectl create secret` invocation) — the same 12 keys generated the same
way, applied as a Secret instead of an `.env` file.

`S43_SECRETS_ROTATED_AT` should be updated (ISO-8601 timestamp) whenever
you rotate; `deploy_preflight.py` checks it isn't more than 90 days stale.

## 5. The Argon2id operator hash — including Compose's `$` escaping trap

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
request). The legacy fallback exists for break-glass access when no DB
admin exists yet or when explicitly armed (`S43_BREAK_GLASS_ARMED=true`) —
it is not something a normal operator/admin account needs.

**For beta, legacy authentication must be rejected.** The Kubernetes beta
overlay now sets this:

```yaml
# deploy/kubernetes/overlays/beta/configmap-patch.yaml
S43_REJECT_LEGACY_AUTH: "true"
```

For a Compose-based beta, set `S43_REJECT_LEGACY_AUTH=true` in your beta
`.env` file. The code-level default remains `false` (accept legacy auth) —
this is a deliberate, clearly-labeled local-development compatibility
option, so `docker-compose up` for local dev and the existing test suite
keep working unmodified. It is only for a target you consider "beta or
beyond" that this must be turned on explicitly, and `deploy_preflight.py`
(§15) now **fails** (not merely notes) a beta/non-local target where it
is left off.

This does not disable break-glass entirely — it disables the *password
fallback for already-issued legacy tokens*. Recovery access when locked out
still works through the normal bootstrap/break-glass login flow; it just
can no longer be satisfied by a per-request password on an old-style token
afterward.

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
resulting digest yourself:
```bash
docker tag sentinel43-api:<tag> <registry>/sentinel43-api@<local-build>
docker push <registry>/sentinel43-api:<tag>
# capture the digest docker push reports, then:
cd deploy/kubernetes/overlays/beta
kustomize edit set image sentinel43-api=<registry>/sentinel43-api@sha256:<digest>
```
Record which git commit SHA the pushed image was built from (e.g. tag the
image with it, or note it alongside the digest) — this is part of the
evidence retained per §21. A CI job that automates this push+pin step for
beta does not currently exist in `.github/workflows/k8s.yml` (it exists only
for the disposable `dev` overlay/kind-smoke path); until one is added, this
is a manual operator step.

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

Also manual only, via `kubectl cp` off the `s43-api-state` PVC:
```bash
POD=$(kubectl get pod -n sentinel43 -l app=s43-api -o jsonpath='{.items[0].metadata.name}')
kubectl cp sentinel43/$POD:/app/sentinel43_state/audit.sqlite3 ./audit-$(date +%Y%m%d).sqlite3
kubectl cp sentinel43/$POD:/app/sentinel43_state/dead_letter.sqlite3 ./dead-letter-$(date +%Y%m%d).sqlite3
```
**Copying a live SQLite file can capture a torn write.** If the copy needs
to be authoritative (e.g. before a destructive change), quiesce the pod
first: scale `s43-api` to 0, copy, scale back to 1.

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
for the full rationale — note that document's own prose about the
placeholder string is stale relative to the actual YAML above; the YAML is
the source of truth.

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
  the authoritative store), not just from the in-memory buffer.

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
This is a **manual** procedure — it is not run in CI today
(`scripts/k8s_policy_check.py` only statically checks that NetworkPolicy
objects exist and reference real selectors; it does not prove enforcement
at runtime). Run it against your actual cluster's CNI before trusting the
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
- The date and value-source of the last secret rotation
  (`S43_SECRETS_ROTATED_AT`).
- Backup timestamps and their storage location (§11, §12).

## 22. What this runbook does not establish

Completing this runbook, and every check within it passing, demonstrates a
**controlled beta** is correctly configured and operating as designed. It
does **not** by itself establish:

- **Production readiness** — that requires separate operational,
  performance, and support-posture evidence this runbook does not cover.
- **Public-sector readiness** (e.g. CJIS or equivalent compliance) — that
  requires separate compliance review, evidence, and formal authorization
  entirely outside this document's scope.

Do not represent a controlled beta, however well it passes the checks
above, as satisfying either of those tiers.
