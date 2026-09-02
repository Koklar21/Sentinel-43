# MIGRATION_DEPLOYMENT_BETA.md

Beta-execution Phase 1 — Alembic wired into the supported beta deployment as
the single, ordered, one-shot schema step, plus the runtime schema-version
gate and the backup/restore recovery proof.

Companions: `MIGRATION_ARCHITECTURE_PASS5AM.md` (design), `BETA_EXECUTION.md`
(checkpoint).

---

## 1. What changed

| File | Change |
|---|---|
| `docker-compose.yml` | New one-shot `s43-migrate` service (`alembic upgrade head`); `s43-api` now `depends_on: s43-migrate: service_completed_successfully` (and still `s43-db: service_healthy`). `s43-setup`'s `generate_secrets.py` path corrected to `core/scripts/…` (finding A5). |
| `deploy/kubernetes/base/migration-job.yaml` | Job command `python -c "… init_models() …"` → `["alembic","upgrade","head"]`. Comment rewritten for the fresh / adopt / incompatible cases. |
| `core/auth/schema_version.py` | **New.** Runtime schema-revision check: compares `alembic_version` to the single head shipped in `migrations/versions/`. States: `ok / behind / ahead / unstamped / fresh / unreachable / n/a`. |
| `core/api/main.py` | `GET /ready` (readiness) now returns **503** when `schema_version` reports the DB is not at head, in a non-local environment. `GET /health` (liveness) unchanged — never touches the DB. |
| `core/auth/users.py` | `init_models()` is a **no-op in non-local environments** (`_schema_is_alembic_managed()`), so `create_all` can never race the migration Job. `S43_SCHEMA_CREATE_ALL=true` overrides. |
| `deploy/kubernetes/README.md`, `s43-api-deployment.yaml` | Migration section + probe comments updated. |

No change to: the two metadata objects, `0001_baseline` / `0002_sessions`,
the refresh-hash shape-B index, the `ON DELETE RESTRICT` FK, any `/auth/*`
route, `X-S43-Password`, the WebSocket contract, or any service-identity
verifier.

---

## 2. Ordering (Compose)

```
s43-db  (healthcheck: pg_isready)
   │  service_healthy
   ▼
s43-migrate  ── alembic upgrade head ── exits 0
   │  service_completed_successfully
   ▼
s43-api  (also waits on s43-redis healthy, s43-core started)
```

`s43-core` (Watchtower) starts in parallel with `s43-migrate` — it does not
own any `users` / `sessions` schema. `alembic upgrade head` is **idempotent**:
on a database already at head it is a no-op, so `s43-migrate` runs on every
`docker compose up` with no downside.

### Ordering (Kubernetes)

`base/migration-job.yaml` is the single actor. Operator flow
(`deploy/kubernetes/README.md`):

```
kubectl apply -k deploy/kubernetes/overlays/<dev|beta>
kubectl wait --for=condition=Complete job/s43-migration -n sentinel43 --timeout=120s
# only then is the s43-api Deployment expected to serve
```

Defence in depth: every `s43-api` pod's **readiness** probe returns 503 while
its database is behind/ahead/unstamped, so `RollingUpdate` (with
`maxUnavailable: 0`) will not route traffic to a replica pointed at an
un-migrated DB even if the Job ordering is skipped.

---

## 3. Fresh vs existing database

| Case | Behaviour | Operator action |
|---|---|---|
| **Fresh** (new volume / PVC) | `0001_baseline` creates `users`, `0002_sessions` creates `sessions`. | none |
| **Existing pre-Alembic** (`users` from the old `create_all`, no `alembic_version`) | `s43-migrate` **fails** — `0001_baseline.upgrade()` refuses to CREATE an existing `users`. `env.py` first runs `migrations/baseline.py`'s **semantic** compatibility check. | `docker compose run --rm s43-migrate alembic stamp 0001_baseline` (k8s: a one-off pod, same image + `envFrom`), then bring the stack up. |
| **Incompatible** existing schema (missing column, wrong type/nullability, missing uniqueness) | `assert_users_baseline` raises `BaselineIncompatibleError`; `alembic` exits 1; the Job/service fails; rollout is blocked. Message names the drifting **columns only** — no row data, credentials, or connection string. | fix the DB or point Alembic at the right one; retry. Nothing was stamped or changed. |

Verified on disposable PostgreSQL 16.3:
`core/tests/test_migrations_pg.py` (fresh, adopt, ×4 incompatible-refusal,
downgrade, data-preservation) and `core/tests/test_schema_version_pg.py`
(ok / behind / ahead / unstamped / fresh / n/a + the `/ready` 503 wiring).

---

## 4. Runtime schema-version gate

`core/auth/schema_version.py :: schema_report()`:

- Reads `to_regclass('public.alembic_version')` / `'public.users'` and
  `SELECT version_num FROM alembic_version` on one pooled connection.
- Compares `version_num` to `ScriptDirectory(...).get_heads()` (must be
  exactly one) and its full ancestry.
- `serving_blocked` is **only ever True** in a non-local environment
  (`SENTINEL_ENV` not in dev/local/test) with the check enabled
  (`S43_SCHEMA_VERSION_CHECK`, default on outside local).

`GET /ready`:

```
schema at head          → 200 {"status":"ready","service":"sentinel-43-api"}
schema behind/ahead/…    → 503 {"status":"not_ready","reason":"schema_version",
                                "schema_state":"behind","detail":"… run `alembic upgrade head`"}
local env / no DATABASE_URL → always 200
```

`GET /health` is unchanged and never calls this — a schema mismatch or a DB
outage must not restart pods.

**Not implemented (out of scope, documented):** an in-process revoked-`sid`
LRU / short poll to bound *access-token* revocation below 15 min
(MIGRATION_ARCHITECTURE_PASS5AM §14 / AUTH_ARCHITECTURE_PASS4 §3.3). The
readiness gate is about *schema*, not sessions.

---

## 5. Backup / restore — recovery proof

Rollback is **not** "always harmless". `alembic downgrade 0001_baseline`
drops `sessions` and **destroys every active session**. `alembic downgrade
base` is a fail-safe no-op (transactional DDL rolls back at `0001`'s
unsupported downgrade). The real recovery path for a bad migration is
**restore a backup taken before it**, not a downgrade.

Procedure (Compose; k8s equivalent in `deploy/kubernetes/README.md`):

```bash
# BACKUP — before any migration on an existing beta database
docker compose exec s43-db pg_dump -U s43 -Fc s43 > s43-$(date +%Y%m%dT%H%M%S).dump

# RESTORE — into a FRESH database, then repoint / swap
docker compose exec s43-db createdb -U s43 s43_restore
docker compose exec -T s43-db pg_restore -U s43 -d s43_restore < s43-YYYYmmddTHHMMSS.dump
# verify, then rename: DROP DATABASE s43; ALTER DATABASE s43_restore RENAME TO s43;
```

**Proven** (`core/tests/test_backup_restore_pg.py`, real `pg_dump` → restore
into a separate database):

- every `users` row restores with identity + security columns unchanged
  (`username`, `role`, `is_active`, hashes, timestamps);
- every `sessions` row restores, including `refresh_generation`,
  `revoked_at`, `revoked_reason`;
- **a session revoked before the backup restores as revoked** —
  `SessionRecord.is_live()` returns `False`. A restore is not a way to
  resurrect a logged-out or theft-revoked session. (A restore *does* bring
  back sessions that were live at backup time; that is expected — the
  operator revokes any that should not survive, e.g. via
  `revoke_all_user_sessions`.)
- `alembic_version` restores at `0002_sessions`, so the restored database is
  immediately consistent with the running code.

---

## 6. `create_all` → Alembic transition status

| Path | Before | After Phase 1 |
|---|---|---|
| `core/api/routers/bootstrap.py` lazy `init_models()` | ran `create_all` on every `/bootstrap/*` request | still calls `init_models()`, which is now a **no-op** in non-local envs (logs and returns). Local/test: still create-if-missing. |
| `deploy/kubernetes/base/migration-job.yaml` | `python -c "… init_models() …"` | `alembic upgrade head` |
| `docker-compose.yml` | no migration step (bootstrap routes did it lazily) | `s43-migrate` one-shot before `s43-api` |
| `core/auth/sessions.py::ensure_session_schema()` | test-only, never at startup | unchanged (test-only) |
| test suites (`test_session_layer_pg`, `test_account_transactions_pg`) | build schema via `metadata.create_all` on disposable DBs | unchanged — isolated test use, justified |

There is now **no environment** in which `create_all` and Alembic both evolve
the production schema. A future pass may delete the bootstrap `init_models()`
call entirely once every supported path is Alembic-first.
