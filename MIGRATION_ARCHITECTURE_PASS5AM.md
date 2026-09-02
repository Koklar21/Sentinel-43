# MIGRATION_ARCHITECTURE_PASS5AM.md

Sentinel-43 — Pass 5A-Migration. How Alembic is wired as the authoritative
production schema migration mechanism, and the design decisions behind the
`sessions` migration.

Companion docs: `MIGRATION_BASELINE_PASS5AM.md` (baseline / existing-DB
adoption), `PASS5AM_VALIDATION.md` (test evidence), `HANDOFF_PASS5AM.md`.

Code state: integration branch `integration/beta-hardening-20260901`, on top
of the Pass 5A HEAD `7a72976`.

---

## 1. Scope (mission §2)

This pass **establishes the mechanism and the schema**. It does NOT activate
the new authentication architecture, does NOT wire any `/auth/*` route, does
NOT run migrations against a live database, and does NOT change how the
running Compose stack or the Kubernetes deployment bootstrap the schema
today (those changes are *designed* here and deferred — §6, §7).

New / changed files:

| File | Purpose |
|---|---|
| `alembic.ini` | Alembic config. **No connection string** — env.py reads `DATABASE_URL`. |
| `migrations/env.py` | Async env; combined `target_metadata`; baseline gate; **no app import**. |
| `migrations/script.py.mako` | Revision template. |
| `migrations/baseline.py` | Semantic compatibility check for adopting an existing pre-Alembic DB. |
| `migrations/versions/0001_baseline.py` | Historical anchor — the `users` table. |
| `migrations/versions/0002_sessions.py` | The `sessions` table (Pass 5A foundation). |
| `core/auth/users.py` | + `NAMING_CONVENTION`; `Base` gets a `MetaData(naming_convention=...)`. |
| `core/auth/sessions.py` | `SessionBase` gets the same convention; `refresh_hash` → **partial unique index** (shape B). |
| `requirements.txt` | + `alembic>=1.13`. |
| `core/tests/test_migrations_pg.py` | 25 migration + Alembic-schema session tests. |

`init_models()` / `migration-job.yaml` / `docker-compose.yml` / every `.env*`
— **unchanged** (mission §24, §27, §30).

---

## 2. Directory / config structure (§D)

```
alembic.ini                     # script_location = migrations ; prepend_sys_path = .
migrations/
    __init__.py                 # package, so env.py can `from migrations.baseline import ...`
    env.py
    script.py.mako
    baseline.py
    versions/
        0001_baseline.py        # down_revision = None
        0002_sessions.py        # down_revision = "0001_baseline"
```

Smallest conventional layout. No wrappers, no abstractions. Revision ids are
human `NNNN_slug` (not hashes) so the linear chain is obvious at a glance and
lexically sortable.

Run from the repository root (which is `/app` in the container image):

```
alembic upgrade head              # fresh DB → users, then sessions
alembic stamp 0001_baseline       # existing pre-Alembic DB → adopt (see baseline doc)
alembic downgrade 0001_baseline   # drop sessions (DESTROYS session state)
alembic heads                     # must always print exactly one head
alembic current                   # what revision is this DB at
alembic check                     # autogenerate drift check (CI)
```

---

## 3. Database connection handling (§4)

`migrations/env.py` obtains the URL from **`core.auth.users._database_url()`**
— the exact function the application uses (`DATABASE_URL`,
`postgresql+asyncpg://...`, raises if unset). Therefore:

- **No `sqlalchemy.url` in `alembic.ini`.** The `[alembic]` section has no URL
  key at all.
- Nothing prints the URL. `alembic.ini`'s `sqlalchemy.engine` logger is
  pinned at `WARN` so a connection string / SQL parameters are never echoed.
  `env.py` never `print()`s or logs the URL.
- Usable **unchanged** from: isolated dev (`export DATABASE_URL=...; alembic
  upgrade head`), CI (same), the Compose stack (a one-shot service with the
  same env, §6), the Kubernetes Job (`envFrom` the existing Secret, §7).

Engine: `async_engine_from_config` with `poolclass=NullPool` (a migration
opens one connection, does its work, disposes — no pool needed). Migrations
run via `connection.run_sync(_do_run_migrations)` — the standard Alembic
async pattern.

**Commit correctness note:** the baseline compatibility check
(`_maybe_check_baseline`) runs *inside* `context.begin_transaction()`, not
before it. Running its reflection queries on the bare connection first would
open an implicit transaction that the async→sync adapter never commits,
silently swallowing the migration's own commit. (Found and fixed during
Pass 5AM validation — see `PASS5AM_VALIDATION.md`.)

---

## 4. Metadata / base architecture (§E, §7, §AH)

### 4.1 Two bounded contexts, two `MetaData`

`core.auth.users.Base` owns `users`. `core.auth.sessions.SessionBase` owns
`sessions`. They are **separate `MetaData` instances** — deliberately, and
this pass preserves that:

- `users.init_models()` (`Base.metadata.create_all`) still creates **only
  `users`**. It is untouched. The §7 / Pass 5A boundary — "do not make
  init_models() begin creating sessions" — holds because the sessions table
  is on a different metadata that `init_models()` never touches.
- Verified: `Base.metadata is SessionBase.metadata` → `False`;
  `Base.metadata.tables == {"users"}`.

### 4.2 `target_metadata` for autogenerate — the COMBINED view (§7, §AH)

`env.py` builds a **third**, throw-away `MetaData` (`combined`) purely for
Alembic's `target_metadata`:

```python
def _build_target_metadata() -> MetaData:
    combined = MetaData(naming_convention=NAMING_CONVENTION)
    for md in (Base.metadata, SessionBase.metadata):
        for table in md.tables.values():
            table.to_metadata(combined)          # copies users, then sessions
    sessions = combined.tables.get("sessions")
    if sessions is not None and not sessions.foreign_key_constraints:
        sessions.append_constraint(
            ForeignKeyConstraint(
                ["user_id"], ["users.user_id"],
                ondelete="RESTRICT", name="fk_sessions_user_id_users",
            )
        )
    return combined

target_metadata = _build_target_metadata()
```

Why:

1. **`target_metadata` must include BOTH bases** (mission §7). If it only had
   `Base.metadata`, a future `alembic revision --autogenerate` — *even one
   unrelated to sessions* — would see `sessions` as an unknown table and
   propose `DROP TABLE sessions`. The combined metadata prevents that.
2. **`users` is copied first** so `sessions.user_id`'s foreign key resolves
   against it *inside `combined`* (a cross-`MetaData` string FK cannot
   resolve otherwise).
3. **The FK is reconstructed on the `combined` copy** because the ORM
   `SessionRecord.user_id` is a *plain indexed column with no
   `ForeignKey` object* — that keeps the two ORM metadata objects genuinely
   independent (so `SessionBase.metadata.create_all` still works standalone
   for test helpers, and the §7 boundary is unambiguous). `0002_sessions`
   creates the real FK; `combined` mirrors it so autogenerate sees no
   spurious "drop the FK" diff.

**Result, verified:** with the DB at `head`, `alembic check` reports
*"No new upgrade operations detected."* — the ORM models, the two migrations,
and `target_metadata` all agree (mission §21).

### 4.3 `env.py` does NOT start the application (§23)

`env.py` imports exactly three things: `core.auth.users`
(`NAMING_CONVENTION`, `Base`, `_database_url`), `core.auth.sessions`
(`SessionBase`), and `migrations.baseline`. All three are import-side-effect
free (no DB connection, no FastAPI app, no middleware, no network). It never
imports `core.api.*`. Test `test_env_does_not_import_the_application` deletes
`core.api.main` from `sys.modules`, runs `alembic upgrade head`, and asserts
it did not come back.

---

## 5. Naming convention (§5, §AF)

Applied to **both** metadata objects (`core.auth.users.NAMING_CONVENTION`,
imported into `sessions.py`):

```python
{
  "ix": "ix_%(table_name)s_%(column_0_N_name)s",
  "uq": "uq_%(table_name)s_%(column_0_N_name)s",
  "ck": "ck_%(table_name)s_%(constraint_name)s",
  "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
  "pk": "pk_%(table_name)s",
}
```

Covers pk / fk / uq / ck / ix. Fixed **now**, before revision 0001, because a
`downgrade()` that does `DROP CONSTRAINT <name>` needs a name that is
reproducible across environments and Alembic runs — a Postgres
backend-generated name is not.

Fresh Alembic-created schema uses these names:
`pk_users`, `uq_users_email`, `ix_users_username` (unique),
`pk_sessions`, `fk_sessions_user_id_users`, `ix_sessions_user_id`,
`ix_sessions_prev_refresh_hash`, `ix_sessions_expires_at`,
`uq_sessions_active_refresh_hash`.

**Existing pre-Alembic databases** carry Postgres defaults (`users_pkey`,
`users_email_key`; the username unique index was already `ix_users_username`
by SQLAlchemy's own default, so that one matches). When such a database is
*stamped* at 0001 the names are **not** rewritten — the baseline check
(`migrations/baseline.py`) compares column/constraint *semantics*, not names.
A future dedicated "rename users constraints to the convention" migration can
close that gap; it is **out of scope here** (mission §5) and is recorded in
`HANDOFF_PASS5AM.md §AC`. Until then, `alembic check` against a *stamped*
(not fresh) database will show a `pk_users` / `uq_users_email` rename as
pending — that is expected and documented, not drift in the code.

---

## 6. `refresh_hash` constraint — exact shape (§14, §AG)

**Implemented: SHAPE B.** A PostgreSQL **partial unique index** over the
active (non-revoked) rows only:

```sql
CREATE UNIQUE INDEX uq_sessions_active_refresh_hash
    ON sessions (refresh_hash) WHERE revoked_at IS NULL;
```

In the ORM (`core/auth/sessions.py`):

```python
__table_args__ = (
    Index("uq_sessions_active_refresh_hash", "refresh_hash",
          unique=True, postgresql_where=text("revoked_at IS NULL")),
)
```

Pass 5A originally declared `refresh_hash` as an *unconditional*
`unique=True` (shape A). Pass 5AM changes it to shape B in both the model and
`0002_sessions`, so they agree.

### Why shape B, not shape A

| | Shape A (unconditional UNIQUE) | Shape B (partial UNIQUE WHERE revoked_at IS NULL) |
|---|---|---|
| "one parent generation → ≤1 valid successor" (the Pass 5A concurrency invariant) | enforced | enforced |
| two *active* rows with the same `refresh_hash` | rejected | rejected |
| a *revoked* historical row keeping a hash that a later *active* row also holds | **rejected** — breaks legitimate rotation/replay history | **permitted** |
| accommodates a future multi-row generation-retention design | no | yes |

Sentinel-43's current `rotate_refresh()` mutates a single row in place
(`prev_refresh_hash ← refresh_hash; refresh_hash ← new`), so with 256-bit
random secrets shapes A and B are behaviourally identical for every real
service-layer operation. Shape B is chosen as the more conservative,
future-proof constraint that "constrains only the active/valid state while
preserving historical rows" (mission §14).

### The two verifying tests (mission §33)

- `test_sessions_partial_unique_rejects_second_active` — two rows,
  `revoked_at IS NULL`, same `refresh_hash` → `IntegrityError`. (Would pass
  under both shapes; pins the invariant.)
- `test_sessions_partial_unique_permits_revoked_historical_plus_active` — one
  **revoked** row and one **active** row with the *same* `refresh_hash` →
  both persist. **This fails under shape A and passes under shape B** — it is
  the case that actually distinguishes the two.

(`_lock_session_for_refresh()` also queries `prev_refresh_hash`; that column
is a plain, non-unique index — reuse detection needs to *find* superseded
values, not enforce uniqueness on them.)

---

## 7. User foreign key — RESTRICT (§15, §M)

**Decision path (mission §15), evidence recorded:**

1. **Is user deletion implemented anywhere in `core/`?**
   `grep -rnE '@router\.delete|session\.delete\(.*[Uu]ser|DELETE FROM users'`
   → **no matches.** `core/api/routers/users.py` exposes create / list /
   PATCH(role,is_active) / password-reset — **no delete route.** "Removing" an
   operator is done with `is_active = False` (Pass 3). The only
   `session.delete()` in non-test `core/` is `purge_expired_sessions()`
   deleting *session* rows.

2. → **Case 2: no deletion pathway exists.** Default to
   **`ON DELETE RESTRICT`** — the least-surprising, least-destructive choice
   when there is no existing deletion behaviour to design against. If a user
   `DELETE` is added later, RESTRICT fails closed (the delete errors) rather
   than silently cascading away session rows, forcing the
   cascade-vs-restrict-vs-set-null question to be answered explicitly then.

This is **not** Case 3 (deletion exists but its session interaction is
undefined) — a simple *absence* of deletion is Case 2, so no STOP was
triggered (mission §15).

`0002_sessions` emits
`FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE RESTRICT`, name
`fk_sessions_user_id_users`. Tests: `test_sessions_fk_on_delete_restrict`
(deleting a user with a live session → `IntegrityError`; an orphan
`user_id` insert → `IntegrityError`), `test_sessions_fk_is_restrict_not_cascade`
(reflects `ondelete == "RESTRICT"`).

---

## 8. Indexes on `sessions` — each justified (§16)

| index | columns | supports |
|---|---|---|
| `pk_sessions` | `sid` | primary lookup `get_session_by_sid()` |
| `uq_sessions_active_refresh_hash` (partial unique) | `refresh_hash` WHERE `revoked_at IS NULL` | `_lock_session_for_refresh()` `WHERE refresh_hash = :h` **and** the shape-B uniqueness guard — one index, both jobs |
| `ix_sessions_prev_refresh_hash` | `prev_refresh_hash` | the `OR prev_refresh_hash = :h` arm of `_lock_session_for_refresh()` (single-step reuse detection) |
| `ix_sessions_user_id` | `user_id` | `revoke_all_user_sessions()` and the operator's own "active sessions" list |
| `ix_sessions_expires_at` | `expires_at` | `purge_expired_sessions()` housekeeping scan |

No index on `revoked_at` alone — not justified by any query
(`revoke_all_user_sessions` filters `user_id` first). `expires_at` gains an
index that the Pass 5A model didn't have (a pure addition — the model was
updated to match).

---

## 9. Migration graph (§17)

Exactly one head: `0002_sessions`. Linear chain
`base → 0001_baseline → 0002_sessions`. No branch labels, no merge revisions.

Automated guard: `test_migrations_pg.py::test_single_head`
(`ScriptDirectory.from_config(cfg).get_heads() == ["0002_sessions"]`) and
`test_linear_history`. CI should run `alembic heads` and fail if it prints
more than one line.

---

## 10. Downgrade semantics (§12, §18, §N)

| command | effect | data |
|---|---|---|
| `alembic downgrade 0001_baseline` (or `-1` from head) | `0002_sessions.downgrade()` → `DROP TABLE sessions` (its indexes drop with it). `users` and everything else untouched. | **DESTROYS ALL ACTIVE SESSION STATE.** Documented in the file header and here. |
| `alembic downgrade base` | Runs `0002` downgrade, then hits `0001_baseline.downgrade()` which **`raise RuntimeError(...)`**. PostgreSQL transactional DDL (Alembic default, one transaction for the whole invocation) **rolls the entire thing back** — `users`, `sessions`, and `alembic_version` are all left exactly as they were. | **Nothing lost.** `alembic downgrade base` is a fail-safe no-op. |

`0001_baseline.downgrade()` is intentionally unsupported (mission §12):
reversing it means `DROP TABLE users`, destroying every account. Data safety
over migration symmetry.

Caveat: the `downgrade base` fail-safe relies on the default
transaction-per-invocation. If an operator sets
`transaction_per_migration=True`, `0002`'s drop would commit before `0001`
fails — losing sessions but **still protecting `users`**. Either way `users`
is safe.

Repeatability proven: `test_downgrade_upgrade_repeatable`
(`0001 → head → 0001 → head → 0001 → head`) and
`test_naming_convention_deterministic_across_roundtrip` (constraint/index
names identical before and after a full down/up cycle).

---

## 11. `create_all` / Alembic transition (§24, §O)

**Target:** Alembic is the sole authority for the **production PostgreSQL**
schema.

Current reality and the transition:

| Caller of `init_models()` / `create_all` | Status after Pass 5AM | Future |
|---|---|---|
| `core/api/routers/bootstrap.py` (`/bootstrap/status`, `/bootstrap/admin`) — lazy `await init_models()` | **unchanged** in this pass. Still create-if-missing for `users` only. Harmless: on an Alembic-managed DB the `users` table already exists so `create_all(checkfirst=True)` is a no-op; it never touches `sessions` (different metadata). | A later deployment pass gates it to dev-only, or removes it once `alembic upgrade head` is guaranteed to have run first. |
| `deploy/kubernetes/base/migration-job.yaml` — `python -c "... init_models() ..."` | **unchanged** in this pass (mission §27 — changing it changes deployment behaviour). | Deployment pass: `command: ["alembic", "upgrade", "head"]` (design in §13). |
| `docker-compose.yml` | no migration step today (bootstrap routes do it lazily) | Deployment pass: a one-shot `s43-migrate` service (design in §12). |
| `core/auth/sessions.py::ensure_session_schema()` / `drop_session_schema()` | **test-only helpers**, never called at startup. Retained for ad-hoc local use. | May be removed once all session tests build schema via Alembic. |
| `test_session_layer_pg.py::_db()`, `test_account_transactions_pg.py::_db()` | build schema via `metadata.create_all` — **test isolation**, disposable DBs only. Kept. `test_migrations_pg.py` additionally exercises the session layer on an **Alembic-built** schema (mission §21/§22). | — |

**Rule:** no code path may let Alembic *and* `create_all` both evolve the
*production* schema. Today only Alembic adds new objects; `create_all`
remains solely as an idempotent create-if-missing safety net for the *one*
pre-existing table (`users`) and only via the bootstrap routes. The
deployment pass removes even that overlap.

---

## 12. Compose migration model (§27, §Q) — DESIGN ONLY, not activated

The running local stack is **not touched**. `docker-compose.yml` is **not
modified** in this pass (changing it would alter current behaviour —
mission §27). Proposed future shape:

```yaml
  s43-migrate:
    build: { context: ., dockerfile: core/api/Dockerfile }
    command: ["alembic", "upgrade", "head"]
    environment:
      DATABASE_URL: ${DATABASE_URL}
    depends_on:
      s43-db: { condition: service_healthy }
    profiles: ["migrate"]      # or a gate the api service waits on
    restart: "no"
```

Operator flow: `docker compose run --rm s43-migrate` (or
`docker compose --profile migrate up s43-migrate` and wait for exit 0)
**before** `docker compose up -d s43-api`. The `bootstrap` routes' lazy
`init_models()` stays as a harmless fallback until a later pass removes it.

For an **existing** local database (created by the old `init_models()`):
`docker compose run --rm s43-migrate alembic stamp 0001_baseline` once
(env.py runs the compatibility check), then the normal `upgrade head`.

---

## 13. Kubernetes migration model (§28, §R) — DESIGN ONLY, not deployed

`deploy/kubernetes/base/migration-job.yaml` already implements the right
*shape* — a single-execution `Job`, `restartPolicy: Never`,
`backoffLimit: 3`, its own ServiceAccount and NetworkPolicy, non-root, RO
rootfs, Secret-sourced env. **It is not modified or deployed here**
(mission §28 — no deploy, no CHANGEME replacement).

The one change a deployment pass makes:

```yaml
      containers:
        - name: migrate
          command: ["alembic", "upgrade", "head"]   # was: python -c "... init_models() ..."
```

This satisfies every §28 requirement already:

- **Exactly one migration actor** — one `Job`, not a per-replica init
  container. The API `Deployment` is applied *after* `kubectl wait
  --for=condition=Complete job/s43-migration` (already the documented flow in
  `deploy/kubernetes/README.md`).
- **Failure prevents rollout** — `alembic` exits non-zero on any migration
  error *or* on an incompatible baseline (verified: exit 1 +
  `BaselineIncompatibleError`), the `Job` fails, the operator does not
  proceed to the API `Deployment`.
- **Sanitized logs** — `alembic.ini` pins `sqlalchemy.engine` at WARN; the
  `Job`'s stdout/stderr carry migration step names and, on failure, the
  sanitized `BaselineIncompatibleError` (schema property names only). No
  connection string, no row data (verified).
- **Credentials from Secret refs** — `envFrom: secretRef: sentinel43-secrets`
  (unchanged); `DATABASE_URL` is already a key there.
- **No automatic destructive downgrade** — the `Job` only ever runs `upgrade
  head`. `downgrade` is a deliberate manual `kubectl exec` / one-off Job an
  operator writes, never automated.

Existing k8s database adoption: a one-off `Job` (or `kubectl exec` into a
migrate pod) running `alembic stamp 0001_baseline` once, then the standard
`upgrade head` Job.

---

## 14. Schema-version compatibility design (§26) — DOCUMENTED, not implemented

Future application startup behaviour for a schema/version mismatch. **Not
implemented in Pass 5AM** — mission §26 says do not activate a new startup
refusal mechanism unless required for migration test correctness (it is
not).

| State | Meaning | Preferred future posture |
|---|---|---|
| A. DB `alembic_version` == code's expected head | normal | serve |
| B. DB behind code (`alembic_version` < head) | migration not yet run | **refuse to start** with a clear "run `alembic upgrade head`" message (non-local env); warn in dev |
| C. DB ahead of code (`alembic_version` > head, unknown revision) | a newer deploy migrated; this replica is old | **refuse to start** — an old replica must not run against a newer schema |
| D. no `alembic_version` table, `users` present | pre-Alembic DB never adopted | **refuse** — operator must `alembic stamp 0001_baseline` (which runs the compat check) |
| D'. no `alembic_version`, no `users` | genuinely fresh | dev: allowed (bootstrap `init_models()` today); prod: migration Job must run first |
| E. `users` present but schema-incompatible | wrong DB, or drift | already covered — `migrations/baseline.py` refuses adoption |

Implementation sketch for the deployment pass: a small
`assert_schema_current()` called from `core/api/main.py`'s
`_validate_security_config()` sibling, reading `alembic_version` and
comparing to `alembic.script.ScriptDirectory(...).get_current_head()`. Gated
on `not _is_local_environment()`. **Migration stays an explicit operator /
Job step (§25)** — the app checks, it does not migrate, and no replica races
to migrate.

---

## 15. What this pass does NOT do

- Run any migration against a non-disposable database (mission §15, §38).
- Modify `init_models()`, `migration-job.yaml`, `docker-compose.yml`, or any
  `.env*` (§24, §27, §30).
- Activate a startup schema-version check (§26).
- Touch `/auth/*` routes, `X-S43-Password`, WebSocket auth, service-token
  auth, or the env operator (§30, §31, §32).
- Resolve F-TLS-1, #11, or the `X-S43-Password` retirement (§29, §31, §37).
