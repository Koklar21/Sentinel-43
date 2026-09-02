# SESSION_MIGRATION_DECISION_PASS5A.md

Sentinel-43 — Pass 5A, Sections 13–15: migration-tooling decision and the
proposed `sessions` schema.

**This is also the mission §14 INTERIM DECISION REPORT.** Pass 5A stops here:
a tool is recommended and the schema is specified and validated against a
disposable PostgreSQL, but **no migration infrastructure, no migration-history
file, and no change to production DB bootstrap has been created.** Crossing
that line requires explicit authorization (see §6).

---

## 1. Where the project is today

- **No migration tool.** Schema creation is
  `core/auth/users.py::init_models()` → `SQLAlchemy Base.metadata.create_all()`
  (idempotent, create-if-missing, no ALTER path).
- `deploy/kubernetes/base/migration-job.yaml` wraps *that exact function* in a
  one-shot `Job` — the README explicitly frames this as "instead of inventing
  a new migration system."
- Docker Compose relies on `init_models()` being called at API startup.
- Queued schema changes beyond `sessions`:
  - P3-7 — `users.role` `CHECK (role IN ('operator','admin'))`
  - P3-8 — case-insensitive uniqueness on `users.username` / `users.email`
    (`citext` or a functional unique index) — needs a live-data collision
    inventory first
  - `AUTH_ARCHITECTURE_PASS4.md` §6 optional: `login_attempts` table (only if
    multi-replica throttle is required), `users.password_changed_at` (optional)
- So the real question is not "sessions table, yes/no" — it is "the project
  needs a real migration mechanism now; which one."

---

## 2. Options evaluated (Section 13)

Evaluated against every criterion the authorization (§13) names:

| criterion | A — Alembic | B — minimal project-native runner |
|---|---|---|
| **SQLAlchemy compatibility** | purpose-built for SQLAlchemy; `target_metadata` wired to `users.Base` + `SessionBase` | agnostic — you run raw `text()` / `asyncpg`; the ORM models and the SQL can silently drift |
| **PostgreSQL support** | native; `inet`, partial indexes, `ON DELETE CASCADE`, `op.execute()` for anything Alembic doesn't model | native (it's your SQL) |
| **Forward migration** | `alembic upgrade head` / `+1` | `python -m core.db.migrate` applies pending files in order |
| **Rollback** | first-class `downgrade()` per revision; `alembic downgrade -1` | forward-only unless you also hand-write `*.down.sql` + a downgrade command |
| **Migration ordering** | revision graph (`down_revision`); detects + refuses divergent heads; supports explicit merges | lexical filename order only; two branches that both add `0003_*` collide silently |
| **State tracking** | `alembic_version` table (single current revision), managed for you | you build + maintain `schema_migrations(version, applied_at)` and decide checksum / tamper policy yourself |
| **CI / testing** | `alembic upgrade head` + `alembic check` (autogenerate drift) in CI catches "model changed, migration missing"; round-trip `upgrade`→`downgrade`→`upgrade` is a standard test | you write every check; no drift detection exists unless you build it |
| **Production deployment** | `alembic upgrade head` slots into the existing `migration-job.yaml` Job pattern + a one-shot Compose service; well-documented failure/retry behaviour | same shape (`python -m core.db.migrate`), but the failure/partial-apply/lock semantics are yours to get right |
| **Operational complexity** | one-time setup (`alembic.ini`, `env.py`, baseline stamp) + contributors learn the revision workflow; after that it's a solved problem | trivial today; every added migration and every new contributor grows the maintenance surface of *your* tool (checksums, partial-failure recovery, "applied but file edited", dry-run, squash) |
| **Dependency** | adds `alembic` (+ `Mako`); SQLAlchemy already present | none |
| **Autogenerate** | `alembic revision --autogenerate` diffs models vs DB | none — every change is hand-written SQL |
| **Async** | `alembic init -t async` — matches `create_async_engine` | trivial |

### Option C — status quo (`create_all` only)

Rejected. `create_all` cannot add a column, a constraint, or an index to an
existing table, cannot be rolled back, and gives no ordering or history. P3-7
alone (a CHECK on an existing column) is impossible with it. Not viable.

---

## 3. Recommendation — **Alembic** (Option A)

Reasoning:

1. **There is already a migration backlog** (`sessions`, P3-7, P3-8, maybe
   `login_attempts`). A bespoke runner is "minimal" only at n=1. At n≥3, with
   more than one contributor, Alembic's revision graph, `downgrade()`, and
   autogenerate drift-check are exactly the things a hand-rolled runner keeps
   re-learning the hard way.
2. **Alembic *is* the minimal correct choice for SQLAlchemy.** Choosing it is
   not "inventing a migration system" — it is adopting the standard one. The
   repo's minimalism argument cuts the other way: writing and maintaining
   `core/db/migrate.py` is more bespoke surface than `alembic.ini` + generated
   `env.py`.
3. **The operational pattern already exists.** `migration-job.yaml` runs a
   one-shot migration step before the API serves traffic. Swapping
   `init_models()` → `alembic upgrade head` is a small, documented change to a
   file that already exists for this purpose; Compose gets an equivalent
   one-shot service or an entrypoint guard.
4. **Autogenerate is a real safety net here** — the models are the source of
   truth (`User`, and now `SessionRecord`), and `--autogenerate` will flag a
   model change that lacks a migration in CI.
5. **Baseline is cheap**: one initial revision whose `upgrade()` is the
   current `create_all` output for `users` (so a fresh DB and an existing
   deployed DB converge), applied to existing deployments via
   `alembic stamp <baseline>` after verifying their `users` table already
   matches.

Where Option B would win — a project that will realistically only ever have
one or two migrations, single maintainer, no CI — is not this project.

---

## 4. Proposed `sessions` schema (Section 15) — production DDL

The SQLAlchemy model (`core/auth/sessions.py::SessionRecord`) is the source of
truth; this is the equivalent hand-written DDL an Alembic `upgrade()` would
emit, with the PostgreSQL-specific refinements the portable ORM types don't
express:

```sql
CREATE TABLE sessions (
    sid                 uuid         PRIMARY KEY,
    user_id             uuid         NOT NULL
                                     REFERENCES users(user_id) ON DELETE CASCADE,
    refresh_hash        text         NOT NULL,
    prev_refresh_hash   text,
    refresh_generation  integer      NOT NULL DEFAULT 0,
    issued_at           timestamptz  NOT NULL DEFAULT now(),
    last_seen_at        timestamptz  NOT NULL DEFAULT now(),
    rotated_at          timestamptz,
    expires_at          timestamptz  NOT NULL,
    revoked_at          timestamptz,
    revoked_reason      varchar(64),
    client_ip           inet,                 -- ORM model uses varchar(45); inet in prod
    user_agent          varchar(256)
);

CREATE UNIQUE INDEX ux_sessions_refresh_hash        ON sessions (refresh_hash);
CREATE INDEX        ix_sessions_prev_refresh_hash   ON sessions (prev_refresh_hash)
                                                    WHERE prev_refresh_hash IS NOT NULL;
CREATE INDEX        ix_sessions_user_id_live        ON sessions (user_id)
                                                    WHERE revoked_at IS NULL;
CREATE INDEX        ix_sessions_expires_at          ON sessions (expires_at);
```

Notes:

- `sid` is generated application-side (`uuid4`), mirroring `users.user_id`; no
  `gen_random_uuid()` / `pgcrypto` dependency.
- `ON DELETE CASCADE`: deleting a user removes their sessions. Additive and
  non-destructive to `users`.
- Partial index `WHERE revoked_at IS NULL` keeps the hot "a user's live
  sessions" lookup small.
- The `create_all` form (used by the disposable-PG tests) produces plain
  (non-partial) indexes and `varchar(45)` for `client_ip`; the rotation /
  reuse / concurrency semantics under test do not depend on the difference.
  The Alembic migration must use the DDL above, not `create_all`.
- `refresh_hash`/`prev_refresh_hash` are declared `text` in prod (hash length
  is fixed at 64 by the app; no need to constrain in DDL) vs `String(64)` in
  the ORM — harmless.

### 4.1 Rollback

`downgrade()` = `DROP TABLE sessions;`. Safe: the table is additive, nothing
else references it, and in Pass 5A/early-5B nothing writes to it in
production. Once browser sessions are *live*, a rollback also means reverting
the `/auth/*` route code that depends on it — standard coupled
code+schema rollback, called out in the Pass 5B plan.

### 4.2 Deployment procedure (for the migration pass — NOT executed here)

1. Add `alembic` to `requirements*.txt`; `alembic init -t async migrations`.
2. Author revision `0001_baseline` (current `users` schema) and
   `0002_sessions` (DDL above).
3. Existing deployments: verify `users` matches baseline, then
   `alembic stamp 0001_baseline`.
4. `migration-job.yaml`: `command: ["alembic", "upgrade", "head"]`.
   Compose: a one-shot `s43-migrate` service (`profiles: [migrate]` or
   `depends_on` gate) running the same; API startup stops calling
   `init_models()` for schema creation (or keeps it as a no-op safety net
   guarded to dev only).
5. `kubectl wait --for=condition=Complete job/s43-migration` before the API
   Deployment is expected to serve a fresh DB (already the documented flow).
6. Roll back with `alembic downgrade -1` (+ revert coupled route code once
   sessions are live).

### 4.3 PostgreSQL version / isolation assumptions (Section 15)

- Validated against **PostgreSQL 16.3** (matches `docker-compose.yml` and the
  k8s `postgres:16.3` StatefulSet image).
- Default isolation **READ COMMITTED**. The session layer's correctness
  (§SESSION_MODEL_PASS5A §5) needs only:
  (a) `SELECT … FOR UPDATE` blocks a second writer until the first commits;
  (b) READ COMMITTED re-checks the lock predicate against the latest committed
  row version (EvalPlanQual).
  It does **not** require SERIALIZABLE and adds no advisory-lock dependency
  (unlike the `users` first-admin invariant, which does use
  `pg_advisory_xact_lock`).
- `inet`, partial indexes, `ON DELETE CASCADE`: all standard PostgreSQL, no
  extension required.

---

## 5. What Pass 5A validated without creating migration state

- `SessionBase.metadata.create_all` against disposable `postgres:16.3`
  (`--rm --tmpfs`, `127.0.0.1:55433`, torn down) — schema stands up, unique
  constraint enforced, FK-less `user_id` (logical) exercised against real
  `users` rows.
- 17 rotation / reuse / revocation / logout / concurrency tests
  (`test_session_layer_pg.py`) — **17 passed**.
- The schema exists **only** in `core/auth/sessions.py` as an ORM model on an
  isolated `MetaData`, and in the test setup. `init_models()` is unchanged;
  `git grep` confirms nothing imports `sessions` at app-startup scope.

---

## 6. MANDATORY STOP (mission §14, §30)

**Pass 5A does NOT cross into any of the following. Each requires explicit
authorization:**

- Adding `alembic` (or any migration dependency) to requirements.
- Creating `alembic.ini`, `migrations/env.py`, `migrations/versions/*`, or any
  equivalent bespoke runner + `schema_migrations` table.
- A migration-history file of any kind entering the repository.
- Changing `core/auth/users.py::init_models()`.
- Changing `deploy/kubernetes/base/migration-job.yaml` or `docker-compose.yml`
  bootstrap behaviour.
- Creating the `sessions` table in any non-disposable / repository-tracked
  database or migration state.

**Decision requested from the mission owner:** approve **Alembic** (§3) as the
Sentinel-43 migration tool, and authorize a dedicated migration pass to (a)
introduce Alembic + the `0001_baseline` stamp, then (b) add `0002_sessions`
(§4). P3-7 / P3-8 can ride the same pass or a later one.
