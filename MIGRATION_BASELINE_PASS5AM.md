# MIGRATION_BASELINE_PASS5AM.md

Sentinel-43 — Pass 5A-Migration. The pre-Alembic schema inventory, the
`0001_baseline` revision, how an existing Sentinel-43 database is adopted
into Alembic without recreating it, and the drift-refusal behaviour.

Companion: `MIGRATION_ARCHITECTURE_PASS5AM.md`, `PASS5AM_VALIDATION.md`.

---

## 1. Pre-Alembic schema inventory (§6, §F)

**Method.** Inspected: every SQLAlchemy `DeclarativeBase` / `MetaData` in
`core/`, the `User` model, `init_models()`, `create_all()` call sites,
`core/api/routers/bootstrap.py`, tests that create tables, and the full git
history of `core/auth/users.py`. Grepped the whole tree for `.sql` files,
`CREATE TABLE`, `__tablename__`, `metadata.create_all`.

**Finding — the production PostgreSQL schema is exactly one table: `users`.**

- `core.auth.users.Base` → `users`. This is the only persistent production
  table.
- `core.auth.sessions.SessionBase` → `sessions` — **new in Pass 5A, never in
  production** (its own metadata; `init_models()` never creates it).
- `core/sentinel43_core_db.py` and `core/s34_auth/ledger.py` contain
  `CREATE TABLE` but are **separate SQLite files** for dead/standalone code
  paths — `grep` confirms nothing in `core/` imports them and
  `core/api/main.py` does not reference them. Not part of the PostgreSQL
  schema Alembic manages.
- No `.sql` files, no other `__tablename__`, no other `create_all`.

**Finding — the `User` model source IS the historical schema.** The full git
history of `core/auth/users.py` shows the `User` class is **byte-identical**
to its original definition in `fce06d8`. There was never a migration — every
Sentinel-43 database was created by `create_all()` from this exact model. So
"the model" and "what any existing database contains" are the same thing
(the only difference an existing DB has is *constraint names* — see §4).

### 1.1 The `users` table (the 0001 baseline)

| column | type | nullable | notes |
|---|---|---|---|
| `user_id` | `uuid` | NOT NULL | primary key; app-side default `uuid.uuid4` (no server default) |
| `username` | `varchar(128)` | NOT NULL | UNIQUE (via a unique index — model has `unique=True, index=True`) |
| `email` | `varchar(255)` | NULL | UNIQUE |
| `password_hash` | `varchar(255)` | NOT NULL | Argon2id encoded hash |
| `role` | `varchar(32)` | NOT NULL | app-side default `"operator"` (no server default) |
| `is_active` | `boolean` | NOT NULL | app-side default `True` (no server default) |
| `created_at` | `timestamptz` | NOT NULL | app-side default `now()` (no server default) |
| `last_login_at` | `timestamptz` | NULL | |

- **Primary key:** `user_id`.
- **Unique:** `username` (unique index), `email` (unique constraint).
- **Indexes:** the `username` unique index. No other indexes.
- **Server defaults:** none. All defaults are Python-side
  (`mapped_column(default=...)`), so they never appear in DDL and an existing
  DB has none either — consistent.
- **Foreign keys:** none.
- **Check constraints:** none. (The `role IN ('operator','admin')` CHECK is
  finding P3-7 — deferred, needs a live-data inventory; **not** in 0001.)

### 1.2 Constraint / index names

**Fresh Alembic-created** (naming convention, §MIGRATION_ARCHITECTURE §5):
`pk_users`, `uq_users_email`, `ix_users_username`.

**Existing pre-Alembic** (old `create_all`, no convention): `users_pkey`
(Postgres default PK name), `users_email_key` (Postgres default unique name),
`ix_users_username` (SQLAlchemy's own default index name — happens to match).

---

## 2. `0001_baseline` (§8, §H)

`migrations/versions/0001_baseline.py`, `down_revision = None`. Historical
anchor for the schema that existed before `sessions`. Two paths:

### 2.1 FRESH database — `upgrade()` runs

`alembic upgrade head` on an empty database runs `0001_baseline.upgrade()`,
which `op.create_table("users", ...)` + `op.create_index("ix_users_username",
..., unique=True)` — producing exactly §1.1 with the convention names.

Guard: `upgrade()` first checks `inspect(bind).has_table("users")`. If
`users` already exists it **`raise RuntimeError`** telling the operator to
use `alembic stamp 0001_baseline` instead — rather than fail halfway through
a `CREATE TABLE users` that already exists.

**Verified** (`test_fresh_db_upgrade_0001`, `test_fresh_db_upgrade_head`):
the resulting schema is inspected column-by-column, PK and unique
constraints checked semantically, `alembic_version` = the expected revision.
Command exit code alone is not trusted (mission §11).

### 2.2 EXISTING pre-Alembic database — `stamp`, don't `upgrade`

```
alembic stamp 0001_baseline      # env.py runs the compatibility check first
alembic upgrade head             # then only 0002_sessions runs
```

`stamp` writes `alembic_version = 0001_baseline` **without** running
`upgrade()` — the table is not recreated, no data is touched.

`env.py` runs the baseline check automatically whenever it sees a `users`
table and no `alembic_version` table (i.e. exactly this "adopting an
existing DB" moment), for **both** `stamp` and `upgrade`. So a plain
`alembic stamp 0001_baseline` cannot succeed on an incompatible database.

**Verified** (`test_existing_compatible_stamp_then_upgrade`,
`test_user_data_preserved_through_baseline_adoption`): a pre-Alembic `users`
table with **Postgres-default constraint names** and 4 representative rows
(operator / admin / active-with-`last_login_at` / disabled) is stamped and
upgraded; all 4 rows are **byte-identical** before and after, and `sessions`
is created empty.

---

## 3. Baseline compatibility check (§9, §G)

`migrations/baseline.py`. `assert_users_baseline(connection)` — raises
`BaselineIncompatibleError` (fail closed, never stamp anyway) if the
existing `users` table is not semantically compatible with 0001.

Checks (semantics, not names):

- **table exists**
- **every expected column present**, with a compatible **type family**
  (string / uuid / bool / datetime — reflected type mapped to a family, so
  `varchar` vs `text` vs `character varying` all pass; `integer` where a
  string is expected fails)
- **nullability** matches for each column (PK columns exempt — always NOT
  NULL)
- **primary key columns** == `["user_id"]`
- **`username` and `email` are each UNIQUE** — satisfied by a unique
  constraint *or* a single-column unique index (the model produces one of
  each)
- **no unexpected NOT-NULL column without a default** — so a stricter schema
  (e.g. someone added a required column) cannot be silently adopted

Not checked (deliberately — "irrelevant backend-generated" per mission §9):
constraint / index *names*, index presence beyond uniqueness, column order,
comments, storage parameters.

---

## 4. Drift reporting (§10, §J)

On incompatibility the error is a single `BaselineIncompatibleError` whose
message is:

```
This database's existing schema is NOT compatible with the Sentinel-43
0001_baseline and will not be adopted into Alembic. Resolve the differences
below (or point Alembic at the correct database) and retry. Nothing was
changed or stamped.
  - column 'users.role' is missing
  - column 'users.email' is missing its expected UNIQUE constraint/index
  - column 'users.username' is missing its expected UNIQUE constraint/index
```

Report items are of the form: *missing column*, *incompatible type
(expected X, found Y)*, *wrong nullability (expected NULL/NOT NULL, found
...)*, *missing UNIQUE constraint/index*, *unexpected NOT NULL column with no
default*, *primary key columns differ*.

**Never** in the output: row contents, credential/hash values, connection
URLs, secrets, environment variables. **Verified** — a grep of the failing
`alembic` output for `postgresql://`, `:x@`, `password`, `s43t:x` finds
nothing.

`alembic` exits **1** on `BaselineIncompatibleError` (verified) so a CI step
or Kubernetes `Job` fails the rollout.

**Verified** (`test_incompatible_pre_alembic_refused`, parametrized over 4
broken schemas: missing `role`; `username` not unique; `role` wrong
nullability; `password_hash` wrong type): both `alembic stamp` and `alembic
upgrade head` raise, and afterwards there is no `alembic_version` table and
no `sessions` table — nothing was adopted or changed.

---

## 5. `0002_sessions` schema (§13, §K, §L)

`migrations/versions/0002_sessions.py`, `down_revision = "0001_baseline"`.
Implements exactly `core/auth/sessions.py :: SessionRecord` /
`SESSION_MODEL_PASS5A.md` — no speculative fields, **no `role` column**
(role is read from `users` at refresh time).

```sql
CREATE TABLE sessions (
    sid                 uuid          NOT NULL,
    user_id             uuid          NOT NULL,
    refresh_hash        varchar(64)   NOT NULL,
    prev_refresh_hash   varchar(64),
    refresh_generation  integer       NOT NULL,
    issued_at           timestamptz   NOT NULL,
    last_seen_at        timestamptz   NOT NULL,
    rotated_at          timestamptz,
    expires_at          timestamptz   NOT NULL,
    revoked_at          timestamptz,
    revoked_reason      varchar(64),
    client_ip           varchar(45),
    user_agent          varchar(256),
    CONSTRAINT pk_sessions PRIMARY KEY (sid),
    CONSTRAINT fk_sessions_user_id_users
        FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE RESTRICT
);
CREATE INDEX ix_sessions_user_id            ON sessions (user_id);
CREATE INDEX ix_sessions_prev_refresh_hash  ON sessions (prev_refresh_hash);
CREATE INDEX ix_sessions_expires_at         ON sessions (expires_at);
CREATE UNIQUE INDEX uq_sessions_active_refresh_hash
    ON sessions (refresh_hash) WHERE revoked_at IS NULL;   -- shape B (§14)
```

- **PK:** `sid` (`pk_sessions`), app-side `uuid.uuid4`.
- **FK:** `user_id → users.user_id ON DELETE RESTRICT` (`fk_sessions_user_id_users`)
  — see `MIGRATION_ARCHITECTURE_PASS5AM.md §7` for the decision.
- **Uniqueness:** partial unique index over active rows only (shape B) —
  see `MIGRATION_ARCHITECTURE_PASS5AM.md §6`.
- **Indexes:** 4, each justified in `MIGRATION_ARCHITECTURE_PASS5AM.md §8`.
- **Server defaults:** none (all Python-side, matching the model and 0001's
  style).
- **No raw refresh credential column** — only `refresh_hash` /
  `prev_refresh_hash` (SHA-256 hex).

Verified structurally against the ORM: `test_fresh_db_sessions_schema_matches_model`
compares reflected columns and index names to `SessionRecord.__table__`;
`alembic check` reports no diff between the models + migrations and a DB at
`head`.

### 5.1 `0002_sessions` downgrade

`op.drop_table("sessions")` — the table and its four indexes. `users` and
everything else untouched. **DESTROYS ALL ACTIVE SESSION STATE** (stated in
the file header). Verified: `test_downgrade_0002_to_0001`,
`test_downgrade_upgrade_repeatable`.

---

## 6. Compatibility effects (§14 interim report / §L)

- **Additive only.** `0002_sessions` adds one table + one FK *to* `users`
  (Postgres records it on `users` as an inbound reference but does not alter
  `users`' own definition). No column, type, constraint, or index on `users`
  changes.
- **Legacy auth unaffected.** `users` is byte-for-byte what it was;
  `X-S43-Password`, JWT verification, `require_operator` / `require_admin`,
  the login route — none touch `sessions` and none change.
- **`init_models()` unaffected.** Still `Base.metadata.create_all` = `users`
  only.
- **Existing databases:** adopt via `stamp` (compat-checked) then `upgrade`
  — zero data change, `sessions` added empty. A fresh DB gets both tables
  from `alembic upgrade head`.
- **Rollback:** `alembic downgrade 0001_baseline` drops `sessions` (session
  state lost, accounts safe). `alembic downgrade base` fails safe (whole
  transaction rolls back; nothing lost).
- **Deferred, unchanged:** the `users` constraint-name convention gap for
  *stamped* databases (§4; a future rename migration), P3-7 role CHECK,
  P3-8 case-insensitive uniqueness.
