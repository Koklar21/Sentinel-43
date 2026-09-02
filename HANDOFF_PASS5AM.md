# HANDOFF_PASS5AM.md

Sentinel-43 — Pass 5A-Migration handoff. Alembic established as the
authoritative production schema migration mechanism; `0001_baseline` +
`0002_sessions` authored and validated against disposable PostgreSQL.
Structured per authorization §40 (sections A–AH).

**This pass does NOT begin Pass 5B, does NOT wire any `/auth/*` route, does
NOT run against a live database, and does NOT deploy anything.** Stop after
this document and await explicit authorization (§41).

Companion docs: `MIGRATION_ARCHITECTURE_PASS5AM.md`,
`MIGRATION_BASELINE_PASS5AM.md`, `PASS5AM_VALIDATION.md`.

---

## A. Verified starting state

| | |
|---|---|
| Working clone | `C:\Users\heero\Sentinel-43-work` (non-synced; `origin` + `evidence-local` push disabled) |
| Branch | `integration/beta-hardening-20260901` |
| HEAD at start | `7a729764aa9f38f60ef3bd28d4829d389e5de544` (`7a72976`) — the verified Pass 5A HEAD in the recovery bundle |
| `git status` | clean |
| `git fsck --full` | no missing / broken / corrupt / error lines — only benign dangling objects (Pass 0 recovery extraction + earlier-pass rebases) |
| merge-base with `origin/main` | `8d2b80f` (== `origin/main`) |
| Original OneDrive repo | untouched — HEAD `e859b61`, clean |
| Pass 5A recovery bundle | present, `git bundle verify` → "records a complete history", HEAD `7a72976` |
| Pass 5A full-suite baseline | 360 passed (recorded `PASS5A_VALIDATION.md §7`) |
| Pass 5A security-invariant baseline | 13/13 — **re-confirmed** in this pass after the §5 model change |
| Pre-work recovery snapshot | `…\sentinel43-recovery\pass5am-20260901\sentinel43-integration-pass5am-PRE.bundle` created before any change |

No repository state was repaired. Starting state matched the authorization
exactly.

## B. Ending commit

`git log` on `integration/beta-hardening-20260901` — the Pass 5AM commit
chain on top of `7a72976` (§AC lists the logical split). Working tree clean.
Branch **not pushed**. Original OneDrive repo still `e859b61`.

## C. Exact Alembic version

**`alembic 1.19.1`** (installed into `.venv-pass1`; `requirements.txt` pins
`alembic>=1.13`). SQLAlchemy 2.0.52, asyncpg 0.31.0, psycopg 3.3.5 (sync
inspection in the migration test only).

## D. Alembic directory / config structure

```
alembic.ini                              # script_location=migrations ; prepend_sys_path=. ; path_separator=os
                                         # NO sqlalchemy.url  (env.py reads DATABASE_URL)
                                         # sqlalchemy.engine logger pinned WARN (no URL/param echo)
migrations/
    __init__.py                          # package, so env.py can import migrations.baseline
    env.py                               # async; combined target_metadata; baseline gate; NO app import
    script.py.mako
    baseline.py                          # semantic compatibility check for adopting an existing DB
    versions/
        0001_baseline.py                 # down_revision=None  — the `users` table
        0002_sessions.py                 # down_revision="0001_baseline" — the `sessions` table
```

Smallest conventional layout, no wrappers. Details:
`MIGRATION_ARCHITECTURE_PASS5AM.md §2`.

## E. Metadata / base architecture

- `core.auth.users.Base` → `users` ; `core.auth.sessions.SessionBase` →
  `sessions`. **Separate `MetaData` instances** — preserved. `Base.metadata
  is SessionBase.metadata` → `False`; `init_models()`
  (`Base.metadata.create_all`) still builds **only `users`**.
- Both metadata objects carry the **same `NAMING_CONVENTION`** (defined in
  `users.py`, imported into `sessions.py`).
- `env.py` builds a throw-away **combined** `MetaData` (via `Table.to_metadata`,
  `users` first) for `target_metadata`, and reconstructs the
  `fk_sessions_user_id_users` FK on the combined `sessions` copy so
  autogenerate has the full, faithful picture. See §AH.
- `alembic check` with the DB at `head` → **"No new upgrade operations
  detected."**

## F. Pre-Alembic schema inventory

The production PostgreSQL schema is **exactly one table: `users`**
(`core.auth.users.Base`). The `User` model is **byte-identical to its
original definition** (git-verified back to `fce06d8`) — the model source IS
the historical schema; there was never a migration, only `create_all()`.
`sessions` is new (Pass 5A), never in production.
`core/sentinel43_core_db.py` / `core/s34_auth/ledger.py` are separate SQLite
files for dead code, not part of this schema. Full column/type/constraint
table: `MIGRATION_BASELINE_PASS5AM.md §1`.

## G. Baseline validation mechanism

`migrations/baseline.py :: assert_users_baseline(connection)` — raises
`BaselineIncompatibleError` (fail closed) if the existing `users` table is
not **semantically** compatible with 0001: checks table + every column
(presence, type family, nullability), PK columns == `["user_id"]`, `username`
and `email` each UNIQUE (constraint *or* unique index), and no unexpected
NOT-NULL-without-default column. Compares **semantics, not names**
(Postgres-default `users_pkey` / `users_email_key` are accepted).
`env.py` invokes it automatically when a `users` table exists and no
`alembic_version` table does — for both `stamp` and `upgrade`.

## H. `0001_baseline` behavior

- **Fresh DB** (`alembic upgrade head`): `upgrade()` creates `users` with the
  convention names (`pk_users`, `uq_users_email`, `ix_users_username`
  unique). Guarded: refuses if `users` already exists (points operator to
  `stamp`).
- **Existing DB**: `alembic stamp 0001_baseline` — writes the version row,
  does not run `upgrade()`, does not touch the table.
- **`downgrade()`**: `raise RuntimeError` — intentionally unsupported
  (dropping `users` destroys every account). Mission §12.

## I. Existing-DB stamp procedure

```
export DATABASE_URL=postgresql+asyncpg://…            # the app's own var
alembic stamp 0001_baseline    # env.py runs assert_users_baseline() first;
                               #   refuses (exit 1) on any incompatibility
alembic upgrade head           # only 0002_sessions runs -> `sessions` created empty
```

Verified with a pre-Alembic `users` (Postgres-default constraint names) + 4
representative rows: stamped, upgraded, **all rows byte-identical
before/after**. `MIGRATION_BASELINE_PASS5AM.md §2.2`.

## J. Drift-refusal behavior

Incompatible existing schema → `BaselineIncompatibleError` with a **sanitized**
multi-line report (schema property names only — *missing column*,
*incompatible type (expected X, found Y)*, *wrong nullability*, *missing
UNIQUE constraint/index*, *PK columns differ*, *unexpected required
column*). **Never** row data / hashes / URLs / secrets — grep-verified.
`alembic` **exits 1**. Nothing is stamped or changed. Verified ×4 (missing
`role`; `username` not unique; `role` nullability; `password_hash` type).

## K. `0002_sessions` schema

`sessions(sid uuid PK, user_id uuid NOT NULL, refresh_hash varchar(64) NOT
NULL, prev_refresh_hash varchar(64), refresh_generation integer NOT NULL,
issued_at/last_seen_at/expires_at timestamptz NOT NULL, rotated_at/revoked_at
timestamptz, revoked_reason varchar(64), client_ip varchar(45), user_agent
varchar(256))`. **No `role` column** (role comes from `users` at refresh
time). No raw refresh credential stored. Full DDL:
`MIGRATION_BASELINE_PASS5AM.md §5`. Matches `SessionRecord` exactly
(`alembic check` clean; structural test).

## L. PK / FK / unique / index decisions

| object | decision |
|---|---|
| `pk_sessions` | PK on `sid` (app-side `uuid4`) |
| `fk_sessions_user_id_users` | `user_id → users.user_id` **ON DELETE RESTRICT** (§M) |
| `uq_sessions_active_refresh_hash` | **partial** unique index on `refresh_hash` **WHERE `revoked_at IS NULL`** — SHAPE B (§AG) |
| `ix_sessions_user_id` | `revoke_all_user_sessions()` + operator session list |
| `ix_sessions_prev_refresh_hash` | reuse-detection lookup (`OR prev_refresh_hash = :h`) |
| `ix_sessions_expires_at` | `purge_expired_sessions()` scan |

Each index justified in `MIGRATION_ARCHITECTURE_PASS5AM.md §8`. No index on
`revoked_at` alone (not justified).

## M. User deletion / FK rationale

Mission §15 decision path: **grep confirms NO user-deletion pathway exists
anywhere in `core/`** (no `@router.delete`, no `session.delete()` of a
`User`, no raw `DELETE FROM users`; "removal" = `is_active = False`). →
**Case 2** → default to **`ON DELETE RESTRICT`** (least-surprising,
least-destructive; fails closed if deletion is added later without
revisiting this). Not Case 3, no STOP. Full reasoning:
`MIGRATION_ARCHITECTURE_PASS5AM.md §7`.

## N. Downgrade semantics

| command | effect | data safety |
|---|---|---|
| `alembic downgrade 0001_baseline` (or `-1`) | `DROP TABLE sessions` (+ its indexes). `users` untouched. | **DESTROYS ALL ACTIVE SESSION STATE**; accounts safe |
| `alembic downgrade base` | `0002` downgrade then `0001` `RuntimeError`; **transactional DDL rolls everything back** | fail-safe no-op — nothing lost |

Repeatability proven (`0001↔head` ×3; constraint names identical across the
round-trip). `MIGRATION_ARCHITECTURE_PASS5AM.md §10`.

## O. `create_all` / Alembic transition

**Alembic is the sole authority for the production PostgreSQL schema.**
`init_models()` / `bootstrap` lazy `create_all` and `migration-job.yaml`'s
`init_models()` invocation are **unchanged in this pass** (§27 / §30) — they
remain an idempotent create-if-missing safety net for the *one* pre-existing
table (`users`) and never touch `sessions` (different metadata). A later
**deployment pass** swaps `migration-job.yaml` to `alembic upgrade head`,
adds the Compose one-shot migrate step, and gates/removes the bootstrap
`init_models()`. Full table: `MIGRATION_ARCHITECTURE_PASS5AM.md §11`.

## P. Schema-version operational design

Documented, **not implemented** (§26): future startup behaviour for DB
at/behind/ahead of code, no `alembic_version` table, incompatible
pre-Alembic. Preferred posture — the app **refuses** an unsafe mismatch in
non-local environments; migration stays an explicit operator/Job step; no
replica races to migrate. Sketch: `assert_schema_current()` reading
`alembic_version` vs `ScriptDirectory.get_current_head()`, gated on
`not _is_local_environment()`. `MIGRATION_ARCHITECTURE_PASS5AM.md §14`.

## Q. Compose migration plan

**Design only — `docker-compose.yml` not modified** (§27). Proposed: a
`s43-migrate` one-shot service (`command: ["alembic","upgrade","head"]`,
`DATABASE_URL` from env, `depends_on: s43-db healthy`, `profiles: [migrate]`)
run before `s43-api`. Existing local DB: `alembic stamp 0001_baseline` once,
then normal upgrades. `MIGRATION_ARCHITECTURE_PASS5AM.md §12`.

## R. Kubernetes migration plan

**Design only — nothing deployed, no CHANGEME replaced** (§28).
`deploy/kubernetes/base/migration-job.yaml` already has the right shape
(single-execution `Job`, `restartPolicy: Never`, own SA + NetworkPolicy,
non-root, RO rootfs, Secret env). The deployment pass changes exactly one
line: `command: ["alembic","upgrade","head"]`. This already satisfies every
§28 requirement — one actor, failure blocks rollout (`alembic` exits 1),
sanitized logs (WARN engine logger; sanitized `BaselineIncompatibleError`),
Secret-sourced creds, no per-replica migration, no auto destructive
downgrade. `MIGRATION_ARCHITECTURE_PASS5AM.md §13`.

## S. Fresh-DB test results

`test_fresh_db_upgrade_0001` — `alembic upgrade 0001_baseline` on an empty
disposable PG → `users` present, `sessions` absent, schema **inspected**
(columns, types, nullability, PK cols, `username`+`email` uniqueness),
`alembic_version = 0001_baseline`.
`test_fresh_db_upgrade_head` + `test_fresh_db_sessions_schema_matches_model`
— `head` → `users` + `sessions`; `sessions` columns and the exact 4 index
names match `SessionRecord.__table__`; no `role` column. **PASS.**

## T. Existing-DB stamp / upgrade results

`test_existing_compatible_stamp_then_upgrade` — pre-Alembic `users`
(Postgres-default names) + 4 rows → stamp → upgrade → `sessions` empty, 4
rows intact, version `0002_sessions`.
`test_user_data_preserved_through_baseline_adoption` — every
identity/security field of every representative user (operator / admin /
active-with-`last_login_at` / disabled) **byte-identical** before and after.
**PASS.**

## U. Intentional-drift refusal results

`test_incompatible_pre_alembic_refused` (parametrized ×4) — missing `role` /
`username` not unique / `role` wrong nullability / `password_hash` wrong type
→ both `alembic stamp` and `alembic upgrade head` raise
`BaselineIncompatibleError`; afterwards no `alembic_version`, no `sessions`.
**PASS.** No auto-repair, no stamp-anyway.

## V. Downgrade / re-upgrade results

`test_downgrade_0002_to_0001` (sessions gone, users + version intact),
`test_downgrade_upgrade_repeatable` (`0001→head` ×3),
`test_baseline_downgrade_to_base_refused_and_rolls_back` (RuntimeError; whole
transaction rolls back; `users` + `sessions` + version unchanged),
`test_naming_convention_deterministic_across_roundtrip` (constraint/index
names identical before/after; names follow the convention). **PASS.**

## W. Alembic-created session-layer results

`test_session_primitives_layer_on_alembic_schema` — create / rotate /
single-step-reuse-revoke / idempotent-logout against a schema built by
`alembic upgrade head`. **PASS.** Model and migration agree behaviourally.

## X. Concurrency results (on the Alembic-created schema)

`test_concurrent_refresh_one_successor_on_alembic_schema[2,5]` — 2 and 5
simultaneous refreshes with the same credential → **exactly one** `ROTATED`
(generation → 1), the rest `RefreshReuseError`, session
`refresh_reuse`-revoked. `test_refresh_vs_logout_and_disablement_on_alembic_schema`,
`test_expiry_vs_refresh_on_alembic_schema` — pass. **"Never more than one
valid successor refresh generation" holds** — enforced by the shape-B
partial unique index + `SELECT … FOR UPDATE`.

## Y. Complete regression results

- `test_migrations_pg.py` — **25 passed** (disposable `postgres:16.3`).
- Session/account/user suites re-run after the §5 model change —
  **98 passed** (`test_session_primitives` 29, `test_session_layer_pg` 19,
  `test_service_identity_separation` 12, `test_account_transactions_pg` 9,
  `test_users_admin` 25, `test_bootstrap_isolated` 4).
- Full isolated suite (`-rsxX`, PG DSN set, `test_bootstrap.py` /
  `test_system_smoke.py` excluded per the standing rule): **385 collected /
  385 passed / 0 failed / 0 errors / 0 skipped / 0 xfail / exit 0** in
  857.47 s (Pass 5A baseline 360 + the 25 `test_migrations_pg.py` tests). 5
  warnings, all the pre-existing `StarletteDeprecationWarning`. Detail +
  the `sys.modules` pollution fix that a first run surfaced:
  `PASS5AM_VALIDATION.md §6.3` / §7.

## Z. Security-invariant results

Security-invariant script — **13/13** (re-run after the §5 model change): /v1
scope/role separation, /users admin gate, Watchtower auth + probe openness,
users router mounted. Service-identity separation
(`test_service_identity_separation.py`) 12 passed. Firewall / proxy-trust /
`:9100` / fail-closed startup / first-admin advisory lock / malformed-hash
fail-closed / event-loop Argon2 / login throttle / legacy JWT /
X-S43-Password / WebSocket — green in the full-suite run.

## AA. F-TLS-1 status

**UNCHANGED — still BLOCKING for production browser-session cutover.** Not
touched in this pass (persistence infrastructure only). No ad-hoc TLS added
to FastAPI/uvicorn. Full detail: `AUTH_TLS_POSTURE_PASS5A.md`. Gates Phase B+
of the `X-S43-Password` retirement and any browser-session activation.

## AB. #11 status

**UNCHANGED — open.** Environment operator, SHA-256 fallback, `.env`
contract, break-glass mechanism all untouched (§31). Future target remains a
scoped break-glass; implementation not authorized.

## AC. Unresolved findings

1. **F-TLS-1** (blocking, deployment) — no secure production TLS posture in
   repo evidence.
2. **`X-S43-Password` retirement** — not started; gated on F-TLS-1 + Pass 5B.
3. **#11** env-operator — open; needs operator sign-off + a `.env` change.
4. **Session layer not wired** — no `/auth/refresh|logout`, no cookie, no
   CSRF activation (Pass 5B).
5. **`migration-job.yaml` / Compose still run `init_models()`** — the
   deployment pass swaps them to `alembic upgrade head` (design in §Q/§R;
   deferred per §27).
6. **`users` constraint-name convention gap for *stamped* databases** — a
   pre-Alembic DB keeps `users_pkey` / `users_email_key`; `alembic check`
   against such a DB shows a rename as pending. A future one-off "rename
   users constraints" migration closes it (out of scope, §5).
7. **Schema-version startup check** — designed (§P), not implemented (§26).
8. **Multi-replica login throttle** — still in-process/per-pod (Pass 5A
   §F); a `login_attempts` table can ride a future migration.
9. Carried: P3-7 `role` CHECK constraint, P3-8 case-insensitive
   username/email uniqueness (both need a live-data collision inventory).

**None of #1–#9 are marked RESOLVED** (§37). Migration-specific behaviour
(baseline adoption, drift refusal, downgrade safety, shape-B constraint,
RESTRICT FK) IS backed by behavioural tests.

## AD. Exact Pass 5B prerequisites

Pass 5B (route wiring) cannot start until:

1. **Run the migration on the target.** A named production/staging target
   (Phase 14), then either `alembic upgrade head` (fresh) or `alembic stamp
   0001_baseline` + `alembic upgrade head` (existing), executed as an
   explicit operator/Job step — plus the deployment-pass changes to
   `migration-job.yaml` / Compose (§Q, §R) if that target uses them.
2. **F-TLS-1 disposition** — confirm edge TLS + HSTS for the target, or
   explicitly accept browser sessions ship dev-only until then.
3. **Pass 5B scope sign-off** — wire `/auth/login` (+ `create_session`, set
   the `HttpOnly; Secure; SameSite=Strict; Path=/auth` refresh cookie, issue
   a `sid`-bound 15-min access token), `POST /auth/refresh`
   (cookie + `X-S43-CSRF` → `rotate_refresh`; commit the revoke on
   `RefreshReuseError` / `SessionOwnerInactiveError` then 401 + clear
   cookie), `POST /auth/logout` (→ `logout_by_refresh`), and wire
   `revoke_all_user_sessions` into `set_user_password` /
   `set_user_active(False)` / `set_user_role`. Legacy Bearer JWT +
   `X-S43-Password` stay accepted (Phase B dual contract).

## AE. Confirmation no prohibited actions occurred

No push / force-push / merge to main / `origin/main` change / PR / GitHub
settings / visibility change / OneDrive-repo change / Compose start-stop-
restart-rebuild / live-DB access-migrate-modify / `ALTER ROLE` / credential
rotation / deployment-secret change / deploy / secret exposure / branch or
tag deletion / dangling-object or recovery-bundle removal. All migration
validation used disposable `postgres:16.3` containers (`--rm --tmpfs`),
created, used, and removed. Commits are local to
`integration/beta-hardening-20260901`.

## AF. `naming_convention` applied — and to which metadata objects

`NAMING_CONVENTION` (dict, defined in `core/auth/users.py`) covers
**pk / fk / uq / ck / ix**. Applied to **both**:

- `core.auth.users.Base.metadata` = `MetaData(naming_convention=NAMING_CONVENTION)`
- `core.auth.sessions.SessionBase.metadata` = `MetaData(naming_convention=NAMING_CONVENTION)`
  (imports the same dict from `users.py`)

Fixed **before** revision 0001 was authored (mission §5). Fresh-created
names: `pk_users`, `uq_users_email`, `ix_users_username`, `pk_sessions`,
`fk_sessions_user_id_users`, `ix_sessions_user_id`,
`ix_sessions_prev_refresh_hash`, `ix_sessions_expires_at`,
`uq_sessions_active_refresh_hash`. Determinism proven across a full
downgrade/upgrade round-trip.

## AG. `refresh_hash` constraint — exact shape and why

**SHAPE B implemented.** PostgreSQL partial unique index:

```sql
CREATE UNIQUE INDEX uq_sessions_active_refresh_hash
    ON sessions (refresh_hash) WHERE revoked_at IS NULL;
```

Model (`core/auth/sessions.py`): `Index("uq_sessions_active_refresh_hash",
"refresh_hash", unique=True, postgresql_where=text("revoked_at IS NULL"))`.
Pass 5A had an unconditional `unique=True` (shape A); Pass 5AM changes it to
shape B in both model and `0002_sessions`.

**Why B:** it enforces "one parent generation → at most one valid successor"
(rejects two *active* rows with the same hash) while permitting a
revoked/superseded historical row to retain a hash that a later active row
could also hold — which an unconditional UNIQUE (shape A) would reject,
breaking legitimate rotation/replay history. Shape B "constrains only the
active/valid state while preserving historical rows" (mission §14).

**Distinguishing test** (mission §33): `test_sessions_partial_unique_permits_
revoked_historical_plus_active` inserts a **revoked** row and an **active**
row sharing a `refresh_hash` — **fails under shape A, passes under shape B**.
Paired with `test_sessions_partial_unique_rejects_second_active` (two active,
same hash → `IntegrityError`).

## AH. `target_metadata` construction for autogenerate

`migrations/env.py :: _build_target_metadata()`:

```python
combined = MetaData(naming_convention=NAMING_CONVENTION)
for md in (Base.metadata, SessionBase.metadata):     # users first, then sessions
    for table in md.tables.values():
        table.to_metadata(combined)
sessions = combined.tables["sessions"]
if not sessions.foreign_key_constraints:
    sessions.append_constraint(ForeignKeyConstraint(
        ["user_id"], ["users.user_id"],
        ondelete="RESTRICT", name="fk_sessions_user_id_users"))
target_metadata = combined
```

- **Both bases** are in `target_metadata` (mission §7) — so a future
  `alembic revision --autogenerate` (even one unrelated to sessions) never
  sees `sessions` as unknown and proposes dropping it.
- `users` is copied first so the cross-context `sessions.user_id` FK resolves
  in `combined`.
- The ORM `SessionRecord.user_id` is a plain column (no `ForeignKey` object)
  to keep the two metadata objects genuinely independent; the real FK
  (`0002_sessions`) is mirrored onto the `combined` copy so autogenerate is
  faithful.
- The **runtime `create_all` boundary is separate and unaffected**:
  `init_models()` uses `Base.metadata` (only `users`), never `combined`,
  never `SessionBase.metadata`.
- Verified: `alembic check` with the DB at `head` → *"No new upgrade
  operations detected."*

---

## Final STOP (§41)

Do not begin Pass 5B. Do not wire `/auth/refresh` or `/auth/logout`. Do not
activate refresh cookies or CSRF. Do not migrate browser authentication. Do
not change WebSockets. Do not change #11. Do not push. Do not deploy.
Await explicit authorization.
