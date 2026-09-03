# PASS5AM_VALIDATION.md

Sentinel-43 — Pass 5A-Migration validation record. Evidence for
`MIGRATION_ARCHITECTURE_PASS5AM.md`, `MIGRATION_BASELINE_PASS5AM.md`, and the
mission §33 test matrix.

- **Branch:** `integration/beta-hardening-20260901`
- **Starting HEAD:** `7a72976` (verified Pass 5A HEAD, recovery bundle
  `pass5am-20260901/…-PRE.bundle`)
- **Ending HEAD:** the Pass 5AM commit chain on top of `7a72976` (see
  `git log`)
- **Working clone:** `C:\Users\heero\Sentinel-43-work` (non-synced; `origin`
  + `evidence-local` push disabled)
- **Original OneDrive repo:** untouched, HEAD `e859b61`
- **Disposable PostgreSQL:** `postgres:16.3` (`--rm --tmpfs`,
  `127.0.0.1:55435` / `55436`), removed after the run

---

## 1. Environment (§34)

| tool | version |
|---|---|
| Python | 3.13.5 |
| PostgreSQL | 16.3 (Debian; `postgres:16.3`), default isolation **READ COMMITTED** |
| Alembic | **1.19.1** |
| SQLAlchemy | 2.0.52 |
| asyncpg | 0.31.0 (app + migrations) |
| psycopg | 3.3.5 (sync inspection engine in `test_migrations_pg.py` only) |
| pytest | 9.1.1 |
| argon2-cffi | 25.1.0 |
| PyJWT | 2.13.0 |

Concurrency-sensitive tests: the session-layer suite relies only on
`SELECT … FOR UPDATE` + READ COMMITTED predicate re-check (EvalPlanQual),
not SERIALIZABLE; the session layer uses no advisory lock. `users`
first-admin concurrency (Pass 3) uses `pg_advisory_xact_lock`. Migration
tests use PostgreSQL transactional DDL (Alembic default: one transaction per
`alembic` invocation).

---

## 2. Starting-state verification (§1, already accepted)

`7a72976`; branch `integration/beta-hardening-20260901`; `git status` clean;
`git fsck` — only benign dangling objects; merge-base with `origin/main` ==
`8d2b80f`; original OneDrive repo `e859b61` clean; Pass 5A recovery bundle
present and verifying; Pass 5A baseline 360 passed / SI 13/13 (re-confirmed).

Pre-work recovery snapshot created before any change:
`…\sentinel43-recovery\pass5am-20260901\sentinel43-integration-pass5am-PRE.bundle`
(`git bundle verify` → "records a complete history").

---

## 3. Changes landed

```
 alembic.ini                                  new
 migrations/__init__.py                       new
 migrations/env.py                            new
 migrations/script.py.mako                    new
 migrations/baseline.py                       new
 migrations/versions/0001_baseline.py         new
 migrations/versions/0002_sessions.py         new
 requirements.txt                             + alembic>=1.13
 core/auth/users.py                           + NAMING_CONVENTION; Base gets MetaData(naming_convention=...)
 core/auth/sessions.py                        SessionBase gets the same convention;
                                              refresh_hash: unconditional unique -> partial unique index (shape B);
                                              expires_at gains an index
 core/tests/test_migrations_pg.py             new (25 tests, PG-only)
 MIGRATION_ARCHITECTURE_PASS5AM.md            new
 MIGRATION_BASELINE_PASS5AM.md                new
 PASS5AM_VALIDATION.md                        new
 HANDOFF_PASS5AM.md                           new
```

**Unchanged** (verified — 0 lines diff vs `7a72976`):
`core/auth/users.py::init_models()` body, `core/api/routers/bootstrap.py`,
`core/api/routers/users.py`, `core/api/routers/auth.py`, `core/api/main.py`,
`core/api/deps/*`, `core/monitoring/*`, `deploy/**` (incl.
`migration-job.yaml`), `docker-compose.yml`, every `.env*`.

The only behavioural change in application code: `SessionRecord.refresh_hash`
uniqueness is now a partial unique index instead of an unconditional one
(mission §14). The `sessions` table is still created by nothing at app
startup.

---

## 4. Manual Alembic verification (disposable PG)

| step | result |
|---|---|
| `alembic heads` | `0002_sessions (head)` — single head |
| `alembic history` | `<base> → 0001_baseline → 0002_sessions` — linear |
| FRESH DB `alembic upgrade head` | `users` + `sessions` created; `alembic_version = 0002_sessions`; schema inspected via `psql \d` — every column/type/nullability, `pk_users`, `uq_users_email`, `ix_users_username` UNIQUE, `pk_sessions`, `fk_sessions_user_id_users … ON DELETE RESTRICT`, `uq_sessions_active_refresh_hash … WHERE revoked_at IS NULL`, 3 plain indexes — **exactly as designed** |
| `alembic check` (DB at head) | **"No new upgrade operations detected."** — models + migrations + combined `target_metadata` agree (§21) |
| `alembic downgrade 0001_baseline` | `sessions` dropped; `users` + `alembic_version` remain |
| re-`alembic upgrade head` | `sessions` recreated; version back to `0002_sessions` |
| `alembic downgrade base` | runs `0002` downgrade, hits `0001` `RuntimeError`; **transactional DDL rolls the whole thing back** — `users`, `sessions`, `alembic_version` all intact, version still `0002_sessions`. Fail-safe. |
| EXISTING pre-Alembic `users` (Postgres-default names) + 3 rows → `alembic stamp 0001_baseline` → `alembic upgrade head` | compat check passed; stamped; only `0002` ran; **all 3 rows preserved**; `sessions` created empty |
| INCOMPATIBLE `users` (no `role`) → `alembic stamp` / `upgrade` | `BaselineIncompatibleError` (sanitized: "column 'users.role' is missing", …); **alembic exit code 1**; nothing stamped/changed |
| grep the failing output for `postgresql://` / `:x@` / `password` / DSN | **nothing** — no credential/URL leak (§4, §10, §28) |

---

## 5. `test_migrations_pg.py` — §33 MIGRATION matrix + §21/§22

```
25 passed   (disposable postgres:16.3, S43_TEST_PG_DSN set)
```

| mission §33 item | test(s) |
|---|---|
| graph has one head | `test_single_head`, `test_linear_history` |
| fresh DB → 0001 | `test_fresh_db_upgrade_0001` (schema inspected, not just exit code) |
| fresh DB → head | `test_fresh_db_upgrade_head`, `test_fresh_db_sessions_schema_matches_model` |
| existing compatible → validate → stamp → head | `test_existing_compatible_stamp_then_upgrade` |
| incompatible pre-Alembic → refuse | `test_incompatible_pre_alembic_refused` (parametrized ×4: missing role / username not unique / role nullability / password_hash type) |
| head → 0001 | `test_downgrade_0002_to_0001` |
| 0001 → head again | `test_downgrade_upgrade_repeatable` (×3 cycles) |
| baseline downgrade refused + rolls back | `test_baseline_downgrade_to_base_refused_and_rolls_back` |
| user data preservation | `test_user_data_preserved_through_baseline_adoption` (operator/admin/active+last_login/disabled — byte-identical before/after) |
| sessions constraints (shape B) | `test_sessions_partial_unique_rejects_second_active`, `test_sessions_partial_unique_permits_revoked_historical_plus_active` |
| sessions indexes | `test_fresh_db_sessions_schema_matches_model` (exact index-name set) |
| FK behavior | `test_sessions_fk_on_delete_restrict`, `test_sessions_fk_is_restrict_not_cascade` |
| naming convention applied + deterministic across down/up round-trip | `test_naming_convention_deterministic_across_roundtrip` |
| refresh_hash rejects a 2nd simultaneously-active successor | `test_sessions_partial_unique_rejects_second_active` |
| refresh_hash permits a rotated non-revoked... row coexisting with successor (**proves shape B, not A**) | `test_sessions_partial_unique_permits_revoked_historical_plus_active` — a revoked historical row + an active successor sharing a `refresh_hash`; **rejected under shape A, permitted under shape B** |
| env.py does not import/start the app (§23) | `test_env_does_not_import_the_application` |

**§21 / §22 — session layer + concurrency on the ALEMBIC-created schema:**

| item | test |
|---|---|
| primitives / create / rotate / reuse-revoke / logout on `alembic upgrade head` schema | `test_session_primitives_layer_on_alembic_schema` |
| two & five simultaneous refreshes → exactly one successor, generation 1, reuse-revoke tripped | `test_concurrent_refresh_one_successor_on_alembic_schema[2,5]` |
| refresh racing logout + refresh racing account disablement | `test_refresh_vs_logout_and_disablement_on_alembic_schema` |
| expiration racing refresh | `test_expiry_vs_refresh_on_alembic_schema` |

> **"Never more than one valid successor refresh generation" holds on the
> Alembic-built schema** — the shape-B partial unique index enforces it at
> the database level and the `SELECT … FOR UPDATE` in `rotate_refresh()`
> serialises the racers.

---

## 6. §33 SESSION + SECURITY + FULL

### 6.1 Session suites (unchanged Pass 5A code, re-run after the §5 model change)

Disposable PG, `S43_TEST_PG_DSN` set:

```
core/tests/test_session_primitives.py           29 passed
core/tests/test_session_layer_pg.py             19 passed
core/tests/test_service_identity_separation.py  12 passed
core/tests/test_account_transactions_pg.py       9 passed
core/tests/test_users_admin.py                  25 passed
core/tests/test_bootstrap_isolated.py            4 passed
                                          -> 98 passed  (459 s)
```

The partial-unique change did not regress `test_refresh_hash_is_unique`
(two active rows, same secret → `IntegrityError`, unchanged).

### 6.2 Security invariants (§25, §32)

- Security-invariant script — **13/13** (re-run after the §5 model change):
  `/v1` scope/role separation, `/users` admin gating, Watchtower auth +
  probe openness, users router mounted.
- Service-identity isolation — `test_service_identity_separation.py` 12
  passed (human JWT / refresh credential ✗ service auth; service token ✗
  human login/session).
- Firewall / proxy-trust / `:9100` non-publication / fail-closed startup /
  first-admin advisory lock / malformed-hash fail-closed / event-loop Argon2
  / login throttle / legacy JWT / X-S43-Password / WebSocket — all in the
  full-suite run below.

### 6.3 Full isolated suite (§26 A–M)

```
pytest core/tests/ -q -rsxX --ignore=core/tests/test_bootstrap.py \
                            --ignore=core/tests/test_system_smoke.py
  (S43_TEST_PG_DSN set to the disposable PG)
```

`test_bootstrap.py` / `test_system_smoke.py` excluded per the standing
no-live-HTTP / no-`requests` rule (consistent with Passes 1–5A).

| metric | value |
|---|---|
| collected | 385 |
| passed | 385 |
| failed | 0 |
| errors | 0 |
| skipped | 0 |
| xfailed / xpassed | 0 |
| warnings | 5 (pre-existing `StarletteDeprecationWarning` only — `starlette.testclient`/`httpx` and `HTTP_422_UNPROCESSABLE_ENTITY`; none from Pass 5AM code) |
| exit code | 0 |
| duration | 857.47 s (0:14:17) |

Pass 5A baseline was 360. Pass 5AM adds the 25 `test_migrations_pg.py`
tests → 385 passed, 0 failed, 0 errored, 0 skipped.

The suite was first run with a stale `sys.modules` entry left by
`test_migrations_pg.py::test_env_does_not_import_the_application`
(`del sys.modules["core.api.main"]` with no restore) → 14 `test_ws_auth.py`
setup errors. The test now snapshots every `core.api.*` module before the
deletion and restores them in a `finally` block; the rerun above is clean.
See §7.

---

## 7. Fix log

- **Migration commit swallowed under async adapter.** First
  `alembic upgrade head` printed "Running upgrade" for both revisions but
  persisted nothing (`alembic_version` did not exist afterward). Cause:
  `env.py` ran the baseline reflection queries *before*
  `context.begin_transaction()`, opening an implicit transaction on the bare
  async→sync-adapted connection that was never committed, which swallowed
  Alembic's own commit. Fix: moved `_maybe_check_baseline(connection)` inside
  the `with context.begin_transaction():` block. Re-verified: both revisions
  persist, `alembic_version = 0002_sessions`.
- **`prepend_sys_path` deprecation warning** from Alembic 1.19
  (`No path_separator found in configuration`). Fixed: `path_separator = os`
  in `alembic.ini` (replaces the older `version_path_separator`).
- **`sys.modules` pollution across test modules.**
  `test_env_does_not_import_the_application` deleted `core.api.main` from
  `sys.modules` to detect an import leak but never restored it, so
  `test_ws_auth.py::setup_module` (`importlib.reload(main_module)`) then
  raised `ImportError: module core.api.main not in sys.modules` — 14 errors
  in the first full-suite run. Fix: snapshot every `core.api` / `core.api.*`
  entry before deletion, restore each with plain assignment in a `finally`
  block (so references other modules already hold keep their identity). The
  leak assertion itself is unchanged. Verified:
  `test_migrations_pg + test_ws_auth + test_jwt_auth` = 76 passed together,
  and the full-suite rerun is 385 passed / 0 errors.

---

## 8. Boundaries honoured (§28, §38, §39)

- No push / force-push / merge / PR / repo-settings / visibility change /
  OneDrive-repo change / branch or tag deletion.
- No dangling / recovery objects removed; previous recovery bundles intact.
- **No migration run against a non-disposable database.** The disposable
  `postgres:16.3` containers were created `--rm --tmpfs`, used, and removed.
  The s43 Compose stack was never started / stopped / restarted / rebuilt;
  its database was never touched; no `ALTER ROLE`; no credential rotation; no
  deployment-secret change; no deploy.
- `init_models()`, `migration-job.yaml`, `docker-compose.yml`, `.env*` —
  unchanged (mission §24, §27, §30, §14 STOP already cleared by the
  authorization; this pass is the authorized migration work).
- No `/auth/*` route wiring; `X-S43-Password` / legacy JWT / `require_*` /
  `reverify_password` / login / WebSocket / service-token / env-operator —
  untouched (§30, §31, §32).
- No secret values in this document, in test output, or in commits. Test DSN
  password is a disposable literal (`x`), loopback only.
- F-TLS-1, #11, X-S43-Password retirement — **not touched, not resolved**
  (§29, §31, §37). Recorded unchanged in `HANDOFF_PASS5AM.md`.

---

## 9. STOP CONDITIONS (§39) — none triggered

- Repository state stable throughout (`7a72976` base, clean tree).
- Alembic represents the baseline safely (0001 fresh-create + semantic-check
  stamp; 0001 downgrade unsupported).
- Baseline compatibility is determinable from repository evidence (the
  `User` model is the byte-stable historical schema — git-verified).
- Stamping cannot hide material drift (semantic check refuses; verified ×4).
- `0002_sessions` matches the Pass 5A model exactly (`alembic check` clean;
  structural test).
- User-deletion semantics are unambiguous — **Case 2** (no deletion pathway
  exists), so RESTRICT with no STOP.
- No destructive change to user records on upgrade; downgrade does not touch
  user records.
- Single Alembic head throughout.
- `env.py` does not import/start the app (tested).
- Session concurrency guarantees hold on the migrated schema (tested).
- Migration tests use only disposable PostgreSQL.
- No secrets exposed.
- Nothing required auth-route activation or exceeded the migration-only
  authorization.
