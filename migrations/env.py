# =============================================================================
# Sentinel-43 — Alembic environment (Pass 5A-Migration)
#
# Mission constraints honoured here:
#  §4  connection comes from DATABASE_URL (core.auth.users._database_url) —
#      never hardcoded, never logged, never in alembic.ini.
#  §7  target_metadata is the COMBINED view of BOTH declarative bases
#      (core.auth.users.Base + core.auth.sessions.SessionBase) so a future
#      `alembic revision --autogenerate` never treats `sessions` as unknown
#      and proposes dropping it. The runtime create_all() boundary
#      (init_models() only builds `users`) is unaffected — that lives in
#      core/auth/users.py, not here.
#  §23 NO application startup: this file imports only the two side-effect-free
#      model modules. It never imports core.api.main, builds a FastAPI app,
#      constructs middleware, or mutates the database outside explicit Alembic
#      operations.
#  §9  an existing pre-Alembic database (has `users`, no `alembic_version`) is
#      semantically validated before Alembic touches it — see baseline.py.
# =============================================================================

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import ForeignKeyConstraint, MetaData, pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# --- model metadata (side-effect-free imports only) --------------------------
from core.auth.users import NAMING_CONVENTION, Base, _database_url
from core.auth.sessions import SessionBase  # noqa: F401  (registers the table)
from migrations.baseline import assert_users_baseline

config = context.config
if config.config_file_name is not None:
    # disable_existing_loggers defaults to True, which silently disables
    # every logger already in the process that alembic.ini's own [loggers]
    # section (root, sqlalchemy, alembic) doesn't name -- including every
    # Sentinel-43 application logger. In production this runs inside the
    # short-lived, single-purpose s43-migrate container, so the blast
    # radius there is contained; in-process callers (tests, or any future
    # code path that runs a migration inline rather than via that separate
    # container) would otherwise have their own logging silently go dark
    # for the rest of the process.
    fileConfig(config.config_file_name, disable_existing_loggers=False)


# --- combined autogenerate metadata (§7 / §AH) ------------------------------
# One MetaData holding copies of every table from both bases, so autogenerate
# compares the DB against the FULL intended schema. Copy `users` first so the
# `sessions.user_id` foreign key (created by 0002_sessions, ON DELETE
# RESTRICT) resolves against it here too — the ORM SessionRecord keeps a
# logical (plain-column) FK to preserve the bounded-context boundary
# (users.init_models() must never build `sessions`), so we reconstruct the
# real FK on the combined copy to keep autogenerate faithful.
def _build_target_metadata() -> MetaData:
    combined = MetaData(naming_convention=NAMING_CONVENTION)
    for md in (Base.metadata, SessionBase.metadata):
        for table in md.tables.values():
            table.to_metadata(combined)
    sessions = combined.tables.get("sessions")
    if sessions is not None and not sessions.foreign_key_constraints:
        sessions.append_constraint(
            ForeignKeyConstraint(
                ["user_id"], ["users.user_id"],
                ondelete="RESTRICT",
                name="fk_sessions_user_id_users",
            )
        )
    return combined


target_metadata = _build_target_metadata()


def _url() -> str:
    """DATABASE_URL via the app's established config path. Not logged."""
    return _database_url()


def _maybe_check_baseline(connection: Connection) -> None:
    """
    §9: if this database already has `users` but is not yet under Alembic
    control (no `alembic_version`), it is an existing pre-Alembic database
    being adopted — validate its schema semantically before Alembic proceeds
    (whether the operator ran `stamp` or `upgrade`). Fresh databases (no
    `users`) sail straight through to 0001_baseline.upgrade().
    """
    from sqlalchemy import inspect

    insp = inspect(connection)
    if insp.has_table("users") and not insp.has_table("alembic_version"):
        assert_users_baseline(connection)


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    # The baseline check runs INSIDE Alembic's migration transaction so its
    # reflection queries don't leave a stray uncommitted transaction on the
    # connection (which would swallow the migration's own commit under the
    # async->sync adapter).
    with context.begin_transaction():
        _maybe_check_baseline(connection)
        context.run_migrations()


async def _run_async_migrations() -> None:
    connectable = async_engine_from_config(
        {"sqlalchemy.url": _url()},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(_run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
