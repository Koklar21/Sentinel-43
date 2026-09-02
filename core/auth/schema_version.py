# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is distributed under a dual-license model:
#
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
# =============================================================================

"""
File: core/auth/schema_version.py

Runtime schema-version compatibility check (beta-execution Phase 1).

Alembic is the sole authority for the production PostgreSQL schema
(MIGRATION_ARCHITECTURE_PASS5AM.md §11). Migrations are an explicit operator /
Job step -- the API never runs them (§25). This module lets the API *refuse to
serve normal traffic* when the database it is pointed at is not at the schema
revision this code expects: behind (migration not run yet), ahead (an old
replica after a newer deploy migrated), never adopted (a pre-Alembic database
that was never stamped), or unreachable.

Design (MIGRATION_ARCHITECTURE_PASS5AM.md §14):

  * **Liveness vs readiness stay distinct.** This check belongs on the
    *readiness* probe (`GET /ready`) -- a schema mismatch means "don't send
    this pod traffic", not "kill this pod". `GET /health` (liveness) never
    calls this.
  * **The API never migrates.** This module only inspects `alembic_version`
    and compares it to the revision graph shipped in `migrations/versions/`.
  * **Local development is not gated.** When ``_is_local_environment()`` (the
    same predicate the rest of the app uses) the check is advisory: the state
    is reported but ``serving_blocked`` is always False, so a developer
    iterating against a scratch database is never locked out.
  * **No DATABASE_URL → not applicable.** A deployment with no database
    configured runs on the env-var operator fallback; there is no schema to
    check, so the check passes.

Zero import-time side effects: the Alembic script directory is read lazily
and cached; no database connection is made on import.
"""

from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass
from enum import Enum
from typing import Optional

# -----------------------------------------------------------------------------
# Environment predicate -- kept byte-identical in intent to core.api.main's
# _is_local_environment() so "local" means the same thing everywhere.
# -----------------------------------------------------------------------------
_LOCAL_ENVIRONMENTS = frozenset({"development", "dev", "local", "test"})


def _is_local_environment() -> bool:
    return os.getenv("SENTINEL_ENV", "production").strip().lower() in _LOCAL_ENVIRONMENTS


def _check_enabled() -> bool:
    """
    The check is on by default in non-local environments and off in local
    ones. ``S43_SCHEMA_VERSION_CHECK`` (true/false) overrides either way -- an
    operator can force it on locally to rehearse, or off in an emergency
    (documented as a break-glass, not a routine setting).
    """
    raw = os.getenv("S43_SCHEMA_VERSION_CHECK")
    if raw is not None:
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return not _is_local_environment()


class SchemaState(str, Enum):
    OK = "ok"                    # alembic_version == the single head revision
    BEHIND = "behind"            # DB is at an ancestor of head -- migration not run yet
    AHEAD = "ahead"             # DB revision is unknown to this code -- a newer deploy migrated
    UNSTAMPED = "unstamped"      # `users` exists but no `alembic_version` -- pre-Alembic DB, never adopted
    FRESH = "fresh"             # empty database -- no `users`, no `alembic_version`
    UNREACHABLE = "unreachable"  # could not connect / query
    NOT_APPLICABLE = "n/a"       # no DATABASE_URL configured


@dataclass(frozen=True)
class SchemaReport:
    state: SchemaState
    current: Optional[str]        # alembic_version.version_num, or None
    expected: Optional[str]       # the single head revision this code ships
    detail: str
    serving_blocked: bool         # True → /ready must return 503

    def as_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "current": self.current,
            "expected": self.expected,
            "detail": self.detail,
            "serving_blocked": self.serving_blocked,
        }


# -----------------------------------------------------------------------------
# Alembic revision graph (shipped in the image) -- read once, cached.
# -----------------------------------------------------------------------------
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_ALEMBIC_INI = _REPO_ROOT / "alembic.ini"
_MIGRATIONS_DIR = _REPO_ROOT / "migrations"

_head_cache: Optional[str] = None
_ancestry_cache: Optional[frozenset[str]] = None


def _load_graph() -> tuple[Optional[str], frozenset[str]]:
    """(head_revision, {every revision at-or-before head}). Cached."""
    global _head_cache, _ancestry_cache
    if _head_cache is not None and _ancestry_cache is not None:
        return _head_cache, _ancestry_cache
    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        cfg = Config(str(_ALEMBIC_INI)) if _ALEMBIC_INI.is_file() else Config()
        cfg.set_main_option("script_location", str(_MIGRATIONS_DIR))
        script = ScriptDirectory.from_config(cfg)
        heads = script.get_heads()
        if len(heads) != 1:
            # Multiple heads is a build error -- surface it rather than guess.
            _head_cache, _ancestry_cache = None, frozenset()
            return _head_cache, _ancestry_cache
        head = heads[0]
        ancestry = {rev.revision for rev in script.walk_revisions("base", head)}
        _head_cache, _ancestry_cache = head, frozenset(ancestry)
    except Exception:
        _head_cache, _ancestry_cache = None, frozenset()
    return _head_cache, _ancestry_cache


def expected_head() -> Optional[str]:
    return _load_graph()[0]


def _classify(current: Optional[str], users_exists: bool) -> tuple[SchemaState, str]:
    head, ancestry = _load_graph()
    if head is None:
        return SchemaState.UNREACHABLE, "the shipped Alembic revision graph could not be read or has multiple heads"
    if current is None:
        if users_exists:
            return (
                SchemaState.UNSTAMPED,
                "database has a 'users' table but no 'alembic_version' -- it was never adopted into Alembic; "
                "run `alembic stamp 0001_baseline` (semantic check) then `alembic upgrade head`",
            )
        return (
            SchemaState.FRESH,
            "database is empty -- run `alembic upgrade head` before serving traffic",
        )
    if current == head:
        return SchemaState.OK, f"schema is at the expected revision {head}"
    if current in ancestry:
        return (
            SchemaState.BEHIND,
            f"database is at {current}; this code expects {head} -- run `alembic upgrade head`",
        )
    return (
        SchemaState.AHEAD,
        f"database is at {current}, which this code does not know -- a newer deployment migrated; "
        f"this replica ({head}) must not serve against it",
    )


async def schema_report(engine: object | None = None) -> SchemaReport:
    """
    Inspect the configured database and report how its schema revision relates
    to the one this code ships. Never raises. ``serving_blocked`` is only ever
    True in a non-local environment with the check enabled.
    """
    enabled = _check_enabled()

    if not os.getenv("DATABASE_URL", "").strip():
        return SchemaReport(
            state=SchemaState.NOT_APPLICABLE,
            current=None,
            expected=expected_head(),
            detail="no DATABASE_URL configured -- schema-version check not applicable",
            serving_blocked=False,
        )

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncEngine

    try:
        if engine is None:
            from .users import get_engine

            engine = get_engine()
        assert isinstance(engine, AsyncEngine)
        async with engine.connect() as conn:
            has_av = (
                await conn.execute(
                    text("SELECT to_regclass('public.alembic_version')")
                )
            ).scalar() is not None
            has_users = (
                await conn.execute(text("SELECT to_regclass('public.users')"))
            ).scalar() is not None
            current: Optional[str] = None
            if has_av:
                current = (
                    await conn.execute(text("SELECT version_num FROM alembic_version"))
                ).scalar()
    except Exception as exc:  # noqa: BLE001 -- any failure is "unreachable"
        return SchemaReport(
            state=SchemaState.UNREACHABLE,
            current=None,
            expected=expected_head(),
            detail=f"could not query the database schema version: {type(exc).__name__}",
            serving_blocked=enabled,
        )

    state, detail = _classify(current, users_exists=has_users)
    blocked = enabled and state is not SchemaState.OK
    return SchemaReport(
        state=state,
        current=current,
        expected=expected_head(),
        detail=detail,
        serving_blocked=blocked,
    )


__all__ = ["SchemaState", "SchemaReport", "schema_report", "expected_head"]
