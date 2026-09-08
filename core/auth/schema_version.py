# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Runtime database schema compatibility reporting for Sentinel-43.

Alembic is the sole authority for production schema evolution. The API never
runs migrations here; it only compares the database revision with the revision
graph shipped in the current image.

This check belongs to readiness, not liveness.
"""

from __future__ import annotations

import os
import pathlib
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Final


_LOCAL_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"development", "dev", "local", "test"}
)

_TRUE_VALUES: Final[frozenset[str]] = frozenset(
    {"1", "true", "yes", "on", "enabled"}
)
_FALSE_VALUES: Final[frozenset[str]] = frozenset(
    {"0", "false", "no", "off", "disabled"}
)

_REPO_ROOT: Final[pathlib.Path] = pathlib.Path(__file__).resolve().parents[2]
_ALEMBIC_INI: Final[pathlib.Path] = _REPO_ROOT / "alembic.ini"
_MIGRATIONS_DIR: Final[pathlib.Path] = _REPO_ROOT / "migrations"

_graph_lock = threading.Lock()
_graph_cache: "RevisionGraph | None" = None


class SchemaState(str, Enum):
    OK = "ok"
    BEHIND = "behind"
    AHEAD = "ahead"
    UNSTAMPED = "unstamped"
    FRESH = "fresh"
    UNREACHABLE = "unreachable"
    GRAPH_INVALID = "graph_invalid"
    NOT_APPLICABLE = "n/a"


@dataclass(frozen=True, slots=True)
class RevisionGraph:
    head: str | None
    ancestry: frozenset[str]
    error: str | None = None


@dataclass(frozen=True, slots=True)
class SchemaReport:
    state: SchemaState
    current: str | None
    expected: str | None
    detail: str
    serving_blocked: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "current": self.current,
            "expected": self.expected,
            "detail": self.detail,
            "serving_blocked": self.serving_blocked,
        }


def _environment() -> str:
    raw = (
        os.getenv("SENTINEL_ENV")
        or os.getenv("S43_ENV")
        or "production"
    ).strip().lower()

    aliases = {
        "dev": "development",
        "local": "development",
        "prod": "production",
        "stage": "staging",
    }

    return aliases.get(raw, raw)


def _is_local_environment() -> bool:
    return _environment() in _LOCAL_ENVIRONMENTS


def _check_enabled() -> bool:
    raw = os.getenv("S43_SCHEMA_VERSION_CHECK")

    if raw is None or not raw.strip():
        return not _is_local_environment()

    normalized = raw.strip().lower()

    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False

    if not _is_local_environment():
        raise RuntimeError(
            f"S43_SCHEMA_VERSION_CHECK must be boolean; got {raw!r}"
        )

    return False


def _load_graph_uncached() -> RevisionGraph:
    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        if not _MIGRATIONS_DIR.is_dir():
            return RevisionGraph(
                head=None,
                ancestry=frozenset(),
                error="migrations directory is missing",
            )

        config = (
            Config(str(_ALEMBIC_INI))
            if _ALEMBIC_INI.is_file()
            else Config()
        )

        config.set_main_option(
            "script_location",
            str(_MIGRATIONS_DIR),
        )

        script = ScriptDirectory.from_config(
            config
        )

        heads = list(
            script.get_heads()
        )

        if len(heads) != 1:
            return RevisionGraph(
                head=None,
                ancestry=frozenset(),
                error=(
                    f"expected exactly one Alembic head, found {len(heads)}"
                ),
            )

        head = heads[0]

        ancestry = frozenset(
            revision.revision
            for revision in script.walk_revisions(
                base="base",
                head=head,
            )
        )

        if head not in ancestry:
            ancestry = frozenset(
                set(ancestry)
                | {
                    head
                }
            )

        return RevisionGraph(
            head=head,
            ancestry=ancestry,
            error=None,
        )

    except Exception as exc:
        return RevisionGraph(
            head=None,
            ancestry=frozenset(),
            error=(
                f"failed to load Alembic revision graph: "
                f"{type(exc).__name__}"
            ),
        )


def _load_graph() -> RevisionGraph:
    global _graph_cache

    if _graph_cache is None:
        with _graph_lock:
            if _graph_cache is None:
                _graph_cache = (
                    _load_graph_uncached()
                )

    return _graph_cache


def clear_revision_graph_cache_for_tests() -> None:
    global _graph_cache

    with _graph_lock:
        _graph_cache = None


def expected_head() -> str | None:
    return _load_graph().head


def _classify(
    current: str | None,
    users_exists: bool,
) -> tuple[SchemaState, str]:
    graph = _load_graph()

    if graph.error is not None or graph.head is None:
        return (
            SchemaState.GRAPH_INVALID,
            graph.error
            or "Alembic revision graph is invalid",
        )

    if current is None:
        if users_exists:
            return (
                SchemaState.UNSTAMPED,
                (
                    "database contains application tables but has no "
                    "alembic_version row"
                ),
            )

        return (
            SchemaState.FRESH,
            (
                "database has not been initialized by Alembic"
            ),
        )

    if current == graph.head:
        return (
            SchemaState.OK,
            (
                f"schema is at expected revision {graph.head}"
            ),
        )

    if current in graph.ancestry:
        return (
            SchemaState.BEHIND,
            (
                f"database revision {current} is behind expected "
                f"revision {graph.head}"
            ),
        )

    return (
        SchemaState.AHEAD,
        (
            f"database revision {current} is unknown to this code; "
            f"expected {graph.head}"
        ),
    )


async def schema_report(
    engine: object | None = None,
) -> SchemaReport:
    """Report database/Alembic compatibility without applying migrations."""

    try:
        enabled = _check_enabled()
    except RuntimeError as exc:
        return SchemaReport(
            state=SchemaState.GRAPH_INVALID,
            current=None,
            expected=expected_head(),
            detail=str(exc),
            serving_blocked=True,
        )

    graph = _load_graph()

    if graph.error is not None:
        return SchemaReport(
            state=SchemaState.GRAPH_INVALID,
            current=None,
            expected=None,
            detail=graph.error,
            serving_blocked=enabled,
        )

    database_url = os.getenv(
        "DATABASE_URL",
        "",
    ).strip()

    if not database_url:
        return SchemaReport(
            state=SchemaState.NOT_APPLICABLE,
            current=None,
            expected=graph.head,
            detail=(
                "DATABASE_URL is not configured; schema check is not applicable"
            ),
            serving_blocked=False,
        )

    from sqlalchemy import text

    try:
        if engine is None:
            from .users import get_engine

            engine = get_engine()

        connect = getattr(
            engine,
            "connect",
            None,
        )

        if not callable(connect):
            raise TypeError(
                "engine does not provide an async connect() method"
            )

        async with connect() as connection:
            has_alembic_version = (
                await connection.execute(
                    text(
                        "SELECT to_regclass('public.alembic_version')"
                    )
                )
            ).scalar() is not None

            has_users = (
                await connection.execute(
                    text(
                        "SELECT to_regclass('public.users')"
                    )
                )
            ).scalar() is not None

            current: str | None = None

            if has_alembic_version:
                rows = list(
                    (
                        await connection.execute(
                            text(
                                "SELECT version_num FROM alembic_version"
                            )
                        )
                    ).scalars().all()
                )

                if len(rows) > 1:
                    return SchemaReport(
                        state=SchemaState.GRAPH_INVALID,
                        current=None,
                        expected=graph.head,
                        detail=(
                            "alembic_version contains multiple revision rows"
                        ),
                        serving_blocked=enabled,
                    )

                if rows:
                    current = str(
                        rows[0]
                    )

    except Exception as exc:
        return SchemaReport(
            state=SchemaState.UNREACHABLE,
            current=None,
            expected=graph.head,
            detail=(
                "could not query database schema version: "
                f"{type(exc).__name__}"
            ),
            serving_blocked=enabled,
        )

    state, detail = _classify(
        current,
        users_exists=has_users,
    )

    blocked = (
        enabled
        and state is not SchemaState.OK
    )

    return SchemaReport(
        state=state,
        current=current,
        expected=graph.head,
        detail=detail,
        serving_blocked=blocked,
    )


__all__ = [
    "SchemaReport",
    "SchemaState",
    "clear_revision_graph_cache_for_tests",
    "expected_head",
    "schema_report",
]
