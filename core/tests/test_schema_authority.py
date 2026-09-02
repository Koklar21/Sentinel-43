# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_schema_authority.py
#
# Beta-execution Phase 1 -- Alembic is the sole production schema authority.
# init_models()/create_all must be a no-op in a non-local environment so it
# can never race the migration Job's DDL (MIGRATION_ARCHITECTURE_PASS5AM.md
# §11/§24). No database required.
# =============================================================================

from __future__ import annotations

import asyncio

import pytest

import core.auth.users as users


@pytest.mark.parametrize("env", ["production", "staging", "beta", "prod"])
def test_init_models_is_a_noop_in_non_local_envs(monkeypatch, env):
    monkeypatch.setenv("SENTINEL_ENV", env)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("S43_SCHEMA_CREATE_ALL", raising=False)

    called = False

    def _boom():  # get_engine() must never be reached on the no-op path
        nonlocal called
        called = True
        raise AssertionError("init_models() touched the engine in a non-local env")

    monkeypatch.setattr(users, "get_engine", _boom)

    # No DATABASE_URL, no engine -- yet this must not raise: it returns early.
    asyncio.run(users.init_models())
    assert called is False
    assert users._schema_is_alembic_managed() is True


@pytest.mark.parametrize("env", ["development", "dev", "local", "test"])
def test_init_models_still_creates_in_local_envs(monkeypatch, env):
    monkeypatch.setenv("SENTINEL_ENV", env)
    assert users._schema_is_alembic_managed() is False


def test_explicit_create_all_flag_overrides(monkeypatch):
    monkeypatch.setenv("SENTINEL_ENV", "production")
    monkeypatch.setenv("S43_SCHEMA_CREATE_ALL", "true")
    assert users._schema_is_alembic_managed() is False

    monkeypatch.setenv("S43_SCHEMA_CREATE_ALL", "false")
    monkeypatch.setenv("SENTINEL_ENV", "development")
    assert users._schema_is_alembic_managed() is True
