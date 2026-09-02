# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_deploy_migration_wiring.py
#
# Beta-execution Phase 1 -- the deployment artifacts run Alembic as a single
# ordered, one-shot migration step (Compose + Kubernetes), and nothing runs
# create_all against the production schema any more.
# =============================================================================

from __future__ import annotations

import pathlib

import pytest

yaml = pytest.importorskip("yaml")

_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _load(rel: str):
    return yaml.safe_load((_ROOT / rel).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Docker Compose
# ---------------------------------------------------------------------------

def test_compose_has_one_shot_alembic_migrate_service():
    compose = _load("docker-compose.yml")
    svc = compose["services"]["s43-migrate"]
    assert svc["command"] == ["alembic", "upgrade", "head"]
    assert svc["restart"] == "no"
    # runs after Postgres is healthy
    assert svc["depends_on"]["s43-db"]["condition"] == "service_healthy"
    # reads the connection URL from the environment, no hardcoded credential
    assert "DATABASE_URL" in svc["environment"]
    assert "${DATABASE_URL}" in str(svc["environment"]["DATABASE_URL"])


def test_compose_api_waits_for_migration_to_complete():
    compose = _load("docker-compose.yml")
    dep = compose["services"]["s43-api"]["depends_on"]
    assert dep["s43-migrate"]["condition"] == "service_completed_successfully"
    assert dep["s43-db"]["condition"] == "service_healthy"


def test_compose_migrate_never_runs_a_downgrade():
    compose = _load("docker-compose.yml")
    cmd = " ".join(compose["services"]["s43-migrate"]["command"])
    assert "downgrade" not in cmd


# ---------------------------------------------------------------------------
# Kubernetes migration Job
# ---------------------------------------------------------------------------

def _k8s_docs():
    text = (_ROOT / "deploy/kubernetes/base/migration-job.yaml").read_text(encoding="utf-8")
    return list(yaml.safe_load_all(text))


def test_k8s_migration_job_runs_alembic_upgrade_head():
    job = next(d for d in _k8s_docs() if d and d.get("kind") == "Job")
    container = job["spec"]["template"]["spec"]["containers"][0]
    assert container["command"] == ["alembic", "upgrade", "head"]
    # one actor, never restarts into a second run
    assert job["spec"]["template"]["spec"]["restartPolicy"] == "Never"
    # credentials come from the Secret, not the manifest
    envfrom = container["envFrom"]
    assert any("secretRef" in e for e in envfrom)


def test_k8s_migration_job_is_least_privilege():
    job = next(d for d in _k8s_docs() if d and d.get("kind") == "Job")
    sc = job["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    assert sc["readOnlyRootFilesystem"] is True
    assert sc["allowPrivilegeEscalation"] is False
    assert sc["capabilities"]["drop"] == ["ALL"]


def test_k8s_migration_job_does_not_call_init_models():
    text = (_ROOT / "deploy/kubernetes/base/migration-job.yaml").read_text(encoding="utf-8")
    # the command line must not shell out to the old create_all path
    assert "init_models()" not in text.split("command:")[-1]
