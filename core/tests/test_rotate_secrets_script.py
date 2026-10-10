# =============================================================================
# Sentinel-43
#
# Focused regression coverage for the coordinated local secret rotation tool.
# =============================================================================

from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO / "core" / "scripts" / "rotate_secrets.py"

_spec = importlib.util.spec_from_file_location("s43_rotate_secrets", _SCRIPT)
assert _spec is not None and _spec.loader is not None
rotate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rotate)


def _base_env() -> dict[str, str]:
    values = {key: "a" * 64 for key in rotate.SECRET_KEYS}
    values.update(
        {
            "POSTGRES_PASSWORD": "1" * 64,
            "DATABASE_URL": (
                "postgresql+asyncpg://s43:"
                + ("1" * 64)
                + "@s43-db:5432/s43?sslmode=disable"
            ),
            "SENTINEL_ENV": "development",
            "S43_ENV": "development",
            "S43_AUDIT_HMAC_KEY": "2" * 64,
            "S43_JORM_ENABLED": "true",
            "S43_JORM_ROOT_KEY": "3" * 64,
            "S43_SPARTA_ENABLED": "false",
            "S43_EBPF_ENABLED": "false",
            "S43_ROUTER_ENABLED": "false",
        }
    )
    return values


def test_database_url_password_rewrite_preserves_shape():
    original = (
        "postgresql+asyncpg://s43:old@s43-db:5432/s43"
        "?sslmode=disable"
    )

    rewritten = rotate._database_url_with_password(original, "new-secret")

    assert rewritten == (
        "postgresql+asyncpg://s43:new-secret@s43-db:5432/s43"
        "?sslmode=disable"
    )


def test_state_preserving_rotation_keeps_durable_roots():
    existing = _base_env()

    replacements, rotated = rotate._build_replacements(
        existing,
        full_reset=False,
    )

    assert replacements["S43_AUDIT_HMAC_KEY"] == existing["S43_AUDIT_HMAC_KEY"]
    assert replacements["S43_JORM_ROOT_KEY"] == existing["S43_JORM_ROOT_KEY"]
    assert "S43_AUDIT_HMAC_KEY" not in rotated
    assert "S43_JORM_ROOT_KEY" not in rotated
    assert replacements["POSTGRES_PASSWORD"] != existing["POSTGRES_PASSWORD"]
    assert replacements["POSTGRES_PASSWORD"] in replacements["DATABASE_URL"]
    assert rotate.ROTATION_TIMESTAMP_KEY in replacements


def test_full_reset_rotates_durable_roots():
    existing = _base_env()

    replacements, rotated = rotate._build_replacements(
        existing,
        full_reset=True,
    )

    assert replacements["S43_AUDIT_HMAC_KEY"] != existing["S43_AUDIT_HMAC_KEY"]
    assert replacements["S43_JORM_ROOT_KEY"] != existing["S43_JORM_ROOT_KEY"]
    assert "S43_AUDIT_HMAC_KEY" in rotated
    assert "S43_JORM_ROOT_KEY" in rotated



def test_state_preserving_rotation_rotates_router_token_when_enabled():
    existing = _base_env()
    existing["S43_ROUTER_ENABLED"] = "true"
    existing["S43_ROUTER_INGEST_TOKEN"] = "old-router-token-" + ("x" * 40)

    replacements, rotated = rotate._build_replacements(
        existing,
        full_reset=False,
    )

    assert "S43_ROUTER_INGEST_TOKEN" in rotated
    assert replacements["S43_ROUTER_INGEST_TOKEN"] != existing["S43_ROUTER_INGEST_TOKEN"]
    assert len(replacements["S43_ROUTER_INGEST_TOKEN"]) >= 32

def test_duplicate_env_assignments_are_rejected(tmp_path: Path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "POSTGRES_PASSWORD=one\nPOSTGRES_PASSWORD=two\n",
        encoding="utf-8",
    )

    with pytest.raises(rotate.RotationError, match="Duplicate"):
        rotate._read_env(env_path)


def _write_env(path: Path, values: dict[str, str]) -> None:
    path.write_text(
        "\n".join(f"{key}={value}" for key, value in values.items()) + "\n",
        encoding="utf-8",
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission semantics required")
def test_atomic_env_replacement_is_owner_only_even_under_common_umask(tmp_path: Path):
    env_path = tmp_path / ".env"
    env_path.write_text("EXAMPLE=old\n", encoding="utf-8")
    os.chmod(env_path, 0o600)

    previous_umask = os.umask(0o022)
    try:
        rotate._atomic_update_env(env_path, {"EXAMPLE": "new"})
    finally:
        os.umask(previous_umask)

    assert env_path.read_text(encoding="utf-8") == "EXAMPLE=new\n"
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600
    assert env_path.stat().st_mode & 0o077 == 0


def test_rotation_rollback_backup_is_ephemeral(tmp_path: Path):
    env_path = tmp_path / ".env"
    env_path.write_text("SECRET=value\\n", encoding="utf-8")
    with rotate._temporary_env_backup(env_path) as backup:
        assert backup.read_bytes() == env_path.read_bytes()
        assert backup.name == "rollback.env"
        assert backup.parent.parent == tmp_path
        if os.name == "posix":
            assert stat.S_IMODE(backup.stat().st_mode) == 0o600
        rotate._atomic_update_env(env_path, {"SECRET": "changed"})
        rotate._restore_env(backup, env_path)
        assert env_path.read_text(encoding="utf-8") == "SECRET=value\\n"
    assert not backup.exists()
    assert not backup.parent.exists()


def test_rotation_rollback_backup_removed_after_exception(tmp_path: Path):
    env_path = tmp_path / ".env"
    env_path.write_text("SECRET=value\\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="simulated failure"):
        with rotate._temporary_env_backup(env_path) as backup:
            raise RuntimeError("simulated failure")
    assert not backup.exists()
    assert not backup.parent.exists()


def test_compose_forwards_selected_env_file(monkeypatch, tmp_path: Path):
    env_path = tmp_path / "config" / "local.env"
    env_path.parent.mkdir(parents=True)
    env_path.write_text("S43_ENV=development\n", encoding="utf-8")
    captured: list[str] = []

    def fake_run(args, **kwargs):
        _ = kwargs
        captured.extend(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(rotate, "_run", fake_run)

    rotate._compose(env_path, "config", "--quiet")

    assert captured == [
        "docker",
        "compose",
        "--env-file",
        str(env_path),
        "config",
        "--quiet",
    ]


def test_compose_selected_env_file_overrides_exported_shell_values(monkeypatch, tmp_path: Path):
    env_path = tmp_path / ".env"
    _write_env(
        env_path,
        {
            "POSTGRES_PASSWORD": "file-password",
            "DATABASE_URL": "postgresql+asyncpg://s43:file-password@s43-db/s43",
        },
    )
    monkeypatch.setenv("POSTGRES_PASSWORD", "stale-shell-password")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+asyncpg://s43:stale-shell-password@s43-db/s43",
    )
    captured_env: dict[str, str] = {}

    def fake_run(args, **kwargs):
        _ = args
        captured_env.update(kwargs["env"])
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(rotate, "_run", fake_run)

    rotate._compose(env_path, "config", "--quiet")

    assert "POSTGRES_PASSWORD" not in captured_env
    assert "DATABASE_URL" not in captured_env


def test_rotation_caller_set_includes_migration_consumer():
    assert "s43-migrate" in rotate.CALLER_SERVICES


def test_stop_callers_rejects_any_service_left_running(monkeypatch, tmp_path: Path):
    env_path = tmp_path / ".env"
    calls: list[tuple[str, ...]] = []

    def fake_compose(selected_env, *args, **kwargs):
        assert selected_env == env_path
        calls.append(tuple(args))
        if args[0] == "stop":
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[0] == "ps":
            return subprocess.CompletedProcess(args, 0, "s43-api\n", "")
        raise AssertionError(f"unexpected compose call: {args}")

    monkeypatch.setattr(rotate, "_compose", fake_compose)

    with pytest.raises(rotate.RotationError, match="still running"):
        rotate._stop_callers(env_path)

    assert calls[0] == ("stop", *rotate.CALLER_SERVICES)
    assert calls[1][:4] == ("ps", "--status", "running", "--services")


def test_stop_failure_aborts_before_postgres_password_change(monkeypatch, tmp_path: Path):
    env_path = tmp_path / ".env"
    existing = _base_env()
    _write_env(env_path, existing)

    replacements = dict(existing)
    replacements["POSTGRES_PASSWORD"] = "9" * 64
    replacements["DATABASE_URL"] = rotate._database_url_with_password(
        existing["DATABASE_URL"],
        replacements["POSTGRES_PASSWORD"],
    )
    replacements[rotate.ROTATION_TIMESTAMP_KEY] = "2026-10-03T00:00:00+00:00"

    monkeypatch.setattr(
        rotate,
        "_build_replacements",
        lambda current, *, full_reset: (replacements, ["POSTGRES_PASSWORD"]),
    )
    monkeypatch.setattr(rotate, "_print_plan", lambda **kwargs: None)

    def stop_fails(selected_env):
        assert selected_env == env_path
        raise rotate.RotationError("caller shutdown failed")

    postgres_changed = False

    def record_postgres_change(selected_env, password):
        nonlocal postgres_changed
        _ = selected_env, password
        postgres_changed = True

    monkeypatch.setattr(rotate, "_stop_callers", stop_fails)
    monkeypatch.setattr(rotate, "_alter_postgres_role", record_postgres_change)

    with pytest.raises(rotate.RotationError, match="caller shutdown failed"):
        rotate._state_preserving_rotation(
            env_path,
            dry_run=False,
            no_restart=False,
        )

    assert postgres_changed is False
    assert env_path.read_text(encoding="utf-8").startswith("S43_JWT_SECRET=")
