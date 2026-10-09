"""Regression checks for the Compose secret bootstrap entrypoint.

These tests never invoke Docker or start a service.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from scripts import compose_bootstrap


def test_new_install_provisions_database_url_without_docker(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    with patch.object(compose_bootstrap.subprocess, "run") as run, patch.object(
        compose_bootstrap.subprocess, "call"
    ) as call:
        assert compose_bootstrap.main(["--env-file", str(env)]) == 0
    values = compose_bootstrap.parse_env_file(env)
    assert values["POSTGRES_PASSWORD"]
    assert values["DATABASE_URL"].startswith("postgresql+asyncpg://s43:")
    assert values["DATABASE_URL"].endswith("@s43-db:5432/s43")
    run.assert_not_called()
    call.assert_not_called()


def test_second_run_preserves_all_values(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    assert compose_bootstrap.main(["--env-file", str(env)]) == 0
    before = env.read_bytes()
    assert compose_bootstrap.main(["--env-file", str(env)]) == 0
    assert env.read_bytes() == before


def test_existing_empty_env_fails_closed(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("", encoding="utf-8")
    with pytest.raises(SystemExit):
        compose_bootstrap.main(["--env-file", str(env)])
    assert env.read_text(encoding="utf-8") == ""


def test_beta_requires_explicit_start(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        compose_bootstrap.main(["--env-file", str(tmp_path / ".env"), "--beta"])
    assert not (tmp_path / ".env").exists()


def test_symlink_refused_before_resolution(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("DO_NOT_TOUCH", encoding="utf-8")
    link = tmp_path / ".env"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not supported on this platform")
    with pytest.raises(SystemExit):
        compose_bootstrap.main(["--env-file", str(link)])
    assert target.read_text(encoding="utf-8") == "DO_NOT_TOUCH"


def test_invalid_existing_password_not_rotated(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    assert compose_bootstrap.main(["--env-file", str(env)]) == 0
    original = env.read_text(encoding="utf-8")
    changed = original.replace(
        "POSTGRES_PASSWORD=" + compose_bootstrap.parse_env_file(env)["POSTGRES_PASSWORD"],
        "POSTGRES_PASSWORD=CHANGE_ME",
    )
    env.write_text(changed, encoding="utf-8")
    with pytest.raises(SystemExit):
        compose_bootstrap.main(["--env-file", str(env)])
    assert env.read_text(encoding="utf-8") == changed


def test_compose_config_failure_blocks_up(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    assert compose_bootstrap.main(["--env-file", str(env)]) == 0
    # The bootstrap correctly rejects inherited secrets that conflict with the
    # chosen env file. Isolate this test from host/earlier-test credentials so
    # it exercises Compose validation rather than that unrelated safety gate.
    with patch.dict(compose_bootstrap.os.environ, compose_bootstrap.parse_env_file(env)):
        with patch.object(compose_bootstrap.subprocess, "run") as run, patch.object(
            compose_bootstrap.subprocess, "call"
        ) as call:
            run.return_value.returncode = 1
            assert compose_bootstrap.main(["--env-file", str(env), "--start"]) == 1
            assert run.call_args.args[0][-2:] == ["config", "--quiet"]
            call.assert_not_called()
