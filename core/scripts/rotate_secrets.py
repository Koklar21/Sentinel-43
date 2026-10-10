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

"""Coordinated local Docker Compose secret rotation.

This is the orchestration layer around the canonical secret generator.

Why it exists:
    - POSTGRES_PASSWORD and DATABASE_URL must move together.
    - A live PostgreSQL role must be changed before services restart.
    - S43_SECRETS_ROTATED_AT must reflect an actual completed rotation.
    - Rotating S43_AUDIT_HMAC_KEY against an existing audit ledger makes that
      ledger unverifiable, so routine state-preserving rotation must keep that
      durable integrity root stable.
    - Ordinary rotation and destructive "rotate absolutely everything" are
      different operations and must not be conflated.

Modes:
    default
        State-preserving local rotation. Rotates operational deployment
        credentials, updates the live PostgreSQL role, rewrites DATABASE_URL,
        preserves S43_AUDIT_HMAC_KEY and S43_JORM_ROOT_KEY, validates, and
        recreates the Compose stack.

    --full-reset --yes
        Rotates every managed deployment secret, including durable integrity
        roots, then removes Compose volumes before recreating the stack.
        This intentionally starts PostgreSQL and the local audit ledger fresh.

The local break-glass S43_OPERATOR_PASSWORD_HASH is deliberately not generated
here. It is a human-selected credential verifier, not a random deployment
secret. Generate it separately with the canonical --password-hash flow.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import os
import secrets
import tempfile
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit


_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from core.cli.generate_secrets import (  # noqa: E402
    SECRET_KEYS,
    check_env_file,
    generate_env_values,
)


LOCAL_ENVIRONMENTS = frozenset({"development", "dev", "local", "test", "testing"})
ROTATION_TIMESTAMP_KEY = "S43_SECRETS_ROTATED_AT"
CALLER_SERVICES = ("s43-proxy", "s43-api", "s43-core", "s43-migrate")

# These roots protect persisted material and cannot be changed in-place without
# invalidating that material. Routine rotation therefore preserves them.
DURABLE_STATE_ROOTS = frozenset(
    {
        "S43_AUDIT_HMAC_KEY",
        "S43_JORM_ROOT_KEY",
    }
)

# Secrets present in .env.example but intentionally outside the canonical
# generate_secrets.py registry. Rotate them when configured/enabled.
OPTIONAL_SECRET_GENERATORS = {
    "S43_JORM_ROOT_KEY": lambda: secrets.token_hex(32),
    "S43_SPARTA_TOKEN_SECRET": lambda: secrets.token_urlsafe(32),
    "S43_SPARTA_NODE_TOKEN": lambda: secrets.token_urlsafe(32),
    "S43_EBPF_INGEST_TOKEN": lambda: secrets.token_urlsafe(32),
    "S43_ROUTER_INGEST_TOKEN": lambda: secrets.token_urlsafe(32),
}

FEATURE_ENABLE_KEY = {
    "S43_JORM_ROOT_KEY": "S43_JORM_ENABLED",
    "S43_SPARTA_TOKEN_SECRET": "S43_SPARTA_ENABLED",
    "S43_SPARTA_NODE_TOKEN": "S43_SPARTA_ENABLED",
    "S43_EBPF_INGEST_TOKEN": "S43_EBPF_ENABLED",
    "S43_ROUTER_INGEST_TOKEN": "S43_ROUTER_ENABLED",
}


class RotationError(RuntimeError):
    pass


def _run(
    args: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
    capture: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=_REPO_ROOT,
        input=input_text,
        text=True,
        capture_output=capture,
        check=False,
        env=env,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RotationError(
            f"Command failed ({result.returncode}): {' '.join(args)}"
            + (f"\n{detail}" if detail else "")
        )
    return result


def _compose(
    env_path: Path,
    *args: str,
    **kwargs,
) -> subprocess.CompletedProcess[str]:
    """Run Compose with the selected env file authoritative over the caller shell."""
    compose_env = os.environ.copy()
    # Compose gives exported shell variables precedence over --env-file. Remove
    # every key owned by the selected file from the child process environment so
    # stale shell exports cannot silently override a just-rotated credential.
    for key in _read_env(env_path):
        compose_env.pop(key, None)

    return _run(
        [
            "docker",
            "compose",
            "--env-file",
            str(env_path),
            *args,
        ],
        env=compose_env,
        **kwargs,
    )


def _read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    duplicates: set[str] = set()

    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue

        key, value = stripped.split("=", 1)
        key = key.strip()
        if key in values:
            duplicates.add(key)
            continue
        values[key] = value

    if duplicates:
        raise RotationError(
            "Duplicate .env key(s): " + ", ".join(sorted(duplicates))
        )

    return values


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _require_local(values: dict[str, str]) -> None:
    sentinel_env = values.get("SENTINEL_ENV", "").strip().lower()
    s43_env = values.get("S43_ENV", "").strip().lower()

    if sentinel_env not in LOCAL_ENVIRONMENTS or s43_env not in LOCAL_ENVIRONMENTS:
        raise RotationError(
            "This workflow is local-Compose only. "
            "SENTINEL_ENV and S43_ENV must both be local/dev/test values."
        )


def _database_url_with_password(database_url: str, password: str) -> str:
    parsed = urlsplit(database_url)
    if not parsed.scheme or not parsed.hostname:
        raise RotationError("DATABASE_URL is missing a valid scheme or hostname.")

    username = parsed.username or "s43"
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    port = f":{parsed.port}" if parsed.port else ""
    netloc = (
        f"{quote(username, safe='')}:{quote(password, safe='')}@{host}{port}"
    )

    return urlunsplit(
        (
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )


def _assert_owner_only(path: Path) -> None:
    """Fail closed if a POSIX secret file is readable by group/other users."""
    if os.name != "posix":
        return

    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise RotationError(
            f"Secret file permissions are too broad for {path}: {mode:04o}"
        )


def _atomic_replace_owner_only(path: Path, payload: bytes) -> None:
    """Durably replace a secret file without ever creating a broad-permission inode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.rotate.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None
    try:
        fd = os.open(temp, flags, 0o600)
        if os.name == "posix":
            os.fchmod(fd, 0o600)

        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

        if os.name == "posix":
            os.chmod(temp, 0o600)
            _assert_owner_only(temp)

        os.replace(temp, path)

        if os.name == "posix":
            os.chmod(path, 0o600)
            _assert_owner_only(path)
    finally:
        if fd is not None:
            os.close(fd)
        temp.unlink(missing_ok=True)


def _atomic_update_env(path: Path, replacements: dict[str, str]) -> None:
    original = path.read_text(encoding="utf-8-sig").splitlines()
    seen: set[str] = set()
    output: list[str] = []

    for raw in original:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            output.append(raw)
            continue

        key, _ = stripped.split("=", 1)
        key = key.strip()

        if key in seen:
            raise RotationError(f"Duplicate .env key detected: {key}")
        seen.add(key)

        if key in replacements:
            output.append(f"{key}={replacements[key]}")
        else:
            output.append(raw)

    missing = [key for key in replacements if key not in seen]
    if missing:
        if output and output[-1].strip():
            output.append("")
        output.append("# Sentinel-43 coordinated secret rotation")
        for key in missing:
            output.append(f"{key}={replacements[key]}")

    payload = ("\n".join(output).rstrip() + "\n").encode("utf-8")
    _atomic_replace_owner_only(path, payload)


@contextmanager
def _temporary_env_backup(path: Path):
    """Keep rollback bytes only for the duration of the rotation.

    A temporary, owner-restricted file avoids accumulating timestamped copies
    of credentials. It is removed on both success and ordinary exceptions.
    """
    with tempfile.TemporaryDirectory(prefix=".s43-rotation-", dir=path.parent) as directory:
        backup = Path(directory) / "rollback.env"
        _atomic_replace_owner_only(backup, path.read_bytes())
        yield backup


def _restore_env(backup: Path, path: Path) -> None:
    _atomic_replace_owner_only(path, backup.read_bytes())


def _configured_optional_secret(
    key: str,
    values: dict[str, str],
) -> bool:
    current = values.get(key, "").strip()
    enabled_key = FEATURE_ENABLE_KEY[key]
    return bool(current) or _truthy(values.get(enabled_key))


def _build_replacements(
    existing: dict[str, str],
    *,
    full_reset: bool,
) -> tuple[dict[str, str], list[str]]:
    generated = generate_env_values()
    rotated: list[str] = []

    for key in SECRET_KEYS:
        if key in DURABLE_STATE_ROOTS and not full_reset:
            if not existing.get(key, "").strip():
                raise RotationError(
                    f"{key} is required for state-preserving rotation but is missing."
                )
            generated[key] = existing[key]
        else:
            rotated.append(key)

    replacements = dict(generated)

    for key, generator in OPTIONAL_SECRET_GENERATORS.items():
        if not _configured_optional_secret(key, existing):
            continue

        if key in DURABLE_STATE_ROOTS and not full_reset:
            if not existing.get(key, "").strip():
                raise RotationError(
                    f"{key} is enabled/configured but missing."
                )
            replacements[key] = existing[key]
        else:
            replacements[key] = generator()
            rotated.append(key)

    database_url = existing.get("DATABASE_URL", "").strip()
    if not database_url:
        raise RotationError("DATABASE_URL is missing.")

    replacements["DATABASE_URL"] = _database_url_with_password(
        database_url,
        replacements["POSTGRES_PASSWORD"],
    )
    replacements[ROTATION_TIMESTAMP_KEY] = datetime.now(timezone.utc).isoformat()

    return replacements, sorted(set(rotated))


def _validate_env(path: Path) -> None:
    present, missing, invalid = check_env_file(path)
    _ = present
    if missing or invalid:
        details: list[str] = []
        if missing:
            details.append("missing=" + ",".join(sorted(missing)))
        if invalid:
            details.append(
                "invalid="
                + ",".join(f"{key}:{reason}" for key, reason in sorted(invalid.items()))
            )
        raise RotationError(
            "Managed secret validation failed: " + "; ".join(details)
        )


def _wait_for_postgres(env_path: Path, timeout_seconds: int = 60) -> None:
    deadline = time.monotonic() + timeout_seconds

    while time.monotonic() < deadline:
        result = _compose(
            env_path,
            "exec",
            "-T",
            "s43-db",
            "pg_isready",
            "-U",
            "s43",
            "-d",
            "s43",
            "-h",
            "127.0.0.1",
            check=False,
            capture=True,
        )
        if result.returncode == 0:
            return
        time.sleep(2)

    raise RotationError("PostgreSQL did not become ready within 60 seconds.")


def _alter_postgres_role(env_path: Path, password: str) -> None:
    # Generated POSTGRES_PASSWORD values are hexadecimal today, but escape
    # single quotes defensively so this remains safe if the generator changes.
    escaped = password.replace("'", "''")
    sql = f"ALTER ROLE s43 WITH PASSWORD '{escaped}';\n"

    _compose(
        env_path,
        "exec",
        "-T",
        "s43-db",
        "psql",
        "-U",
        "s43",
        "-d",
        "postgres",
        "-v",
        "ON_ERROR_STOP=1",
        input_text=sql,
    )


def _stop_callers(env_path: Path) -> None:
    """Stop credential consumers and verify none remain running."""
    _compose(env_path, "stop", *CALLER_SERVICES)

    result = _compose(
        env_path,
        "ps",
        "--status",
        "running",
        "--services",
        *CALLER_SERVICES,
        capture=True,
    )
    still_running = [
        line.strip()
        for line in (result.stdout or "").splitlines()
        if line.strip()
    ]
    if still_running:
        raise RotationError(
            "Credential consumers are still running after stop: "
            + ", ".join(sorted(set(still_running)))
        )


def _print_plan(
    *,
    full_reset: bool,
    rotated: list[str],
    env_path: Path,
) -> None:
    print("Sentinel-43 coordinated secret rotation")
    print(f"  env file: {env_path}")
    print(f"  mode: {'FULL RESET' if full_reset else 'state-preserving'}")
    print(f"  rotated keys: {len(rotated)}")
    for key in rotated:
        print(f"    - {key}")
    print(f"  rotation timestamp: {ROTATION_TIMESTAMP_KEY}")
    print("  DATABASE_URL: synchronized with the new POSTGRES_PASSWORD")
    if full_reset:
        print("  persistent Compose volumes: REMOVED")
        print("  audit/Jormungandr durable roots: ROTATED")
    else:
        print("  PostgreSQL role s43: updated before service restart")
        print("  audit/Jormungandr durable roots: PRESERVED")


def _state_preserving_rotation(
    env_path: Path,
    *,
    dry_run: bool,
    no_restart: bool,
) -> None:
    existing = _read_env(env_path)
    _require_local(existing)

    old_pg_password = existing.get("POSTGRES_PASSWORD", "").strip()
    if not old_pg_password:
        raise RotationError("POSTGRES_PASSWORD is missing.")

    replacements, rotated = _build_replacements(
        existing,
        full_reset=False,
    )

    _print_plan(
        full_reset=False,
        rotated=rotated,
        env_path=env_path,
    )

    if dry_run:
        print("Dry run only; no files, database roles, or containers were changed.")
        return

    with _temporary_env_backup(env_path) as backup:

        # Keep the database available but fail closed unless every credential
        # consumer is stopped before the shared PostgreSQL password changes.
        _stop_callers(env_path)
        _compose(env_path, "up", "-d", "s43-db")
        _wait_for_postgres(env_path)

        db_role_changed = False
        env_changed = False

        try:
            _alter_postgres_role(env_path, replacements["POSTGRES_PASSWORD"])
            db_role_changed = True

            _atomic_update_env(env_path, replacements)
            env_changed = True

            _validate_env(env_path)
            _compose(env_path, "config", "--quiet")

        except Exception:
            # Before services consume the new values, restore the two coupled
            # credential stores together.
            if env_changed:
                _restore_env(backup, env_path)

            if db_role_changed:
                try:
                    _alter_postgres_role(env_path, old_pg_password)
                except Exception as rollback_exc:
                    print(
                        "WARNING: PostgreSQL credential rollback also failed: "
                        f"{rollback_exc}",
                        file=sys.stderr,
                    )

            raise

        if no_restart:
            print(
                "Rotation committed. Services were not restarted because --no-restart "
                "was supplied."
            )
            return

        _compose(env_path, "up", "-d", "--force-recreate")
        print("Rotation complete. Compose services recreated with the new credentials.")


def _full_reset_rotation(
    env_path: Path,
    *,
    dry_run: bool,
    no_restart: bool,
    confirmed: bool,
) -> None:
    if not confirmed:
        raise RotationError(
            "--full-reset is destructive and requires --yes. "
            "It removes PostgreSQL and Sentinel-43 persistent Compose volumes."
        )

    existing = _read_env(env_path)
    _require_local(existing)

    replacements, rotated = _build_replacements(
        existing,
        full_reset=True,
    )

    _print_plan(
        full_reset=True,
        rotated=rotated,
        env_path=env_path,
    )

    if dry_run:
        print("Dry run only; no files, volumes, or containers were changed.")
        return

    with _temporary_env_backup(env_path) as backup:

        # Validate the future environment BEFORE deleting state.
        try:
            _atomic_update_env(env_path, replacements)
            _validate_env(env_path)
            _compose(env_path, "config", "--quiet")
        except Exception:
            _restore_env(backup, env_path)
            raise

        _compose(env_path, "down", "-v", "--remove-orphans")

        if no_restart:
            print(
                "Full rotation committed and persistent volumes removed. "
                "Services were not restarted because --no-restart was supplied."
            )
            return

        _compose(env_path, "up", "-d", "--force-recreate")
        print(
            "Full rotation complete. Fresh persistent state was created under the "
            "new credential and integrity roots."
        )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="s43-rotate-secrets",
        description=(
            "Coordinate local Sentinel-43 Docker Compose secret rotation, "
            "including PostgreSQL credential persistence."
        ),
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        metavar="PATH",
        help="Environment file to rotate (default: .env).",
    )
    parser.add_argument(
        "--full-reset",
        action="store_true",
        help=(
            "Rotate durable integrity roots too and remove Compose volumes. "
            "Requires --yes."
        ),
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm the destructive --full-reset operation.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the rotation plan without changing anything.",
    )
    parser.add_argument(
        "--no-restart",
        action="store_true",
        help="Commit rotation but do not bring the full stack back up.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    env_path = Path(args.env_file)
    if not env_path.is_absolute():
        env_path = _REPO_ROOT / env_path

    if not env_path.is_file():
        print(f"ERROR: {env_path} does not exist.", file=sys.stderr)
        return 1

    try:
        _compose(env_path, "version", capture=True)

        if args.full_reset:
            _full_reset_rotation(
                env_path,
                dry_run=args.dry_run,
                no_restart=args.no_restart,
                confirmed=args.yes,
            )
        else:
            _state_preserving_rotation(
                env_path,
                dry_run=args.dry_run,
                no_restart=args.no_restart,
            )

    except (OSError, RotationError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print()
    print(
        "S43_OPERATOR_PASSWORD_HASH was intentionally not changed. "
        "For local break-glass rotation use:"
    )
    print(
        '  docker compose --env-file "'
        + str(env_path)
        + '" --profile setup run --rm -it s43-setup --password-hash'
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
