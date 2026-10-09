#!/usr/bin/env python3
"""Provision secrets before a governed Compose startup; never rotate implicitly.

Run from any directory: python scripts/compose_bootstrap.py [--start] [--beta]
No Docker command is executed unless --start is explicitly requested.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.cli.generate_secrets import (  # noqa: E402
    check_env_file, generate_env_values, parse_env_file, write_env_file,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    parser.add_argument("--start", action="store_true", help="Start Docker Compose after provisioning")
    parser.add_argument("--beta", action="store_true", help="Include controlled-beta Compose override")
    args = parser.parse_args(argv)
    path = args.env_file.resolve()
    if args.beta and not args.start:
        parser.error("--beta requires --start")
    if path.is_symlink():
        parser.error("Refusing symlinked secret environment file")
    if path.exists() and not path.is_file():
        parser.error("Secret environment path is not a regular file")
    if path.exists() and path.stat().st_size == 0:
        parser.error("Empty existing environment file: repair explicitly")

    # A fresh installation may be provisioned. Existing installations may
    # gain missing keys, but an existing DB URL is never silently rewritten.
    before = parse_env_file(path)
    if path.exists() and "POSTGRES_PASSWORD" not in before:
        parser.error("Existing environment lacks POSTGRES_PASSWORD; provision/repair manually to avoid DB lockout")
    if path.exists() and not before.get("DATABASE_URL"):
        parser.error("Existing environment lacks DATABASE_URL; configure it manually")
    if path.exists() and "POSTGRES_PASSWORD" in before and "DATABASE_URL" in before:
        # No implicit database credential migration. Existing URL remains authoritative.
        from urllib.parse import urlsplit
        try:
            if urlsplit(before["DATABASE_URL"]).password != before["POSTGRES_PASSWORD"]:
                parser.error("DATABASE_URL and POSTGRES_PASSWORD differ; reconcile manually")
        except ValueError:
            parser.error("DATABASE_URL is malformed")

    if not path.exists():
        values = generate_env_values()
        password = values["POSTGRES_PASSWORD"]
        values["DATABASE_URL"] = "postgresql+asyncpg://s43:" + quote(password, safe="") + "@s43-db:5432/s43"
        # Write the complete file atomically with owner-only creation.
        from core.cli.generate_secrets import render_env_block, _atomic_write_text
        _atomic_write_text(path, render_env_block(values) + "DATABASE_URL=" + values["DATABASE_URL"] + "\n")
    else:
        # Refuse invalid values instead of overwriting or silently rotating.
        _, _, invalid = check_env_file(path)
        if invalid:
            parser.error("Invalid existing secret keys: " + ", ".join(sorted(invalid)))
        write_env_file(path, generate_env_values(), force=False)

    _, missing, invalid = check_env_file(path)
    if missing or invalid:
        parser.error("Secret provisioning incomplete: " + ", ".join(missing + list(invalid)))
    final = parse_env_file(path)
    if not final.get("DATABASE_URL") or not final.get("POSTGRES_PASSWORD"):
        parser.error("Database configuration incomplete")
    print("Deployment secrets provisioned and validated; existing values preserved.")
    if not args.start:
        print("Docker not started. Pass --start when ready.")
        return 0

    # Compose interpolates process environment ahead of --env-file. Reject
    # conflicting inherited values so the checked file is authoritative.
    for key in final:
        if key in os.environ and os.environ[key] != final[key]:
            parser.error("Conflicting inherited environment variable: " + key)

    cmd = ["docker", "compose", "--env-file", str(path), "-f", str(ROOT / "docker-compose.yml")]
    if args.beta:
        cmd += ["-f", str(ROOT / "docker-compose.beta.yml")]
    # Do not print expanded Compose configuration, which can contain secrets.
    cmd += ["up", "-d", "--build"]
    try:
        return subprocess.call(cmd, cwd=ROOT, env=os.environ.copy())
    except FileNotFoundError:
        print("Docker executable not found; no containers started.", file=sys.stderr)
        return 127


if __name__ == "__main__":
    raise SystemExit(main())
