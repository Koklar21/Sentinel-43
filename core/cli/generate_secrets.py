# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is distributed under a dual-license model:
#   1. GNU Affero General Public License (AGPL v3.0)
#   2. Commercial License
#
# core/cli/generate_secrets.py
# =============================================================================
"""
Sentinel-43 Secret Generator — canonical implementation.

Called by three surfaces:
  scripts/generate_secrets.py          direct script execution (pre-install)
  s43-generate-secrets                 installed entry point (pyproject.toml)
  docker compose --profile setup run   Docker setup service

Safety contract:
  - Never imported by the application at runtime.
  - Never rotates secrets silently.
  - Never overwrites existing .env values without --force.
  - Never prints raw secret values except to stdout on explicit request.
  - Does not start background threads, open ports, or write outside the
    target .env file.

Usage:
  python scripts/generate_secrets.py                  print to stdout
  python scripts/generate_secrets.py --write .env     append missing secrets
  python scripts/generate_secrets.py --write .env --force   rotate all
  python scripts/generate_secrets.py --check .env     validate existing .env
  python scripts/generate_secrets.py --password-hash  generate operator hash
"""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import sys
from getpass import getpass
from pathlib import Path
from typing import Final


# =============================================================================
# Bootstrap constants — imported from core.bootstrap when available.
# Fallback values match bootstrap.py so the tool stays correct when run
# before the package is installed (e.g. first-time setup from a fresh clone).
# =============================================================================

try:
    from core.bootstrap import APPROVED_JWT_ALGORITHMS, _MIN_PEPPER_BYTES  # type: ignore[import]
    _BOOTSTRAP_IMPORTED = True
except ImportError:
    APPROVED_JWT_ALGORITHMS: frozenset[str] = frozenset({"HS256"})  # type: ignore[assignment]
    _MIN_PEPPER_BYTES: int = 32                                       # type: ignore[assignment]
    _BOOTSTRAP_IMPORTED = False


# =============================================================================
# Secret registry
#
# Each entry is (env_key, generator_fn, section_comment).
# Section comments produce grouped output in render_env_block().
#
# Keys excluded from this registry (managed separately):
#   S43_OPERATOR_PASSWORD_HASH  — derived from user password, use --password-hash
#   DATABASE_URL                — derived from POSTGRES_PASSWORD, not random
#   S43_JORM_ROOT_KEY           — only needed when S43_JORM_ENABLED=true
#   S43_SPARTA_TOKEN_SECRET     — only needed when S43_SPARTA_ENABLED=true
#   S43_SPARTA_NODE_TOKEN       — only needed when S43_SPARTA_ENABLED=true
# =============================================================================

# Generator callables: each takes num_bytes (int) and returns a str.
# token_hex    — for salts, peppers, DB passwords (avoids URL-special chars)
# token_urlsafe — for bearer tokens and JWT secrets (shorter, header-safe)
def _hex(n: int) -> str:
    return secrets.token_hex(n)

def _url(n: int) -> str:
    return secrets.token_urlsafe(n)


_REGISTRY: tuple[tuple[str, object, str | None], ...] = (
    # (env_key, generator_fn, section_heading or None)
    ("S43_JWT_SECRET",               _url,  "JWT signing"),
    ("S43_AUTH_PEPPER",              _hex,  "Auth key-store hardening (required in production by bootstrap.py)"),
    ("SENTINEL_LOG_SALT",            _hex,  "Log pseudonymization (required in production by sentinel_ai_escalation.py)"),
    ("SENTINEL_REMOTE_TOKEN_OWNER",  _url,  "Remote gateway operator tokens"),
    ("SENTINEL_REMOTE_TOKEN_ADMIN",  _url,  None),
    ("SENTINEL_REMOTE_TOKEN_AUDITOR",_url,  None),
    ("S43_FENRIR_API_TOKEN",         _url,  "Fenrir internal API token (required when S43_FENRIR_ENABLED=true)"),
    ("POSTGRES_PASSWORD",            _hex,  "Infrastructure"),
    ("REDIS_PASSWORD",               _hex,  None),
)

SECRET_KEYS: Final[tuple[str, ...]] = tuple(key for key, _, _ in _REGISTRY)

# Values that indicate a secret has never been set.
_PLACEHOLDERS: Final[frozenset[str]] = frozenset({
    "", "CHANGE_ME", "CHANGE_ME_IN_PROD", "CHANGEME",
    "dev-placeholder", "development", "password", "secret",
    "your-secret-here", "replace-me",
})

DEFAULT_BYTES: Final[int] = 32


# =============================================================================
# Generators
# =============================================================================

def generate_env_values(*, num_bytes: int = DEFAULT_BYTES) -> dict[str, str]:
    """Generate a fresh value for every key in SECRET_KEYS."""
    if num_bytes < 32:
        raise ValueError("num_bytes must be >= 32")
    return {key: gen(num_bytes) for key, gen, _ in _REGISTRY}


# =============================================================================
# .env file helpers
# =============================================================================

def parse_env_file(path: Path) -> dict[str, str]:
    """
    Parse KEY=VALUE pairs from a .env file.

    Skips comments and blank lines. Does not expand shell variables.
    Returns an empty dict if the file does not exist.
    """
    if not path.exists():
        return {}

    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def render_env_block(values: dict[str, str]) -> str:
    """
    Render generated values as a structured, copy-pasteable .env block.
    Sections are grouped with comments matching the registry headings.
    """
    lines: list[str] = [
        "# =============================================================================",
        "# Sentinel-43 generated secrets",
        "# Generated once. Store securely. Do not commit .env to version control.",
        "# Rotate intentionally with: python scripts/generate_secrets.py --write .env --force",
        "# =============================================================================",
        "",
    ]

    last_section: str | None = object()  # sentinel — different from None and any string

    for key, _, section in _REGISTRY:
        if section is not None and section != last_section:
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(f"# {section}")
            last_section = section
        lines.append(f"{key}={values[key]}")

    lines += [
        "",
        "# --- Set these manually (not randomly generated) ---",
        "# S43_OPERATOR_PASSWORD_HASH=<run: python scripts/generate_secrets.py --password-hash>",
        "# DATABASE_URL=postgresql+asyncpg://s43:<POSTGRES_PASSWORD>@s43-db:5432/s43",
        "",
    ]

    # LF line endings — avoids \r\n issues inside Docker containers on Windows.
    return "\n".join(lines)


def write_env_file(
    path: Path,
    values: dict[str, str],
    *,
    force: bool = False,
) -> list[str]:
    """
    Write generated secrets to a .env file.

    Default (force=False):
      - Keys already present: left unchanged.
      - Keys missing: appended at the end.

    With force=True:
      - Keys in SECRET_KEYS that already exist: replaced in-place.
      - All other lines, comments, and ordering: preserved.
      - Keys still missing after scan: appended.

    Returns the list of keys that were actually written or updated.

    Writes LF line endings (newline="\\n") regardless of OS to ensure
    Docker containers read the file correctly on Windows hosts.
    """
    if not path.exists():
        path.write_text(render_env_block(values), encoding="utf-8", newline="\n")
        return list(SECRET_KEYS)

    original = path.read_text(encoding="utf-8").splitlines()
    output: list[str] = []
    written: list[str] = []
    seen: set[str] = set()

    for raw in original:
        stripped = raw.strip()

        if "=" not in stripped or stripped.startswith("#"):
            output.append(raw)
            continue

        key, _ = stripped.split("=", 1)
        key = key.strip()

        if key in values:
            seen.add(key)
            if force:
                output.append(f"{key}={values[key]}")
                written.append(key)
            else:
                output.append(raw)
        else:
            output.append(raw)

    missing = [k for k in SECRET_KEYS if k not in seen]
    if missing:
        if output and output[-1].strip():
            output.append("")
        output.append("# Sentinel-43 generated secrets")
        for key in missing:
            output.append(f"{key}={values[key]}")
            written.append(key)

    path.write_text(
        "\n".join(output).rstrip() + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return written


def check_env_file(path: Path) -> tuple[list[str], list[str], list[str]]:
    """
    Validate an existing .env file against SECRET_KEYS.

    Returns (present, missing, placeholder) lists of key names.
    A key is 'placeholder' if it exists but its value is in _PLACEHOLDERS.
    Exit code convention: 0 if missing+placeholder is empty, else 1.
    """
    existing = parse_env_file(path)
    present:     list[str] = []
    missing:     list[str] = []
    placeholder: list[str] = []

    for key in SECRET_KEYS:
        value = existing.get(key, "")
        if value in _PLACEHOLDERS:
            if key in existing:
                placeholder.append(key)
            else:
                missing.append(key)
        else:
            present.append(key)

    return present, missing, placeholder


# =============================================================================
# Algorithm / bootstrap cross-checks
# =============================================================================

def _warn_if_bootstrap_mismatch() -> None:
    """
    Warn if the runtime bootstrap constants differ from the generator's
    hardcoded fallbacks. Indicates bootstrap.py was not importable.
    """
    if not _BOOTSTRAP_IMPORTED:
        print(
            "Warning: core.bootstrap could not be imported. "
            "Using hardcoded fallback constants. "
            "Run from the repo root or install the package for full validation.",
            file=sys.stderr,
        )


def _validate_jwt_algorithm(algorithm: str) -> None:
    """
    Warn if S43_JWT_ALGORITHM in the environment is not in the approved set.
    This is advisory — the generator does not refuse to run.
    """
    if algorithm and algorithm not in APPROVED_JWT_ALGORITHMS:
        print(
            f"Warning: S43_JWT_ALGORITHM={algorithm!r} is not in the approved "
            f"algorithm set {sorted(APPROVED_JWT_ALGORITHMS)}. "
            "Update S43_JWT_ALGORITHM in .env before deployment.",
            file=sys.stderr,
        )


# =============================================================================
# Password hash flow
# =============================================================================

def password_hash_flow() -> int:
    """
    Interactively generate S43_OPERATOR_PASSWORD_HASH.

    Sentinel-43 uses sha256(password).hexdigest() for closed beta.
    Upgrade to Argon2/bcrypt before public release.
    The hash is printed to stdout only — never logged or written to disk
    by this function. Paste the output into .env manually.
    """
    print(
        "Generating S43_OPERATOR_PASSWORD_HASH\n"
        "Note: SHA-256 is used for closed beta. Upgrade to Argon2/bcrypt "
        "before public release.",
        file=sys.stderr,
    )

    try:
        password_1 = getpass("Operator password: ")
        password_2 = getpass("Confirm password:  ")
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.", file=sys.stderr)
        return 130

    if not password_1:
        print("ERROR: password cannot be empty.", file=sys.stderr)
        return 2

    if password_1 != password_2:
        print("ERROR: passwords do not match.", file=sys.stderr)
        return 2

    digest = hashlib.sha256(password_1.encode("utf-8")).hexdigest()
    print(f"S43_OPERATOR_PASSWORD_HASH={digest}")
    print(
        "\nPaste the line above into .env. "
        "Do not commit .env to version control.",
        file=sys.stderr,
    )
    return 0


# =============================================================================
# CLI
# =============================================================================

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="generate_secrets",
        description="Generate Sentinel-43 deployment secrets safely.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Print all generated secrets to stdout (safe to review before writing):
    python scripts/generate_secrets.py

  Write missing secrets into .env without touching existing values:
    python scripts/generate_secrets.py --write .env

  Rotate all generated secrets in .env (use intentionally):
    python scripts/generate_secrets.py --write .env --force

  Validate an existing .env for missing or placeholder secrets:
    python scripts/generate_secrets.py --check .env

  Generate the operator password hash interactively:
    python scripts/generate_secrets.py --password-hash

  Docker setup service (see docker-compose.setup.yml):
    docker compose --profile setup run --rm s43-setup --write /app/.env
""",
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--write",
        metavar="ENV_FILE",
        help="Write missing generated secrets to ENV_FILE. Safe by default — "
             "existing values are never overwritten without --force.",
    )
    mode.add_argument(
        "--check",
        metavar="ENV_FILE",
        help="Validate ENV_FILE for missing or placeholder secrets. "
             "Exits 0 if all present, 1 if any missing or placeholder.",
    )
    mode.add_argument(
        "--password-hash",
        action="store_true",
        help="Prompt for an operator password and print S43_OPERATOR_PASSWORD_HASH.",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="With --write: replace existing generated keys with fresh values. "
             "Use intentionally during planned secret rotation.",
    )
    parser.add_argument(
        "--bytes",
        type=int,
        default=DEFAULT_BYTES,
        metavar="N",
        help=f"Entropy bytes per secret (default: {DEFAULT_BYTES}, minimum: 32).",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    _warn_if_bootstrap_mismatch()

    # --- --password-hash ---
    if args.password_hash:
        return password_hash_flow()

    # --- --check ---
    if args.check:
        env_path = Path(args.check)
        if not env_path.exists():
            print(f"ERROR: {env_path} does not exist.", file=sys.stderr)
            return 1

        present, missing, placeholder = check_env_file(env_path)
        width = max(len(k) for k in SECRET_KEYS)

        print(f"Checking {env_path} ({len(SECRET_KEYS)} required secrets):\n")
        for key in SECRET_KEYS:
            if key in present:
                marker = "✓"
                status = "present"
            elif key in placeholder:
                marker = "!"
                status = "PLACEHOLDER — replace before deployment"
            else:
                marker = "✗"
                status = "MISSING"
            print(f"  {marker}  {key:<{width}}  {status}")

        problems = len(missing) + len(placeholder)
        print()
        if problems == 0:
            print(f"All {len(SECRET_KEYS)} secrets present. ✓")
            return 0
        else:
            print(
                f"{problems} problem(s) found. "
                f"Run: python scripts/generate_secrets.py --write {env_path}"
            )
            return 1

    # --- entropy validation ---
    if args.bytes < 32:
        print("ERROR: --bytes must be >= 32.", file=sys.stderr)
        return 2

    # --- advisory algorithm check ---
    _validate_jwt_algorithm(os.getenv("S43_JWT_ALGORITHM", ""))

    values = generate_env_values(num_bytes=args.bytes)

    # --- --write ---
    if args.write:
        env_path = Path(args.write)
        written = write_env_file(env_path, values, force=args.force)

        if written:
            action = "Rotated" if args.force else "Wrote"
            print(f"{action} {len(written)} key(s) to {env_path}:")
            for key in written:
                print(f"  + {key}")
            print(
                f"\nNext step: set S43_OPERATOR_PASSWORD_HASH with --password-hash\n"
                f"Then rebuild: docker compose build --no-cache s43-api"
            )
        else:
            print(
                f"No changes made to {env_path}.\n"
                "All generated keys already exist. "
                "Use --force to rotate intentionally."
            )
        return 0

    # --- default: print to stdout ---
    print(render_env_block(values), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())