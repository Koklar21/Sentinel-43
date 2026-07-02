# =============================================================================
# Sentinel-43 Secret Generator
#
# Purpose:
#   Generate strong one-time bootstrap secrets for Sentinel-43 deployments.
#
# Safety rules:
#   - Does NOT run at app startup.
#   - Does NOT silently rotate secrets.
#   - Does NOT overwrite existing .env values unless --force is passed.
#   - Does NOT log secrets anywhere except stdout or the selected env file.
#   - Intended for setup/bootstrap, not runtime.
#
# Usage:
#   python scripts/generate_secrets.py
#   python scripts/generate_secrets.py --write .env
#   python scripts/generate_secrets.py --write .env --force
#   python scripts/generate_secrets.py --password-hash
#
# =============================================================================

from __future__ import annotations

import argparse
import hashlib
import secrets
import sys
from getpass import getpass
from pathlib import Path


DEFAULT_SECRET_BYTES = 32  # token_hex(32) => 64 hex characters


# Keep this list aligned with:
#   - .env.example / deployment .env requirements
#   - core/bootstrap.py production secret validation
#   - remote gateway token configuration
#   - Fenrir enablement requirements
#
# Do not include S43_OPERATOR_PASSWORD_HASH here. That must be derived from the
# actual operator password via --password-hash.
SECRET_KEYS: tuple[str, ...] = (
    "S43_JWT_SECRET",
    "S43_AUTH_PEPPER",
    "SENTINEL_LOG_SALT",
    "S43_FENRIR_API_TOKEN",
    "SENTINEL_REMOTE_TOKEN_OWNER",
    "SENTINEL_REMOTE_TOKEN_ADMIN",
    "SENTINEL_REMOTE_TOKEN_AUDITOR",
    "POSTGRES_PASSWORD",
    "REDIS_PASSWORD",
)


def generate_hex_secret(num_bytes: int = DEFAULT_SECRET_BYTES) -> str:
    """Return a cryptographically secure hex secret."""
    if num_bytes < 32:
        raise ValueError("Secret length must be at least 32 bytes.")
    return secrets.token_hex(num_bytes)


def generate_env_values(*, num_bytes: int = DEFAULT_SECRET_BYTES) -> dict[str, str]:
    """Generate fresh values for all Sentinel-43 bootstrap secrets."""
    return {key: generate_hex_secret(num_bytes) for key in SECRET_KEYS}


def parse_env_file(path: Path) -> dict[str, str]:
    """
    Parse a simple KEY=VALUE .env file.

    This parser intentionally ignores shell expansion and advanced dotenv
    features. The generator only needs to know which keys already exist.
    """
    values: dict[str, str] = {}

    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()

    return values


def render_env_block(values: dict[str, str]) -> str:
    """Render generated values as a copy/pasteable .env block."""
    lines = [
        "# =============================================================================",
        "# Sentinel-43 generated secrets",
        "# Generated once. Store securely. Do not commit .env.",
        "# =============================================================================",
    ]

    for key in SECRET_KEYS:
        lines.append(f"{key}={values[key]}")

    return "\n".join(lines) + "\n"


def write_env_file(path: Path, values: dict[str, str], *, force: bool = False) -> list[str]:
    """
    Append or replace generated secrets in an env file.

    Default behavior:
      - Missing generated keys are appended.
      - Existing generated keys are left unchanged.

    With force=True:
      - Existing generated keys are replaced.
      - Other keys and comments are preserved.
    """
    if not path.exists():
        path.write_text(render_env_block(values), encoding="utf-8")
        return list(SECRET_KEYS)

    original_lines = path.read_text(encoding="utf-8").splitlines()
    output_lines: list[str] = []
    written: list[str] = []
    seen_keys: set[str] = set()

    for raw_line in original_lines:
        stripped = raw_line.strip()

        if "=" not in stripped or stripped.startswith("#"):
            output_lines.append(raw_line)
            continue

        key, _old_value = stripped.split("=", 1)
        key = key.strip()

        if key in values:
            seen_keys.add(key)

            if force:
                output_lines.append(f"{key}={values[key]}")
                written.append(key)
            else:
                output_lines.append(raw_line)
        else:
            output_lines.append(raw_line)

    missing_keys = [key for key in SECRET_KEYS if key not in seen_keys]

    if missing_keys:
        if output_lines and output_lines[-1].strip():
            output_lines.append("")

        output_lines.append("# Sentinel-43 generated secrets")
        for key in missing_keys:
            output_lines.append(f"{key}={values[key]}")
            written.append(key)

    path.write_text("\n".join(output_lines).rstrip() + "\n", encoding="utf-8")
    return written


def password_hash_flow() -> int:
    """
    Generate S43_OPERATOR_PASSWORD_HASH from an operator password.

    Sentinel-43 currently uses sha256(password).hexdigest() for closed beta.
    Upgrade to Argon2 or bcrypt before public release.
    """
    password_1 = getpass("Operator password: ")
    password_2 = getpass("Confirm password: ")

    if not password_1:
        print("ERROR: password cannot be empty.", file=sys.stderr)
        return 2

    if password_1 != password_2:
        print("ERROR: passwords do not match.", file=sys.stderr)
        return 2

    digest = hashlib.sha256(password_1.encode("utf-8")).hexdigest()
    print(f"S43_OPERATOR_PASSWORD_HASH={digest}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate Sentinel-43 bootstrap secrets safely.",
    )
    parser.add_argument(
        "--bytes",
        type=int,
        default=DEFAULT_SECRET_BYTES,
        help="Random bytes per secret. Default: 32 bytes => 64 hex characters.",
    )
    parser.add_argument(
        "--write",
        metavar="ENV_FILE",
        help="Write missing generated secrets to an env file, usually .env.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace existing generated keys in the target env file.",
    )
    parser.add_argument(
        "--password-hash",
        action="store_true",
        help="Prompt for an operator password and print S43_OPERATOR_PASSWORD_HASH.",
    )

    args = parser.parse_args(argv)

    if args.password_hash:
        return password_hash_flow()

    if args.bytes < 32:
        print("ERROR: --bytes must be at least 32.", file=sys.stderr)
        return 2

    values = generate_env_values(num_bytes=args.bytes)

    if args.write:
        env_path = Path(args.write)
        written = write_env_file(env_path, values, force=args.force)

        if written:
            print(f"Wrote {len(written)} key(s) to {env_path}:")
            for key in written:
                print(f"  - {key}")
        else:
            print(
                f"No changes made to {env_path}. "
                "All generated keys already exist. Use --force to rotate intentionally."
            )

        return 0

    print(render_env_block(values), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

out = Path("/mnt/data/generate_secrets_recode.py")
out.write_text(script, encoding="utf-8")
print(f"Created {out}")
