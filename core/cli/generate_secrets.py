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

"""Sentinel-43 deployment secret generator.

Responsibilities:
    - generate cryptographically strong deployment secrets
    - safely add or intentionally rotate managed .env keys
    - validate managed .env secrets
    - generate the break-glass Argon2id password hash interactively
      (local/dev/test only: that login is refused outside it)

This module does not rotate secrets automatically, does not modify DATABASE_URL,
and must not be imported by the running API as a security dependency.
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import sys
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import Callable, Final
from urllib.parse import urlsplit


MIN_SECRET_BYTES: Final[int] = 32
MAX_SECRET_BYTES: Final[int] = 128

_PLACEHOLDERS: Final[frozenset[str]] = frozenset(
    {
        "",
        "CHANGE_ME",
        "CHANGE_ME_IN_PROD",
        "CHANGEME",
        "dev-placeholder",
        "development",
        "password",
        "secret",
        "your-secret-here",
        "replace-me",
    }
)

_ENV_KEY_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*$"
)


def _hex(num_bytes: int) -> str:
    return secrets.token_hex(
        num_bytes
    )


def _urlsafe(num_bytes: int) -> str:
    return secrets.token_urlsafe(
        num_bytes
    )


@dataclass(frozen=True, slots=True)
class SecretSpec:
    key: str
    generator: Callable[[int], str]
    section: str | None
    min_bytes: int = MIN_SECRET_BYTES


_SECRET_SPECS: Final[tuple[SecretSpec, ...]] = (
    SecretSpec(
        "S43_JWT_SECRET",
        _urlsafe,
        "JWT signing",
    ),
    SecretSpec(
        "S43_AUTH_PEPPER",
        _hex,
        "Authentication hardening",
    ),
    SecretSpec(
        "S43_SESSION_HASH_PEPPER",
        _hex,
        None,
    ),
    SecretSpec(
        "SENTINEL_LOG_SALT",
        _hex,
        "Log pseudonymization",
    ),
    SecretSpec(
        "SENTINEL_REMOTE_TOKEN_OWNER",
        _urlsafe,
        "Remote gateway tokens",
    ),
    SecretSpec(
        "SENTINEL_REMOTE_TOKEN_ADMIN",
        _urlsafe,
        None,
    ),
    SecretSpec(
        "SENTINEL_REMOTE_TOKEN_AUDITOR",
        _urlsafe,
        None,
    ),
    SecretSpec(
        "S43_FENRIR_API_TOKEN",
        _urlsafe,
        "Fenrir",
    ),
    SecretSpec(
        "S43_WATCHTOWER_SERVICE_TOKEN",
        _urlsafe,
        "Watchtower",
    ),
    SecretSpec(
        # Keys the authoritative HMAC-chained audit ledger. docker-compose
        # hard-requires this on s43-api and s43-core, so it must come out of
        # the documented secret-generation path or a correct setup still
        # fails Compose's required-variable check.
        #
        # Hex on purpose: core.audit.store decodes an all-hex, even-length
        # value via bytes.fromhex and then enforces >= 32 decoded bytes.
        # token_hex(32) yields 64 hex characters = exactly 32 bytes.
        "S43_AUDIT_HMAC_KEY",
        _hex,
        "Audit integrity",
    ),
    SecretSpec(
        "POSTGRES_PASSWORD",
        _hex,
        "Infrastructure",
    ),
    SecretSpec(
        "REDIS_PASSWORD",
        _hex,
        None,
    ),
)

SECRET_KEYS: Final[tuple[str, ...]] = tuple(
    spec.key
    for spec in _SECRET_SPECS
)

DEFAULT_BYTES: Final[int] = MIN_SECRET_BYTES


# =============================================================================
# Generation
# =============================================================================

def generate_env_values(
    *,
    num_bytes: int = DEFAULT_BYTES,
) -> dict[str, str]:
    if not MIN_SECRET_BYTES <= num_bytes <= MAX_SECRET_BYTES:
        raise ValueError(
            f"num_bytes must be between {MIN_SECRET_BYTES} and {MAX_SECRET_BYTES}"
        )

    return {
        spec.key: spec.generator(
            max(
                num_bytes,
                spec.min_bytes,
            )
        )
        for spec in _SECRET_SPECS
    }


# =============================================================================
# .env parsing / rendering
# =============================================================================

def _decode_env_value(
    value: str,
) -> str:
    value = value.strip()

    if len(value) >= 2:
        if (
            value[0] == value[-1]
            and value[0] in {'"', "'"}
        ):
            return value[1:-1]

    return value


def parse_env_file(
    path: Path,
) -> dict[str, str]:
    """Parse simple KEY=VALUE entries without shell expansion."""
    if not path.exists():
        return {}

    values: dict[str, str] = {}

    for raw_line in path.read_text(
        encoding="utf-8"
    ).splitlines():
        stripped = raw_line.strip()

        if (
            not stripped
            or stripped.startswith("#")
            or "=" not in stripped
        ):
            continue

        key, raw_value = stripped.split(
            "=",
            1,
        )

        key = key.strip()

        if not _ENV_KEY_RE.fullmatch(
            key
        ):
            continue

        values[key] = _decode_env_value(
            raw_value
        )

    return values


def render_env_block(
    values: dict[str, str],
) -> str:
    missing = [
        key
        for key in SECRET_KEYS
        if key not in values
    ]

    if missing:
        raise ValueError(
            f"missing generated values for: {', '.join(missing)}"
        )

    lines: list[str] = [
        "# =============================================================================",
        "# Sentinel-43 generated secrets",
        "# Store securely. Never commit this file.",
        "# =============================================================================",
        "",
    ]

    last_section: str | None = None

    for spec in _SECRET_SPECS:
        if (
            spec.section is not None
            and spec.section != last_section
        ):
            if lines[-1] != "":
                lines.append(
                    ""
                )

            lines.append(
                f"# {spec.section}"
            )
            last_section = spec.section

        lines.append(
            f"{spec.key}={values[spec.key]}"
        )

    lines.extend(
        [
            "",
            "# Set manually:",
            "# S43_OPERATOR_PASSWORD_HASH=<generated with --password-hash; "
            "local/dev/test only, leave unset for beta/production>",
            "# DATABASE_URL=postgresql+asyncpg://s43:<POSTGRES_PASSWORD>@s43-db:5432/s43",
            "",
        ]
    )

    return "\n".join(
        lines
    )


def _atomic_write_text(
    path: Path,
    content: str,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp = path.with_name(
        f".{path.name}.tmp"
    )

    try:
        # Owner-only from creation: the file holds live secrets, so it must
        # never exist under the default umask, even briefly.
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        os.replace(
            temp,
            path,
        )
    finally:
        try:
            temp.unlink(
                missing_ok=True
            )
        except OSError:
            pass


def write_env_file(
    path: Path,
    values: dict[str, str],
    *,
    force: bool = False,
) -> list[str]:
    """Add missing managed keys or intentionally rotate them with --force."""
    if not path.exists():
        _atomic_write_text(
            path,
            render_env_block(
                values
            ),
        )
        return list(
            SECRET_KEYS
        )

    original = path.read_text(
        encoding="utf-8"
    ).splitlines()

    output: list[str] = []
    seen: set[str] = set()
    changed: list[str] = []

    for raw_line in original:
        stripped = raw_line.strip()

        if (
            not stripped
            or stripped.startswith("#")
            or "=" not in stripped
        ):
            output.append(
                raw_line
            )
            continue

        key, _ = stripped.split(
            "=",
            1,
        )
        key = key.strip()

        if key not in values:
            output.append(
                raw_line
            )
            continue

        if key in seen:
            raise ValueError(
                f"duplicate managed key in {path}: {key}"
            )

        seen.add(
            key
        )

        if force:
            output.append(
                f"{key}={values[key]}"
            )
            changed.append(
                key
            )
        else:
            output.append(
                raw_line
            )

    missing = [
        key
        for key in SECRET_KEYS
        if key not in seen
    ]

    if missing:
        if (
            output
            and output[-1].strip()
        ):
            output.append(
                ""
            )

        output.append(
            "# Sentinel-43 generated secrets"
        )

        for key in missing:
            output.append(
                f"{key}={values[key]}"
            )
            changed.append(
                key
            )

    if changed:
        _atomic_write_text(
            path,
            "\n".join(
                output
            ).rstrip()
            + "\n",
        )

    return changed


# =============================================================================
# Validation
# =============================================================================

def _estimate_secret_bytes(
    value: str,
) -> int:
    """Best-effort byte estimate for values emitted by this generator."""
    if (
        len(value) % 2 == 0
        and value
        and all(
            char in "0123456789abcdefABCDEF"
            for char in value
        )
    ):
        return len(value) // 2

    # token_urlsafe(n) uses base64url without padding. This safely
    # underestimates the original random byte count by at most one byte.
    if re.fullmatch(
        r"[A-Za-z0-9_-]+",
        value,
    ):
        return (
            len(value) * 3
        ) // 4

    return len(
        value.encode(
            "utf-8"
        )
    )


def validate_secret_value(
    spec: SecretSpec,
    value: str,
) -> str | None:
    normalized = value.strip()

    if normalized in _PLACEHOLDERS:
        return "placeholder"

    if _estimate_secret_bytes(
        normalized
    ) < spec.min_bytes:
        return (
            f"too short; expected at least {spec.min_bytes} bytes of secret material"
        )

    return None


def check_env_file(
    path: Path,
) -> tuple[
    list[str],
    list[str],
    dict[str, str],
]:
    existing = parse_env_file(
        path
    )

    present: list[str] = []
    missing: list[str] = []
    invalid: dict[str, str] = {}

    for spec in _SECRET_SPECS:
        if spec.key not in existing:
            missing.append(
                spec.key
            )
            continue

        problem = validate_secret_value(
            spec,
            existing[spec.key],
        )

        if problem is None:
            present.append(
                spec.key
            )
        else:
            invalid[spec.key] = problem

    return (
        present,
        missing,
        invalid,
    )


def _approved_jwt_algorithms() -> frozenset[str]:
    try:
        from core.security.jwt_constants import APPROVED_JWT_ALGORITHMS
    except ImportError:
        return frozenset(
            {"HS256"}
        )

    return frozenset(
        APPROVED_JWT_ALGORITHMS
    )


def _validate_jwt_algorithm(
    algorithm: str,
) -> str | None:
    if not algorithm:
        return None

    approved = _approved_jwt_algorithms()

    if algorithm not in approved:
        return (
            f"S43_JWT_ALGORITHM={algorithm!r} is not approved; "
            f"expected one of {sorted(approved)}"
        )

    return None


def _database_url_warning(
    path: Path,
    *,
    generated_values: dict[str, str],
    changed_keys: list[str],
) -> str | None:
    if "POSTGRES_PASSWORD" not in changed_keys:
        return None

    existing = parse_env_file(
        path
    )

    database_url = existing.get(
        "DATABASE_URL",
        "",
    )

    if not database_url:
        return (
            "POSTGRES_PASSWORD changed but DATABASE_URL is not configured. "
            "Set DATABASE_URL before starting the API."
        )

    try:
        parsed = urlsplit(
            database_url
        )
    except ValueError:
        return (
            "POSTGRES_PASSWORD changed and DATABASE_URL could not be parsed. "
            "Update DATABASE_URL manually."
        )

    new_password = generated_values[
        "POSTGRES_PASSWORD"
    ]

    if parsed.password != new_password:
        return (
            "POSTGRES_PASSWORD changed but DATABASE_URL still contains a "
            "different password. Update DATABASE_URL and the actual database "
            "role password before restarting Sentinel-43."
        )

    return None


# =============================================================================
# Password hashing
# =============================================================================

def password_hash_flow() -> int:
    try:
        password_1 = getpass(
            "Operator password: "
        )
        password_2 = getpass(
            "Confirm password:  "
        )
    except (
        KeyboardInterrupt,
        EOFError,
    ):
        print(
            "\nCancelled.",
            file=sys.stderr,
        )
        return 130

    if not password_1:
        print(
            "ERROR: password cannot be empty.",
            file=sys.stderr,
        )
        return 2

    if password_1 != password_2:
        print(
            "ERROR: passwords do not match.",
            file=sys.stderr,
        )
        return 2

    from core.auth.users import (
        hash_password,
        is_valid_argon2id_hash,
    )

    digest = hash_password(
        password_1
    )

    if not is_valid_argon2id_hash(
        digest
    ):
        print(
            "ERROR: generated password hash failed Sentinel-43 validation.",
            file=sys.stderr,
        )
        return 1

    # Compose's .env-file interpolation treats a bare "$" as the start of a
    # variable reference, and an Argon2id digest always contains several of
    # them ($argon2id$v=19$m=...$salt$hash) -- pasted verbatim into .env,
    # every one of those is silently swallowed before the container ever
    # sees it, and the API then fails every login with "Break-glass
    # credentials are not configured correctly." Doubling each "$" is
    # exactly what Compose's own docs prescribe for a literal "$" in a .env
    # value, and Compose undoes it before the value reaches the container.
    env_file_safe = digest.replace("$", "$$")
    print(
        f"S43_OPERATOR_PASSWORD_HASH={env_file_safe}"
    )
    print(
        "# Safe to paste directly into .env for Docker Compose "
        "(the $ characters above are doubled for Compose's .env "
        "interpolation; the API will see the real Argon2id hash).",
        file=sys.stderr,
    )
    return 0


# =============================================================================
# CLI
# =============================================================================

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="s43-generate-secrets",
        description="Generate and validate Sentinel-43 deployment secrets.",
    )

    mode = parser.add_mutually_exclusive_group()

    mode.add_argument(
        "--write",
        metavar="ENV_FILE",
        help=(
            "Write missing managed secrets to ENV_FILE. "
            "Existing values are preserved unless --force is supplied."
        ),
    )

    mode.add_argument(
        "--check",
        metavar="ENV_FILE",
        help="Validate managed secrets in ENV_FILE.",
    )

    mode.add_argument(
        "--password-hash",
        action="store_true",
        help=(
            "Interactively generate S43_OPERATOR_PASSWORD_HASH (break-glass, "
            "local/dev/test only; its login is refused outside it)."
        ),
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="With --write, intentionally rotate all managed generated secrets.",
    )

    parser.add_argument(
        "--bytes",
        type=int,
        default=DEFAULT_BYTES,
        metavar="N",
        help=(
            f"Random bytes per generated secret "
            f"(default {DEFAULT_BYTES}; range "
            f"{MIN_SECRET_BYTES}..{MAX_SECRET_BYTES})."
        ),
    )

    return parser


def _ensure_utf8_stdio() -> None:
    for stream in (
        sys.stdout,
        sys.stderr,
    ):
        try:
            stream.reconfigure(
                encoding="utf-8",
                errors="replace",
            )
        except (
            AttributeError,
            ValueError,
        ):
            pass


def main(
    argv: list[str] | None = None,
) -> int:
    _ensure_utf8_stdio()

    parser = _build_parser()
    args = parser.parse_args(
        argv
    )

    if args.force and not args.write:
        parser.error(
            "--force is valid only with --write"
        )

    if args.password_hash:
        return password_hash_flow()

    if args.check:
        env_path = Path(
            args.check
        )

        if not env_path.is_file():
            print(
                f"ERROR: {env_path} does not exist or is not a file.",
                file=sys.stderr,
            )
            return 1

        existing = parse_env_file(
            env_path
        )

        jwt_problem = _validate_jwt_algorithm(
            existing.get(
                "S43_JWT_ALGORITHM",
                "",
            )
        )

        present, missing, invalid = check_env_file(
            env_path
        )

        width = max(
            len(
                key
            )
            for key in SECRET_KEYS
        )

        for key in SECRET_KEYS:
            if key in present:
                marker = "✓"
                state = "present"
            elif key in invalid:
                marker = "!"
                state = invalid[
                    key
                ]
            else:
                marker = "✗"
                state = "missing"

            print(
                f"{marker}  {key:<{width}}  {state}"
            )

        if jwt_problem:
            print(
                f"!  {jwt_problem}",
                file=sys.stderr,
            )

        problems = (
            len(
                missing
            )
            + len(
                invalid
            )
            + (
                1
                if jwt_problem
                else 0
            )
        )

        return (
            0
            if problems == 0
            else 1
        )

    try:
        values = generate_env_values(
            num_bytes=args.bytes
        )
    except ValueError as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )
        return 2

    if args.write:
        env_path = Path(
            args.write
        )

        try:
            changed = write_env_file(
                env_path,
                values,
                force=args.force,
            )
        except (
            OSError,
            ValueError,
        ) as exc:
            print(
                f"ERROR: failed to update {env_path}: {exc}",
                file=sys.stderr,
            )
            return 1

        warning = _database_url_warning(
            env_path,
            generated_values=values,
            changed_keys=changed,
        )

        if warning:
            print(
                f"WARNING: {warning}",
                file=sys.stderr,
            )

        if changed:
            action = (
                "Rotated"
                if args.force
                else "Wrote"
            )

            print(
                f"{action} {len(changed)} managed secret(s) in {env_path}."
            )

            for key in changed:
                print(
                    f"  + {key}"
                )
        else:
            print(
                f"No managed secret changes were required in {env_path}."
            )

        return 0

    jwt_problem = _validate_jwt_algorithm(
        os.getenv(
            "S43_JWT_ALGORITHM",
            "",
        )
    )

    if jwt_problem:
        print(
            f"WARNING: {jwt_problem}",
            file=sys.stderr,
        )

    print(
        render_env_block(
            values
        ),
        end="",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )


__all__ = [
    "DEFAULT_BYTES",
    "MIN_SECRET_BYTES",
    "SECRET_KEYS",
    "SecretSpec",
    "check_env_file",
    "generate_env_values",
    "main",
    "parse_env_file",
    "password_hash_flow",
    "render_env_block",
    "validate_secret_value",
    "write_env_file",
]
