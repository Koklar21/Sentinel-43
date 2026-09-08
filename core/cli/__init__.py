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

"""Generate cryptographically strong random secrets."""

from __future__ import annotations

import argparse
import secrets
from collections.abc import Generator
from typing import Final


MIN_SECRET_BYTES: Final[int] = 32
MAX_SECRET_BYTES: Final[int] = 128
MAX_SECRET_COUNT: Final[int] = 100


def generate_secret(
    nbytes: int = MIN_SECRET_BYTES,
    *,
    fmt: str = "urlsafe",
) -> str:
    """Generate one cryptographically strong secret."""
    nbytes = int(nbytes)

    if not MIN_SECRET_BYTES <= nbytes <= MAX_SECRET_BYTES:
        raise ValueError(
            f"nbytes must be between "
            f"{MIN_SECRET_BYTES} and {MAX_SECRET_BYTES}"
        )

    if fmt == "urlsafe":
        return secrets.token_urlsafe(nbytes)

    if fmt == "hex":
        return secrets.token_hex(nbytes)

    raise ValueError(
        f"fmt must be 'urlsafe' or 'hex', got {fmt!r}"
    )


def generate_secrets(
    count: int = 1,
    nbytes: int = MIN_SECRET_BYTES,
    *,
    fmt: str = "urlsafe",
) -> Generator[str, None, None]:
    """Yield one or more cryptographically strong secrets."""
    count = int(count)

    if not 1 <= count <= MAX_SECRET_COUNT:
        raise ValueError(
            f"count must be between 1 and {MAX_SECRET_COUNT}"
        )

    for _ in range(count):
        yield generate_secret(
            nbytes,
            fmt=fmt,
        )


def main(
    argv: list[str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate cryptographically strong random secrets. "
            "Output goes to stdout, one secret per line."
        )
    )

    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=1,
        metavar="N",
        help=(
            f"Number of secrets to generate "
            f"(default: 1, maximum: {MAX_SECRET_COUNT})."
        ),
    )

    parser.add_argument(
        "-b",
        "--bytes",
        type=int,
        default=MIN_SECRET_BYTES,
        dest="nbytes",
        metavar="BYTES",
        help=(
            f"Entropy bytes per secret "
            f"(default: {MIN_SECRET_BYTES}, "
            f"range: {MIN_SECRET_BYTES}..{MAX_SECRET_BYTES})."
        ),
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=("urlsafe", "hex"),
        default="urlsafe",
        dest="fmt",
        help=(
            "Output encoding. Use 'urlsafe' for bearer/JWT secrets "
            "and 'hex' for salts or peppers."
        ),
    )

    args = parser.parse_args(argv)

    try:
        for secret in generate_secrets(
            args.count,
            args.nbytes,
            fmt=args.fmt,
        ):
            print(secret)

    except ValueError as exc:
        parser.error(
            str(exc)
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )


__all__ = [
    "MAX_SECRET_BYTES",
    "MAX_SECRET_COUNT",
    "MIN_SECRET_BYTES",
    "generate_secret",
    "generate_secrets",
    "main",
]
