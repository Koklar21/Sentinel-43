"""CLI utilities for generating secure random secrets."""

from __future__ import annotations

import argparse
import secrets
from collections.abc import Iterator

__all__ = ["generate_secret", "generate_secrets", "main"]

MIN_SECRET_BYTES = 32


def generate_secret(length: int = MIN_SECRET_BYTES) -> str:
    """Generate a URL-safe cryptographic secret."""
    length = int(length)
    if length < MIN_SECRET_BYTES:
        raise ValueError(f"length must be at least {MIN_SECRET_BYTES} bytes")
    return secrets.token_urlsafe(length)


def generate_secrets(count: int = 1, length: int = MIN_SECRET_BYTES) -> Iterator[str]:
    """Yield count secure random secrets."""
    count = int(count)
    if count < 1:
        raise ValueError("count must be at least 1")

    for _ in range(count):
        yield generate_secret(length)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate secure random secrets")
    parser.add_argument("-n", "--count", type=int, default=1)
    parser.add_argument("-l", "--length", type=int, default=MIN_SECRET_BYTES)

    args = parser.parse_args(argv)

    try:
        for secret in generate_secrets(args.count, args.length):
            print(secret)
    except ValueError as exc:
        parser.error(str(exc))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())