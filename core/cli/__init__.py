"""CLI utilities for secret generation.

Provides simple functions to generate secure random tokens and a small
command-line interface for quick use.
"""
from __future__ import annotations

import argparse
import secrets
from typing import Iterator

__all__ = ["generate_secret", "generate_secrets", "main"]


def generate_secret(length: int = 32) -> str:
    """Generate a URL-safe secret token.

    Args:
        length: number of random bytes to use (default 32). The returned
            string length will be larger because it's base64-like.

    Returns:
        A URL-safe text token.
    """
    return secrets.token_urlsafe(length)


def generate_secrets(count: int = 1, length: int = 32) -> Iterator[str]:
    """Yield `count` secrets of given byte length.

    Useful for programmatic consumption.
    """
    for _ in range(max(0, int(count))):
        yield generate_secret(length)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate secure random secrets")
    parser.add_argument("-n", "--count", type=int, default=1, help="number of secrets to generate")
    parser.add_argument("-l", "--length", type=int, default=32, help="number of random bytes per secret")
    args = parser.parse_args(argv)

    for s in generate_secrets(args.count, args.length):
        print(s)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
