"""CLI utilities for generating secure random secrets.

``generate_secret`` / ``generate_secrets`` produce cryptographically strong
random values suitable for use as JWT signing keys, auth peppers, salts, and
bearer tokens.

*nbytes* is always the number of **entropy bytes**, not output characters:
  - urlsafe format: ceil(nbytes * 4/3) base64url characters (e.g. 32 → 43)
  - hex format:     nbytes * 2 hex characters          (e.g. 32 → 64)
"""

from __future__ import annotations

import argparse
import secrets
from collections.abc import Generator

__all__ = ["generate_secret", "generate_secrets", "main"]

MIN_SECRET_BYTES = 32


def generate_secret(
    nbytes: int = MIN_SECRET_BYTES,
    *,
    fmt: str = "urlsafe",
) -> str:
    """Generate a cryptographic secret.

    Args:
        nbytes: Number of random bytes to generate (minimum 32).
                Output length depends on *fmt* — this is entropy bytes,
                not character count.
        fmt:    Output encoding: ``"urlsafe"`` (base64url, default) or
                ``"hex"``. Use ``"urlsafe"`` for bearer tokens and JWT
                secrets; use ``"hex"`` for salts and peppers.

    Returns:
        Encoded secret string.

    Raises:
        ValueError: If *nbytes* < 32 or *fmt* is unrecognised.
    """
    nbytes = int(nbytes)
    if nbytes < MIN_SECRET_BYTES:
        raise ValueError(f"nbytes must be at least {MIN_SECRET_BYTES}")

    if fmt == "urlsafe":
        return secrets.token_urlsafe(nbytes)
    if fmt == "hex":
        return secrets.token_hex(nbytes)

    raise ValueError(f"fmt must be 'urlsafe' or 'hex', got {fmt!r}")


def generate_secrets(
    count: int = 1,
    nbytes: int = MIN_SECRET_BYTES,
    *,
    fmt: str = "urlsafe",
) -> Generator[str, None, None]:
    """Yield *count* secure random secrets.

    Args:
        count:  Number of secrets to generate (minimum 1).
        nbytes: Entropy bytes per secret (minimum 32).
        fmt:    Output encoding — ``"urlsafe"`` or ``"hex"``.

    Yields:
        Encoded secret strings.

    Raises:
        ValueError: If *count* < 1, *nbytes* < 32, or *fmt* is unrecognised.
    """
    count = int(count)
    if count < 1:
        raise ValueError("count must be at least 1")

    for _ in range(count):
        yield generate_secret(nbytes, fmt=fmt)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate cryptographically strong random secrets. "
            "Output goes to stdout, one secret per line."
        )
    )
    parser.add_argument(
        "-n", "--count",
        type=int,
        default=1,
        metavar="N",
        help="Number of secrets to generate (default: 1).",
    )
    parser.add_argument(
        "-b", "--bytes",
        type=int,
        default=MIN_SECRET_BYTES,
        dest="nbytes",
        metavar="BYTES",
        help=(
            f"Entropy bytes per secret (default: {MIN_SECRET_BYTES}, minimum: {MIN_SECRET_BYTES}). "
            "Output length varies by format: urlsafe produces ceil(BYTES*4/3) chars, "
            "hex produces BYTES*2 chars."
        ),
    )
    parser.add_argument(
        "-f", "--format",
        choices=["urlsafe", "hex"],
        default="urlsafe",
        dest="fmt",
        help=(
            "Output encoding (default: urlsafe). "
            "Use 'urlsafe' for JWT secrets and bearer tokens; "
            "use 'hex' for salts and peppers."
        ),
    )

    args = parser.parse_args(argv)

    try:
        for secret in generate_secrets(args.count, args.nbytes, fmt=args.fmt):
            print(secret)
    except ValueError as exc:
        # parser.error exits with code 2 and prints to stderr — correct for
        # bad argument values regardless of whether they came from flags or
        # programmatic misuse.
        parser.error(str(exc))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
