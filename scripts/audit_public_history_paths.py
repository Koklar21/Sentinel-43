#!/usr/bin/env python3
"""Read-only pre-publication Git history path audit.

Flags paths that may contain private material across *all* reachable refs.
This is NOT a secret-content scanner and cannot clear a repo for publication.
Only path names are printed, never file contents or credential values.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys

SENSITIVE = re.compile(
    r"(^|/)(?:\.env(?:\.[^/]*)?|account\.conf|http\.header|"
    r"id_(?:rsa|ed25519|ecdsa)|[^/]+\.(?:pem|key|p12|pfx|jks|keystore))$",
    re.IGNORECASE,
)
CERT_STATE = re.compile(r"(^|/)deploy/proxy/certs/(?:ca/|[^/]+_ecc/)", re.IGNORECASE)


def git(*args: str) -> bytes:
    return subprocess.run(["git", *args], check=True, stdout=subprocess.PIPE).stdout


def inspect_paths(paths: list[str]) -> list[str]:
    return sorted({p for p in paths if (SENSITIVE.search(p) or CERT_STATE.search(p))\n                   and not re.search(r"(^|/)\\.env\\.(?:example|sample|template)$", p, re.IGNORECASE)})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", action="store_true", help="Include all reachable Git refs")
    args = parser.parse_args()
    try:
        if args.history:
            # Commit tree enumeration includes deleted and renamed files in history.
            # --all covers local refs only: fetch all remotes/branches/tags first.
            raw = git("log", "--all", "--pretty=format:", "--name-only", "-z")
        else:
            raw = git("ls-files", "-z")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"ERROR: unable to inspect Git paths: {type(exc).__name__}", file=sys.stderr)
        return 2
    paths = [p.decode("utf-8", errors="replace").strip() for p in raw.split(b"\0") if p.strip()]
    flagged = inspect_paths(paths)
    if flagged:
        print(f"REVIEW REQUIRED: {len(flagged)} sensitive-looking tracked/history path(s):")
        for path in flagged:
            print(f"  {path}")
        print("No contents inspected. Review privately; run a dedicated whole-history secret scanner.")
        return 1
    print("No sensitive-looking paths detected in inspected Git refs.")
    print("NOT a secret-content scan; hardcoded tokens can appear in ordinary source files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
