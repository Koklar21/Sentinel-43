"""Non-mutating secret preparation. Delegates actual provisioning to reviewed bootstrap."""
from __future__ import annotations
import argparse
from pathlib import Path

def inspect(path: Path):
    if path.is_symlink():
        return 2, "Refusing symlink environment file"
    if path.exists():
        if not path.is_file():
            return 2, "Environment path is not a regular file"
        return 0, "Existing environment preserved. Validate using deployment preflight."
    return 2, "Environment missing. Provision with the reviewed Compose bootstrap (PR #442)."

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", default=".env")
    args = parser.parse_args()
    code, message = inspect(Path(args.env_file))
    print(message)
    return code

if __name__ == "__main__":
    raise SystemExit(main())
