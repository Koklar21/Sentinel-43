# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# scripts/generate_secrets.py — thin launcher
#
# Delegates entirely to core/cli/generate_secrets.py.
# Exists so the tool is runnable from the repo root before the package
# is installed (e.g. first-time setup from a fresh clone).
#
# Usage: python scripts/generate_secrets.py [args]
# See:   python scripts/generate_secrets.py --help
# =============================================================================

from __future__ import annotations

import sys
from pathlib import Path

# Add repo root to sys.path so core.* is importable without pip install.
# Path(__file__).parent is scripts/, .parent again is the repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    from core.cli.generate_secrets import main
except ImportError as exc:
    print(
        f"ERROR: Could not import core.cli.generate_secrets: {exc}\n"
        "Ensure you are running from the Sentinel-43 repo root and that\n"
        "core/__init__.py and core/cli/__init__.py exist.",
        file=sys.stderr,
    )
    raise SystemExit(1)

if __name__ == "__main__":
    raise SystemExit(main())