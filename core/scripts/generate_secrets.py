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

"""Repository-root launcher for the canonical secret generator."""

from __future__ import annotations

import sys
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parent.parent

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


try:
    from core.cli.generate_secrets import main
except ImportError as exc:
    print(
        f"ERROR: Could not import core.cli.generate_secrets: {exc}\n"
        "Ensure the Sentinel-43 repository structure is intact.",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc


if __name__ == "__main__":
    raise SystemExit(main())
