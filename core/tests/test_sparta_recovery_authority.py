# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sparta recovery authority-boundary contract."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SPARTA = REPO_ROOT / "core" / "monitoring" / "sparta_core.py"


def test_node_api_exposes_no_direct_recovery_acknowledgement():
    source = SPARTA.read_text(encoding="utf-8")

    assert '@router.post("/unlock")' not in source
    assert "class NodeUnlockRequest" not in source
    assert "def unlock_lockdown(" not in source


def test_internal_recovery_primitive_remains_fail_closed_on_integrity():
    source = SPARTA.read_text(encoding="utf-8")
    start = source.index("    def acknowledge_recovery(")
    end = source.index("\n    async def run(", start)
    block = source[start:end]

    assert "result = self.check_integrity()" in block
    assert "if not result.ok:" in block
    assert "if self._state is not SpartaState.COMPROMISED:" in block
    assert "self._state = SpartaState.OPERATIONAL" in block
