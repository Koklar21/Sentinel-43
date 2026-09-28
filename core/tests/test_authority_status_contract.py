# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Read-only Sentinel-43 authority status contract."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
AUTHORITY = REPO_ROOT / "core" / "governance" / "runtime_authority.py"
API_MAIN = REPO_ROOT / "core" / "api" / "main.py"


def test_authority_snapshot_exposes_provenance_not_subordinate_objects():
    source = AUTHORITY.read_text(encoding="utf-8")

    assert "def authority_snapshot(" in source
    assert '"owner_components": self.owner_component_identities' in source
    assert '"owner_engine": self.engine_identity' in source
    assert '"recommendation_store_attached": self.recommendation_store_attached' in source
    assert '"external_execution_supported": False' in source

    snapshot_block = source.split("def authority_snapshot(", 1)[1].split(
        "def attach_recommendation_store(", 1
    )[0]
    assert '"orchestrator"' not in snapshot_block
    assert '"store"' not in snapshot_block


def test_system_status_reports_the_live_authority_snapshot():
    source = API_MAIN.read_text(encoding="utf-8")

    assert "runtime.sentinel43.authority_snapshot()" in source
    assert '"sentinel43_authority": authority_snapshot' in source
