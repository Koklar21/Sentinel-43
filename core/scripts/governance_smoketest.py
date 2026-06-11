# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
#
# Sentinel-43 is distributed under a dual-license model:
#
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
#
# Unauthorized copying, redistribution, relicensing, reverse engineering,
# or commercial exploitation outside the terms of the applicable license
# is strictly prohibited.
#
# By accessing, modifying, distributing, or using this software, you agree
# to comply with the terms of the applicable license.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
#
# Commercial Licensing:
# Contact the copyright holder for commercial licensing terms.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from core.config import get_settings
from core.logging.setup import configure_logging
from core.governance.orchestrator import (
    CallerContext,
    build_orchestrator_from_settings,
)


REQUIRED_SETTINGS = (
    "env",
    "strict_mode",
    "default_mode",
    "data_dir",
)


def _print_banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def _require_setting(settings: Any, name: str) -> Any:
    if not hasattr(settings, name):
        raise AttributeError(f"Required setting missing: {name}")
    return getattr(settings, name)


def _decision_reason(decision: Any) -> str:
    reason = getattr(decision, "reason", None)
    return reason if isinstance(reason, str) else ""


def _decision_mode(decision: Any) -> str | None:
    mode = getattr(decision, "mode", None)
    return mode if isinstance(mode, str) else None


def main() -> int:
    _print_banner("Sentinel-43 Governance Orchestrator Smoke Test")

    settings = get_settings()

    for name in REQUIRED_SETTINGS:
        _require_setting(settings, name)

    configure_logging(settings)
    orch = build_orchestrator_from_settings(settings)

    print(f"env           : {settings.env}")
    print(f"strict_mode   : {settings.strict_mode}")
    print(f"default_mode  : {settings.default_mode}")
    print(f"data_dir      : {settings.data_dir}")

    caller_user = CallerContext(
        caller_id="user123",
        caller_roles={"user"},
        authenticated_at=datetime.now(timezone.utc),
    )

    caller_admin = CallerContext(
        caller_id="admin1",
        caller_roles={"admin"},
        authenticated_at=datetime.now(timezone.utc),
    )

    meta = {
        "location": "CO",
        "device_id": "device-abc-123",
        "txn_type": "test",
        "channel": "smoke",
        "risk_flags": ["none"],
        "random_junk_field": "should_not_appear_in_filtered_meta",
    }

    _print_banner("Test 1: Authorized self transaction")
    d1 = orch.process_transaction(
        caller=caller_user,
        user_id="user123",
        amount_str="12.5000",
        metadata=meta,
    )
    print(d1)

    _print_banner("Test 2: Unauthorized cross-user transaction (expect BLOCKED)")
    d2 = orch.process_transaction(
        caller=caller_user,
        user_id="victim999",
        amount_str="1.0000",
        metadata=meta,
    )
    print(d2)

    _print_banner("Test 3: Admin cross-user transaction")
    d3 = orch.process_transaction(
        caller=caller_admin,
        user_id="victim999",
        amount_str="1.0000",
        metadata=meta,
    )
    print(d3)

    _print_banner("Test 4: Velocity trip (spam within window)")

    velocity_tripped = False

    for i in range(20):
        di = orch.process_transaction(
            caller=caller_user,
            user_id="user123",
            amount_str="1.0000",
            metadata=meta,
        )

        print(f"Attempt {i + 1:02d}: {di}")

        reason = _decision_reason(di)

        if getattr(di, "status", None) == "BLOCKED" and "VELOCITY" in reason:
            velocity_tripped = True
            break

    if not velocity_tripped:
        print("WARNING: velocity guard never tripped after 20 attempts")

    _print_banner("Test 5: Force HUMAN_GATED mode (plumbing test)")

    d5 = orch.process_transaction(
        caller=caller_user,
        user_id="user123",
        amount_str="25.00",
        metadata=meta,
        mode="HUMAN_GATED",
    )

    print(d5)

    observed_mode = _decision_mode(d5)

    if observed_mode != "HUMAN_GATED":
        print(
            "WARNING: HUMAN_GATED mode was requested, "
            f"but decision reported mode={observed_mode!r}"
        )

    _print_banner("Done")
    print("If Test 2 BLOCKED, authz is working.")
    print("If Test 4 BLOCKED with VELOCITY_*, spam gate is working.")
    print("If Test 5 reports HUMAN_GATED, mode plumbing is working.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
