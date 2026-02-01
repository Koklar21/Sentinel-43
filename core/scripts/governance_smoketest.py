from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

# Adjust these imports if your repo root/package name differs
from core.config import get_settings
from core.logging.setup import configure_logging
from core.governance.orchestrator import build_orchestrator_from_settings, CallerContext


def _print_banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main() -> int:
    _print_banner("Sentinel-43 Governance Orchestrator Smoke Test")

    settings = get_settings()
    configure_logging(settings)

    orch = build_orchestrator_from_settings(settings)

    print(f"env           : {getattr(settings, 'env', 'unknown')}")
    print(f"strict_mode   : {getattr(settings, 'strict_mode', 'unknown')}")
    print(f"default_mode  : {getattr(settings, 'default_mode', 'unknown')}")
    print(f"data_dir      : {getattr(settings, 'data_dir', 'unknown')}")

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
        # noise that should be filtered
        "random_junk_field": "should_not_appear_in_filtered_meta",
    }

    # 1) Authorized self transaction (should APPROVE in most policies)
    _print_banner("Test 1: Authorized self transaction")
    d1 = orch.process_transaction(
        caller=caller_user,
        user_id="user123",
        amount_str="12.5000",
        metadata=meta,
    )
    print(d1)

    # 2) Unauthorized access (should BLOCK)
    _print_banner("Test 2: Unauthorized cross-user transaction (expect BLOCKED)")
    d2 = orch.process_transaction(
        caller=caller_user,
        user_id="victim999",
        amount_str="1.0000",
        metadata=meta,
    )
    print(d2)

    # 3) Admin cross-user (should pass authz, then policy decides)
    _print_banner("Test 3: Admin cross-user transaction")
    d3 = orch.process_transaction(
        caller=caller_admin,
        user_id="victim999",
        amount_str="1.0000",
        metadata=meta,
    )
    print(d3)

    # 4) Velocity trip: spam within window
    _print_banner("Test 4: Velocity trip (spam within window)")
    for i in range(0, 20):
        di = orch.process_transaction(
            caller=caller_user,
            user_id="user123",
            amount_str="1.0000",
            metadata=meta,
        )
        print(f"Attempt {i+1:02d}: {di}")
        if di.status == "BLOCKED" and "VELOCITY" in di.reason:
            break

    # 5) Human-gated behavior: force HUMAN_GATED mode for a risky action path
    # Note: our current orchestrator maps txns to action="write".
    # If your governance marks "write" as allowed in HUMAN_GATED, this will still approve.
    # This test mostly proves mode plumbs through.
    _print_banner("Test 5: Force HUMAN_GATED mode (plumbing test)")
    d5 = orch.process_transaction(
        caller=caller_user,
        user_id="user123",
        amount_str="25.00",
        metadata=meta,
        mode="HUMAN_GATED",
    )
    print(d5)

    _print_banner("Done")
    print("If Test 2 BLOCKED, authz is working.")
    print("If Test 4 BLOCKED with VELOCITY_*, spam gate is working.")
    print("If outputs are consistent, audit/decision plumbing is working.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())