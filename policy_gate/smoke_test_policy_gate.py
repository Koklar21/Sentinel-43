from __future__ import annotations

import os
from decimal import Decimal
from pathlib import Path

# Import the engine from your policy gate module
# Adjust import if your package layout differs.
from Sentinel43N.policy_gate.ghost_governance import engine, CONFIG


def _print_banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main() -> int:
    _print_banner("Sentinel-43 Policy Gate Smoke Test")

    # 1) Set audit outputs to a local temp-ish area (so you know where files are)
    # If CONFIG is MappingProxyType, you can't change it directly. So we just show paths.
    sqlite_path = Path(CONFIG["AUDIT_SQLITE_PATH"]).resolve()
    jsonl_path = Path(CONFIG["AUDIT_JSONL_FILE"]).resolve()

    print(f"Audit SQLite path: {sqlite_path}")
    print(f"Audit JSONL path : {jsonl_path}")
    print(f"Policy version   : {CONFIG['POLICY_VERSION']}")

    # 2) Make sure HMAC secret exists for "real" run
    # If you want to test missing-secret behavior, comment this out.
    os.environ.setdefault("GHOST_DEVICE_HASH_SECRET", "dev-only-secret-change-me")

    # 3) A good metadata packet (only allowlisted keys will be logged)
    meta = {
        "location": "NE",
        "device_id": "device-abc-123",
        "session_id": "sess-001",
        "request_id": "req-001",
        "ip_address": "12.34.56.78",
        "device_integrity": "ok",
        "region_code": "US-NE",

        # This should NOT be logged if your allowlist is working:
        "random_junk_field": "should_not_appear_in_audit_snapshot",
    }

    # 4) APPROVED transaction
    _print_banner("Test 1: APPROVED transaction")
    d1 = engine.process_transaction(user_id="u123", amount_str="12.5000", metadata=meta)
    print(d1)

    # 5) Financial hard limit block
    _print_banner("Test 2: BLOCKED by financial hard limit")
    d2 = engine.process_transaction(user_id="u123", amount_str="999.0000", metadata=meta)
    print(d2)

    # 6) Velocity limit (default: 3 per 60 seconds). We already used 2 above for u123.
    # Next calls should trip velocity if they’re close together.
    _print_banner("Test 3: Velocity trip (spam within window)")
    d3 = engine.process_transaction(user_id="u123", amount_str="1.0000", metadata=meta)
    print("Attempt 1:", d3)
    d4 = engine.process_transaction(user_id="u123", amount_str="1.0000", metadata=meta)
    print("Attempt 2:", d4)

    # 7) Missing metadata block
    _print_banner("Test 4: BLOCKED due to missing metadata")
    d5 = engine.process_transaction(user_id="u999", amount_str="5.0000", metadata={})
    print(d5)

    # 8) Missing secret behavior test (should log a warning and continue logging)
    _print_banner("Test 5: Missing HMAC secret behavior")
    if "GHOST_DEVICE_HASH_SECRET" in os.environ:
        del os.environ["GHOST_DEVICE_HASH_SECRET"]
    d6 = engine.process_transaction(user_id="u777", amount_str="2.0000", metadata=meta)
    print(d6)

    _print_banner("Audit file existence check")
    print("SQLite exists:", sqlite_path.exists())
    print("JSONL exists :", jsonl_path.exists())

    print("\nIf SQLite exists, your persistence anchor is working.")
    print("If JSONL exists, your secondary sink is working.")
    print("If velocity tripped, your spam gate is working.")
    print("If random_junk_field never shows up in metadata_snapshot, allowlist is working.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())