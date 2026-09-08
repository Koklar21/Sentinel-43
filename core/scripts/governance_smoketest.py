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

"""Governance orchestrator smoke test.

This script exercises the canonical orchestrator with explicit dependencies.
It does not use the removed build_orchestrator_from_settings() bridge.

Prerequisite:
    SystemOrchestrator must call VelocityGuard.allow(user_id), matching the
    canonical VelocityGuard interface.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from core.audit.store import AuditConfig, AuditStore
from core.governance.orchestrator import (
    CallerContext,
    DecisionStatus,
    GovernanceMode,
    ReasonCode,
    SystemOrchestrator,
)
from core.governance.velocity_guard import (
    VelocityConfig,
    VelocityGuard,
)


def _print_banner(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def _assert_status(
    decision,
    expected: DecisionStatus,
    *,
    label: str,
) -> None:
    if decision.status is not expected:
        raise AssertionError(
            f"{label}: expected status={expected.value}, "
            f"got {decision.status!r}"
        )


def _build_test_orchestrator(
    root: Path,
) -> SystemOrchestrator:
    audit_store = AuditStore(
        AuditConfig(
            sqlite_path=root / "governance-smoke.sqlite3",
            signing_key="governance-smoke-test-key-" + ("x" * 32),
            jsonl_path=None,
        )
    )
    audit_store.initialize()

    velocity_guard = VelocityGuard(
        VelocityConfig(
            window_seconds=60.0,
            limit=5,
            gc_interval_seconds=60.0,
            max_tracked_users=100,
        )
    )

    return SystemOrchestrator(
        audit_store=audit_store,
        velocity_guard=velocity_guard,
        environment="test",
        default_mode=GovernanceMode.HUMAN_GATED,
        hash_device_ids=False,
        monitoring_manager=None,
    )


def main() -> int:
    _print_banner("Sentinel-43 Governance Orchestrator Smoke Test")

    with tempfile.TemporaryDirectory(
        prefix="s43-governance-smoke-"
    ) as temp_dir:
        orch = _build_test_orchestrator(
            Path(temp_dir)
        )

        now = datetime.now(
            timezone.utc
        )

        caller_user = CallerContext(
            caller_id="user123",
            caller_roles=frozenset(
                {"user"}
            ),
            authenticated_at=now,
        )

        caller_admin = CallerContext(
            caller_id="admin1",
            caller_roles=frozenset(
                {"admin"}
            ),
            authenticated_at=now,
        )

        metadata = {
            "location": "CO",
            "device_id": "device-abc-123",
            "txn_type": "test",
            "channel": "smoke",
            "risk_flags": ["none"],
            "random_junk_field": (
                "must not appear in filtered audit metadata"
            ),
        }

        _print_banner(
            "Test 1: Authorized self transaction"
        )

        d1 = orch.process_transaction(
            caller=caller_user,
            user_id="user123",
            amount_str="12.5000",
            metadata=metadata,
            risk_score="10",
        )

        print(d1)

        if d1.status not in {
            DecisionStatus.APPROVED,
            DecisionStatus.REVIEW,
        }:
            raise AssertionError(
                f"authorized self transaction unexpectedly returned {d1.status!r}"
            )

        _print_banner(
            "Test 2: Unauthorized cross-user transaction"
        )

        d2 = orch.process_transaction(
            caller=caller_user,
            user_id="victim999",
            amount_str="1.0000",
            metadata=metadata,
            risk_score="10",
        )

        print(d2)

        _assert_status(
            d2,
            DecisionStatus.BLOCKED,
            label="unauthorized cross-user transaction",
        )

        if d2.reason is not ReasonCode.AUTHORIZATION_FAILED:
            raise AssertionError(
                "unauthorized cross-user transaction did not return "
                "AUTHORIZATION_FAILED"
            )

        _print_banner(
            "Test 3: Admin cross-user transaction"
        )

        d3 = orch.process_transaction(
            caller=caller_admin,
            user_id="victim999",
            amount_str="1.0000",
            metadata=metadata,
            risk_score="10",
        )

        print(d3)

        if d3.status is DecisionStatus.BLOCKED:
            raise AssertionError(
                "admin cross-user transaction was unexpectedly blocked"
            )

        _print_banner(
            "Test 4: Velocity trip"
        )

        velocity_tripped = False

        for attempt in range(
            1,
            10,
        ):
            decision = orch.process_transaction(
                caller=caller_user,
                user_id="velocity-user",
                amount_str="1.0000",
                metadata=metadata,
                risk_score="10",
            )

            print(
                f"Attempt {attempt:02d}: {decision}"
            )

            if (
                decision.status
                is DecisionStatus.BLOCKED
                and decision.reason
                in {
                    ReasonCode.VELOCITY_LIMIT,
                    ReasonCode.VELOCITY_CAP_EXCEEDED,
                }
            ):
                velocity_tripped = True
                break

        if not velocity_tripped:
            raise AssertionError(
                "velocity guard did not trip within the expected test window"
            )

        _print_banner(
            "Test 5: Non-admin mode override cannot weaken configured mode"
        )

        d5 = orch.process_transaction(
            caller=caller_user,
            user_id="mode-user",
            amount_str="25.00",
            metadata=metadata,
            mode=GovernanceMode.SHADOW.value,
            risk_score="10",
        )

        print(d5)

        # The orchestrator is configured HUMAN_GATED. A non-admin caller may
        # not weaken it to SHADOW. A write under HUMAN_GATED must therefore
        # remain a real pending human review with a decision_id.
        if d5.status is not DecisionStatus.REVIEW:
            raise AssertionError(
                "non-admin mode override did not remain HUMAN_GATED"
            )

        if not d5.decision_id:
            raise AssertionError(
                "HUMAN_GATED write did not create a pending review"
            )

        _print_banner(
            "Test 6: Human review resolution"
        )

        review = orch.process_transaction(
            caller=caller_admin,
            user_id="review-user",
            amount_str="25.00",
            metadata=metadata,
            mode=GovernanceMode.HUMAN_GATED.value,
            risk_score="75",
        )

        print(
            "Review decision:",
            review,
        )

        if review.status is DecisionStatus.REVIEW:
            if not review.decision_id:
                raise AssertionError(
                    "REVIEW decision did not include decision_id"
                )

            resolved = orch.resolve_human_decision(
                review.decision_id,
                approved=True,
                operator_id="admin1",
                reason="governance smoke-test approval",
            )

            print(
                "Resolution:",
                resolved,
            )

            if resolved.get(
                "outcome"
            ) != "APPROVED":
                raise AssertionError(
                    "human review resolution was not APPROVED"
                )

        _print_banner(
            "Done"
        )

        print(
            "Governance smoke checks completed successfully."
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
