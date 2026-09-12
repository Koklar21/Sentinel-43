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
#
# dashboard/tests/test_findings_client.py
#
# Post-merge baseline remediation, Section C.
#
# Mirrors the existing reliability_client contract tests
# (dashboard/tests/test_dashboard_core_contract.py) for the new operator
# findings client: bad input rejected before ever reaching the API,
# unknown/unexpected server fields never rendered, failures reported without
# crashing, and -- because this is visibility only, never remediation -- no
# approval/enforcement surface exists to call in the first place.
# =============================================================================

from __future__ import annotations

import re

import pytest

from dashboard.services.findings_client import (
    MAX_LIMIT,
    describe_failure,
    get_findings,
    summarize_findings,
)


@pytest.mark.parametrize("limit", [0, -1, MAX_LIMIT + 1, "abc"])
def test_bad_limit_is_rejected_before_reaching_the_api(limit):
    result = get_findings(limit=limit)
    assert result["ok"] is False


def test_findings_are_reprojected_and_unknown_fields_dropped():
    summary = summarize_findings(
        {
            "ok": True,
            "data": {
                "count": 1,
                "findings": [
                    {
                        "id": "evt-1",
                        "event_id": "evt-1",
                        "source": "fenrir",
                        "subsystem": "fenrir",
                        "severity": "HIGH",
                        "threat_kind": "credential_stuffing",
                        "confidence": 0.9,
                        "authorization": "Bearer should-never-render",
                    }
                ],
            },
        }
    )

    assert summary["available"] is True
    assert summary["total"] == 1
    row = summary["findings"][0]
    assert row["event_id"] == "evt-1"
    assert row["subsystem"] == "fenrir"
    assert row["severity"] == "HIGH"
    assert "authorization" not in row


def test_sparta_finding_is_reprojected_with_integrity_status():
    summary = summarize_findings(
        {
            "ok": True,
            "data": {
                "count": 1,
                "findings": [
                    {
                        "id": "evt-2",
                        "source": "SpartaCore",
                        "subsystem": "sparta-node",
                        "integrity_status": "compromised",
                    }
                ],
            },
        }
    )
    row = summary["findings"][0]
    assert row["subsystem"] == "sparta-node"
    assert row["integrity_status"] == "compromised"


def test_findings_view_reports_api_failure_without_crashing():
    summary = summarize_findings({"ok": False, "status_code": 503})
    assert summary["available"] is False
    assert summary["findings"] == []
    assert summary["error"]


def test_malformed_response_reports_unavailable_not_a_crash():
    summary = summarize_findings({"ok": True, "data": "not-a-dict"})
    assert summary["available"] is False
    assert summary["findings"] == []


@pytest.mark.parametrize(
    "status,fragment",
    [
        (401, "signed in"),
        (403, "not authorized"),
        (503, "unavailable"),
    ],
)
def test_failures_are_distinguished_not_all_server_offline(status, fragment):
    message = describe_failure({"ok": False, "status_code": status})
    assert fragment.lower() in message.lower()
    assert "offline" not in message.lower()


def test_findings_client_exposes_no_approval_or_enforcement_surface():
    """The dashboard renders findings. It never acts on them.

    Asserted on the module's public API rather than its prose: there is no
    approve/enforce/remediate/schedule entry point to call at all.
    """
    import dashboard.services.findings_client as client

    public = [name for name in dir(client) if not name.startswith("_")]
    forbidden = [
        name
        for name in public
        if re.search(
            r"(^|_)(approve|enforce|execute|remediate|schedule|autorun)(_|$)",
            name,
        )
    ]
    assert not forbidden, forbidden


def test_get_findings_builds_a_bounded_query_string():
    calls: list[str] = []

    class _Recording:
        def get(self, path):
            calls.append(path)

            class _R:
                def to_dict(self):
                    return {"ok": True, "status_code": 200, "data": {"count": 0, "findings": []}}

            return _R()

    get_findings(client=_Recording(), limit=10, source="fenrir", severity="HIGH")
    assert len(calls) == 1
    assert "limit=10" in calls[0]
    assert "source=fenrir" in calls[0]
    assert "severity=HIGH" in calls[0]
