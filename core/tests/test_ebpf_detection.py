# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
from core.detection.ebpf_agent import classify_exec


def test_ebpf_transient_exec_is_evidence_only():
    kind, severity, reason = classify_exec("/tmp/dropper")
    assert kind == "ebpf_suspicious_exec"
    assert severity == "medium"
    assert reason


def test_ebpf_normal_exec_is_informational():
    kind, severity, reason = classify_exec("/usr/bin/python3")
    assert kind == "ebpf_process_exec"
    assert severity == "informational"
    assert reason == ""


def test_ebpf_detector_source_has_no_enforcement_dependencies():
    import inspect
    import core.detection.ebpf_agent as module

    source = inspect.getsource(module)
    forbidden = (
        "quarantine",
        "kill_process",
        "terminate_container",
        "modify_policy",
        "approve_action",
    )
    assert not any(name in source for name in forbidden)
