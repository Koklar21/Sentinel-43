# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
import pytest
from pydantic import ValidationError

from core.api.routers.ebpf import EbpfEvent
from core.detection.ebpf_agent import _ExecEvent, build_payload, classify_exec


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


def test_ebpf_ingress_rejects_non_ip_host():
    with pytest.raises(ValidationError):
        EbpfEvent(
            event_id="evt-1",
            host_ip="not-an-ip",
            pid=1,
            uid=1,
            filename="/tmp/dropper",
        )


def test_ebpf_sensor_payload_cannot_choose_detection_semantics():
    event = _ExecEvent()
    event.pid = 42
    event.uid = 1000
    event.comm = b"dropper"
    event.filename = b"/tmp/dropper"

    payload = build_payload(event, "192.0.2.10")

    assert payload["filename"] == "/tmp/dropper"
    assert payload["host_ip"] == "192.0.2.10"
    assert "event_type" not in payload
    assert "severity" not in payload
    assert "reason" not in payload



def test_ebpf_sensor_does_not_silently_drop_delivery_failures():
    import inspect
    import core.detection.ebpf_agent as module

    source = inspect.getsource(module)
    assert "delivery_failures += 1" in source
    assert "queue_drops += 1" in source
    assert 'warn_loss("delivery_failed")' in source
    assert 'warn_loss("delivery_queue_full")' in source
