import pytest
from pydantic import ValidationError

from core.api.routers.host_network import HostNetworkEvent


def _event(**overrides):
    data = {
        "event_id": "evt-1",
        "host_ip": "192.0.2.10",
        "direction": "outbound",
        "protocol": "tcp",
        "local_ip": "192.0.2.10",
        "local_port": 50000,
        "remote_ip": "198.51.100.20",
        "remote_port": 443,
        "process_id": 42,
        "process_name": "browser",
        "state": "Established",
    }
    data.update(overrides)
    return HostNetworkEvent(**data)


def test_host_network_event_is_bounded_facts():
    event = _event()
    assert event.remote_port == 443
    assert not hasattr(event, "severity")
    assert not hasattr(event, "action")


def test_host_network_rejects_non_ip():
    with pytest.raises(ValidationError):
        _event(remote_ip="not-an-ip")


def test_host_network_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        _event(password="should-never-be-accepted")
