# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial

import pytest
from pydantic import ValidationError

from core.api.routers import agent_runtime
from core.api.routers.agent_runtime import AgentActivityEvent


class _Manager:
    def __init__(self):
        self.calls = []

    def analyze_event(self, event, **kwargs):
        self.calls.append((event, kwargs))


def _event(**overrides):
    values = {
        "event_id": "agent-event-1",
        "activity": "agent_secret_access",
        "subject_ip": "192.0.2.30",
        "agent_id": "agent-7",
        "tool_name": "vault.read",
        "resource": "secret/example",
    }
    values.update(overrides)
    return AgentActivityEvent(**values)


def test_agent_runtime_rejects_unknown_activity():
    with pytest.raises(ValidationError):
        _event(activity="agent_make_me_admin")


def test_agent_runtime_rejects_non_ip_subject():
    with pytest.raises(ValidationError):
        _event(subject_ip="agent.example")


def test_agent_runtime_assigns_trusted_provenance(monkeypatch):
    manager = _Manager()
    monkeypatch.setenv("S43_AGENT_RUNTIME_ENABLED", "true")
    monkeypatch.setenv("S43_AGENT_RUNTIME_INGEST_TOKEN", "test-token")
    monkeypatch.setattr(agent_runtime, "get_monitoring_manager", lambda: manager)

    result = agent_runtime.ingest_agent_activity(
        _event(),
        authorization="Bearer test-token",
    )

    assert result["accepted"] is True
    assert len(manager.calls) == 1
    event, kwargs = manager.calls[0]
    assert event["source"] == "sentinel-agent-runtime"
    assert event["source_identity"] == "service:agent-runtime"
    assert event["event_type"] == "agent_secret_access"
    assert kwargs["source_ip"] == "192.0.2.30"
    assert kwargs["source_identity"] == "service:agent-runtime"
    assert kwargs["trusted_producer"] == "agent_runtime"
