# =============================================================================
# Sentinel-43
#
# Focused router telemetry ingress and local-collector regression coverage.
# =============================================================================

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from core.api.routers import router_telemetry
from core.detection.router_event_classifier import classify_router_event


_REPO = Path(__file__).resolve().parents[2]
_COLLECTOR = _REPO / "scripts" / "router_syslog_collector.py"
_POWERSHELL = _REPO / "scripts" / "router-monitor.ps1"
_MAIN = _REPO / "core" / "api" / "main.py"

_spec = importlib.util.spec_from_file_location("s43_router_collector", _COLLECTOR)
assert _spec is not None and _spec.loader is not None
collector = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(collector)


class _Manager:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def analyze_event(self, payload, **kwargs):
        self.calls.append({"payload": payload, **kwargs})
        return SimpleNamespace(alert_count=0)


def _event(message: str, **kwargs) -> router_telemetry.RouterEvent:
    values = {
        "event_id": "router-event-1",
        "router_ip": "192.168.1.1",
        "message": message,
    }
    values.update(kwargs)
    return router_telemetry.RouterEvent(**values)


def _configure(monkeypatch) -> None:
    monkeypatch.setenv("S43_ROUTER_ENABLED", "true")
    monkeypatch.setenv("S43_ROUTER_INGEST_TOKEN", "r" * 48)
    monkeypatch.setenv("S43_ROUTER_SOURCE_IP", "192.168.1.1")


def test_classifier_extracts_subject_and_owns_port_scan_semantics():
    result = classify_router_event(
        message="kernel: PORT SCAN detected SRC=192.168.1.50 DST=192.168.1.1",
    )

    assert result.event_type == "port_scan"
    assert result.source_ip == "192.168.1.50"
    assert result.detector_eligible is True
    assert result.success is False


def test_firewall_block_is_monitored_without_self_declaring_threat():
    result = classify_router_event(
        message="firewall SRC=198.51.100.7 DST=192.168.1.10",
        action="drop",
    )

    assert result.event_type == "router_firewall_block"
    assert result.source_ip == "198.51.100.7"
    assert result.detector_eligible is False
    assert result.success is False


def test_high_signal_without_subject_ip_does_not_enter_detector():
    result = classify_router_event(message="port scan detected")

    assert result.event_type == "port_scan"
    assert result.source_ip == ""
    assert result.detector_eligible is False
    assert result.reason.endswith("_without_subject_ip")


def test_router_ingress_uses_registered_producer_only_for_high_signal(monkeypatch):
    _configure(monkeypatch)
    manager = _Manager()
    monkeypatch.setattr(router_telemetry, "get_monitoring_manager", lambda: manager)

    response = router_telemetry.ingest_router_event(
        _event("PORT SCAN detected SRC=192.168.1.50 DST=192.168.1.1"),
        authorization="Bearer " + ("r" * 48),
    )

    assert response["accepted"] is True
    assert response["event_type"] == "port_scan"
    assert response["detector_ingested"] is True
    assert len(manager.calls) == 1
    call = manager.calls[0]
    assert call["trusted_producer"] == "router"
    assert call["source_ip"] == "192.168.1.50"
    assert call["source_identity"] == "anonymous"
    payload = call["payload"]
    assert payload["source"] == "sentinel-router"
    assert payload["success"] is False


def test_routine_router_observation_stays_out_of_detector(monkeypatch):
    _configure(monkeypatch)
    manager = _Manager()
    monkeypatch.setattr(router_telemetry, "get_monitoring_manager", lambda: manager)

    response = router_telemetry.ingest_router_event(
        _event("dhcp lease renewed for living-room-tv"),
        authorization="Bearer " + ("r" * 48),
    )

    assert response["event_type"] == "router_observation"
    assert response["detector_ingested"] is False
    assert manager.calls[0]["trusted_producer"] is None


def test_router_ingress_rejects_bad_token(monkeypatch):
    _configure(monkeypatch)

    with pytest.raises(HTTPException) as exc_info:
        router_telemetry.ingest_router_event(
            _event("router observation"),
            authorization="Bearer wrong",
        )

    assert exc_info.value.status_code == 401


def test_router_ingress_rejects_unexpected_router(monkeypatch):
    _configure(monkeypatch)

    with pytest.raises(HTTPException) as exc_info:
        router_telemetry.ingest_router_event(
            router_telemetry.RouterEvent(
                event_id="router-event-2",
                router_ip="192.168.1.254",
                message="router observation",
            ),
            authorization="Bearer " + ("r" * 48),
        )

    assert exc_info.value.status_code == 403


def test_collector_extracts_bounded_router_facts():
    payload = collector._facts(
        "DROP SRC=198.51.100.8 DST=192.168.1.10 SPT=4444 DPT=22 PROTO=TCP",
        "192.168.1.1",
    )

    assert payload["router_ip"] == "192.168.1.1"
    assert payload["source_ip"] == "198.51.100.8"
    assert payload["destination_ip"] == "192.168.1.10"
    assert payload["source_port"] == 4444
    assert payload["destination_port"] == 22
    assert payload["protocol"] == "tcp"
    assert payload["action"] == "drop"
    assert "event_type" not in payload
    assert "severity" not in payload


def test_collector_reloads_router_token_after_env_rotation(tmp_path: Path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "\n".join(
            [
                "S43_ROUTER_ENABLED=true",
                "S43_ROUTER_INGEST_TOKEN=" + ("a" * 48),
                "S43_ROUTER_SOURCE_IP=192.168.1.1",
                "S43_ROUTER_SYSLOG_PORT=5514",
                "S43_ROUTER_MAX_EVENTS_PER_SECOND=50",
                "S43_ROUTER_API_URL=https://localhost/internal/router/events",
                "S43_ROUTER_CA_CERT=deploy/proxy/certs/s43.crt",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    settings = collector._settings(env_path)
    assert collector._refresh_token_if_changed(settings) == "a" * 48

    old_mtime = env_path.stat().st_mtime_ns
    env_path.write_text(
        env_path.read_text(encoding="utf-8").replace("a" * 48, "b" * 48),
        encoding="utf-8",
    )
    # Filesystems with coarse timestamp behavior still need an observable change.
    if env_path.stat().st_mtime_ns == old_mtime:
        import os
        os.utime(env_path, ns=(old_mtime + 1_000_000_000, old_mtime + 1_000_000_000))

    assert collector._refresh_token_if_changed(settings) == "b" * 48



def test_main_registers_router_route_and_trusted_producer():
    source = _MAIN.read_text(encoding="utf-8")

    assert 'from .routers.router_telemetry import router as router_telemetry_router' in source
    assert 'app.include_router(router_telemetry_router)' in source
    assert '"router": "sentinel-router"' in source


def test_powershell_wrapper_keeps_token_out_of_status_output():
    source = _POWERSHELL.read_text(encoding="utf-8")

    assert '[ValidateSet("Configure", "Listen", "Test", "Status", "Disable")]' in source
    assert 'Write-Host "  token:        $tokenState"' in source
    assert 'Write-Host "  token:        $token"' not in source
    assert 'S43_ROUTER_INGEST_TOKEN' in source
    assert 'router_syslog_collector.py' in source
