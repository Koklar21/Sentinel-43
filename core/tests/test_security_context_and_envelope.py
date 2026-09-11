# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_security_context_and_envelope.py
#
# Contracts established by the core-wiring pass:
#
#   1. ONE canonical request security context (core/security_context.py).
#      The firewall owns the trusted-proxy decision; downstream code reads
#      its answer rather than re-deriving one. Three modules previously had
#      their own client-IP resolvers that disagreed on the unknown-peer case.
#
#   2. ONE normalized event envelope (core/monitoring/event_types.py) with
#      provenance that survives normalization, and explicit rejection of
#      unsupported schema versions.
#
#   3. Independent firewall rate budgets per traffic class, so a
#      malfunctioning internal producer cannot starve operator traffic.
# =============================================================================

from __future__ import annotations

import json

import pytest

from core.api.middleware.sentinel_firewall_middleware import (
    FirewallConfig,
    SentinelFirewall,
    TrafficClass,
)
from core.monitoring.event_types import (
    EVENT_SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    normalize_event,
)
from core.security_context import (
    UNKNOWN_CLIENT,
    IdentityType,
    SecurityContext,
    attach_security_context,
    client_ip_of,
    sanitize_correlation_id,
)


class _FakeState:
    """Stands in for starlette's request.state (attribute access over a dict)."""

    def __init__(self, data: dict) -> None:
        self.__dict__.update(data)


class _FakeClient:
    def __init__(self, host: str) -> None:
        self.host = host


class _FakeRequest:
    def __init__(self, state: dict | None = None, peer: str | None = None):
        self.state = _FakeState(state or {})
        self.client = _FakeClient(peer) if peer else None


# --------------------------------------------------------------------------- #
# 1. canonical security context
# --------------------------------------------------------------------------- #

def test_context_is_preferred_over_the_raw_peer():
    state: dict = {}
    attach_security_context(
        state,
        SecurityContext(
            request_id="r1", correlation_id="c1", client_ip="198.51.100.7"
        ),
    )
    request = _FakeRequest(state, peer="10.0.0.1")
    assert client_ip_of(request) == "198.51.100.7"


def test_falls_back_to_the_peer_when_no_context():
    assert client_ip_of(_FakeRequest(peer="203.0.113.9")) == "203.0.113.9"


def test_unknown_peer_has_one_answer_everywhere():
    """The three old resolvers disagreed here: None vs "unknown"."""
    assert client_ip_of(_FakeRequest()) == UNKNOWN_CLIENT


def test_resolver_never_consults_forwarded_headers_itself():
    """Honouring X-Forwarded-For is the firewall's decision alone."""
    import inspect

    import core.security_context as sc

    source = inspect.getsource(sc.client_ip_of)
    assert "forwarded" not in source.lower().replace("forwarded headers", "")


def test_identity_starts_anonymous_and_is_narrowed_immutably():
    context = SecurityContext(request_id="r", correlation_id="c")
    assert context.identity_type is IdentityType.ANONYMOUS
    assert context.authenticated is False

    narrowed = context.authenticated_as(
        IdentityType.SERVICE_FENRIR, "fenrir-hunter"
    )
    assert narrowed.identity_type is IdentityType.SERVICE_FENRIR
    assert narrowed.authenticated is True
    # The original is untouched -- provenance is never mutated in place.
    assert context.identity_type is IdentityType.ANONYMOUS


def test_firewall_findings_survive_identity_narrowing():
    context = SecurityContext(
        request_id="r",
        correlation_id="c",
        client_ip="198.51.100.7",
        via_trusted_proxy=True,
    ).authenticated_as(IdentityType.OPERATOR, "alice")

    assert context.client_ip == "198.51.100.7"
    assert context.via_trusted_proxy is True


def test_human_and_service_identities_are_distinguishable():
    assert IdentityType.OPERATOR.is_human
    assert not IdentityType.OPERATOR.is_service
    for service in (
        IdentityType.SERVICE_FENRIR,
        IdentityType.SERVICE_WATCHTOWER,
        IdentityType.SERVICE_SPARTA_NODE,
        IdentityType.SERVICE_REMOTE_GATEWAY,
    ):
        assert service.is_service
        assert not service.is_human


def test_context_projection_carries_no_credential_field():
    context = SecurityContext(request_id="r", correlation_id="c")
    assert set(context.to_dict()) == {
        "request_id", "correlation_id", "client_ip", "via_trusted_proxy",
        "identity_type", "principal_id", "firewall_allowed",
        "firewall_reason", "received_at",
    }


@pytest.mark.parametrize(
    "hostile",
    ["bad id with spaces", "x" * 200, "line\nbreak", "tab\there", ""],
)
def test_hostile_inbound_correlation_ids_are_replaced(hostile):
    """Correlation ids reach logs and audit records: reject log injection."""
    result = sanitize_correlation_id(hostile)
    assert result != hostile
    assert result.isalnum()


def test_safe_inbound_correlation_id_is_preserved():
    assert sanitize_correlation_id("trace-abc.123:7") == "trace-abc.123:7"


# --------------------------------------------------------------------------- #
# 2. normalized event envelope
# --------------------------------------------------------------------------- #

def test_envelope_fields_survive_normalization():
    result = normalize_event(
        {
            "kind": "log",
            "integrity_status": "ok",
            "source": "SpartaCore",
            "source_identity": "service:sparta-node",
            "correlation_id": "corr-1",
        }
    )
    event = result.event.to_dict()

    assert event["source"] == "SpartaCore"
    assert event["source_identity"] == "service:sparta-node"
    assert event["correlation_id"] == "corr-1"
    assert event["schema_version"] == EVENT_SCHEMA_VERSION
    assert event["event_id"]
    assert event["ingested_at"]


def test_ingested_at_is_stamped_by_us_not_the_producer():
    """A producer may assert when it created an event, never when we took it."""
    result = normalize_event(
        {"kind": "log", "ingested_at": "1999-01-01T00:00:00+00:00"}
    )
    assert not result.event.ingested_at.startswith("1999")


@pytest.mark.parametrize("version", ["2.0", "0.9", "banana", "1.0.1"])
def test_unsupported_schema_versions_are_rejected_explicitly(version):
    with pytest.raises(ValueError, match="unsupported event schema_version"):
        normalize_event({"kind": "log", "schema_version": version})


def test_supported_schema_version_is_accepted():
    for version in SUPPORTED_SCHEMA_VERSIONS:
        assert normalize_event(
            {"kind": "log", "schema_version": version}
        ).event.schema_version == version


def test_event_id_mirrors_the_event_identity():
    result = normalize_event({"kind": "security", "id": "fixed-id"})
    assert result.event.event_id == "fixed-id"
    assert result.event.to_dict()["event_id"] == "fixed-id"


def test_envelope_is_json_serializable():
    """Events cross process boundaries; the envelope must survive the trip."""
    event = normalize_event({"kind": "log", "source": "x"}).event
    assert json.loads(json.dumps(event.to_dict()))["kind"] == "log"


# --------------------------------------------------------------------------- #
# 3. traffic-class rate budgets
# --------------------------------------------------------------------------- #

def _scope(path: str) -> dict:
    return {
        "type": "http",
        "path": path,
        "method": "GET",
        "headers": [],
        "client": ("203.0.113.10", 5555),
    }


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/internal/events/broadcast", TrafficClass.INTERNAL_FENRIR),
        ("/watchtower/events", TrafficClass.INTERNAL_FENRIR),
        ("/node/status", TrafficClass.SPARTA_NODE),
        ("/remote-gateway/dispatch", TrafficClass.REMOTE_GATEWAY),
        ("/health", TrafficClass.PUBLIC),
        ("/auth/login", TrafficClass.PUBLIC),
    ],
)
def test_traffic_is_classified_by_route(path, expected):
    firewall = SentinelFirewall(app=None, config=FirewallConfig())
    assert firewall._classify(_scope(path), websocket=False) is expected


def test_exhausted_internal_budget_does_not_starve_operator_traffic():
    """A Fenrir retry storm must not deny the operator surface."""
    firewall = SentinelFirewall(
        app=None,
        config=FirewallConfig(
            internal_rate_limit_requests=2,
            http_rate_limit_requests=50,
            monitoring_enabled=False,
        ),
    )

    for _ in range(6):
        firewall._screen_scope(
            _scope("/internal/events/broadcast"), websocket=False
        )

    assert not firewall._screen_scope(
        _scope("/internal/events/broadcast"), websocket=False
    ).allowed
    # Same client, different class: unaffected.
    assert firewall._screen_scope(_scope("/health"), websocket=False).allowed
    assert firewall._screen_scope(
        _scope("/node/status"), websocket=False
    ).allowed
