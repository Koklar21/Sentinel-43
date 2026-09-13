# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_remote_gateway_audit_persistence.py
#
# Coverage for the Remote Gateway's durable audit persistence: every event
# record written by _write_event_record() must also reach the authoritative
# AuditStore when one is registered (core.audit.set_audit_store()), without
# that durable write ever being allowed to break the request path. Before
# this, the Remote Gateway's only record of its own activity was a bounded
# in-memory deque, lost on every restart.
# =============================================================================

from __future__ import annotations

from typing import Any

import pytest

import core.api.routers.remote_gateway as remote_gateway
from core.api.routers.remote_gateway import (
    AuthPrincipal,
    OperatorRole,
    RemoteEventActivationRequest,
    RemoteEventType,
    _persist_event_record,
    _resolve_audit_store,
    _write_event_record,
)


class _FakeAuditStore:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[dict[str, Any]] = []

    def append(self, payload: dict[str, Any]) -> str:
        if self.fail:
            raise RuntimeError("simulated durable audit failure")
        self.calls.append(dict(payload))
        return "fake-event-id"


def _principal(role: OperatorRole = OperatorRole.ADMIN) -> AuthPrincipal:
    return AuthPrincipal(
        principal_id="remote:test",
        role=role,
    )


def _body() -> RemoteEventActivationRequest:
    return RemoteEventActivationRequest(
        operator_id="operator-1",
        operator_role="admin",
        target_id="local-sentinel",
        event_type=RemoteEventType.FORCE_HEALTH_CHECK,
        reason="test event",
        correlation_id="TEST-AUDIT-0001",
        dry_run=True,
    )


@pytest.fixture(autouse=True)
def _reset_audit_store_override() -> Any:
    remote_gateway.set_audit_store(None)
    remote_gateway.EVENT_BUFFER.reset()
    yield
    remote_gateway.set_audit_store(None)
    remote_gateway.EVENT_BUFFER.reset()


def test_resolve_audit_store_falls_back_to_canonical_registry() -> None:
    from core.audit import get_audit_store, set_audit_store

    assert _resolve_audit_store() is None

    sentinel_store = _FakeAuditStore()
    set_audit_store(sentinel_store)
    try:
        assert _resolve_audit_store() is sentinel_store
    finally:
        set_audit_store(None)

    assert get_audit_store() is None


def test_write_event_record_persists_to_durable_store_when_configured() -> None:
    store = _FakeAuditStore()
    remote_gateway.set_audit_store(store)

    event_record_id = _write_event_record(
        principal=_principal(),
        body=_body(),
        accepted=True,
        message="accepted",
    )

    assert len(store.calls) == 1
    persisted = store.calls[0]
    assert persisted["component"] == "remote_gateway"
    assert persisted["event_record_id"] == event_record_id
    assert persisted["correlation_id"] == "TEST-AUDIT-0001"
    assert persisted["accepted"] is True

    # The in-memory buffer is unaffected by durable persistence -- it still
    # backs the /audit/{id} read path independently.
    assert len(remote_gateway.EVENT_BUFFER) == 1


def test_write_event_record_without_configured_store_only_uses_buffer() -> None:
    assert _resolve_audit_store() is None

    _write_event_record(
        principal=_principal(),
        body=_body(),
        accepted=True,
        message="accepted",
    )

    assert len(remote_gateway.EVENT_BUFFER) == 1


def test_durable_write_failure_does_not_raise_or_drop_the_record() -> None:
    remote_gateway.set_audit_store(_FakeAuditStore(fail=True))

    event_record_id = _write_event_record(
        principal=_principal(),
        body=_body(),
        accepted=True,
        message="accepted",
    )

    assert event_record_id
    # The record still lands in the buffer -- a broken durable store must
    # never take down the Remote Gateway's request path.
    assert len(remote_gateway.EVENT_BUFFER) == 1


def test_persist_event_record_is_a_noop_with_no_store_configured() -> None:
    # Must not raise even though there is nothing to persist to.
    _persist_event_record({"correlation_id": "TEST-AUDIT-0002"})
