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

"""Sentinel-43 audit package.

Authoritative local audit persistence is the SQLite/HMAC-chained
``AuditStore`` in ``core.audit.store``. ``core.audit.audit`` provides the
non-authoritative JSONL mirror used for export/inspection only.

Also provides a direct AuditStore handoff, mirroring
``core.monitoring.set_monitoring_manager()``/``get_monitoring_manager()``:
    set_audit_store()
    get_audit_store()
so late-wired callers (e.g. the Remote Gateway) can reach the authoritative
store without importing core.api back.
"""

from typing import Any, Optional

from .audit import (
    AuditJsonlMirror,
    AuditMirrorEncoder,
    AuditMirrorError,
    AuditMirrorFormatError,
    AuditMirrorPersistenceError,
)
from .store import (
    AuditConfig,
    AuditConfigurationError,
    AuditEncoder,
    AuditIntegrityError,
    AuditPersistenceError,
    AuditStore,
    AuditStoreError,
    AuditVerificationResult,
    constant_time_compare,
    utc_now_iso,
)


# =============================================================================
# AuditStore handoff
# =============================================================================

_audit_store: Optional[Any] = None


def set_audit_store(store: Any | None) -> None:
    """
    Register the active AuditStore for modules that need late wiring.

    This is intentionally small and direct, mirroring
    core.monitoring.set_monitoring_manager(): the Remote Gateway (and any
    other module) can import this without creating a dependency from
    core.audit back into core.api.
    """
    global _audit_store
    _audit_store = store


def get_audit_store() -> Optional[Any]:
    """
    Return the active AuditStore, if one has been registered.
    """
    return _audit_store


__all__ = [
    "AuditConfig",
    "AuditConfigurationError",
    "AuditEncoder",
    "AuditIntegrityError",
    "AuditJsonlMirror",
    "AuditMirrorEncoder",
    "AuditMirrorError",
    "AuditMirrorFormatError",
    "AuditMirrorPersistenceError",
    "AuditPersistenceError",
    "AuditStore",
    "AuditStoreError",
    "AuditVerificationResult",
    "constant_time_compare",
    "get_audit_store",
    "set_audit_store",
    "utc_now_iso",
]
