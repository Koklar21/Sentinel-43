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
"""

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
    "utc_now_iso",
]
