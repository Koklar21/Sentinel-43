# =============================================================================
# Copyright (c) 2026 Justin [LastName or Entity]
#
# Sentinel is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
#
# See LICENSE.md and COMMERCIAL_LICENSE.md at the repository root.
# =============================================================================

from __future__ import annotations

from typing import Any, Optional, Protocol


# -----------------------------------------------------------------------------
# Protocols (keeps this file decoupled from concrete implementations)
# -----------------------------------------------------------------------------

class EngineProtocol(Protocol):
    def handle_assessment(self, mode: str, assessment: Any) -> Any: ...
    def approve_action(self, action_id: str, operator_id: str, *, reason: str = "") -> bool: ...
    def veto_action(self, action_id: str, operator_id: str, *, reason: str) -> bool: ...


class StoreProtocol(Protocol):
    def get_status(self, action_id: str) -> Any: ...
    def list_actions(self, *, status: Optional[str] = None, limit: int = 200) -> list[dict[str, Any]]: ...


# -----------------------------------------------------------------------------
# API Surface (internal, deterministic, no enforcement)
# -----------------------------------------------------------------------------

class SentinelCoreAPI:
    """
    Internal API surface for Sentinel-43 core.

    Goals:
    - stable, simple interface
    - deterministic behavior
    - NO enforcement
    - all persistence through core store
    """

    def __init__(self, engine: EngineProtocol, store: StoreProtocol) -> None:
        self._engine = engine
        self._store = store

    # ---------------------------
    # Intake (analysis only)
    # ---------------------------
    def submit_assessment(self, *, mode: str, assessment: Any) -> dict[str, Any]:
        """
        Primary entry point:
        takes ThreatAssessment-like object, returns a structured response.

        Notes:
        - assessment is typed as Any for now to avoid tight coupling.
        - later: replace Any with ThreatAssessment model.
        """
        if not mode:
            return {"ok": False, "error": "mode is required"}

        pa = self._engine.handle_assessment(mode, assessment)

        if pa is None:
            return {
                "ok": True,
                "action_created": False,
                "message": "No action staged (log-only or deduped).",
            }

        status = getattr(pa, "status", None)
        status_str = status.value if hasattr(status, "value") else str(status)

        return {
            "ok": True,
            "action_created": True,
            "action_id": getattr(pa, "action_id", None),
            "status": status_str,
            "execute_at_ms": getattr(pa, "execute_at_ms", None),
            "target_type": getattr(pa, "target_type", None),
        }

    # ---------------------------
    # Oversight controls
    # ---------------------------
    def approve(self, *, action_id: str, operator_id: str, reason: str = "") -> dict[str, Any]:
        if not action_id:
            return {"ok": False, "error": "action_id is required"}
        if not operator_id:
            return {"ok": False, "error": "operator_id is required"}

        ok = self._engine.approve_action(action_id, operator_id, reason=reason)
        return {"ok": ok, "action_id": action_id, "operation": "approve"}

    def veto(self, *, action_id: str, operator_id: str, reason: str) -> dict[str, Any]:
        if not action_id:
            return {"ok": False, "error": "action_id is required"}
        if not operator_id:
            return {"ok": False, "error": "operator_id is required"}
        if not reason:
            return {"ok": False, "error": "reason is required"}

        ok = self._engine.veto_action(action_id, operator_id, reason=reason)
        return {"ok": ok, "action_id": action_id, "operation": "veto"}

    # ---------------------------
    # Read-only (audit/support)
    # ---------------------------
    def get_status(self, *, action_id: str) -> dict[str, Any]:
        if not action_id:
            return {"ok": False, "error": "action_id is required"}

        status = self._store.get_status(action_id)
        return {"ok": True, "action_id": action_id, "status": status}

    def list_actions(self, *, status: Optional[str] = None, limit: int = 200) -> dict[str, Any]:
        if limit <= 0:
            return {"ok": False, "error": "limit must be > 0"}
        if limit > 2000:
            return {"ok": False, "error": "limit too large (max 2000)"}

        rows = self._store.list_actions(status=status, limit=limit)
        return {"ok": True, "count": len(rows), "actions": rows}