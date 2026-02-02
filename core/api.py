from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, Optional

# Import from your core modules (one-file now, separate later)
# from core.models import ThreatAssessment, ResponseDirective
# from core.engine import Sentinel43ResponseEngine
# from core.db import SentinelCoreStore

class SentinelCoreAPI:
    """
    Internal API surface for Sentinel-43 core.

    Goals:
    - stable, simple interface
    - deterministic behavior
    - NO enforcement
    - all persistence through core store
    """

    def __init__(self, engine, store) -> None:
        self._engine = engine
        self._store = store

    # ---------------------------
    # Intake (analysis only)
    # ---------------------------
    def submit_assessment(self, *, mode, assessment) -> Dict[str, Any]:
        """
        Primary entry point:
        takes ThreatAssessment, returns a structured response.
        """
        pa = self._engine.handle_assessment(mode, assessment)

        if pa is None:
            return {
                "ok": True,
                "action_created": False,
                "message": "No action staged (log-only or deduped).",
            }

        return {
            "ok": True,
            "action_created": True,
            "action_id": pa.action_id,
            "status": pa.status.value if hasattr(pa.status, "value") else str(pa.status),
            "execute_at_ms": pa.execute_at_ms,
            "target_type": pa.target_type,
        }

    # ---------------------------
    # Oversight controls
    # ---------------------------
    def approve(self, *, action_id: str, operator_id: str, reason: str = "") -> Dict[str, Any]:
        ok = self._engine.approve_action(action_id, operator_id, reason=reason)
        return {"ok": ok, "action_id": action_id, "operation": "approve"}

    def veto(self, *, action_id: str, operator_id: str, reason: str) -> Dict[str, Any]:
        ok = self._engine.veto_action(action_id, operator_id, reason=reason)
        return {"ok": ok, "action_id": action_id, "operation": "veto"}

    # ---------------------------
    # Read-only (audit/support)
    # ---------------------------
    def get_status(self, *, action_id: str) -> Dict[str, Any]:
        status = self._store.get_status(action_id)
        return {"ok": True, "action_id": action_id, "status": status}

    def list_actions(self, *, status: Optional[str] = None, limit: int = 200) -> Dict[str, Any]:
        rows = self._store.list_actions(status=status, limit=limit)
        return {"ok": True, "count": len(rows), "actions": rows}