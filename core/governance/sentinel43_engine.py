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

"""Runs the owner-designated Sentinel-43 response engine as the decision core.

The engine is ``Sentinel43ResponseEngine`` from ``Sentinel-43/Shadow_mode.py``,
loaded from that file unmodified. Its own code decides:

* what response a threat assessment warrants (``plan_response``),
* whether and how it is staged, including its own dedupe (``stage_directive``),
* whether a human may approve or veto it (``approve_action``/``veto_action``,
  behind its fail-closed ``operator_authenticator``), and
* the resulting status transitions.

Three things are adapted, and only these:

1. **Storage.** The engine's ``ActionStore`` protocol is served by the existing
   ``SentinelCoreStore`` (:class:`CoreStoreActionStore`), so there is one
   durable pending-decision store, not a second SQLite ledger.
2. **Execution is contained.** The engine's only two execution paths --
   the ACTIVE executor thread (``_executor_loop``) and execute-on-approval
   (``_execute_approved_now``) -- are replaced by no-ops in
   :class:`_ContainedEngine`, the store refuses executor claims, and ACTIVE
   staging is refused. Approval is recorded; nothing is executed.
3. **Authentication context.** The engine's authenticator only ever sees an
   operator string, so it is bound to the server-verified principal of the
   decision in progress: it approves nothing outside such a call.
"""

from __future__ import annotations

import contextvars
import hashlib
import importlib.util
import json
import logging
import sys
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

from core.sentinel43_core_db import (
    ActionStatus as CoreStatus,
    PendingAction as CorePendingAction,
    SentinelCoreStore,
)

logger = logging.getLogger("sentinel43.engine")

#: The owner-designated engine source, relative to the repository/app root.
ENGINE_RELATIVE_PATH = Path("Sentinel-43") / "Shadow_mode.py"
ENGINE_CLASS_NAME = "Sentinel43ResponseEngine"
_ENGINE_MODULE_NAME = "sentinel43_owner_shadow_mode"


class EngineUnavailable(RuntimeError):
    """The owner-designated engine could not be loaded; nothing may decide."""


@dataclass(frozen=True, slots=True)
class EngineIdentity:
    """Provenance recorded on every decision the engine makes."""

    path: str
    sha256: str
    engine_class: str
    system_id: str

    def to_dict(self) -> dict[str, str]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "class": self.engine_class,
            "system_id": self.system_id,
        }


_module_lock = threading.Lock()
_loaded: tuple[ModuleType, EngineIdentity] | None = None


def engine_source_path(root: Path | None = None) -> Path:
    base = root if root is not None else Path(__file__).resolve().parents[2]
    return base / ENGINE_RELATIVE_PATH


def load_engine_module(root: Path | None = None) -> tuple[ModuleType, EngineIdentity]:
    """Import the owner file exactly as it is on disk (never edited here)."""
    global _loaded
    with _module_lock:
        if _loaded is not None and root is None:
            return _loaded
        path = engine_source_path(root)
        if not path.is_file():
            raise EngineUnavailable(
                f"owner-designated engine not found at {path}; the image must "
                "ship Sentinel-43/Shadow_mode.py"
            )
        source = path.read_bytes()
        spec = importlib.util.spec_from_file_location(_ENGINE_MODULE_NAME, path)
        if spec is None or spec.loader is None:
            raise EngineUnavailable(f"cannot load engine module from {path}")
        module = importlib.util.module_from_spec(spec)
        # dataclasses resolves annotations through sys.modules.
        sys.modules[_ENGINE_MODULE_NAME] = module
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            sys.modules.pop(_ENGINE_MODULE_NAME, None)
            raise EngineUnavailable(f"engine module failed to import: {exc}") from exc
        if not hasattr(module, ENGINE_CLASS_NAME):
            raise EngineUnavailable(f"{path} does not define {ENGINE_CLASS_NAME}")
        identity = EngineIdentity(
            path=str(ENGINE_RELATIVE_PATH).replace("\\", "/"),
            sha256=hashlib.sha256(source).hexdigest(),
            engine_class=ENGINE_CLASS_NAME,
            system_id=str(getattr(module, "SYSTEM_ID", "")),
        )
        if root is None:
            _loaded = (module, identity)
        return module, identity


# ---------------------------------------------------------------------------
# Operation vocabulary: engine ResponseAction -> established policy action
# ---------------------------------------------------------------------------
#: Only engine actions the policy vocabulary can state EXACTLY are mapped.
#: Everything else the engine recommends (step-up auth, rate limiting,
#: identity blocks, incidents, review flags) has no policy operation and is
#: recorded as unsupported -- never relabeled to obtain an allowed result.
_SUPPORTED_ENGINE_ACTIONS: Mapping[str, tuple[str, str]] = {
    "TEMP_BLOCK_IP": ("network_block", "source_ip"),
    "HARD_BLOCK_IP": ("network_block", "source_ip"),
    "QUARANTINE_SESSION": ("quarantine", "session"),
}


def engine_operations(
    engine_actions: tuple[str, ...] | list[str],
    *,
    subject_key: str,
) -> tuple[list[dict[str, str]], list[str]]:
    """(authorizable operations, unsupported engine actions) for a directive."""
    identity, _sep, source_ip = str(subject_key).rpartition("|")
    operations: list[dict[str, str]] = []
    unsupported: list[str] = []
    for name in engine_actions:
        mapped = _SUPPORTED_ENGINE_ACTIONS.get(str(name))
        if mapped is None:
            unsupported.append(str(name))
            continue
        action, target_type = mapped
        target = source_ip if target_type == "source_ip" else f"{identity}|{source_ip}"
        operation = {
            "action": action,
            "target_type": target_type,
            "target": target,
            "engine_action": str(name),
        }
        if operation not in operations:
            operations.append(operation)
    return operations, unsupported


# ---------------------------------------------------------------------------
# The engine's ActionStore, served by the one durable SentinelCoreStore
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class _StagingContext:
    subject_key: str
    kind: str
    severity: str
    source_kind: str
    score: float


_staging: contextvars.ContextVar[_StagingContext | None] = contextvars.ContextVar(
    "sentinel43_engine_staging", default=None
)


class CoreStoreActionStore:
    """The engine's ``ActionStore`` protocol over ``SentinelCoreStore``.

    Status vocabulary: the engine's STAGED ("awaiting a human") is the core
    store's PENDING, which is what recovery, the ceiling and the dashboard
    already read. Executor operations are refused outright.
    """

    _TO_CORE = {
        "STAGED": CoreStatus.PENDING,
        "PENDING": CoreStatus.PENDING,
        "SHADOWED": CoreStatus.SHADOWED,
        "APPROVED": CoreStatus.APPROVED,
        "VETOED": CoreStatus.VETOED,
        "EXPIRED": CoreStatus.EXPIRED,
    }

    def __init__(self, core_store: SentinelCoreStore) -> None:
        self._core = core_store

    @property
    def core_store(self) -> SentinelCoreStore:
        return self._core

    def _core_status(self, status: Any) -> CoreStatus:
        name = str(getattr(status, "value", status))
        mapped = self._TO_CORE.get(name)
        if mapped is None:
            raise RuntimeError(f"engine status {name!r} is not permitted here")
        return mapped

    # -- protocol -----------------------------------------------------------
    def ensure_schema(self) -> None:
        return None

    def log_event(
        self,
        level: str,
        module: str,
        message: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        log = {
            "ERROR": logger.error,
            "WARN": logger.warning,
            "WARNING": logger.warning,
        }.get(str(level).upper(), logger.info)
        log("[engine:%s] %s %s", module, message, json.dumps(context or {}, default=str))

    def dedupe_check_and_set(self, key: str, ttl_seconds: int) -> bool:
        return self._core.dedupe_allow(f"engine:{key}", ttl_seconds=int(ttl_seconds))

    def insert_pending_action(self, pa: Any) -> None:
        status_name = str(getattr(pa.status, "value", pa.status))
        if status_name == "PENDING":
            # ACTIVE staging (auto-execution after a veto window).
            raise RuntimeError("ACTIVE staging is refused: no autonomous execution")
        context = _staging.get()
        if context is None:
            raise RuntimeError("engine staging outside a governed submission is refused")
        try:
            parsed = json.loads(pa.actions_json)
            names = [parsed.get("primary", "")] + list(parsed.get("additional", []))
        except (TypeError, ValueError, AttributeError) as exc:
            raise RuntimeError("engine produced an unreadable directive") from exc
        self._core.insert_pending(
            CorePendingAction(
                action_id=str(pa.action_id),
                created_at_ms=int(pa.created_at_ms),
                status=self._core_status(pa.status),
                target_type="identity_source_ip",
                target_value=context.subject_key,
                primary_action=str(pa.primary_action),
                actions=tuple(str(n) for n in names if n),
                severity=context.severity,
                kind=context.kind,
                source_kind=context.source_kind,
                score=float(context.score),
                reason=str(pa.reason),
                system_id=str(pa.system_id),
            )
        )

    def update_action_status(
        self,
        action_id: str,
        new_status: Any,
        *,
        operator_id: str | None,
        operator_reason: str | None,
        expected_status: Any,
    ) -> bool:
        new_core = self._core_status(new_status)
        if new_core not in (CoreStatus.APPROVED, CoreStatus.VETOED):
            raise RuntimeError(f"engine transition to {new_core.value} is not permitted")
        return self._core.transition_status(
            action_id,
            expected=self._core_status(expected_status),
            new_status=new_core,
            operator_id=operator_id,
            operator_reason=operator_reason,
        )

    def get_action_status(self, action_id: str) -> str | None:
        status = self._core.get_status(action_id)
        if status is None:
            return None
        return "STAGED" if status is CoreStatus.PENDING else status.value

    def fetch_due_pending(self, *, now_ms: int, limit: int) -> list[Any]:
        return []

    def mark_pending_executing(self, action_id: str) -> bool:
        return False

    def finalize_execution(self, action_id: str, *, ok: bool, operator_reason: str = "") -> None:
        raise RuntimeError("execution is not permitted")

    def expire_overdue(self, *, now_ms: int) -> int:
        # Pending human decisions keep their lifetime; nothing expires them.
        return 0

    def cleanup_old_logs(self, retention_days: int) -> int:
        return 0

    def cleanup_old_actions(self, retention_days: int) -> int:
        return 0


class _NoExecutionIntegration:
    """Stands where the engine's IntegrationHub would. Never reached, because
    both execution paths are contained; refuses loudly if it ever were."""

    @staticmethod
    def execute(_action: Any) -> bool:
        raise RuntimeError("execution is not permitted")


# ---------------------------------------------------------------------------
# The contained engine and its principal-bound authenticator
# ---------------------------------------------------------------------------
_deciding_principal: contextvars.ContextVar[Any | None] = contextvars.ContextVar(
    "sentinel43_engine_principal", default=None
)


class GovernedEngine:
    """The owner engine, running with storage, execution and authentication
    adapted as described in the module docstring."""

    def __init__(
        self,
        core_store: SentinelCoreStore,
        *,
        human_authenticator: Callable[[Any], bool],
        root: Path | None = None,
    ) -> None:
        module, identity = load_engine_module(root)
        self.module = module
        self.identity = identity
        self.store = CoreStoreActionStore(core_store)

        base = getattr(module, ENGINE_CLASS_NAME)

        class _ContainedEngine(base):  # type: ignore[misc, valid-type]
            def _executor_loop(self) -> None:  # noqa: D401 - contained
                # The ACTIVE executor: never runs.
                return None

            def _execute_approved_now(self, action_id: str) -> None:
                # Approval is recorded; there is no executor behind it.
                return None

        def engine_authenticator(operator_id: str) -> bool:
            principal = _deciding_principal.get()
            if principal is None:
                return False
            if str(principal.subject).strip()[:80] != str(operator_id).strip():
                return False
            return bool(human_authenticator(principal))

        self._engine = _ContainedEngine(
            store=self.store,
            operator_authenticator=engine_authenticator,
            integration=_NoExecutionIntegration,
        )

    # -- conversion ---------------------------------------------------------
    def _engine_assessment(self, assessment: Any) -> Any:
        m = self.module

        def member(enum_cls: Any, name: str, fallback: str) -> Any:
            return enum_cls[name] if name in enum_cls.__members__ else enum_cls[fallback]

        # The engine keys identity actions -- and its dedupe -- on
        # ``identity``. Firewall evidence is pre-authentication, so every
        # source arrives as "anonymous"; passed through bare, distinct
        # attackers would collapse into one principal and all but the first
        # would be suppressed. The Heart's subject ("identity|source_ip") is
        # the principal actually being assessed.
        return m.ThreatAssessment(
            identity=f"{assessment.identity}|{assessment.source_ip}",
            source_ip=str(assessment.source_ip),
            threat_kind=member(m.ThreatKind, assessment.threat_kind.value, "UNKNOWN"),
            severity=member(m.ThreatSeverity, assessment.severity.value, "LOW"),
            source_kind=member(
                m.ThreatSourceKind, assessment.source_kind.value, "MIXED_OR_UNKNOWN"
            ),
            score=float(assessment.score),
            indicators=dict(assessment.indicators),
            supporting_tags=list(assessment.supporting_tags),
            window_size=int(assessment.window_size),
            generated_at=float(assessment.generated_at),
        )

    def _mode(self, mode_value: str) -> Any:
        if mode_value not in ("SHADOW", "HUMAN_GATED"):
            raise RuntimeError(f"mode {mode_value!r} is refused: no autonomous execution")
        return self.module.SentinelMode(mode_value)

    # -- decisions ----------------------------------------------------------
    def plan(self, assessment: Any) -> dict[str, Any]:
        """The engine's own response plan for this assessment (pure)."""
        directive = self._engine.plan_response(self._engine_assessment(assessment))
        actions = [directive.primary_action.name] + [
            a.name for a in directive.additional_actions
        ]
        return {
            "directive": directive,
            "actions": actions,
            "summary": {
                "primary_action": directive.primary_action.name,
                "actions": actions,
                "effective_score": float(directive.score),
                "reason": directive.reason,
                "expires_at": directive.expires_at,
                "engine_threat_kind": directive.threat_kind.name,
            },
        }

    def stage(
        self,
        directive: Any,
        *,
        mode_value: str,
        subject_key: str,
        kind: str,
        severity: str,
        source_kind: str,
        score: float,
    ) -> Any:
        """Run the engine's own stage_directive; returns its PendingAction or
        None when the engine suppresses (LOG_ONLY or its dedupe window)."""
        token = _staging.set(
            _StagingContext(
                subject_key=subject_key,
                kind=kind,
                severity=severity,
                source_kind=source_kind,
                score=score,
            )
        )
        try:
            return self._engine.stage_directive(self._mode(mode_value), directive)
        finally:
            _staging.reset(token)

    def approve(self, action_id: str, *, operator_id: str, reason: str, principal: Any) -> bool:
        token = _deciding_principal.set(principal)
        try:
            return bool(self._engine.approve_action(action_id, operator_id, reason))
        finally:
            _deciding_principal.reset(token)

    def veto(self, action_id: str, *, operator_id: str, reason: str, principal: Any) -> bool:
        token = _deciding_principal.set(principal)
        try:
            return bool(self._engine.veto_action(action_id, operator_id, reason))
        finally:
            _deciding_principal.reset(token)

    def shutdown(self) -> None:
        try:
            self._engine.shutdown()
        except Exception:
            logger.debug("engine shutdown failed", exc_info=True)


__all__ = [
    "CoreStoreActionStore",
    "ENGINE_CLASS_NAME",
    "ENGINE_RELATIVE_PATH",
    "EngineIdentity",
    "EngineUnavailable",
    "GovernedEngine",
    "engine_operations",
    "engine_source_path",
    "load_engine_module",
]
