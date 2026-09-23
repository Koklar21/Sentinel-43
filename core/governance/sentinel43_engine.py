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

#: sha256 of the owner-designated Shadow_mode.py this adapter was reviewed
#: against. A different file (edited, replaced, or a stale image) is refused,
#: so nothing decides with an engine nobody reviewed. Changing the owner file
#: is a deliberate act that must update this pin in the same change.
EXPECTED_ENGINE_SHA256 = (
    "6dcad6db464a134ea80e2950bfc8f3f3c0c547bbf7b254d00dfb2d9b76877301"
)


def validated_subject_key(identity: Any, source_ip: Any) -> str:
    """``identity|source_ip`` with both parts checked.

    The identity must be a server-assigned identity type (never free text, so
    no value can contain the separator or impersonate another subject) and
    the address must parse as an IP address.
    """
    import ipaddress

    from core.security_context import IdentityType

    identity_value = str(identity).strip()
    if identity_value not in {member.value for member in IdentityType}:
        raise ValueError(f"subject identity {identity_value!r} is not a known identity type")
    ip_value = str(source_ip).strip()
    try:
        normalized = str(ipaddress.ip_address(ip_value))
    except ValueError as exc:
        raise ValueError(f"subject source address {ip_value!r} is not an IP address") from exc
    return f"{identity_value}|{normalized}"


#: Recorded by the detector from in-process provenance only (see
#: core/detection/sentinel_threat_detector.py), exactly like evidence_sources.
SUBJECT_PRINCIPALS_INDICATOR = "subject_principals"

#: An account identifier is a bounded, printable token: it becomes an
#: operation's target and is shown to a human, so it is never free-form text.
MAX_PRINCIPAL_LENGTH = 200


def principal_of_assessment(assessment: Any) -> str:
    """The ONE account this evidence belongs to, or "".

    A window that saw no account, or more than one, names none: acting on
    "the account" would then be acting on an account nobody reviewed.
    """
    indicators = getattr(assessment, "indicators", None) or {}
    principals = indicators.get(SUBJECT_PRINCIPALS_INDICATOR)

    if not isinstance(principals, (list, tuple, set)):
        return ""

    distinct = {str(value).strip() for value in principals if str(value).strip()}
    if len(distinct) != 1:
        return ""

    principal = distinct.pop()
    if len(principal) > MAX_PRINCIPAL_LENGTH or not principal.isprintable():
        return ""
    return principal


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
        digest = hashlib.sha256(source).hexdigest()
        if digest != EXPECTED_ENGINE_SHA256:
            raise EngineUnavailable(
                f"engine file {path} has sha256 {digest}, not the reviewed "
                f"{EXPECTED_ENGINE_SHA256}; refusing to load it"
            )
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
            sha256=digest,
            engine_class=ENGINE_CLASS_NAME,
            system_id=str(getattr(module, "SYSTEM_ID", "")),
        )
        if root is None:
            _loaded = (module, identity)
        return module, identity


# ---------------------------------------------------------------------------
# What each engine action means, what it targets, and what the EXISTING
# policy authority (core.policy_gate) can say about it
# ---------------------------------------------------------------------------
#: Item statuses. Only APPROVABLE items become authorizable operations; the
#: FULFILLED ones are satisfied by the staged review and its audit record;
#: every other status blocks approval of the whole recommendation, because
#: approving the rest would authorize a different set than the human reviewed.
APPROVABLE = "APPROVABLE"
FULFILLED = "FULFILLED_BY_REVIEW_RECORD"
POLICY_DECISION_REQUIRED = "POLICY_DECISION_REQUIRED"
NO_VALID_TARGET = "NO_VALID_TARGET"
UNKNOWN_ACTION = "UNKNOWN_ACTION"
#: Any item in one of these states blocks approval of the whole
#: recommendation. One definition, used by the assessment and by the
#: orchestrator, so the two can never disagree about what blocks approval.
BLOCKING_STATUSES = frozenset(
    {POLICY_DECISION_REQUIRED, NO_VALID_TARGET, UNKNOWN_ACTION}
)
_BLOCKING = BLOCKING_STATUSES

#: engine action -> (meaning, target type, existing policy action or None).
#: Every action is mapped to the policy operation that states ITS meaning --
#: throttling, a stronger authentication factor and an account suspension are
#: each their own operation, never relabelled as a network block.
ACTION_CATALOG: Mapping[str, tuple[str, str | None, str | None]] = {
    "TEMP_BLOCK_IP": (
        "Block traffic from the source address for the engine's temporary "
        "block period (ResponsePolicy.temp_block_seconds, default 15 minutes).",
        "source_ip",
        "network_block",
    ),
    "HARD_BLOCK_IP": (
        "Block traffic from the source address for the engine's extended "
        "block period (ResponsePolicy.hard_block_seconds, default 6 hours).",
        "source_ip",
        "network_block",
    ),
    "QUARANTINE_SESSION": (
        "Quarantine the principal's authenticated session(s).",
        "session",
        "quarantine",
    ),
    "STEP_UP_AUTH": (
        "Require the principal to re-authenticate with a stronger factor.",
        "account",
        "step_up_auth",
    ),
    "RATE_LIMIT": (
        "Throttle the request rate of this subject: the caller class and "
        "source address the evidence was observed from.",
        "subject",
        "rate_limit",
    ),
    "TEMP_BLOCK_IDENTITY": (
        "Block the principal's account for the temporary block period.",
        "account",
        "account_block_temporary",
    ),
    "HARD_BLOCK_IDENTITY": (
        "Block the principal's account for the extended block period.",
        "account",
        "account_block_extended",
    ),
    "OPEN_INCIDENT": (
        "Open a durable internal incident record for follow-up on this "
        "subject.",
        "subject",
        "incident_open",
    ),
    "REQUIRE_HUMAN_REVIEW": (
        "A human must review this recommendation.",
        None,
        None,
    ),
    "LOG_ONLY": ("Record the finding.", None, None),
    "FLAG_SUSPICIOUS": ("Flag the principal as suspicious.", None, None),
}

_FULFILLED_ACTIONS = frozenset({"REQUIRE_HUMAN_REVIEW", "LOG_ONLY", "FLAG_SUSPICIOUS"})

#: Actions that act on one named account or session. The subject key names a
#: CLASS of caller and an address, so these act on the ``principal`` the
#: request pipeline established for that evidence instead
#: (SecurityContext.principal_id, carried through as in-process provenance).
#: Without one there is no account to act on: approving such an action would
#: either authorize nothing or, read as its identity type, authorize an action
#: against every caller of that class -- neither is what a reviewer saw.
_ACCOUNT_ACTIONS = frozenset(
    {"STEP_UP_AUTH", "TEMP_BLOCK_IDENTITY", "HARD_BLOCK_IDENTITY", "QUARANTINE_SESSION"}
)
_ANONYMOUS = "anonymous"


def assess_actions(
    engine_actions: tuple[str, ...] | list[str],
    *,
    subject_key: str,
    principal: str | None = None,
) -> dict[str, Any]:
    """Classify every action of one engine recommendation, and decide whether
    the recommendation as a whole can be approved under existing policy.

    ``principal`` is the single account the evidence belongs to, established
    by the request pipeline. It is never derived from the subject key and
    never invented: an unauthenticated source, or a window holding more than
    one account, has none.
    """
    identity, _sep, source_ip = str(subject_key).rpartition("|")
    unauthenticated = identity == _ANONYMOUS
    principal = str(principal or "").strip()
    if unauthenticated:
        # An unauthenticated source has no account, whatever was recorded.
        principal = ""
    items: list[dict[str, Any]] = []
    operations: list[dict[str, str]] = []

    for raw in engine_actions:
        name = str(raw)
        entry = ACTION_CATALOG.get(name)
        if entry is None:
            items.append(
                {
                    "engine_action": name,
                    "meaning": None,
                    "target_type": None,
                    "target": None,
                    "policy_action": None,
                    "status": UNKNOWN_ACTION,
                    "reason": "The engine produced an action this build does not know.",
                }
            )
            continue
        meaning, target_type, policy_action = entry
        if target_type == "source_ip":
            target = source_ip
        elif target_type in ("account", "session"):
            # The account itself, never the subject key: an account action
            # must not be recorded as acting on a caller class.
            target = principal or None
        elif target_type is not None:
            target = subject_key
        else:
            target = None
        item: dict[str, Any] = {
            "engine_action": name,
            "meaning": meaning,
            "target_type": target_type,
            "target": target,
            "policy_action": policy_action,
        }
        if name in _FULFILLED_ACTIONS:
            item["status"] = FULFILLED
            item["reason"] = (
                "Satisfied by the staged human review and its audit record."
            )
        elif name in _ACCOUNT_ACTIONS and not principal:
            # No account is invented, and no address operation is substituted
            # for one: the action simply has nothing to act on here.
            item["status"] = NO_VALID_TARGET
            item["target"] = None
            item["reason"] = (
                "An unauthenticated source has no account or session to act on."
                if unauthenticated
                else (
                    "The evidence does not name one account to act on: the "
                    f"subject identifies a caller class ({identity}) and an "
                    "address, and no single authenticated account was recorded "
                    "for it."
                )
            )
        elif policy_action is not None:
            item["status"] = APPROVABLE
            item["reason"] = f"Existing policy action '{policy_action}'."
            operation = {
                "action": policy_action,
                "target_type": str(target_type),
                "target": str(target),
                "engine_action": name,
            }
            if operation not in operations:
                operations.append(operation)
        else:
            item["status"] = POLICY_DECISION_REQUIRED
            item["reason"] = (
                "The policy vocabulary (core.policy_gate) has no operation with "
                "this meaning."
            )
        items.append(item)

    blocking = [item for item in items if item["status"] in _BLOCKING]
    reasons = [f"{item['engine_action']}: {item['reason']}" for item in blocking]
    if not operations and not blocking:
        reasons.append("The recommendation contains no operation to authorize.")
    return {
        "items": items,
        "operations": operations,
        "approval": {
            "available": bool(operations) and not blocking,
            "reasons": reasons,
            "blocking_actions": [item["engine_action"] for item in blocking],
        },
    }


def engine_operations(
    engine_actions: tuple[str, ...] | list[str],
    *,
    subject_key: str,
    principal: str | None = None,
) -> tuple[list[dict[str, str]], list[str]]:
    """(authorizable operations, actions that are neither authorizable nor
    satisfied by the review record) for one recommendation."""
    assessed = assess_actions(
        engine_actions, subject_key=subject_key, principal=principal
    )
    unsupported = [
        item["engine_action"]
        for item in assessed["items"]
        if item["status"] not in (APPROVABLE, FULFILLED)
    ]
    return assessed["operations"], unsupported


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
    principal: str = ""


_staging: contextvars.ContextVar[_StagingContext | None] = contextvars.ContextVar(
    "sentinel43_engine_staging", default=None
)

#: The server-verified human principal of the decision in progress. Set only
#: by GovernedEngine.approve/veto, for the duration of one call, in the
#: calling thread's context copy; never visible to other requests or threads.
_deciding_principal: contextvars.ContextVar[Any | None] = contextvars.ContextVar(
    "sentinel43_engine_principal", default=None
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

    #: Engine events that record a governance-relevant fact about a decision,
    #: rather than operational noise. These reach the canonical audit ledger;
    #: everything else is logged only. The engine names its own modules.
    _AUDITED_MODULES = frozenset({"OVERSIGHT", "STAGING", "RESPONSE"})

    def __init__(
        self,
        core_store: SentinelCoreStore,
        audit_sink: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> None:
        self._core = core_store
        self._audit_sink = audit_sink

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

        # The engine's own account of what it decided belongs in the one
        # authoritative ledger, not only in process logs -- and in that
        # ledger, never a second one. A sink failure must not change what the
        # engine decided, so it is logged and swallowed here; the decision
        # records the orchestrator writes are the ones that fail closed.
        sink = self._audit_sink
        if sink is None or str(module).upper() not in self._AUDITED_MODULES:
            return
        try:
            sink(
                {
                    "subsystem": "sentinel43_engine",
                    "component": "sentinel43_engine",
                    "decision": "ENGINE_EVENT",
                    "reason_code": str(message)[:200],
                    "level": str(level).upper(),
                    "engine_module": str(module),
                    "engine_context": dict(context or {}),
                }
            )
        except Exception:
            logger.error("engine event could not be audited", exc_info=True)

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
                principal_id=context.principal,
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
        if _deciding_principal.get() is None:
            # Only SystemOrchestrator.resolve_recommendation opens a decision
            # context. A direct call on this store -- or on the engine --
            # outside it changes nothing.
            raise PermissionError(
                "engine store transitions are only permitted inside a governed "
                "human decision"
            )
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
class GovernedEngine:
    """The owner engine, running with storage, execution and authentication
    adapted as described in the module docstring."""

    def __init__(
        self,
        core_store: SentinelCoreStore,
        *,
        human_authenticator: Callable[[Any], bool],
        root: Path | None = None,
        audit_sink: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> None:
        module, identity = load_engine_module(root)
        self.module = module
        self.identity = identity
        self.store = CoreStoreActionStore(core_store, audit_sink)

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
        subject_key = validated_subject_key(assessment.identity, assessment.source_ip)
        return m.ThreatAssessment(
            identity=subject_key,
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
        principal: str = "",
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
                principal=principal,
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
    "ACTION_CATALOG",
    "BLOCKING_STATUSES",
    "EXPECTED_ENGINE_SHA256",
    "GovernedEngine",
    "MAX_PRINCIPAL_LENGTH",
    "SUBJECT_PRINCIPALS_INDICATOR",
    "principal_of_assessment",
    "validated_subject_key",
    "assess_actions",
    "engine_operations",
    "engine_source_path",
    "load_engine_module",
]
