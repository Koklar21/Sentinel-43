# =============================================================================
# Sentinel-43
#
# Copyright (c) 2025-2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Owner-designated Sentinel-43 response engine.

This is the live response-planning and staging engine loaded by
core.governance.sentinel43_engine.GovernedEngine.

The engine owns:
- threat assessment -> response planning,
- response action vocabulary,
- deterministic directive construction,
- engine-level dedupe,
- SHADOW observation staging,
- HUMAN_GATED staging,
- authenticated approve/veto transitions.

The engine does NOT own:
- a standalone database,
- an executor thread,
- ACTIVE/autonomous execution,
- external integrations,
- API authentication,
- audit-key management,
- lifecycle composition.

Storage and authoritative audit are injected by Sentinel43RuntimeAuthority
through the governed store adapter. Only SHADOW and HUMAN_GATED are valid
modes. This file cannot start a second Sentinel-43 runtime by itself.
"""

from __future__ import annotations

import enum
import hashlib
import ipaddress
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple


logger = logging.getLogger(__name__)


def _env(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is not None:
        return value
    legacy = name.replace("SENTINEL_", "AEGIS_", 1)
    return os.getenv(legacy, default)


SYSTEM_ID = _env("SENTINEL_SYSTEM_ID", "SENTINEL-43-NEXUS-01")


def _log_salt() -> str:
    value = _env("SENTINEL_LOG_SALT", "").strip()
    environment = (
        os.getenv("SENTINEL_ENV")
        or os.getenv("S43_ENV")
        or "production"
    ).strip().lower()
    local = environment in {"development", "dev", "local", "test"}

    if local:
        return value or "CHANGE_ME_IN_PROD"

    if not value or value in {"CHANGE_ME", "CHANGE_ME_IN_PROD"}:
        raise RuntimeError(
            "SENTINEL_LOG_SALT must be a generated secret outside local/test"
        )

    return value


LOG_SALT = _log_salt()
DEFAULT_DEDUPE_TTL_SECONDS = int(_env("SENTINEL_ACTION_DEDUPE_TTL", "60"))


# =============================================================================
# Modes
# =============================================================================


class SentinelMode(str, enum.Enum):
    SHADOW = "SHADOW"
    HUMAN_GATED = "HUMAN_GATED"


class OpMode(str, enum.Enum):
    SHADOW = "SHADOW_ADVISORY"
    HUMAN_GATED = "HUMAN_GATED"


def _map_mode(mode: OpMode) -> SentinelMode:
    if mode is OpMode.SHADOW:
        return SentinelMode.SHADOW
    if mode is OpMode.HUMAN_GATED:
        return SentinelMode.HUMAN_GATED
    raise ValueError("mode must be SHADOW or HUMAN_GATED")


# =============================================================================
# Threat contract
# =============================================================================


class ThreatKind(enum.Enum):
    GENERIC_INTRUSION = enum.auto()
    MALWARE_DELIVERY = enum.auto()
    SPYWARE_ACTIVITY = enum.auto()
    DATA_EXFILTRATION = enum.auto()
    CREDENTIAL_ATTACK = enum.auto()
    UNKNOWN = enum.auto()


class ThreatSourceKind(enum.Enum):
    HUMAN_LIKELY = enum.auto()
    AI_AUTOMATION_LIKELY = enum.auto()
    MIXED_OR_UNKNOWN = enum.auto()


class ThreatSeverity(enum.Enum):
    LOW = enum.auto()
    MEDIUM = enum.auto()
    HIGH = enum.auto()
    CRITICAL = enum.auto()


@dataclass(frozen=True)
class ThreatAssessment:
    identity: str
    source_ip: str
    threat_kind: ThreatKind
    severity: ThreatSeverity
    source_kind: ThreatSourceKind
    score: float
    indicators: Optional[object] = None
    supporting_tags: List[str] = field(default_factory=list)
    window_size: int = 0
    generated_at: float = field(default_factory=time.time)


# =============================================================================
# Response contract
# =============================================================================


class ResponseAction(enum.Enum):
    LOG_ONLY = enum.auto()
    FLAG_SUSPICIOUS = enum.auto()
    STEP_UP_AUTH = enum.auto()
    RATE_LIMIT = enum.auto()
    TEMP_BLOCK_IDENTITY = enum.auto()
    TEMP_BLOCK_IP = enum.auto()
    HARD_BLOCK_IDENTITY = enum.auto()
    HARD_BLOCK_IP = enum.auto()
    QUARANTINE_SESSION = enum.auto()
    REQUIRE_HUMAN_REVIEW = enum.auto()
    OPEN_INCIDENT = enum.auto()


@dataclass(frozen=True)
class ResponsePolicy:
    medium_threshold: float = 40.0
    high_threshold: float = 65.0
    critical_threshold: float = 85.0
    automation_medium_bonus: float = 5.0
    automation_high_bonus: float = 10.0
    temp_block_seconds: int = 900
    hard_block_seconds: int = 3600 * 6
    auto_open_incident_on_critical: bool = True
    auto_require_human_review_on_high: bool = True


@dataclass
class ResponseDirective:
    identity: str
    source_ip: str
    primary_action: ResponseAction
    additional_actions: List[ResponseAction] = field(default_factory=list)
    reason: str = ""
    expires_at: Optional[float] = None
    threat_kind: ThreatKind = ThreatKind.UNKNOWN
    threat_severity: ThreatSeverity = ThreatSeverity.LOW
    source_kind: ThreatSourceKind = ThreatSourceKind.MIXED_OR_UNKNOWN
    score: float = 0.0
    created_at: float = field(default_factory=time.time)


# =============================================================================
# Staging contract
# =============================================================================


class ActionStatus(str, enum.Enum):
    SHADOWED = "SHADOWED"
    STAGED = "STAGED"
    PENDING = "PENDING"
    VETOED = "VETOED"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True)
class PendingAction:
    action_id: str
    created_at_ms: int
    execute_at_ms: Optional[int]
    status: ActionStatus
    target_type: str
    target_value: str
    primary_action: str
    actions_json: str
    severity: str
    kind: str
    source_kind: str
    score: float
    reason: str
    system_id: str = SYSTEM_ID
    operator_id: Optional[str] = None
    operator_reason: Optional[str] = None


class ActionStore(Protocol):
    def ensure_schema(self) -> None: ...
    def log_event(
        self,
        level: str,
        module: str,
        message: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> None: ...
    def dedupe_check_and_set(self, key: str, ttl_seconds: int) -> bool: ...
    def insert_pending_action(self, action: PendingAction) -> None: ...
    def update_action_status(
        self,
        action_id: str,
        new_status: ActionStatus,
        *,
        operator_id: Optional[str],
        operator_reason: Optional[str],
        expected_status: ActionStatus,
    ) -> bool: ...
    def get_action_status(self, action_id: str) -> Optional[str]: ...


_SAFE_COMPONENT_RE = re.compile(r"[^a-zA-Z0-9.:_\-@|]")


def sanitize_key_component(value: str, *, max_len: int = 200) -> str:
    text = str(value or "").strip()
    text = _SAFE_COMPONENT_RE.sub("", text)
    return text[:max_len]


def pseudonymize(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "EMPTY"
    digest = hashlib.sha256(f"{LOG_SALT}:{raw}".encode("utf-8")).hexdigest()
    return digest[:16]


def normalize_ip(value: str) -> str:
    raw = str(value or "").strip()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return raw


def _now_ms() -> int:
    return int(time.time() * 1000)


def _json_dumps(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


class IntegrationHub:
    """External execution is intentionally unavailable in the owner engine."""

    @staticmethod
    def execute(_action: PendingAction) -> bool:
        raise RuntimeError(
            "external execution is not supported by the owner response engine"
        )


# =============================================================================
# Owner response engine
# =============================================================================


class Sentinel43ResponseEngine:
    """Plan and stage governed responses using an injected authoritative store."""

    def __init__(
        self,
        store: Optional[ActionStore] = None,
        policy: Optional[ResponsePolicy] = None,
        dedupe_ttl_seconds: int = DEFAULT_DEDUPE_TTL_SECONDS,
        *,
        operator_authenticator: Optional[Callable[[str], bool]] = None,
        integration: Optional[type] = None,
    ) -> None:
        if store is None:
            raise ValueError(
                "Sentinel43ResponseEngine requires an injected governed ActionStore"
            )

        self.store = store
        self.policy = policy or ResponsePolicy()
        self.dedupe_ttl_seconds = int(dedupe_ttl_seconds)
        self._operator_authenticator = (
            operator_authenticator or (lambda _operator: False)
        )
        self._integration = integration or IntegrationHub

        self.store.ensure_schema()
        self.store.log_event(
            "INFO",
            "BOOT",
            "Sentinel-43 owner response engine initialized.",
            {"system_id": SYSTEM_ID},
        )

    def shutdown(self) -> None:
        self.store.log_event(
            "INFO",
            "SYSTEM",
            "Owner response engine released.",
            {"system_id": SYSTEM_ID},
        )

    def handle_assessment(
        self,
        mode: SentinelMode,
        assessment: ThreatAssessment,
    ) -> Optional[PendingAction]:
        directive = self.plan_response(assessment)
        return self.stage_directive(mode, directive)

    # ------------------------------------------------------------------
    # Human decision controls
    # ------------------------------------------------------------------

    def approve_action(
        self,
        action_id: str,
        operator_id: str,
        reason: str = "",
    ) -> bool:
        operator = str(operator_id or "").strip()[:80]
        decision_reason = str(reason or "").strip()[:300]

        if not operator or not self._operator_authenticator(operator):
            self.store.log_event(
                "ERROR",
                "OVERSIGHT",
                "Unauthorized approval attempt",
                {"action_id": action_id, "operator_id": operator},
            )
            return False

        ok = self.store.update_action_status(
            action_id,
            ActionStatus.APPROVED,
            operator_id=operator,
            operator_reason=decision_reason,
            expected_status=ActionStatus.STAGED,
        )
        self.store.log_event(
            "WARN" if ok else "ERROR",
            "OVERSIGHT",
            "Action approved" if ok else "Approval failed",
            {"action_id": action_id, "operator_id": operator},
        )
        return ok

    def veto_action(
        self,
        action_id: str,
        operator_id: str,
        reason: str,
    ) -> bool:
        operator = str(operator_id or "").strip()[:80]
        decision_reason = str(reason or "").strip()[:300]

        if not operator or not self._operator_authenticator(operator):
            self.store.log_event(
                "ERROR",
                "OVERSIGHT",
                "Unauthorized veto attempt",
                {"action_id": action_id, "operator_id": operator},
            )
            return False

        ok = self.store.update_action_status(
            action_id,
            ActionStatus.VETOED,
            operator_id=operator,
            operator_reason=decision_reason,
            expected_status=ActionStatus.STAGED,
        )
        self.store.log_event(
            "WARN" if ok else "ERROR",
            "OVERSIGHT",
            "Action vetoed" if ok else "Veto failed",
            {"action_id": action_id, "operator_id": operator},
        )
        return ok

    # ------------------------------------------------------------------
    # Planning
    # ------------------------------------------------------------------

    def plan_response(self, assessment: ThreatAssessment) -> ResponseDirective:
        normalized_ip = normalize_ip(assessment.source_ip)
        normalized = ThreatAssessment(
            identity=assessment.identity,
            source_ip=normalized_ip,
            threat_kind=assessment.threat_kind,
            severity=assessment.severity,
            source_kind=assessment.source_kind,
            score=float(assessment.score),
            indicators=assessment.indicators,
            supporting_tags=list(assessment.supporting_tags),
            window_size=int(assessment.window_size),
            generated_at=float(assessment.generated_at),
        )

        effective_score = self._apply_automation_risk_adjustment(normalized)

        if (
            normalized.severity == ThreatSeverity.LOW
            and effective_score < self.policy.medium_threshold
        ):
            return self._build_low(normalized, effective_score)

        if normalized.severity in (
            ThreatSeverity.MEDIUM,
            ThreatSeverity.HIGH,
        ):
            return self._build_mid_high(normalized, effective_score)

        if normalized.severity == ThreatSeverity.CRITICAL:
            return self._build_critical(normalized, effective_score)

        return self._build_mid_high(normalized, effective_score)

    def _apply_automation_risk_adjustment(
        self,
        assessment: ThreatAssessment,
    ) -> float:
        score = float(assessment.score)
        if assessment.source_kind == ThreatSourceKind.AI_AUTOMATION_LIKELY:
            if assessment.severity in (
                ThreatSeverity.LOW,
                ThreatSeverity.MEDIUM,
            ):
                score += self.policy.automation_medium_bonus
            else:
                score += self.policy.automation_high_bonus
        return min(100.0, score)

    def _build_low(
        self,
        assessment: ThreatAssessment,
        score: float,
    ) -> ResponseDirective:
        actions = [ResponseAction.LOG_ONLY]
        if assessment.threat_kind in (
            ThreatKind.MALWARE_DELIVERY,
            ThreatKind.SPYWARE_ACTIVITY,
        ):
            actions.append(ResponseAction.FLAG_SUSPICIOUS)

        return ResponseDirective(
            identity=assessment.identity,
            source_ip=assessment.source_ip,
            primary_action=actions[0],
            additional_actions=actions[1:],
            reason=f"Low severity (score={score:.1f})",
            threat_kind=assessment.threat_kind,
            threat_severity=assessment.severity,
            source_kind=assessment.source_kind,
            score=score,
        )

    def _build_mid_high(
        self,
        assessment: ThreatAssessment,
        score: float,
    ) -> ResponseDirective:
        actions: List[ResponseAction] = []

        if assessment.threat_kind in (
            ThreatKind.CREDENTIAL_ATTACK,
            ThreatKind.GENERIC_INTRUSION,
        ):
            actions.append(ResponseAction.STEP_UP_AUTH)

        actions.append(ResponseAction.RATE_LIMIT)

        temp_block = score >= self.policy.high_threshold
        expires_at = None

        if temp_block:
            actions.append(ResponseAction.TEMP_BLOCK_IDENTITY)
            expires_at = time.time() + self.policy.temp_block_seconds

        if (
            assessment.source_kind == ThreatSourceKind.AI_AUTOMATION_LIKELY
            and temp_block
        ):
            actions.append(ResponseAction.TEMP_BLOCK_IP)

        if (
            self.policy.auto_require_human_review_on_high
            and assessment.severity == ThreatSeverity.HIGH
        ):
            actions.append(ResponseAction.REQUIRE_HUMAN_REVIEW)

        return ResponseDirective(
            identity=assessment.identity,
            source_ip=assessment.source_ip,
            primary_action=actions[0] if actions else ResponseAction.LOG_ONLY,
            additional_actions=actions[1:],
            reason=f"Medium/High severity (score={score:.1f})",
            expires_at=expires_at,
            threat_kind=assessment.threat_kind,
            threat_severity=assessment.severity,
            source_kind=assessment.source_kind,
            score=score,
        )

    def _build_critical(
        self,
        assessment: ThreatAssessment,
        score: float,
    ) -> ResponseDirective:
        actions: List[ResponseAction] = [
            ResponseAction.QUARANTINE_SESSION,
            ResponseAction.HARD_BLOCK_IDENTITY,
            ResponseAction.HARD_BLOCK_IP,
        ]

        if self.policy.auto_open_incident_on_critical:
            actions.append(ResponseAction.OPEN_INCIDENT)

        if self.policy.auto_require_human_review_on_high:
            actions.append(ResponseAction.REQUIRE_HUMAN_REVIEW)

        return ResponseDirective(
            identity=assessment.identity,
            source_ip=assessment.source_ip,
            primary_action=actions[0],
            additional_actions=actions[1:],
            reason=f"CRITICAL threat (score={score:.1f})",
            expires_at=time.time() + self.policy.hard_block_seconds,
            threat_kind=assessment.threat_kind,
            threat_severity=assessment.severity,
            source_kind=assessment.source_kind,
            score=score,
        )

    # ------------------------------------------------------------------
    # Staging
    # ------------------------------------------------------------------

    def stage_directive(
        self,
        mode: SentinelMode,
        directive: ResponseDirective,
    ) -> Optional[PendingAction]:
        if not isinstance(mode, SentinelMode):
            try:
                mode = SentinelMode(str(getattr(mode, "value", mode)).strip())
            except ValueError as exc:
                raise ValueError(
                    "mode must be SHADOW or HUMAN_GATED"
                ) from exc

        if (
            directive.primary_action == ResponseAction.LOG_ONLY
            and not directive.additional_actions
        ):
            return None

        target_type, raw_target_value = self._pick_primary_target(directive)
        target_value = sanitize_key_component(raw_target_value, max_len=200)

        if not target_value:
            self.store.log_event(
                "ERROR",
                "RESPONSE",
                "Invalid target value after sanitization",
                {"target_type": target_type},
            )
            return None

        dedupe_key = (
            f"{sanitize_key_component(target_type, max_len=16)}:"
            f"{target_value}:"
            f"{sanitize_key_component(directive.primary_action.name, max_len=40)}:"
            f"{sanitize_key_component(directive.threat_kind.name, max_len=40)}"
        )

        if not self.store.dedupe_check_and_set(
            dedupe_key,
            self.dedupe_ttl_seconds,
        ):
            self.store.log_event(
                "INFO",
                "RESPONSE",
                "Duplicate directive suppressed",
                {
                    "dedupe_key": dedupe_key,
                    "ttl_seconds": self.dedupe_ttl_seconds,
                },
            )
            return None

        status = (
            ActionStatus.SHADOWED
            if mode is SentinelMode.SHADOW
            else ActionStatus.STAGED
        )

        action = PendingAction(
            action_id=f"ACT-{uuid.uuid4().hex}".upper(),
            created_at_ms=_now_ms(),
            execute_at_ms=None,
            status=status,
            target_type=target_type,
            target_value=raw_target_value,
            primary_action=directive.primary_action.name,
            actions_json=_json_dumps(
                {
                    "primary": directive.primary_action.name,
                    "additional": [
                        action.name for action in directive.additional_actions
                    ],
                    "expires_at": directive.expires_at,
                }
            ),
            severity=directive.threat_severity.name,
            kind=directive.threat_kind.name,
            source_kind=directive.source_kind.name,
            score=float(directive.score),
            reason=directive.reason,
            system_id=SYSTEM_ID,
        )

        self.store.insert_pending_action(action)
        self.store.log_event(
            "INFO",
            "STAGING",
            "Action staged",
            {
                "action_id": action.action_id,
                "status": action.status.value,
                "mode": mode.value,
                "target_type": action.target_type,
                "target_hash": pseudonymize(action.target_value),
                "primary_action": action.primary_action,
            },
        )
        return action

    @staticmethod
    def _pick_primary_target(
        directive: ResponseDirective,
    ) -> Tuple[str, str]:
        if directive.primary_action in {
            ResponseAction.TEMP_BLOCK_IP,
            ResponseAction.HARD_BLOCK_IP,
        }:
            return "ip", directive.source_ip
        return "identity", directive.identity


__all__ = [
    "ActionStatus",
    "ActionStore",
    "IntegrationHub",
    "OpMode",
    "PendingAction",
    "ResponseAction",
    "ResponseDirective",
    "ResponsePolicy",
    "SYSTEM_ID",
    "Sentinel43ResponseEngine",
    "SentinelMode",
    "ThreatAssessment",
    "ThreatKind",
    "ThreatSeverity",
    "ThreatSourceKind",
    "_map_mode",
    "normalize_ip",
    "pseudonymize",
    "sanitize_key_component",
]
