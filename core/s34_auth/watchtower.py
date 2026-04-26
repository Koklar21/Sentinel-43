# =============================================================================
# Sentinel-43 Watchtower Node
# =============================================================================
#
# Copyright (c) 2026 Justin / Sentinel-43 Project
# All rights reserved.
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
#
# Classification: INTERNAL
#
# =============================================================================

from __future__ import annotations

import enum
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinel43.watchtower")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - Sentinel-43 - Watchtower - %(levelname)s - %(message)s",
    )

HAS_PYDANTIC = False
HAS_PYDANTIC_V2 = False

try:
    from pydantic import BaseModel, Field, conint

    HAS_PYDANTIC = True

    try:
        from pydantic import ConfigDict, computed_field

        HAS_PYDANTIC_V2 = True
    except Exception:
        ConfigDict = None  # type: ignore

        def computed_field(*args, **kwargs):  # type: ignore
            def decorator(fn):
                return property(fn)
            return decorator

except Exception:
    class BaseModel:  # type: ignore
        def __init__(self, **data: Any):
            for k, v in data.items():
                setattr(self, k, v)

    def Field(default=None, **kwargs):  # type: ignore
        if "default_factory" in kwargs:
            return kwargs["default_factory"]()
        return default

    def conint(*, ge=None, le=None, **kwargs):  # type: ignore
        return int

    def computed_field(*args, **kwargs):  # type: ignore
        def decorator(fn):
            return property(fn)
        return decorator


def _utc_ts() -> float:
    return time.time()


def _clamp_int(name: str, value: Any, lo: int, hi: int) -> int:
    try:
        iv = int(value)
    except Exception as exc:
        raise ValueError(f"{name} must be an int in [{lo},{hi}], got {value!r}") from exc

    if not lo <= iv <= hi:
        raise ValueError(f"{name} must be in [{lo},{hi}], got {iv}")

    return iv


def _read_or_make_id(data: Dict[str, Any], key: str) -> str:
    value = data.get(key)
    if isinstance(value, str) and value.strip():
        return value
    return str(uuid.uuid4())


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}

    if isinstance(value, (int, float)):
        return value != 0

    return False


@dataclass(frozen=True)
class ThresholdProfile:
    failed_logins: int
    phishing_score: int


def thresholds_for(sensitivity: Any) -> ThresholdProfile:
    level = _clamp_int("sensitivity", sensitivity, 1, 10)

    failed_logins = int(round(10 - (level - 1) * (6 / 9)))
    phishing_score = int(round(85 - (level - 1) * (25 / 9)))

    return ThresholdProfile(
        failed_logins=failed_logins,
        phishing_score=phishing_score,
    )


class SentinelEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_ts: float = Field(default_factory=_utc_ts)

    source: str = Field("unknown")
    kind: str = Field("generic")
    environment: str = Field("production")

    payload: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        if HAS_PYDANTIC and hasattr(self, "model_dump"):
            return self.model_dump()

        if HAS_PYDANTIC and hasattr(self, "dict"):
            return self.dict()  # type: ignore[attr-defined]

        return {
            "event_id": self.event_id,
            "correlation_id": self.correlation_id,
            "created_ts": float(self.created_ts),
            "source": self.source,
            "kind": self.kind,
            "environment": self.environment,
            "payload": dict(self.payload),
        }


class AlertSeverity(enum.Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class SentinelAlert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_ts: float = Field(default_factory=_utc_ts)

    event_id: str = Field(...)
    correlation_id: str = Field(...)

    tower_id: str = Field(...)
    tower_name: str = Field(...)
    tower_type: str = Field(...)
    position: str = Field(...)

    severity: AlertSeverity = Field(AlertSeverity.WARNING)
    reason: str = Field(...)
    sensitivity: int = Field(5)

    tags: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        if HAS_PYDANTIC and hasattr(self, "model_dump"):
            data = self.model_dump()
            data["severity"] = getattr(self.severity, "value", str(self.severity))
            return data

        if HAS_PYDANTIC and hasattr(self, "dict"):
            data = self.dict()  # type: ignore[attr-defined]
            data["severity"] = getattr(self.severity, "value", str(self.severity))
            return data

        return {
            "alert_id": self.alert_id,
            "created_ts": float(self.created_ts),
            "event_id": self.event_id,
            "correlation_id": self.correlation_id,
            "tower_id": self.tower_id,
            "tower_name": self.tower_name,
            "tower_type": self.tower_type,
            "position": self.position,
            "severity": self.severity.value,
            "reason": self.reason,
            "sensitivity": int(self.sensitivity),
            "tags": list(self.tags),
            "details": dict(self.details),
        }


class WatchtowerState(enum.Enum):
    INITIALIZING = "INITIALIZING"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


class TowerType(enum.Enum):
    TRAFFIC_INBOUND = "TRAFFIC_INBOUND"
    TRAFFIC_OUTBOUND = "TRAFFIC_OUTBOUND"
    INTRUSION_NETWORK = "INTRUSION_NETWORK"
    INTRUSION_AUTH = "INTRUSION_AUTH"
    MALWARE_SIGNATURE = "MALWARE_SIGNATURE"
    MALWARE_BEHAVIOR = "MALWARE_BEHAVIOR"
    PHISHING_CONTENT = "PHISHING_CONTENT"
    PHISHING_DOMAIN = "PHISHING_DOMAIN"


class TowerPosition(enum.Enum):
    N = "N"
    NE = "NE"
    E = "E"
    SE = "SE"
    S = "S"
    SW = "SW"
    W = "W"
    NW = "NW"


class TowerConfig(BaseModel):
    name: str = Field(...)
    position: TowerPosition = Field(...)
    tower_type: TowerType = Field(...)
    enabled: bool = Field(True)
    sensitivity: conint(ge=1, le=10) = Field(5)
    severity: AlertSeverity = Field(AlertSeverity.WARNING)
    tags: List[str] = Field(default_factory=list)

    if HAS_PYDANTIC_V2:
        model_config = ConfigDict(extra="ignore")  # type: ignore[misc]
    elif HAS_PYDANTIC:
        class Config:
            extra = "ignore"

    def validated_sensitivity(self) -> int:
        return _clamp_int("sensitivity", getattr(self, "sensitivity", 5), 1, 10)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "position": self.position.value,
            "tower_type": self.tower_type.value,
            "enabled": bool(self.enabled),
            "sensitivity": self.validated_sensitivity(),
            "severity": getattr(self.severity, "value", str(self.severity)),
            "tags": list(self.tags),
        }


class WatchtowerConfig(BaseModel):
    node_id: str = Field(...)
    environment: str = Field("production")
    host: str = Field("0.0.0.0")
    port: conint(ge=1024, le=65535) = Field(9100)
    towers: List[TowerConfig] = Field(default_factory=list)
    model_name: str = Field("none")
    max_tower_errors_before_degrade: conint(ge=1, le=1000) = Field(25)

    if HAS_PYDANTIC_V2:
        model_config = ConfigDict(extra="ignore")  # type: ignore[misc]
    elif HAS_PYDANTIC:
        class Config:
            extra = "ignore"

    @computed_field
    def api_url(self) -> str:
        return f"http://{self.host}:{int(self.port)}"

    @classmethod
    def default_octagon(cls, node_id: str) -> "WatchtowerConfig":
        return cls(
            node_id=node_id,
            towers=[
                TowerConfig(
                    name="Inbound Traffic Sentinel",
                    position=TowerPosition.N,
                    tower_type=TowerType.TRAFFIC_INBOUND,
                    tags=["traffic", "inbound"],
                ),
                TowerConfig(
                    name="Outbound Traffic Sentinel",
                    position=TowerPosition.S,
                    tower_type=TowerType.TRAFFIC_OUTBOUND,
                    tags=["traffic", "outbound"],
                ),
                TowerConfig(
                    name="Network Intrusion Guard",
                    position=TowerPosition.E,
                    tower_type=TowerType.INTRUSION_NETWORK,
                    tags=["intrusion", "network"],
                    severity=AlertSeverity.CRITICAL,
                ),
                TowerConfig(
                    name="Auth Intrusion Guard",
                    position=TowerPosition.W,
                    tower_type=TowerType.INTRUSION_AUTH,
                    tags=["intrusion", "auth"],
                    severity=AlertSeverity.CRITICAL,
                ),
                TowerConfig(
                    name="Malware Signature Scanner",
                    position=TowerPosition.NE,
                    tower_type=TowerType.MALWARE_SIGNATURE,
                    tags=["malware"],
                    severity=AlertSeverity.CRITICAL,
                ),
                TowerConfig(
                    name="Malware Behavior Analyzer",
                    position=TowerPosition.SE,
                    tower_type=TowerType.MALWARE_BEHAVIOR,
                    tags=["malware"],
                    severity=AlertSeverity.CRITICAL,
                ),
                TowerConfig(
                    name="Phishing Content Filter",
                    position=TowerPosition.SW,
                    tower_type=TowerType.PHISHING_CONTENT,
                    tags=["phishing"],
                    severity=AlertSeverity.WARNING,
                ),
                TowerConfig(
                    name="Phishing Domain Sentinel",
                    position=TowerPosition.NW,
                    tower_type=TowerType.PHISHING_DOMAIN,
                    tags=["phishing"],
                    severity=AlertSeverity.WARNING,
                ),
            ],
        )

    @classmethod
    def from_env(cls, prefix: str = "S43_WATCHTOWER_") -> "WatchtowerConfig":
        env = os.environ

        def _get(key: str, default: Optional[str] = None) -> Optional[str]:
            return env.get(prefix + key, default)

        node_id = _get("NODE_ID")
        if not node_id:
            raise ValueError(f"{prefix}NODE_ID is required")

        host = _get("HOST", "0.0.0.0") or "0.0.0.0"
        port_raw = _get("PORT", "9100") or "9100"
        environment = _get("ENVIRONMENT", "production") or "production"
        model_name = _get("MODEL_NAME", "none") or "none"

        port = _clamp_int(f"{prefix}PORT", port_raw, 1024, 65535)

        max_errors_raw = _get("MAX_TOWER_ERRORS_BEFORE_DEGRADE")
        max_errors = (
            25
            if max_errors_raw is None
            else _clamp_int("max_tower_errors_before_degrade", max_errors_raw, 1, 1000)
        )

        base = cls.default_octagon(node_id=node_id)

        return cls(
            node_id=node_id,
            environment=environment,
            host=host,
            port=port,
            towers=list(base.towers),
            model_name=model_name,
            max_tower_errors_before_degrade=max_errors,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "environment": self.environment,
            "host": self.host,
            "port": int(self.port),
            "api_url": self.api_url,
            "model_name": self.model_name,
            "max_tower_errors_before_degrade": int(self.max_tower_errors_before_degrade),
            "towers": [tower.to_dict() for tower in self.towers],
        }


RuleResult = Optional[Tuple[str, AlertSeverity, List[str], Dict[str, Any]]]
RuleFn = Callable[[SentinelEvent, ThresholdProfile], RuleResult]

_RULES: Dict[TowerType, RuleFn] = {}
_RULES_LOCK = threading.RLock()


def register_rule(tower_type: TowerType) -> Callable[[RuleFn], RuleFn]:
    def decorator(fn: RuleFn) -> RuleFn:
        with _RULES_LOCK:
            _RULES[tower_type] = fn
        return fn

    return decorator


def _get_registered_rule(tower_type: TowerType) -> Optional[RuleFn]:
    with _RULES_LOCK:
        return _RULES.get(tower_type)


@register_rule(TowerType.TRAFFIC_INBOUND)
def _rule_inbound(event: SentinelEvent, thr: ThresholdProfile) -> RuleResult:
    payload = event.payload

    if (
        payload.get("direction") == "inbound"
        and int(payload.get("bytes", 0) or 0) > 0
        and _as_bool(payload.get("blocked", False))
    ):
        return (
            "Blocked inbound traffic",
            AlertSeverity.WARNING,
            ["traffic", "inbound"],
            {"bytes": payload.get("bytes")},
        )

    return None


@register_rule(TowerType.TRAFFIC_OUTBOUND)
def _rule_outbound(event: SentinelEvent, thr: ThresholdProfile) -> RuleResult:
    payload = event.payload

    if (
        payload.get("direction") == "outbound"
        and payload.get("dest_reputation", "good") in {"bad", "unknown"}
    ):
        return (
            "Outbound to bad/unknown reputation host",
            AlertSeverity.WARNING,
            ["traffic", "outbound"],
            {"dest": payload.get("dest")},
        )

    return None


@register_rule(TowerType.INTRUSION_NETWORK)
def _rule_intrusion_network(event: SentinelEvent, thr: ThresholdProfile) -> RuleResult:
    payload = event.payload

    if event.kind == "network" and _as_bool(payload.get("scan_detected", False)):
        return (
            "Port scan / probe detected",
            AlertSeverity.CRITICAL,
            ["intrusion", "network"],
            {"src_ip": payload.get("src_ip")},
        )

    return None


@register_rule(TowerType.INTRUSION_AUTH)
def _rule_intrusion_auth(event: SentinelEvent, thr: ThresholdProfile) -> RuleResult:
    payload = event.payload

    if event.kind == "auth" and int(payload.get("failed_logins", 0) or 0) >= thr.failed_logins:
        return (
            f"Multiple failed login attempts (>= {thr.failed_logins})",
            AlertSeverity.CRITICAL,
            ["intrusion", "auth"],
            {"failed_logins": payload.get("failed_logins")},
        )

    return None


@register_rule(TowerType.MALWARE_SIGNATURE)
def _rule_malware_signature(event: SentinelEvent, thr: ThresholdProfile) -> RuleResult:
    payload = event.payload

    if event.kind == "file" and _as_bool(payload.get("signature_match", False)):
        return (
            "Known malware signature match",
            AlertSeverity.CRITICAL,
            ["malware", "signature"],
            {"signature": payload.get("signature")},
        )

    return None


@register_rule(TowerType.MALWARE_BEHAVIOR)
def _rule_malware_behavior(event: SentinelEvent, thr: ThresholdProfile) -> RuleResult:
    payload = event.payload

    if event.kind == "process" and _as_bool(payload.get("suspicious_behavior", False)):
        return (
            "Behavioral malware indicator",
            AlertSeverity.CRITICAL,
            ["malware", "behavior"],
            {"proc": payload.get("process_name")},
        )

    return None


@register_rule(TowerType.PHISHING_CONTENT)
def _rule_phishing_content(event: SentinelEvent, thr: ThresholdProfile) -> RuleResult:
    payload = event.payload

    if event.kind == "email" and int(payload.get("phishing_score", 0) or 0) >= thr.phishing_score:
        return (
            f"Phishing-like email content (>= {thr.phishing_score})",
            AlertSeverity.WARNING,
            ["phishing", "content"],
            {"phishing_score": payload.get("phishing_score")},
        )

    return