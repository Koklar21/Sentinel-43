from __future__ import annotations

import enum
import logging
import os
import time
import uuid
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple


# ============================================================
# Logging (Sentinel-43 style)
# ============================================================
logger = logging.getLogger("sentinel43.watchtower")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - Sentinel-43 - Watchtower - %(levelname)s - %(message)s",
    )


# ============================================================
# Pydantic / fallback
# ============================================================
try:
    from pydantic import BaseModel, Field, conint, computed_field
    HAS_PYDANTIC = True
except Exception:
    HAS_PYDANTIC = False

    class BaseModel:  # type: ignore
        def __init__(self, **data: Any):
            for k, v in data.items():
                setattr(self, k, v)

    def Field(default=None, **kwargs):  # type: ignore
        return default

    def conint(*, ge=None, le=None, **kwargs):  # type: ignore
        return int

    def computed_field(*args, **kwargs):  # type: ignore
        def decorator(fn):
            return property(fn)
        return decorator


# ============================================================
# Utilities
# ============================================================
def _utc_ts() -> float:
    return time.time()


def _clamp_int(name: str, v: Any, lo: int, hi: int) -> int:
    try:
        iv = int(v)
    except Exception as e:
        raise ValueError(f"{name} must be an int in [{lo},{hi}], got {v!r}") from e
    if not (lo <= iv <= hi):
        raise ValueError(f"{name} must be in [{lo},{hi}], got {iv}")
    return iv


def _ensure_id(d: Dict[str, Any], key: str) -> str:
    val = d.get(key)
    if isinstance(val, str) and val.strip():
        return val
    new_id = str(uuid.uuid4())
    d[key] = new_id
    return new_id


@dataclass(frozen=True)
class ThresholdProfile:
    failed_logins: int
    phishing_score: int


def thresholds_for(sensitivity: Any) -> ThresholdProfile:
    """
    Sensitivity 1..10 -> threshold profile.
      1 = less sensitive (higher thresholds)
      10 = more sensitive (lower thresholds)
    """
    s = _clamp_int("sensitivity", sensitivity, 1, 10)
    failed_logins = int(round(10 - (s - 1) * (6 / 9)))   # 10 -> 4
    phishing_score = int(round(85 - (s - 1) * (25 / 9))) # 85 -> 60
    return ThresholdProfile(failed_logins=failed_logins, phishing_score=phishing_score)


# ============================================================
# Sentinel-43 Event + Alert Schema
# ============================================================
class SentinelEvent(BaseModel):
    """
    Lightweight schema wrapper (dict-compatible via .to_dict()).
    Use this as your "contract" between intake -> watchtower -> governance.
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_ts: float = Field(default_factory=_utc_ts)

    # Source metadata
    source: str = Field("unknown", description="Producer module/node name (e.g., s34_auth, api_gateway).")
    kind: str = Field("generic", description="Event category (auth/network/file/process/email/url/etc).")
    environment: str = Field("production")

    # Freeform payload
    payload: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        if HAS_PYDANTIC and hasattr(self, "model_dump"):
            return self.model_dump()
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

    # Linkage
    event_id: str = Field(...)
    correlation_id: str = Field(...)

    # Tower info
    tower_id: str = Field(...)
    tower_name: str = Field(...)
    tower_type: str = Field(...)
    position: str = Field(...)

    severity: AlertSeverity = Field(AlertSeverity.WARNING)
    reason: str = Field(...)
    sensitivity: int = Field(5)

    # Optional enrichment
    tags: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        if HAS_PYDANTIC and hasattr(self, "model_dump"):
            d = self.model_dump()
            # pydantic might serialize enums differently depending on version
            d["severity"] = getattr(self.severity, "value", str(self.severity))
            return d
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


# ============================================================
# Enums
# ============================================================
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


# ============================================================
# Config Models
# ============================================================
class TowerConfig(BaseModel):
    name: str = Field(..., description="Human-friendly tower name.")
    position: TowerPosition = Field(..., description="Octagon position.")
    tower_type: TowerType = Field(..., description="Functional role.")
    enabled: bool = Field(True)
    sensitivity: conint(ge=1, le=10) = Field(5, description="1=low noise, 10=hyper sensitive.")
    severity: AlertSeverity = Field(AlertSeverity.WARNING, description="Default alert severity for this tower.")
    tags: List[str] = Field(default_factory=list, description="Static tags emitted on alerts (e.g., ['auth','edge']).")

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
    node_id: str = Field(..., description="Unique Watchtower node ID.")
    environment: str = Field("production", description="Deployment environment label.")
    host: str = Field("0.0.0.0", description="Bind host.")
    port: conint(ge=1024, le=65535) = Field(9100, description="Bind port.")
    towers: List[TowerConfig] = Field(default_factory=list, description="Tower segment configs.")
    model_name: str = Field("none", description="Optional upstream AI model label (metadata only).")

    # reliability knobs
    max_tower_errors_before_degrade: conint(ge=1, le=1000) = Field(25, description="Segment errors before node degrades.")

    @computed_field
    def api_url(self) -> str:
        return f"http://{self.host}:{int(self.port)}"

    if HAS_PYDANTIC:
        class Config:
            env_prefix = "S43_WATCHTOWER_"
            extra = "ignore"

    @classmethod
    def default_octagon(cls, node_id: str) -> "WatchtowerConfig":
        return cls(
            node_id=node_id,
            towers=[
                TowerConfig(name="Inbound Traffic Sentinel", position=TowerPosition.N,  tower_type=TowerType.TRAFFIC_INBOUND, tags=["traffic", "inbound"]),
                TowerConfig(name="Outbound Traffic Sentinel", position=TowerPosition.S, tower_type=TowerType.TRAFFIC_OUTBOUND, tags=["traffic", "outbound"]),
                TowerConfig(name="Network Intrusion Guard", position=TowerPosition.E,  tower_type=TowerType.INTRUSION_NETWORK, tags=["intrusion", "network"], severity=AlertSeverity.CRITICAL),
                TowerConfig(name="Auth Intrusion Guard", position=TowerPosition.W,     tower_type=TowerType.INTRUSION_AUTH, tags=["intrusion", "auth"], severity=AlertSeverity.CRITICAL),
                TowerConfig(name="Malware Signature Scanner", position=TowerPosition.NE, tower_type=TowerType.MALWARE_SIGNATURE, tags=["malware"], severity=AlertSeverity.CRITICAL),
                TowerConfig(name="Malware Behavior Analyzer", position=TowerPosition.SE, tower_type=TowerType.MALWARE_BEHAVIOR, tags=["malware"], severity=AlertSeverity.CRITICAL),
                TowerConfig(name="Phishing Content Filter", position=TowerPosition.SW, tower_type=TowerType.PHISHING_CONTENT, tags=["phishing"], severity=AlertSeverity.WARNING),
                TowerConfig(name="Phishing Domain Sentinel", position=TowerPosition.NW, tower_type=TowerType.PHISHING_DOMAIN, tags=["phishing"], severity=AlertSeverity.WARNING),
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

        try:
            port = int(port_raw)
        except ValueError as e:
            raise ValueError(f"Invalid {prefix}PORT: {port_raw!r}") from e

        if not (1024 <= port <= 65535):
            raise ValueError(f"{prefix}PORT must be between 1024 and 65535, got {port}")

        cfg = cls.default_octagon(node_id=node_id)
        cfg.host = host
        cfg.port = port
        cfg.environment = _get("ENVIRONMENT", "production") or "production"
        cfg.model_name = _get("MODEL_NAME", "none") or "none"

        mte = _get("MAX_TOWER_ERRORS_BEFORE_DEGRADE", None)
        if mte is not None:
            cfg.max_tower_errors_before_degrade = _clamp_int("max_tower_errors_before_degrade", mte, 1, 1000)

        return cfg

    def to_dict(self) -> Dict[str, Any]:
        if HAS_PYDANTIC and hasattr(self, "model_dump"):
            d = self.model_dump()
            d["api_url"] = self.api_url
            return d
        return {
            "node_id": self.node_id,
            "environment": self.environment,
            "host": self.host,
            "port": int(self.port),
            "api_url": self.api_url,
            "model_name": self.model_name,
            "max_tower_errors_before_degrade": int(self.max_tower_errors_before_degrade),
            "towers": [t.to_dict() for t in self.towers],
        }


# ============================================================
# Tower rule registry (pluggable)
# ============================================================
RuleResult = Optional[Tuple[str, AlertSeverity, List[str], Dict[str, Any]]]
RuleFn = Callable[[SentinelEvent, ThresholdProfile], RuleResult]

_RULES: Dict[TowerType, RuleFn] = {}


def register_rule(ttype: TowerType) -> Callable[[RuleFn], RuleFn]:
    def deco(fn: RuleFn) -> RuleFn:
        _RULES[ttype] = fn
        return fn
    return deco


@register_rule(TowerType.TRAFFIC_INBOUND)
def _rule_inbound(event: SentinelEvent, thr: ThresholdProfile) -> RuleResult:
    p = event.payload
    if p.get("direction") == "inbound" and int(p.get("bytes", 0) or 0) > 0 and bool(p.get("blocked", False)):
        return ("Blocked inbound traffic", AlertSeverity.WARNING, ["traffic", "inbound"], {"bytes": p.get("bytes")})
    return None


@register_rule(TowerType.TRAFFIC_OUTBOUND)
def _rule_outbound(event: SentinelEvent, thr: ThresholdProfile) -> RuleResult:
    p = event.payload
    if p.get("direction") == "outbound" and p.get("dest_reputation", "good") in {"bad", "unknown"}:
        return ("Outbound to bad/unknown reputation host", AlertSeverity.WARNING, ["traffic", "outbound"], {"dest": p.get("dest")})
    return None


@register_rule(TowerType.INTRUSION_NETWORK)
def _rule_intrusion_network(event: SentinelEvent, thr: ThresholdProfile) -> RuleResult:
    p = event.payload
    if event.kind == "network" and bool(p.get("scan_detected", False)):
        return ("Port scan / probe detected", AlertSeverity.CRITICAL, ["intrusion", "network"], {"src_ip": p.get("src_ip")})
    return None


@register_rule(TowerType.INTRUSION_AUTH)
def _rule_intrusion_auth(event: SentinelEvent, thr: ThresholdProfile) -> RuleResult:
    p = event.payload
    if event.kind == "auth" and int(p.get("failed_logins", 0) or 0) >= thr.failed_logins:
        return (f"Multiple failed login attempts (>= {thr.failed_logins})", AlertSeverity.CRITICAL, ["intrusion", "auth"], {"failed_logins": p.get("failed_logins")})
    return None


@register_rule(TowerType.MALWARE_SIGNATURE)
def _rule_malware_sig(event: SentinelEvent, thr: ThresholdProfile) -> RuleResult:
    p = event.payload
    if event.kind == "file" and bool(p.get("signature_match", False)):
        return ("Known malware signature match", AlertSeverity.CRITICAL, ["malware", "signature"], {"signature": p.get("signature")})
    return None


@register_rule(TowerType.MALWARE_BEHAVIOR)
def _rule_malware_behavior(event: SentinelEvent, thr: ThresholdProfile) -> RuleResult:
    p = event.payload
    if event.kind == "process" and bool(p.get("suspicious_behavior", False)):
        return ("Behavioral malware indicator", AlertSeverity.CRITICAL, ["malware", "behavior"], {"proc": p.get("process_name")})
    return None


@register_rule(TowerType.PHISHING_CONTENT)
def _rule_phishing_content(event: SentinelEvent, thr: ThresholdProfile) -> RuleResult:
    p = event.payload
    if event.kind == "email" and int(p.get("phishing_score", 0) or 0) >= thr.phishing_score:
        return (f"Phishing-like email content (>= {thr.phishing_score})", AlertSeverity.WARNING, ["phishing", "content"], {"phishing_score": p.get("phishing_score")})
    return None


@register_rule(TowerType.PHISHING_DOMAIN)
def _rule_phishing_domain(event: SentinelEvent, thr: ThresholdProfile) -> RuleResult:
    p = event.payload
    if event.kind == "url" and p.get("domain_reputation", "good") in {"phishing", "unknown"}:
        return ("Suspicious/phishing domain reputation", AlertSeverity.WARNING, ["phishing", "domain"], {"domain": p.get("domain")})
    return None


# ============================================================
# Tower Runtime Object
# ============================================================
class WatchtowerSegment:
    def __init__(self, cfg: TowerConfig):
        self.cfg = cfg
        self.last_scan_ts: Optional[float] = None
        self.alert_count: int = 0
        self.error_count: int = 0

        self._thr = thresholds_for(self.cfg.validated_sensitivity())

    @property
    def id(self) -> str:
        return f"{self.cfg.position.value}:{self.cfg.tower_type.value}"

    def scan(self, event: SentinelEvent) -> Optional[SentinelAlert]:
        if not self.cfg.enabled:
            return None

        self.last_scan_ts = _utc_ts()

        rule = _RULES.get(self.cfg.tower_type)
        if not rule:
            return None

        result = rule(event, self._thr)
        if not result:
            return None

        reason, rule_sev, rule_tags, details = result
        self.alert_count += 1

        # Tower config sets a default severity, but rule can override upward.
        # We take the more severe between cfg.severity and rule_sev.
        sev = _max_severity(self.cfg.severity, rule_sev)

        merged_tags = list(dict.fromkeys([*self.cfg.tags, *rule_tags]))

        return SentinelAlert(
            event_id=event.event_id,
            correlation_id=event.correlation_id,
            tower_id=self.id,
            tower_name=self.cfg.name,
            tower_type=self.cfg.tower_type.value,
            position=self.cfg.position.value,
            severity=sev,
            reason=reason,
            sensitivity=self.cfg.validated_sensitivity(),
            tags=merged_tags,
            details=details,
        )

    def status(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.cfg.name,
            "position": self.cfg.position.value,
            "tower_type": self.cfg.tower_type.value,
            "enabled": bool(self.cfg.enabled),
            "sensitivity": self.cfg.validated_sensitivity(),
            "severity": getattr(self.cfg.severity, "value", str(self.cfg.severity)),
            "thresholds": {
                "failed_logins": self._thr.failed_logins,
                "phishing_score": self._thr.phishing_score,
            },
            "last_scan_ts": self.last_scan_ts,
            "alert_count": self.alert_count,
            "error_count": self.error_count,
        }


def _max_severity(a: AlertSeverity, b: AlertSeverity) -> AlertSeverity:
    order = {
        AlertSeverity.INFO: 1,
        AlertSeverity.WARNING: 2,
        AlertSeverity.CRITICAL: 3,
    }
    return a if order[a] >= order[b] else b


# ============================================================
# Watchtower Node
# ============================================================
class WatchtowerNode:
    _ALLOWED_TRANSITIONS = {
        WatchtowerState.INITIALIZING: {WatchtowerState.ACTIVE, WatchtowerState.DEGRADED, WatchtowerState.FAILED},
        WatchtowerState.ACTIVE: {WatchtowerState.DEGRADED, WatchtowerState.FAILED},
        WatchtowerState.DEGRADED: {WatchtowerState.ACTIVE, WatchtowerState.FAILED},
        WatchtowerState.FAILED: set(),
    }

    def __init__(self, config: WatchtowerConfig):
        self.config = config
        self._lock = threading.RLock()
        self._state: WatchtowerState = WatchtowerState.INITIALIZING

        self.towers: Dict[str, WatchtowerSegment] = {}
        for tcfg in self.config.towers:
            seg = WatchtowerSegment(tcfg)
            if seg.id in self.towers:
                raise ValueError(f"Duplicate tower id '{seg.id}' in config (would overwrite).")
            self.towers[seg.id] = seg

        self._tower_errors_total = 0

        logger.info(
            "[%s] Watchtower initialized with %d segments on %s",
            self.config.node_id,
            len(self.towers),
            self.config.api_url,
        )

    @property
    def state(self) -> WatchtowerState:
        with self._lock:
            return self._state

    def set_state(self, new_state: WatchtowerState) -> None:
        with self._lock:
            cur = self._state
            allowed = self._ALLOWED_TRANSITIONS.get(cur, set())
            if new_state not in allowed and new_state != cur:
                logger.warning(
                    "[%s] Invalid state transition %s -> %s (ignored)",
                    self.config.node_id,
                    cur.value,
                    new_state.value,
                )
                return

            if new_state != cur:
                logger.info(
                    "[%s] Watchtower state: %s -> %s",
                    self.config.node_id,
                    cur.value,
                    new_state.value,
                )
                self._state = new_state

    def start(self) -> None:
        try:
            self.set_state(WatchtowerState.ACTIVE)
        except Exception as exc:
            logger.exception("[%s] Watchtower failed to start: %s", self.config.node_id, exc)
            with self._lock:
                self._state = WatchtowerState.FAILED

    def scan_event(self, event_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Input: raw dict (intake-friendly)
        Output: list of alert dicts (API-friendly)
        """
        with self._lock:
            if self._state != WatchtowerState.ACTIVE:
                logger.debug("[%s] Ignoring event; state=%s", self.config.node_id, self._state.value)
                return []
            towers_snapshot = list(self.towers.items())

        # Normalize/ensure IDs at the edge
        _ensure_id(event_dict, "event_id")
        _ensure_id(event_dict, "correlation_id")
        if "created_ts" not in event_dict:
            event_dict["created_ts"] = _utc_ts()

        # Convert into SentinelEvent
        # Expect: payload is nested, but tolerate old flat events by folding into payload.
        payload = event_dict.get("payload")
        if not isinstance(payload, dict):
            payload = dict(event_dict)
            for k in ("event_id", "correlation_id", "created_ts", "source", "kind", "environment", "payload"):
                payload.pop(k, None)

        event = SentinelEvent(
            event_id=str(event_dict.get("event_id")),
            correlation_id=str(event_dict.get("correlation_id")),
            created_ts=float(event_dict.get("created_ts")),
            source=str(event_dict.get("source", "unknown")),
            kind=str(event_dict.get("kind", "generic")),
            environment=str(event_dict.get("environment", self.config.environment)),
            payload=payload,
        )

        alerts: List[Dict[str, Any]] = []
        for seg_id, seg in towers_snapshot:
            try:
                alert = seg.scan(event)
                if alert:
                    alerts.append(alert.to_dict())
            except Exception as e:
                seg.error_count += 1
                self._tower_errors_total += 1
                logger.exception("[%s] tower scan failed id=%s err=%s", self.config.node_id, seg_id, type(e).__name__)

                # If towers are melting down, degrade the node to stop pretending everything is fine.
                if self._tower_errors_total >= int(self.config.max_tower_errors_before_degrade):
                    self.set_state(WatchtowerState.DEGRADED)

        return alerts

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            st = self._state
            towers_snapshot = list(self.towers.values())

        return {
            "node_id": self.config.node_id,
            "state": st.value,
            "environment": self.config.environment,
            "api_url": self.config.api_url,
            "model_name": self.config.model_name,
            "tower_errors_total": self._tower_errors_total,
            "towers": [seg.status() for seg in towers_snapshot],
        }


# ============================================================
# API factory (framework-agnostic)
# ============================================================
def create_api_app(node: WatchtowerNode) -> Dict[str, Any]:
    """
    Framework-agnostic API descriptor.

    Returns handlers you can bind to routes in FastAPI/Starlette/etc.
    """
    logger.info("Creating API for Sentinel-43 Watchtower node %s", node.config.node_id)

    def health_check() -> Dict[str, Any]:
        return {"status": "ok", "node_state": node.state.value}

    def node_status() -> Dict[str, Any]:
        return node.get_status()

    def analyze(event: Dict[str, Any]) -> Dict[str, Any]:
        alerts = node.scan_event(event)
        return {"alerts": alerts, "alert_count": len(alerts)}

    return {
        "node_id": node.config.node_id,
        "endpoint_handlers": {
            "/health": health_check,
            "/status": node_status,
            "/analyze": analyze,
        },
        "is_ready": node.state == WatchtowerState.ACTIVE,
    }


__all__ = [
    "HAS_PYDANTIC",
    "SentinelEvent",
    "SentinelAlert",
    "AlertSeverity",
    "WatchtowerState",
    "TowerType",
    "TowerPosition",
    "TowerConfig",
    "WatchtowerConfig",
    "WatchtowerSegment",
    "WatchtowerNode",
    "register_rule",
    "create_api_app",
]