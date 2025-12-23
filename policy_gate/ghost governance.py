from __future__ import annotations

import os
import json
import hmac
import hashlib
import logging
import threading
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, date
from decimal import Decimal, InvalidOperation, getcontext
from typing import Dict, List, Tuple, Any, Optional, Set
from collections import deque
from types import MappingProxyType
import statistics
import copy

# -----------------------
# Precision / Money rules
# -----------------------
getcontext().prec = 28
MONEY_QUANT = Decimal("0.0001")

def normalize_amount(amount: Decimal) -> Decimal:
    return amount.quantize(MONEY_QUANT)

# -----------------------
# Config
# -----------------------
_RISK_WEIGHTS = MappingProxyType({
    "baseline": Decimal("0.3"),
    "slow_boil": Decimal("0.5"),
    "outlier": Decimal("0.4"),
    "trust_penalty": Decimal("0.2"),
})

CONFIG = MappingProxyType({
    "FINANCIAL_HARD_LIMIT": Decimal("50.00"),
    "VELOCITY_LIMIT": 3,
    "VELOCITY_WINDOW_SECONDS": 60,
    "RISK_THRESHOLD": Decimal("0.85"),
    "POLICY_VERSION": "2.4-hardened",
    "RISK_WEIGHTS": _RISK_WEIGHTS,
    "SLOW_BOIL_WINDOW": 5,
    "OUTLIER_Z": Decimal("3.0"),
    "MAX_HISTORY_LENGTH": 50,

    # Audit sinks
    "AUDIT_JSONL_FILE": "ghost_audit.jsonl",   # optional
    "AUDIT_SQLITE_PATH": "ghost_audit.sqlite3",

    # Metadata safety
    "INCLUDE_METADATA_SNAPSHOT": True,  # still allowed, but filtered
    "METADATA_ALLOWLIST": set([
        "region_code",
        "session_id",
        "request_id",
        "ip_address",
        "device_integrity",
        "location",
        "device_id",
        # add more explicitly, or it doesn't get logged
    ]),

    # GC
    "GC_INTERVAL_SECONDS": 3600,
})

# -----------------------
# Reason codes
# -----------------------
class ReasonCodes:
    FINANCIAL_LIMIT = "FLAC_FAIL_FINANCIAL_LIMIT_EXCEEDED"
    SANCTIONED_LOCATION = "FLAC_FAIL_LEGAL_SANCTIONED_LOCATION"
    DEVICE_UNTRUSTED = "FLAC_FAIL_COMPLIANCE_DEVICE_UNTRUSTED"
    MISSING_METADATA = "FLAC_FAIL_AUDIT_MISSING_METADATA"
    VELOCITY_EXCEEDED = "FLAC_FAIL_VELOCITY_LIMIT"
    INVALID_AMOUNT = "FLAC_FAIL_INVALID_AMOUNT"
    NEGATIVE_AMOUNT = "FLAC_FAIL_NEGATIVE_AMOUNT"
    INVALID_TIMESTAMP = "FLAC_FAIL_INVALID_TIMESTAMP"
    FUTURE_TIMESTAMP = "FLAC_FAIL_FUTURE_TIMESTAMP"
    CLEARED = "CLEARED_ALL_CHECKS"
    SYSTEM_ERROR = "SYSTEM_EXCEPTION"
    HASH_SECRET_MISSING = "SYSTEM_HASH_SECRET_MISSING"
    SERIALIZATION_ERROR = "SYSTEM_SERIALIZATION_ERROR"
    AI_RISK = "AI_RISK_THRESHOLD_EXCEEDED"

# -----------------------
# Logging
# -----------------------
_logger = logging.getLogger("Sentinel43.PolicyGate")
_logger.setLevel(logging.INFO)
if not _logger.handlers:
    _logger.addHandler(logging.StreamHandler())

# -----------------------
# JSON encoder
# -----------------------
class AuditEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)

# -----------------------
# Data classes
# -----------------------
@dataclass
class TransactionContext:
    user_id: str
    amount: Decimal
    timestamp: datetime
    location: str
    device_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Decision:
    status: str
    risk_score: Decimal
    reason: str

# -----------------------
# Metadata safety
# -----------------------
def _filter_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    if not metadata:
        return {}
    allow = CONFIG["METADATA_ALLOWLIST"]
    out: Dict[str, Any] = {}
    for k, v in metadata.items():
        if k in allow:
            out[k] = v
    return out

def _redact_ip(ip: Optional[str]) -> Optional[str]:
    # Keep coarse info only (privacy + compliance + less liability)
    if not ip or not isinstance(ip, str):
        return ip
    # IPv4 crude redaction: 1.2.3.4 -> 1.2.3.x
    if ip.count(".") == 3:
        parts = ip.split(".")
        return ".".join(parts[:3] + ["x"])
    return ip

# -----------------------
# Input validation
# -----------------------
def validate_context(ctx: TransactionContext) -> Tuple[bool, str]:
    now = datetime.now(timezone.utc)

    if not isinstance(ctx.amount, Decimal):
        try:
            ctx.amount = Decimal(str(ctx.amount))
        except (InvalidOperation, ValueError, TypeError):
            return False, ReasonCodes.INVALID_AMOUNT

    try:
        ctx.amount = normalize_amount(ctx.amount)
    except Exception:
        return False, ReasonCodes.INVALID_AMOUNT

    if ctx.amount.is_nan() or ctx.amount.is_infinite():
        return False, ReasonCodes.INVALID_AMOUNT
    if ctx.amount < 0:
        return False, ReasonCodes.NEGATIVE_AMOUNT

    if not isinstance(ctx.timestamp, datetime) or ctx.timestamp.tzinfo is None:
        return False, ReasonCodes.INVALID_TIMESTAMP
    if ctx.timestamp > now + timedelta(minutes=5):
        return False, ReasonCodes.FUTURE_TIMESTAMP
    if ctx.timestamp.year < 2000:
        return False, ReasonCodes.INVALID_TIMESTAMP

    for f in ["user_id", "device_id", "location"]:
        val = getattr(ctx, f)
        if not isinstance(val, str) or not val.strip():
            return False, f"FLAC_FAIL_INVALID_{f.upper()}"

    return True, ReasonCodes.CLEARED

# -----------------------
# Velocity (single-process default)
# -----------------------
class VelocityGuard:
    def __init__(self):
        self.user_events: Dict[str, deque] = {}
        self.lock = threading.Lock()
        self.last_gc = datetime.now(timezone.utc)

    def _garbage_collect(self, now: datetime):
        if (now - self.last_gc).total_seconds() <= CONFIG["GC_INTERVAL_SECONDS"]:
            return
        cutoff = now - timedelta(seconds=CONFIG["VELOCITY_WINDOW_SECONDS"])
        stale = [uid for uid, dq in self.user_events.items() if (not dq) or (dq[-1] < cutoff)]
        for uid in stale:
            self.user_events.pop(uid, None)
        self.last_gc = now

    def allow(self, user_id: str, now: datetime) -> bool:
        with self.lock:
            try:
                self._garbage_collect(now)
                dq = self.user_events.setdefault(user_id, deque())
                cutoff = now - timedelta(seconds=CONFIG["VELOCITY_WINDOW_SECONDS"])
                while dq and dq[0] < cutoff:
                    dq.popleft()
                if len(dq) >= CONFIG["VELOCITY_LIMIT"]:
                    return False
                dq.append(now)
                return True
            except Exception as e:
                _logger.error(f"VelocityGuard failure, failing closed: {e}")
                return False

# -----------------------
# Governance
# -----------------------
class GovernanceFramework:
    def __init__(self, sanctioned_locations: List[str]):
        self.sanctioned_locations: Set[str] = set(sanctioned_locations or [])

    def run_flac_loops(self, context: TransactionContext) -> Tuple[bool, str]:
        try:
            if context.amount > CONFIG["FINANCIAL_HARD_LIMIT"]:
                return False, ReasonCodes.FINANCIAL_LIMIT
            if context.location in self.sanctioned_locations:
                return False, ReasonCodes.SANCTIONED_LOCATION
            if context.metadata.get("device_integrity") == "compromised":
                return False, ReasonCodes.DEVICE_UNTRUSTED
            if not context.metadata:
                return False, ReasonCodes.MISSING_METADATA
            return True, ReasonCodes.CLEARED
        except Exception as e:
            _logger.error(f"Governance error: {e}")
            return False, ReasonCodes.SYSTEM_ERROR

# -----------------------
# Adaptive intelligence (Decimal-safe enough)
# -----------------------
class AdaptiveIntelligence:
    def __init__(self):
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()

    def get_baseline(self, user_id: str) -> Dict[str, Any]:
        with self.lock:
            return copy.deepcopy(self.profiles.get(user_id, {"history": [], "trust_score": Decimal("0.5")}))

    @staticmethod
    def _linear_regression_slope(vals: List[Decimal]) -> Decimal:
        try:
            n = len(vals)
            if n < 2:
                return Decimal(0)
            x_vals = [Decimal(i) for i in range(n)]
            mean_x = sum(x_vals) / n
            mean_y = sum(vals) / n
            num = sum((x - mean_x) * (y - mean_y) for x, y in zip(x_vals, vals))
            den = sum((x - mean_x) ** 2 for x in x_vals)
            return Decimal(0) if den == 0 else (num / den)
        except Exception:
            return Decimal(0)

    def detect_slow_boil(self, history: List[Decimal], current_amount: Decimal) -> bool:
        try:
            window = CONFIG["SLOW_BOIL_WINDOW"]
            if len(history) < window - 1:
                return False
            series = history[-(window - 1):] + [current_amount]
            slope = self._linear_regression_slope(series)
            return slope > Decimal("0.05")
        except Exception:
            return False

    def evaluate_risk(self, context: TransactionContext) -> Tuple[Decimal, Dict[str, Decimal], Dict[str, Any]]:
        try:
            profile = self.get_baseline(context.user_id)
            history: List[Decimal] = profile["history"]
            components: Dict[str, Decimal] = {}
            weights = CONFIG["RISK_WEIGHTS"]

            if not history:
                components["baseline"] = weights["baseline"]
                components["slow_boil"] = Decimal(0)
                components["outlier"] = Decimal(0)
            else:
                components["baseline"] = weights["baseline"] if len(history) < 5 else Decimal(0)
                components["slow_boil"] = weights["slow_boil"] if self.detect_slow_boil(history, context.amount) else Decimal(0)

                if len(history) >= 5:
                    # Keep it simple: stats needs floats; we normalize first.
                    float_hist = [float(normalize_amount(h)) for h in history]
                    mu = Decimal(str(statistics.mean(float_hist)))
                    sigma = Decimal(str(statistics.pstdev(float_hist))) or Decimal(1)
                    z = (context.amount - mu) / sigma if sigma != 0 else Decimal(0)
                    components["outlier"] = weights["outlier"] if z > CONFIG["OUTLIER_Z"] else Decimal(0)
                else:
                    components["outlier"] = Decimal(0)

            trust_score = profile.get("trust_score", Decimal("0.5"))
            penalty_base = Decimal("0.5") - trust_score
            components["trust_penalty"] = max(Decimal(0), penalty_base) * weights["trust_penalty"]

            risk = min(sum(components.values()), Decimal("1.0"))
            snapshot = {"history_len": len(history), "trust_score": trust_score}
            return risk, components, snapshot
        except Exception as e:
            _logger.error(f"Risk eval failure (fail closed): {e}")
            return Decimal("1.0"), {"error": Decimal("1.0")}, {"error_msg": str(e)}

    def learn(self, context: TransactionContext) -> None:
        with self.lock:
            profile = self.profiles.get(context.user_id, {"history": [], "trust_score": Decimal("0.5")})
            profile["history"].append(context.amount)
            if len(profile["history"]) > CONFIG["MAX_HISTORY_LENGTH"]:
                profile["history"].pop(0)
            self.profiles[context.user_id] = profile

    def reward_trust(self, user_id: str, delta: Decimal = Decimal("0.01")) -> None:
        with self.lock:
            profile = self.profiles.get(user_id, {"history": [], "trust_score": Decimal("0.5")})
            curr = profile["trust_score"]
            profile["trust_score"] = max(Decimal(0), min(Decimal(1), curr + delta))
            self.profiles[user_id] = profile

# -----------------------
# Audit chain persistence (SQLite anchor + log table)
# -----------------------
class AuditStore:
    def __init__(self, sqlite_path: str, jsonl_path: Optional[str] = None):
        self.sqlite_path = sqlite_path
        self.jsonl_path = jsonl_path
        self.lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.sqlite_path, timeout=10, isolation_level=None)
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA synchronous=FULL;")
        return con

    def _init_db(self):
        con = self._connect()
        try:
            con.execute("""
                CREATE TABLE IF NOT EXISTS audit_anchor (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    prev_hash TEXT NOT NULL
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    decision_time TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    prev_hash TEXT NOT NULL
                )
            """)
            # ensure anchor row exists
            row = con.execute("SELECT prev_hash FROM audit_anchor WHERE id=1").fetchone()
            if row is None:
                con.execute("INSERT INTO audit_anchor (id, prev_hash) VALUES (1, 'GENESIS')")
        finally:
            con.close()

    def get_prev_hash(self) -> str:
        con = self._connect()
        try:
            (prev_hash,) = con.execute("SELECT prev_hash FROM audit_anchor WHERE id=1").fetchone()
            return prev_hash
        finally:
            con.close()

    def append(self, payload: Dict[str, Any], payload_hash: str, prev_hash: str) -> None:
        # Writes are serialized here; SQLite handles multi-process WAL fine.
        with self.lock:
            con = self._connect()
            try:
                decision_time = payload.get("decision_time") or datetime.now(timezone.utc).isoformat()
                payload_json = json.dumps(payload, cls=AuditEncoder, sort_keys=True, separators=(",", ":"))

                con.execute(
                    "INSERT INTO audit_log (decision_time, payload_json, payload_hash, prev_hash) VALUES (?, ?, ?, ?)",
                    (decision_time, payload_json, payload_hash, prev_hash),
                )
                con.execute("UPDATE audit_anchor SET prev_hash=? WHERE id=1", (payload_hash,))
            finally:
                con.close()

            # Optional JSONL sink (best-effort)
            if self.jsonl_path:
                try:
                    with open(self.jsonl_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps({"payload": payload, "hash": payload_hash}, cls=AuditEncoder) + "\n")
                        f.flush()
                        os.fsync(f.fileno())
                except Exception as e:
                    _logger.error(f"JSONL audit sink failed (non-fatal): {e}")

# -----------------------
# Secure audit log
# -----------------------
def _get_hmac_secret() -> Optional[bytes]:
    value = os.getenv("GHOST_DEVICE_HASH_SECRET")
    return value.encode("utf-8") if value else None

class SecureAuditLog:
    def __init__(self, store: AuditStore):
        self.store = store

    def _hmac_device(self, device_id: str) -> Tuple[str, Optional[str]]:
        secret = _get_hmac_secret()
        if secret is None:
            _logger.error("Missing GHOST_DEVICE_HASH_SECRET.")
            return "HASH_SECRET_MISSING", ReasonCodes.HASH_SECRET_MISSING
        try:
            digest = hmac.new(secret, device_id.encode(), hashlib.sha256).hexdigest()
            return digest, None
        except Exception as e:
            _logger.error(f"HMAC device hash failed: {e}")
            return "HASH_ERROR", ReasonCodes.SERIALIZATION_ERROR

    @staticmethod
    def _hash_metadata(metadata: Dict[str, Any]) -> str:
        try:
            meta_str = json.dumps(metadata or {}, cls=AuditEncoder, sort_keys=True, separators=(",", ":"))
            return hashlib.sha256(meta_str.encode()).hexdigest()
        except Exception as e:
            _logger.error(f"Metadata hashing failed: {e}")
            return "METADATA_HASH_ERROR"

    def log_decision(
        self,
        context: TransactionContext,
        decision: str,
        reason_code: str,
        risk_score: Decimal,
        risk_components: Dict[str, Decimal],
        model_snapshot: Dict[str, Any],
    ) -> bool:
        try:
            filtered_meta = _filter_metadata(context.metadata)
            if "ip_address" in filtered_meta:
                filtered_meta["ip_address"] = _redact_ip(filtered_meta.get("ip_address"))

            device_hash, hash_err = self._hmac_device(context.device_id)
            metadata_hash = self._hash_metadata(filtered_meta)

            prev_hash = self.store.get_prev_hash()

            snapshot_payload: Dict[str, Any] = dict(model_snapshot or {})
            if hash_err:
                snapshot_payload.setdefault("system_warnings", [])
                snapshot_payload["system_warnings"].append(hash_err)

            payload: Dict[str, Any] = {
                "event_time": context.timestamp.isoformat(),
                "decision_time": datetime.now(timezone.utc).isoformat(),
                "user_id": context.user_id,
                "decision": decision,
                "reason": reason_code,
                "risk_score": risk_score,
                "risk_components": risk_components,
                "amount": context.amount,
                "location": context.location,
                "device_hash": device_hash,
                "metadata_hash": metadata_hash,
                "policy_ver": CONFIG["POLICY_VERSION"],
                "prev_hash": prev_hash,
                "model_snapshot": snapshot_payload,
            }

            if CONFIG.get("INCLUDE_METADATA_SNAPSHOT", True):
                payload["metadata_snapshot"] = filtered_meta

            payload_str = json.dumps(payload, cls=AuditEncoder, sort_keys=True, separators=(",", ":"))
            curr_hash = hashlib.sha256(payload_str.encode()).hexdigest()

            self.store.append(payload=payload, payload_hash=curr_hash, prev_hash=prev_hash)
            _logger.info(json.dumps({"payload": payload, "hash": curr_hash}, cls=AuditEncoder))
            return True
        except Exception as e:
            _logger.error(f"Audit log failed: {e}")
            return False

# -----------------------
# Orchestrator (Policy Gate)
# -----------------------
class SystemOrchestrator:
    def __init__(self, sanctioned_locations: List[str]):
        self.governance = GovernanceFramework(sanctioned_locations)
        self.ai = AdaptiveIntelligence()
        self.velocity_guard = VelocityGuard()

        store = AuditStore(
            sqlite_path=CONFIG["AUDIT_SQLITE_PATH"],
            jsonl_path=CONFIG["AUDIT_JSONL_FILE"],
        )
        self.auditor = SecureAuditLog(store)

    def process_transaction(self, user_id: str, amount_str: str, metadata: Dict[str, Any]) -> Decision:
        try:
            safe_amount = normalize_amount(Decimal(amount_str))
        except (InvalidOperation, ValueError, TypeError):
            # If amount is bad, build minimal ctx for audit anyway
            ctx = TransactionContext(
                user_id=str(user_id or "UNKNOWN"),
                amount=Decimal("0"),
                timestamp=datetime.now(timezone.utc),
                location=str((metadata or {}).get("location", "UNKNOWN")),
                device_id=str((metadata or {}).get("device_id", "UNKNOWN")),
                metadata=metadata or {},
            )
            self.auditor.log_decision(ctx, "BLOCKED", ReasonCodes.INVALID_AMOUNT, Decimal("0"), {}, {"validation_error": "invalid_amount"})
            return Decision("BLOCKED", Decimal("0"), ReasonCodes.INVALID_AMOUNT)

        ctx = TransactionContext(
            user_id=user_id,
            amount=safe_amount,
            timestamp=datetime.now(timezone.utc),
            location=metadata.get("location", "UNKNOWN"),
            device_id=metadata.get("device_id", "UNKNOWN"),
            metadata=metadata or {},
        )

        try:
            valid, msg = validate_context(ctx)
            if not valid:
                self.auditor.log_decision(ctx, "BLOCKED", msg, Decimal("0"), {}, {"validation_error": msg})
                return Decision("BLOCKED", Decimal("0"), msg)

            if not self.velocity_guard.allow(user_id, ctx.timestamp):
                self.auditor.log_decision(ctx, "BLOCKED", ReasonCodes.VELOCITY_EXCEEDED, Decimal("0"), {}, {})
                return Decision("BLOCKED", Decimal("0"), ReasonCodes.VELOCITY_EXCEEDED)

            flac_passed, flac_reason = self.governance.run_flac_loops(ctx)
            if not flac_passed:
                self.auditor.log_decision(ctx, "BLOCKED", flac_reason, Decimal("0"), {}, {})
                return Decision("BLOCKED", Decimal("0"), flac_reason)

            risk_score, components, snapshot = self.ai.evaluate_risk(ctx)
            if risk_score > CONFIG["RISK_THRESHOLD"]:
                self.auditor.log_decision(ctx, "FLAGGED", ReasonCodes.AI_RISK, risk_score, components, snapshot)
                return Decision("FLAGGED", risk_score, ReasonCodes.AI_RISK)

            ok = self.auditor.log_decision(ctx, "APPROVED", ReasonCodes.CLEARED, risk_score, components, snapshot)
            if not ok:
                return Decision("ERROR", Decimal("1.0"), ReasonCodes.SYSTEM_ERROR)

            self.ai.learn(ctx)
            self.ai.reward_trust(user_id)
            return Decision("APPROVED", risk_score, ReasonCodes.CLEARED)

        except Exception as e:
            self.auditor.log_decision(ctx, "ERROR", ReasonCodes.SYSTEM_ERROR, Decimal("1.0"), {}, {"exception": str(e)})
            return Decision("ERROR", Decimal("1.0"), ReasonCodes.SYSTEM_ERROR)

# Exportable engine instance if you want it
engine = SystemOrchestrator(sanctioned_locations=["BLOCKED_REGION_1"])