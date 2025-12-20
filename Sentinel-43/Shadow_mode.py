# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
SENTINEL-43: Nexus Oversight Controller (Hardened)

Public-safe changes vs the earlier prototype:
- No import-time logging hijack (provide configure_logging() instead)
- Strict input validation (ipaddress + length bounds)
- Severity normalization + allowlist
- Non-guessable action IDs (UUID4) + separate dedupe keys
- Bounded corroboration key space (canonical threat types + capped strings)
- Budget can apply to both target and source (optional hooks)
- HUMAN_GATED approvals track operator_id (in-memory; persistence lives in your hardened node)
- Safer timer management + optional shutdown for clean exits

Note:
- This file is still intentionally "execution boundary" friendly:
  real-world effects terminate in IntegrationHub, which you swap to your real firewall/IAM client.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, Optional, Tuple


# ----------------------------
# Identity
# ----------------------------

SYSTEM_ID = "SENTINEL-43-NEXUS-01"


# ----------------------------
# Logging (no import-time side effects)
# ----------------------------

def configure_logging(level: int = logging.INFO) -> None:
    """
    Library-friendly logging setup. Safe to call multiple times.
    """
    root = logging.getLogger()
    if root.handlers:
        return  # already configured by host app
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(module)-18s | %(message)s",
    )


# ----------------------------
# Modes / Severity
# ----------------------------

class OpMode(Enum):
    SHADOW = "SHADOW_ADVISORY"
    HUMAN_GATED = "HUMAN_GATED"
    ACTIVE = "AUTONOMOUS_VETO"


_ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH"}


def _normalize_severity(s: str) -> str:
    s2 = (s or "MEDIUM").strip().upper()
    if s2 not in _ALLOWED_SEVERITIES:
        return "MEDIUM"
    return s2


# ----------------------------
# Integration Hub (Execution Boundary)
# ----------------------------

class IntegrationHub:
    """All real-world effects terminate here. Keep this boring and auditable."""

    @staticmethod
    def execute_firewall_block(ip_address: str, *, reason: str, evidence: dict) -> bool:
        # Real implementation would call your firewall/IAM provider.
        logging.warning(f"[FIREWALL] HARD BLOCK applied to {ip_address} | reason={reason} | evidence={evidence}")
        return True

    @staticmethod
    def log_shadow_action(ip_address: str, *, reason: str, evidence: dict) -> bool:
        logging.info(f"[SHADOW] WOULD have blocked {ip_address} | reason={reason} | evidence={evidence}")
        return True


# ----------------------------
# Policy Objects
# ----------------------------

@dataclass(frozen=True)
class ActionRequest:
    action_id: str
    dedupe_key: str
    target: str                  # e.g., IP
    source: str                  # e.g., sensor name / caller id (optional but useful)
    description: str
    delay_seconds: int
    severity: str                # LOW/MEDIUM/HIGH (validated)
    reason: str
    evidence: dict
    real_payload: Callable[[], None]
    shadow_payload: Callable[[], None]


@dataclass
class BudgetState:
    window_start: float
    used: int


@dataclass
class CorroborationState:
    first_seen: float
    last_seen: float
    count: int


# ----------------------------
# Helpers (validation + bounds)
# ----------------------------

_MAX_TARGET_LEN = 64
_MAX_SOURCE_LEN = 80
_MAX_REASON_LEN = 200
_MAX_EVIDENCE_KEYS = 64


def _safe_str(v: object, *, max_len: int) -> str:
    s = str(v) if v is not None else ""
    s = s.strip()
    if len(s) > max_len:
        return s[:max_len] + "…"
    return s


def _validate_ip(ip: str) -> Tuple[bool, str]:
    ip = _safe_str(ip, max_len=_MAX_TARGET_LEN)
    if not ip:
        return False, "empty_ip"
    try:
        ipaddress.ip_address(ip)
        return True, ip
    except ValueError:
        return False, "invalid_ip"


def _sanitize_evidence(evidence: dict) -> dict:
    """
    Keep evidence reasonably bounded and JSON-friendly.
    This is not a full serializer: it's a guardrail.
    """
    if not isinstance(evidence, dict):
        return {"_evidence_error": "evidence_not_dict"}

    out: dict = {}
    for i, (k, v) in enumerate(evidence.items()):
        if i >= _MAX_EVIDENCE_KEYS:
            out["_truncated"] = True
            break
        key = _safe_str(k, max_len=64)
        out[key] = _safe_str(v, max_len=300)
    return out


# Canonical threat types (prevents someone from spamming novel keys forever)
_CANON_THREAT = {
    "PORT_SCAN",
    "BRUTE_FORCE",
    "CREDENTIAL_STUFFING",
    "MALWARE_BEACON",
    "ANOMALOUS_TRAFFIC",
    "UNKNOWN",
}


def _normalize_threat_type(t: str) -> str:
    t2 = _safe_str(t, max_len=64).upper().replace(" ", "_")
    return t2 if t2 in _CANON_THREAT else "UNKNOWN"


# ----------------------------
# Oversight Engine (Veto + Gating) - hardened
# ----------------------------

class OversightEngine:
    """
    Hardened execution boundary:
    - Dedupe window (prevents replay spam) using dedupe_key
    - Action budgets per target and per source (prevents baiting/runaway + spray)
    - Two-signal confirmation for HIGH (prevents one-signal nukes)
    - Bounded pending actions (prevents timer pileups)
    """

    def __init__(
        self,
        mode_resolver: Callable[[], OpMode],
        *,
        dedupe_ttl_seconds: int = 120,
        max_pending: int = 250,
        budget_window_seconds: int = 300,
        budget_max_actions_per_target: int = 5,
        budget_max_actions_per_source: int = 25,
        require_two_signals_for_high: bool = True,
        corroboration_ttl_seconds: int = 600,
    ) -> None:
        self._mode_resolver = mode_resolver
        self._lock = threading.RLock()

        self._pending_actions: Dict[str, threading.Timer] = {}
        self._gated_actions: Dict[str, ActionRequest] = {}

        # replay defense
        self._recent_dedupe: Dict[str, float] = {}  # dedupe_key -> first_seen_time

        # rate limiting
        self._budget_target: Dict[str, BudgetState] = {}
        self._budget_source: Dict[str, BudgetState] = {}

        # two-signal confirmation
        self._corroboration: Dict[str, CorroborationState] = {}

        self._dedupe_ttl_seconds = int(dedupe_ttl_seconds)
        self._max_pending = int(max_pending)

        self._budget_window_seconds = int(budget_window_seconds)
        self._budget_max_actions_per_target = int(budget_max_actions_per_target)
        self._budget_max_actions_per_source = int(budget_max_actions_per_source)

        self._require_two_signals_for_high = bool(require_two_signals_for_high)
        self._corroboration_ttl_seconds = int(corroboration_ttl_seconds)

    def _now(self) -> float:
        return time.time()

    def _cleanup(self) -> None:
        now = self._now()

        for k, ts in list(self._recent_dedupe.items()):
            if now - ts > self._dedupe_ttl_seconds:
                self._recent_dedupe.pop(k, None)

        for k, st in list(self._corroboration.items()):
            if now - st.last_seen > self._corroboration_ttl_seconds:
                self._corroboration.pop(k, None)

        for target, st in list(self._budget_target.items()):
            if now - st.window_start > self._budget_window_seconds * 4:
                self._budget_target.pop(target, None)

        for source, st in list(self._budget_source.items()):
            if now - st.window_start > self._budget_window_seconds * 4:
                self._budget_source.pop(source, None)

    def _is_duplicate(self, dedupe_key: str) -> bool:
        now = self._now()
        ts = self._recent_dedupe.get(dedupe_key)
        if ts is None:
            self._recent_dedupe[dedupe_key] = now
            return False
        return (now - ts) <= self._dedupe_ttl_seconds

    def _consume_budget(self, bucket: Dict[str, BudgetState], key: str, max_actions: int) -> bool:
        now = self._now()
        st = bucket.get(key)
        if st is None:
            bucket[key] = BudgetState(window_start=now, used=1)
            return True

        if now - st.window_start > self._budget_window_seconds:
            st.window_start = now
            st.used = 1
            return True

        if st.used >= max_actions:
            return False

        st.used += 1
        return True

    def _corroborate(self, *, target: str, reason: str) -> int:
        now = self._now()
        key = f"{target}|{reason}"
        st = self._corroboration.get(key)
        if st is None:
            self._corroboration[key] = CorroborationState(first_seen=now, last_seen=now, count=1)
            return 1
        st.last_seen = now
        st.count += 1
        return st.count

    def schedule_action(self, req: ActionRequest) -> None:
        mode = self._mode_resolver()

        with self._lock:
            self._cleanup()

            if len(self._pending_actions) + len(self._gated_actions) >= self._max_pending:
                logging.error(f"[OVERSIGHT] Back-pressure: too many pending/gated actions. Dropping {req.action_id}")
                return

            if self._is_duplicate(req.dedupe_key):
                logging.info(f"[OVERSIGHT] Duplicate suppressed (dedupe_key): {req.dedupe_key}")
                return

            # budgets: target + source
            if not self._consume_budget(self._budget_target, req.target, self._budget_max_actions_per_target):
                logging.warning(f"[OVERSIGHT] Budget exceeded (target={req.target}). Suppressing {req.action_id}.")
                return

            if req.source and not self._consume_budget(self._budget_source, req.source, self._budget_max_actions_per_source):
                logging.warning(f"[OVERSIGHT] Budget exceeded (source={req.source}). Suppressing {req.action_id}.")
                return

            # two-signal for HIGH
            if req.severity == "HIGH" and self._require_two_signals_for_high:
                count = self._corroborate(target=req.target, reason=req.reason)
                logging.info(f"[OVERSIGHT] Corroboration target={req.target} reason='{req.reason}' -> {count}")
                if count < 2:
                    logging.info(f"[OVERSIGHT] Waiting for second signal before acting on HIGH: {req.action_id}")
                    if mode is OpMode.SHADOW:
                        req.shadow_payload()
                    return

            logging.info(f"[OVERSIGHT] Mode={mode.value} | {req.description}")

            if mode is OpMode.SHADOW:
                req.shadow_payload()
                logging.info("[OVERSIGHT] Advisory logged. No execution.")
                return

            if mode is OpMode.HUMAN_GATED:
                self._gated_actions[req.action_id] = req
                logging.warning(f"[OVERSIGHT] ACTION STAGED: {req.action_id}. Awaiting approval.")
                return

            # ACTIVE: delayed execution with veto window
            logging.warning(f"[OVERSIGHT] ACTION PENDING: {req.action_id}. Executes in {req.delay_seconds}s unless vetoed.")
            timer = threading.Timer(
                req.delay_seconds,
                self._execute_wrapper,
                args=(req.action_id, req.description, req.real_payload),
            )
            timer.daemon = True
            self._pending_actions[req.action_id] = timer
            timer.start()

    def _execute_wrapper(self, action_id: str, description: str, payload: Callable[[], None]) -> None:
        with self._lock:
            timer = self._pending_actions.pop(action_id, None)
            if not timer:
                return

        logging.warning(f"[OVERSIGHT] AUTO-EXECUTING: {description}")
        try:
            payload()
        except Exception as exc:
            logging.error(f"[OVERSIGHT] Execution failed for {action_id}: {exc}")

    def veto_action(self, action_id: str, reason: str, *, operator_id: str = "unknown") -> bool:
        reason = _safe_str(reason, max_len=300)
        operator_id = _safe_str(operator_id, max_len=80)

        with self._lock:
            timer = self._pending_actions.pop(action_id, None)
            if timer:
                timer.cancel()
                logging.warning(f"[OVERSIGHT] VETOED {action_id}. operator={operator_id} reason={reason}")
                return True

            if action_id in self._gated_actions:
                self._gated_actions.pop(action_id, None)
                logging.warning(f"[OVERSIGHT] GATED ACTION DROPPED {action_id}. operator={operator_id} reason={reason}")
                return True

        logging.warning(f"[OVERSIGHT] VETO FAILED: {action_id} not found.")
        return False

    def approve_gated_action(self, action_id: str, *, operator_id: str = "unknown") -> bool:
        operator_id = _safe_str(operator_id, max_len=80)

        with self._lock:
            req = self._gated_actions.pop(action_id, None)

        if not req:
            logging.warning(f"[OVERSIGHT] APPROVAL FAILED: {action_id} not staged.")
            return False

        logging.warning(f"[OVERSIGHT] APPROVED: {action_id}. operator={operator_id} Executing now.")
        try:
            req.real_payload()
            return True
        except Exception as exc:
            logging.error(f"[OVERSIGHT] Approved execution failed for {action_id}: {exc}")
            return False

    def shutdown(self) -> None:
        """
        Best-effort cleanup for pending timers (optional).
        """
        with self._lock:
            for _, timer in list(self._pending_actions.items()):
                try:
                    timer.cancel()
                except Exception:
                    pass
            self._pending_actions.clear()
            self._pending_actions.clear()
            self._gated_actions.clear()
            self._recent_dedupe.clear()
            self._corroboration.clear()
            self._budget_target.clear()
            self._budget_source.clear()


# ----------------------------
# Sentinel Nexus (Top-Level Controller)
# ----------------------------

class SentinelNexus:
    def __init__(self, initial_mode: OpMode = OpMode.SHADOW, *, source_id: str = "sensor.local") -> None:
        self._mode = initial_mode
        self._source_id = _safe_str(source_id, max_len=_MAX_SOURCE_LEN)
        self.oversight = OversightEngine(self.get_mode)

        logging.info(f"[{SYSTEM_ID}] Nexus Online. Operational Mode={self._mode.value} source_id={self._source_id}")

    def set_mode(self, mode: OpMode) -> None:
        self._mode = mode
        logging.warning(f"[{SYSTEM_ID}] Mode switched to {self._mode.value}")

    def get_mode(self) -> OpMode:
        return self._mode

    def handle_threat(
        self,
        *,
        ip_address: str,
        threat_type: str,
        severity: str = "MEDIUM",
        source_id: Optional[str] = None,
    ) -> str:
        """
        Public-safe threat handler:
        - validates target as an IP
        - canonicalizes threat types (prevents unbounded corroboration keys)
        - uses random action_id (not guessable)
        - uses dedupe_key (coarse time bucket + canonical content)
        - budgets per target + per source
        """
        ok, ip = _validate_ip(ip_address)
        if not ok:
            # return a stable-ish token the caller can log without side effects
            token = f"DROP-{uuid.uuid4().hex[:12]}"
            logging.warning(f"[THREAT] Dropped invalid ip_address={_safe_str(ip_address, max_len=120)} token={token}")
            return token

        sev = _normalize_severity(severity)
        ttype = _normalize_threat_type(threat_type)
        src = _safe_str(source_id or self._source_id, max_len=_MAX_SOURCE_LEN)

        # Random action ID: not guessable, not user-controlled
        action_id = f"ACT-{uuid.uuid4().hex}"

        # Dedupe key: prevent repeated triggers for the *same* condition in a short window
        bucket = int(time.time() // 30)
        dedupe_key = f"{ip}|{ttype}|{sev}|{bucket}"

        reason = f"{ttype} detected"
        evidence = _sanitize_evidence(
            {
                "system": SYSTEM_ID,
                "threat_type": ttype,
                "severity": sev,
                "observed_at": int(time.time()),
                "source_id": src,
            }
        )

        req = ActionRequest(
            action_id=action_id,
            dedupe_key=dedupe_key,
            target=ip,
            source=src,
            description=f"Block IP {ip}",
            delay_seconds=5,
            severity=sev,
            reason=_safe_str(reason, max_len=_MAX_REASON_LEN),
            evidence=evidence,
            real_payload=lambda: IntegrationHub.execute_firewall_block(ip, reason=reason, evidence=evidence),
            shadow_payload=lambda: IntegrationHub.log_shadow_action(ip, reason=reason, evidence=evidence),
        )

        logging.info(f"[THREAT] {ttype} detected from {ip} severity={sev} source={src} action_id={action_id}")
        self.oversight.schedule_action(req)
        return action_id