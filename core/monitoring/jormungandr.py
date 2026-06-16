# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
#
# Sentinel-43 is distributed under a dual-license model:
#
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
#
# Unauthorized copying, redistribution, relicensing, reverse engineering,
# or commercial exploitation outside the terms of the applicable license
# is strictly prohibited.
#
# By accessing, modifying, distributing, or using this software, you agree
# to comply with the terms of the applicable license.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
#
# Commercial Licensing:
# Contact the copyright holder for commercial licensing terms.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

"""
Sentinel-43 Jormungandr v2.3 — Cryptographic Security Node

AEAD encrypted audit storage with:

  - AES-256-GCM record encryption.
  - Per-record DEKs wrapped by epoch KEKs with AES Key Wrap.
  - HKDF-SHA-256 epoch KEK derivation.
  - Separate hash-chained audit trails for events and threats.
  - FORENSIC retention mode for retained historical KEKs.
  - WARTIME retention mode for aggressive KEK cache purging.
  - Redacted console output in VIGILANT / HOSTILE posture.
  - Bounded logs via deque(maxlen=...).
  - Bounded MonitoringManager queue with one persistent worker thread.
  - Strict historical AAD identity during decryption.
  - AuditStore-compatible append(payload) interface.

Notes on key hygiene:

  - Old epoch KEKs are removed from the in-process KEK cache according to mode.
  - Python cannot guarantee secure memory zeroization of byte strings.
  - For strong production forward secrecy, provide root_key from KMS/HSM or an
    external key service rather than leaving long-lived root material in process.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
import os
import queue
import secrets
import threading
import uuid
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

logger = logging.getLogger("SentinelJormungandr")


# =============================================================================
# Constants / enums
# =============================================================================

class Posture:
    CALM = "CALM"
    VIGILANT = "VIGILANT"
    HOSTILE = "HOSTILE"


class Mode:
    FORENSIC = "FORENSIC"  # retain N epochs for decryption
    WARTIME = "WARTIME"    # purge old KEKs aggressively from cache


VALID_SEVERITIES: frozenset[str] = frozenset({"Low", "Medium", "High", "Critical"})

_THREAT_SCORE_MAP: dict[str, int] = {
    "Low": 1,
    "Medium": 5,
    "High": 15,
    "Critical": 50,
}


# =============================================================================
# Exceptions
# =============================================================================

class JormungandrError(Exception):
    """Base exception for Jormungandr-specific errors."""


class JormungandrCryptoError(JormungandrError):
    """Raised when a cryptographic operation fails unrecoverably."""


class JormungandrConfigError(JormungandrError):
    """Raised for invalid configuration."""


# =============================================================================
# Environment helpers
# =============================================================================

def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        value = int(raw.strip())
        if not lo <= value <= hi:
            raise ValueError(f"out of [{lo},{hi}]")
        return value
    except ValueError:
        logger.warning("Invalid int for %s=%r, using default %s", name, raw, default)
        return default


# =============================================================================
# Configuration
# =============================================================================

@dataclass(frozen=True)
class JormungandrConfig:
    """
    Immutable configuration for JormungandrNode.

    Environment variables:
      S43_JORM_MODE                  FORENSIC | WARTIME
      S43_JORM_RETAIN_EPOCHS         retained KEK epochs in FORENSIC mode
      S43_JORM_MAX_LAYERS            max firewall layer counter
      S43_JORM_EVENT_LOG_CAP         bounded event log size
      S43_JORM_THREAT_LOG_CAP        bounded threat log size
      S43_JORM_MAX_APPEND_BYTES      max serialized append(payload) bytes
      S43_JORM_MONITORING_QUEUE_SIZE bounded monitoring queue capacity
    """

    mode: str = Mode.FORENSIC
    retain_epochs: int = 8
    max_firewall_layers: int = 74
    event_log_cap: int = 5_000
    threat_log_cap: int = 5_000
    max_append_payload_bytes: int = 262_144
    monitoring_queue_size: int = 1_000

    def __post_init__(self) -> None:
        if self.mode not in {Mode.FORENSIC, Mode.WARTIME}:
            raise JormungandrConfigError(
                f"mode must be FORENSIC or WARTIME, got {self.mode!r}"
            )
        if self.retain_epochs < 1:
            raise JormungandrConfigError("retain_epochs must be >= 1")
        if self.max_firewall_layers < 1:
            raise JormungandrConfigError("max_firewall_layers must be >= 1")
        if self.event_log_cap < 1:
            raise JormungandrConfigError("event_log_cap must be >= 1")
        if self.threat_log_cap < 1:
            raise JormungandrConfigError("threat_log_cap must be >= 1")
        if self.max_append_payload_bytes < 1:
            raise JormungandrConfigError("max_append_payload_bytes must be >= 1")
        if self.monitoring_queue_size < 1:
            raise JormungandrConfigError("monitoring_queue_size must be >= 1")

    @classmethod
    def from_env(cls) -> "JormungandrConfig":
        raw_mode = _env("S43_JORM_MODE", Mode.FORENSIC).upper()
        if raw_mode not in {Mode.FORENSIC, Mode.WARTIME}:
            logger.warning("Invalid S43_JORM_MODE=%r, using FORENSIC", raw_mode)
            raw_mode = Mode.FORENSIC

        return cls(
            mode=raw_mode,
            retain_epochs=_env_int("S43_JORM_RETAIN_EPOCHS", 8, 1, 100),
            max_firewall_layers=_env_int("S43_JORM_MAX_LAYERS", 74, 1, 1_000),
            event_log_cap=_env_int("S43_JORM_EVENT_LOG_CAP", 5_000, 1, 100_000),
            threat_log_cap=_env_int("S43_JORM_THREAT_LOG_CAP", 5_000, 1, 100_000),
            max_append_payload_bytes=_env_int(
                "S43_JORM_MAX_APPEND_BYTES",
                262_144,
                1_024,
                10 * 1024 * 1024,
            ),
            monitoring_queue_size=_env_int(
                "S43_JORM_MONITORING_QUEUE_SIZE",
                1_000,
                1,
                100_000,
            ),
        )


# =============================================================================
# Key management
# =============================================================================

class KeyManager:
    """
    Derives KEKs per epoch from a root key via HKDF-SHA-256.

    Not externally thread-safe. Callers must hold JormungandrNode._lock.
    """

    def __init__(self, root_key: bytes, mode: str, retain_epochs: int) -> None:
        if len(root_key) < 32:
            raise JormungandrConfigError("root_key must be >= 32 bytes")

        self._root_key = root_key
        self.mode = mode
        self.retain_epochs = retain_epochs
        self.epoch: int = 0
        self._kek_by_epoch: dict[int, bytes] = {}

    def _derive_kek(self, epoch: int) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"jorm-kek-epoch-{epoch}".encode(),
        )
        return hkdf.derive(self._root_key)

    def rotate(self) -> int:
        self.epoch += 1
        self._kek_by_epoch[self.epoch] = self._derive_kek(self.epoch)
        self._purge_old_keks()
        return self.epoch

    def _purge_old_keks(self) -> None:
        if self.mode == Mode.FORENSIC:
            cutoff = self.epoch - self.retain_epochs
            for epoch in list(self._kek_by_epoch):
                if epoch < cutoff:
                    del self._kek_by_epoch[epoch]
        elif self.mode == Mode.WARTIME:
            for epoch in list(self._kek_by_epoch):
                if epoch != self.epoch:
                    del self._kek_by_epoch[epoch]

    def get_kek(self, epoch: int) -> bytes | None:
        return self._kek_by_epoch.get(epoch)

    def retained_epochs(self) -> list[int]:
        return sorted(self._kek_by_epoch)


# =============================================================================
# AEAD helpers
# =============================================================================

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def aead_encrypt(payload: bytes, aad: bytes, kek: bytes) -> dict[str, str]:
    """
    Encrypt payload with a random per-record DEK, then wrap that DEK.
    """
    dek = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(dek).encrypt(nonce, payload, aad)
    wrapped_dek = aes_key_wrap(wrapping_key=kek, key_to_wrap=dek)

    return {
        "nonce": _b64e(nonce),
        "dek": _b64e(wrapped_dek),
        "ct": _b64e(ciphertext),
    }


def aead_decrypt(blob: dict[str, str], aad: bytes, kek: bytes) -> bytes:
    """Reverse of aead_encrypt. Raises on any cryptographic failure."""
    nonce = _b64d(blob["nonce"])
    wrapped_dek = _b64d(blob["dek"])
    ciphertext = _b64d(blob["ct"])
    dek = aes_key_unwrap(wrapping_key=kek, wrapped_key=wrapped_dek)
    return AESGCM(dek).decrypt(nonce, ciphertext, aad)


# =============================================================================
# Audit record
# =============================================================================

@dataclass
class AuditRecord:
    timestamp: str
    kind: str
    severity: str | None
    posture: str
    epoch: int
    payload: dict[str, Any]
    prev_hash: str | None
    node_uuid: str
    event_hash: str | None = None

    def __post_init__(self) -> None:
        if not self.node_uuid:
            raise JormungandrConfigError("AuditRecord.node_uuid must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# =============================================================================
# Time helpers
# =============================================================================

def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _utc_now_str() -> str:
    return _utc_now().isoformat()


# =============================================================================
# JormungandrNode
# =============================================================================

class JormungandrNode:
    """
    Cryptographic security node with posture-driven AEAD audit storage.

    Threading model:
      - Public methods and internal audit mutation use one RLock.
      - Monitoring dispatch uses a bounded queue and one persistent worker.
      - Telemetry drop counters are protected by a small stats lock.
    """

    def __init__(
        self,
        config: JormungandrConfig | None = None,
        *,
        root_key: bytes | None = None,
        monitoring_manager: Any | None = None,
    ) -> None:
        self._config = config or JormungandrConfig()
        self._monitoring_manager = monitoring_manager

        self._lock = threading.RLock()
        self._monitoring_stats_lock = threading.Lock()

        self.node_uuid: uuid.UUID = uuid.uuid4()
        self.security_mode: str = "Normal"
        self.posture: str = Posture.CALM
        self.threat_score: int = 0
        self.firewall_layer: int = 0
        self.system_status: dict[str, str] = {}

        self._keymgr = KeyManager(
            root_key=root_key or os.urandom(32),
            mode=self._config.mode,
            retain_epochs=self._config.retain_epochs,
        )
        self._keymgr.rotate()

        self._event_log: deque[AuditRecord] = deque(maxlen=self._config.event_log_cap)
        self._threat_log: deque[AuditRecord] = deque(maxlen=self._config.threat_log_cap)
        self._last_event_hash: str | None = None
        self._last_threat_hash: str | None = None

        self._monitoring_queue: queue.Queue[dict[str, Any] | None] = queue.Queue(
            maxsize=self._config.monitoring_queue_size
        )
        self._monitoring_stop = threading.Event()
        self._monitoring_worker: threading.Thread | None = None
        self._monitoring_events_reported = 0
        self._monitoring_events_dropped = 0

        if self._monitoring_manager is not None:
            self._start_monitoring_worker()

        with self._lock:
            self._status_update(
                "Firewall",
                f"Inactive (Layer 0/{self._config.max_firewall_layers})",
            )
            self._status_update("Posture", self.posture)
            self._event("Jormungandr node initialized; epoch=1", severity=None, encrypt=False)

        logger.info(
            "JormungandrNode started node_uuid=%s mode=%s max_layers=%d",
            self.node_uuid,
            self._config.mode,
            self._config.max_firewall_layers,
        )

    # ------------------------------------------------------------------
    # Monitoring queue
    # ------------------------------------------------------------------

    def _start_monitoring_worker(self) -> None:
        manager = self._monitoring_manager
        if manager is None:
            return

        if self._monitoring_worker is not None and self._monitoring_worker.is_alive():
            return

        def _worker() -> None:
            while True:
                try:
                    event = self._monitoring_queue.get(timeout=0.5)
                except queue.Empty:
                    if self._monitoring_stop.is_set():
                        break
                    continue

                try:
                    if event is None:
                        break
                    try:
                        manager.analyze_event(event)
                    except Exception as exc:
                        logger.debug(
                            "JormungandrNode: MonitoringManager notification failed: %s",
                            exc,
                        )
                    else:
                        with self._monitoring_stats_lock:
                            self._monitoring_events_reported += 1
                finally:
                    self._monitoring_queue.task_done()

        self._monitoring_worker = threading.Thread(
            target=_worker,
            daemon=True,
            name="s43-jormungandr-monitor",
        )
        self._monitoring_worker.start()

    def _enqueue_monitoring_event(self, event: dict[str, Any]) -> None:
        if self._monitoring_manager is None:
            return

        try:
            self._monitoring_queue.put_nowait(event)
        except queue.Full:
            with self._monitoring_stats_lock:
                self._monitoring_events_dropped += 1
            logger.warning(
                "JormungandrNode: monitoring queue full; dropping telemetry event."
            )

    def _notify_monitoring(self, severity: str, source: str, description: str) -> None:
        if self._monitoring_manager is None:
            return
        if severity not in {"High", "Critical"}:
            return

        with self._lock:
            posture = self.posture
            security_mode = self.security_mode
            node_uuid_str = str(self.node_uuid)
            threat_score = self.threat_score

        event: dict[str, Any] = {
            "kind": "security",
            "secrets_exposed": severity == "Critical",
            "privilege_escalation": severity == "Critical",
            "unsigned_artifact": False,
            "debug_mode_enabled": False,
            "auth_failure": False,
            "jormungandr_severity": severity,
            "jormungandr_posture": posture,
            "jormungandr_security_mode": security_mode,
            "jormungandr_threat_score": threat_score,
            "node_uuid": node_uuid_str,
            "source": "JormungandrNode",
            "event_category": "jormungandr_threat",
            "threat_source": source,
            "description": description,
            "timestamp": _utc_now_str(),
        }

        self._enqueue_monitoring_event(event)

    # ------------------------------------------------------------------
    # Internal helpers. Callers must hold self._lock unless noted.
    # ------------------------------------------------------------------

    @staticmethod
    def _aad(
        severity: str | None,
        ts: dt.datetime,
        *,
        node_uuid_str: str,
        posture: str,
    ) -> bytes:
        """
        Build AEAD additional authenticated data from stable per-record context.

        No live self.node_uuid fallback is allowed here. Historical ciphertext
        must decrypt using the exact identity and posture captured on the record.
        """
        if not node_uuid_str:
            raise JormungandrCryptoError("node_uuid_str is required for AAD")
        if not posture:
            raise JormungandrCryptoError("posture is required for AAD")

        base = {
            "node_uuid": node_uuid_str,
            "posture": posture,
            "severity": severity or "",
            "ts_minute": ts.replace(second=0, microsecond=0).isoformat(),
        }
        return json.dumps(base, sort_keys=True).encode()

    @staticmethod
    def _chain_hash(rec: AuditRecord, prev_hash: str | None) -> str:
        material = json.dumps(
            {
                "timestamp": rec.timestamp,
                "kind": rec.kind,
                "severity": rec.severity,
                "posture": rec.posture,
                "epoch": rec.epoch,
                "payload": rec.payload,
                "prev_hash": prev_hash,
            },
            sort_keys=True,
        ).encode()
        return hashlib.sha256(material).hexdigest()

    def _append(
        self,
        store: deque[AuditRecord],
        rec: AuditRecord,
        prev_hash: str | None,
    ) -> str:
        rec.prev_hash = prev_hash
        new_hash = self._chain_hash(rec, prev_hash)
        rec.event_hash = new_hash
        store.append(rec)
        return new_hash

    def _console_log(self, kind: str, message: str, severity: str | None) -> None:
        if self.posture == Posture.CALM:
            output = f"[{kind}] {message}"
        else:
            output = f"[{kind}] (redacted; encrypted) epoch={self._keymgr.epoch}"

        if severity == "Critical":
            logger.critical(output)
        elif severity == "High":
            logger.error(output)
        elif kind == "THREAT":
            logger.warning(output)
        else:
            logger.info(output)

    def _record(self, kind: str, message: str, severity: str | None, encrypt: bool) -> None:
        ts = _utc_now()
        epoch = self._keymgr.epoch
        record_node_uuid = str(self.node_uuid)
        record_posture = self.posture
        aad = self._aad(
            severity,
            ts,
            node_uuid_str=record_node_uuid,
            posture=record_posture,
        )

        if encrypt and record_posture != Posture.CALM:
            kek = self._keymgr.get_kek(epoch)
            if kek is None:
                logger.error(
                    "No KEK available for epoch %d; storing redacted failure record.",
                    epoch,
                )
                payload: dict[str, Any] = {
                    "plaintext": "[ENCRYPTION FAILED: KEK unavailable; payload redacted]",
                    "encryption_failed": True,
                    "redacted": True,
                }
            else:
                try:
                    payload = {"enc": aead_encrypt(message.encode(), aad, kek)}
                except Exception as exc:
                    logger.error("AEAD encrypt failed epoch=%d: %s", epoch, exc)
                    payload = {
                        "plaintext": "[ENCRYPTION FAILED: AEAD failure; payload redacted]",
                        "encryption_failed": True,
                        "redacted": True,
                    }
        else:
            payload = {"plaintext": message}

        rec = AuditRecord(
            timestamp=ts.isoformat(),
            kind=kind,
            severity=severity,
            posture=record_posture,
            epoch=epoch,
            payload=payload,
            prev_hash=None,
            node_uuid=record_node_uuid,
        )

        if kind == "THREAT":
            self._last_threat_hash = self._append(
                self._threat_log,
                rec,
                self._last_threat_hash,
            )
        else:
            self._last_event_hash = self._append(
                self._event_log,
                rec,
                self._last_event_hash,
            )

        self._console_log(kind, message, severity)

    def _event(self, message: str, severity: str | None, encrypt: bool = True) -> None:
        self._record("EVENT", message, severity, encrypt)

    def _status_update(self, component: str, status_text: str) -> None:
        old = self.system_status.get(component, "Unknown")
        self.system_status[component] = status_text
        self._event(
            f"STATUS UPDATE: {component} changed from {old!r} to {status_text!r}",
            severity=None,
            encrypt=True,
        )

    def _log_threat(self, source: str, description: str, severity: str) -> None:
        if severity not in VALID_SEVERITIES:
            raise JormungandrError(f"Invalid severity: {severity!r}")

        if self.posture == Posture.CALM:
            message = f"Source: {source} | {description}"
            encrypt = False
        else:
            message = "Source: [REDACTED] | " + description
            encrypt = True

        self._record("THREAT", message, severity, encrypt)
        self.threat_score += _THREAT_SCORE_MAP[severity]
        self._update_posture()

    def _update_posture(self) -> None:
        old = self.posture

        if self.threat_score > 40:
            new_posture = Posture.HOSTILE
        elif self.threat_score > 10:
            new_posture = Posture.VIGILANT
        else:
            new_posture = Posture.CALM

        if new_posture == old:
            return

        self.posture = new_posture
        self._status_update("Posture", self.posture)

        if old == Posture.CALM and new_posture in {Posture.VIGILANT, Posture.HOSTILE}:
            self._keymgr.rotate()
            self._event(
                f"Key epoch rotated to {self._keymgr.epoch} (posture escalation)",
                severity=None,
                encrypt=False,
            )
        elif old == Posture.VIGILANT and new_posture == Posture.HOSTILE:
            self._keymgr.rotate()
            self._event(
                f"Key epoch rotated to {self._keymgr.epoch} (HOSTILE entry)",
                severity=None,
                encrypt=False,
            )
            self._switch_security_mode("Lockdown")

    def _switch_security_mode(self, mode: str) -> None:
        valid_modes = {"Normal", "Elevated", "Lockdown"}
        if mode not in valid_modes:
            raise JormungandrConfigError(f"Invalid security mode: {mode!r}")
        if self.security_mode == mode:
            return

        old = self.security_mode
        self.security_mode = mode

        if mode in {"Elevated", "Lockdown"}:
            self._keymgr.rotate()
            self._event(
                f"Key epoch rotated to {self._keymgr.epoch} (mode change to {mode})",
                severity=None,
                encrypt=False,
            )

        self._event(
            f"Security mode changed from {old!r} to {mode!r}",
            severity=None,
            encrypt=True,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def advance_firewall(self) -> None:
        with self._lock:
            if self.firewall_layer >= self._config.max_firewall_layers:
                self._event("Firewall already at maximum layer.", severity=None, encrypt=True)
                return

            self.firewall_layer += 1
            difficulty = round(self.firewall_layer * (1 + self.threat_score / 100), 2)
            self._status_update(
                "Firewall",
                f"Active (Layer {self.firewall_layer}/{self._config.max_firewall_layers}, "
                f"Difficulty: {difficulty})",
            )

    def switch_security_mode(self, mode: str) -> None:
        with self._lock:
            self._switch_security_mode(mode)

    def log_threat_and_react(self, source: str, description: str, severity: str) -> None:
        with self._lock:
            self._log_threat(source, description, severity)

            if severity == "Critical":
                self._event(
                    "CRITICAL THREAT DETECTED. Initiating countermeasures.",
                    severity="Critical",
                    encrypt=False,
                )
                self._switch_security_mode("Lockdown")

                old_id = self.node_uuid
                self.node_uuid = uuid.uuid4()
                self._keymgr.rotate()
                self._event(
                    "SHIP OF THESEUS: Identity metamorphosed. "
                    f"OLD: {old_id} NEW: {self.node_uuid}",
                    severity=None,
                    encrypt=True,
                )

        self._notify_monitoring(severity, source, description)

    def append(self, payload: dict[str, Any]) -> None:
        try:
            message = json.dumps(payload, sort_keys=True, default=str)
        except (TypeError, ValueError) as exc:
            logger.warning("JormungandrNode.append: payload serialization failed: %s", exc)
            message = repr(payload)

        payload_size = len(message.encode("utf-8", errors="ignore"))
        if payload_size > self._config.max_append_payload_bytes:
            raise JormungandrConfigError(
                "append payload exceeds S43_JORM_MAX_APPEND_BYTES "
                f"({self._config.max_append_payload_bytes})"
            )

        with self._lock:
            self._event(message, severity=None, encrypt=True)

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            summary = {
                "node_uuid": str(self.node_uuid),
                "security_mode": self.security_mode,
                "posture": self.posture,
                "threat_score": self.threat_score,
                "firewall_layer": f"{self.firewall_layer}/{self._config.max_firewall_layers}",
                "epoch": self._keymgr.epoch,
                "retained_key_epochs": self._keymgr.retained_epochs(),
                "mode": self._config.mode,
                "total_events_logged": len(self._event_log),
                "total_threats_logged": len(self._threat_log),
                "last_event_hash": self._last_event_hash,
                "last_threat_hash": self._last_threat_hash,
                "timestamp": _utc_now_str(),
            }

        with self._monitoring_stats_lock:
            summary["monitoring_events_reported"] = self._monitoring_events_reported
            summary["monitoring_events_dropped"] = self._monitoring_events_dropped
            summary["monitoring_queue_size"] = self._monitoring_queue.qsize()
            summary["monitoring_queue_capacity"] = self._config.monitoring_queue_size

        return summary

    def _decrypt_payload(self, rec: AuditRecord) -> str:
        payload = rec.payload

        if "plaintext" in payload:
            return payload["plaintext"]

        enc = payload.get("enc")
        if not enc:
            return "[MALFORMED RECORD]"

        if not rec.node_uuid:
            return "[DECRYPTION FAILED: Missing historical node identity in record]"

        kek = self._keymgr.get_kek(rec.epoch)
        if not kek:
            return f"[KEY RETIRED epoch={rec.epoch}]"

        try:
            ts = dt.datetime.fromisoformat(rec.timestamp)
            aad = self._aad(
                rec.severity,
                ts,
                node_uuid_str=rec.node_uuid,
                posture=rec.posture,
            )
            return aead_decrypt(enc, aad, kek).decode()
        except Exception as exc:
            logger.debug("Decryption failed epoch=%d: %s", rec.epoch, exc)
            return f"[DECRYPTION FAILED epoch={rec.epoch}]"

    def get_decrypted_logs(self) -> dict[str, Any]:
        with self._lock:
            events = [
                {
                    "timestamp": record.timestamp,
                    "kind": record.kind,
                    "severity": record.severity,
                    "posture": record.posture,
                    "epoch": record.epoch,
                    "node_uuid": record.node_uuid,
                    "message": self._decrypt_payload(record),
                    "prev_hash": record.prev_hash,
                    "event_hash": record.event_hash,
                }
                for record in self._event_log
            ]
            threats = [
                {
                    "timestamp": record.timestamp,
                    "kind": record.kind,
                    "severity": record.severity,
                    "posture": record.posture,
                    "epoch": record.epoch,
                    "node_uuid": record.node_uuid,
                    "message": self._decrypt_payload(record),
                    "prev_hash": record.prev_hash,
                    "event_hash": record.event_hash,
                }
                for record in self._threat_log
            ]
            status_snapshot = dict(self.system_status)

        return {
            "events": events,
            "threats": threats,
            "system_status": status_snapshot,
            "summary": self.get_summary(),
        }

    def verify_chain(self, log: str = "events", mode: str = "window") -> dict[str, Any]:
        if log not in {"events", "threats"}:
            raise JormungandrConfigError(f"Invalid log name: {log!r}")
        if mode not in {"window", "strict"}:
            raise JormungandrConfigError(f"Invalid verify mode: {mode!r}")

        with self._lock:
            store = list(self._event_log if log == "events" else self._threat_log)

        if not store:
            return {
                "valid": True,
                "log": log,
                "mode": mode,
                "length": 0,
                "first_broken_index": None,
                "timestamp": _utc_now_str(),
            }

        if mode == "strict" and store[0].prev_hash is not None:
            return {
                "valid": False,
                "log": log,
                "mode": mode,
                "length": len(store),
                "first_broken_index": 0,
                "reason": "strict mode requires genesis record; retained window has prior chain anchor",
                "timestamp": _utc_now_str(),
            }

        prev = store[0].prev_hash if mode == "window" else None

        for index, record in enumerate(store):
            expected = self._chain_hash(record, prev)
            if record.event_hash != expected:
                return {
                    "valid": False,
                    "log": log,
                    "mode": mode,
                    "length": len(store),
                    "first_broken_index": index,
                    "timestamp": _utc_now_str(),
                }
            prev = record.event_hash

        return {
            "valid": True,
            "log": log,
            "mode": mode,
            "length": len(store),
            "first_broken_index": None,
            "timestamp": _utc_now_str(),
        }

    def close(self) -> None:
        self._monitoring_stop.set()

        worker = self._monitoring_worker
        if worker is None:
            return

        if worker.is_alive():
            try:
                self._monitoring_queue.put_nowait(None)
            except queue.Full:
                pass
            worker.join(timeout=2.0)

    def __enter__(self) -> "JormungandrNode":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


# =============================================================================
# Factory
# =============================================================================

def build_jormungandr(
    *,
    root_key: bytes | None = None,
    monitoring_manager: Any | None = None,
) -> JormungandrNode:
    config = JormungandrConfig.from_env()
    return JormungandrNode(
        config=config,
        root_key=root_key,
        monitoring_manager=monitoring_manager,
    )


__all__ = [
    "AuditRecord",
    "JormungandrConfig",
    "JormungandrConfigError",
    "JormungandrCryptoError",
    "JormungandrError",
    "JormungandrNode",
    "Mode",
    "Posture",
    "aead_decrypt",
    "aead_encrypt",
    "build_jormungandr",
]


# =============================================================================
# Entry point / demo
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    node = JormungandrNode(JormungandrConfig(mode=Mode.FORENSIC, retain_epochs=6))
    try:
        print("--- INITIALIZING JORMUNGANDR v2.3 ---")
        print(json.dumps(node.get_summary(), indent=2))

        print("\n--- SIMULATING LOW/MED THREATS ---")
        node.log_threat_and_react("192.168.1.10", "ICMP Ping Sweep", "Low")
        node.advance_firewall()
        node.log_threat_and_react("192.168.1.15", "UDP Port Scan", "Medium")
        node.advance_firewall()
        print(json.dumps(node.get_summary(), indent=2))

        print("\n--- CRITICAL THREAT & THESEUS ---")
        node.log_threat_and_react(
            "10.20.30.40",
            "Suspected Rootkit Injection Attempt",
            "Critical",
        )
        node.advance_firewall()
        print(json.dumps(node.get_summary(), indent=2))

        print("\n--- CHAIN VERIFICATION ---")
        print("Events:", json.dumps(node.verify_chain("events"), indent=2))
        print("Threats:", json.dumps(node.verify_chain("threats"), indent=2))
    finally:
        node.close()
