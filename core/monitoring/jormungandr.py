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
Sentinel-43 Jormungandr v2.1 — Cryptographic Security Node

AEAD (AES-256-GCM) encrypted audit storage with:
  - Epoch-based key rotation (HKDF-SHA-256 derived KEKs)
  - DEK-per-record wrapped with the current epoch KEK (RFC 3394)
  - Separate hash-chained audit trails for events and threats
  - Forensic (retain N epochs) / Wartime (forward secrecy) retention modes
  - Redacted console output in VIGILANT / HOSTILE posture

Changes from v2:
  - Fix: thread safety via threading.RLock -- every public method and the
    entire _log → _record → _append call chain are now lock-safe. RLock
    used (not Lock) because internal helpers call each other recursively
    under the same held lock.
  - Fix: event_log and threat_log are now deque(maxlen=...) instead of
    unbounded lists trimmed with del store[:n] (O(n) memory move per
    append at capacity; now O(1)).
  - Fix: separate _last_event_hash and _last_threat_hash so each log can
    be forensically verified independently without requiring the other.
  - Fix: encrypt=False on the Ship of Theseus identity log has been
    corrected to encrypt=True -- old/new UUIDs must not be written in
    plaintext while in HOSTILE posture.
  - Fix: dt.datetime.utcnow() replaced with dt.datetime.now(dt.timezone.utc).
  - Fix: MAX_FIREWALL_LAYERS and log caps moved into JormungandrConfig
    (frozen dataclass, S43_JORM_* env vars, safe parsing with fallback).
  - Fix: CRITICAL/HIGH threats now log at logging.critical/error level.
  - Fix: aes_key_wrap / aes_key_unwrap use explicit keyword arguments.
  - Added: JormungandrConfig.from_env() factory for S43_JORM_* env vars.
  - Added: optional MonitoringManager integration -- HIGH/CRITICAL threats
    also emit SecurityEvent payloads into the S43 monitoring pipeline
    (Watchtower SECURITY_BASELINE tower + SentinelWindowStore).
  - Added: append(payload) method providing a governance.py-compatible
    AuditStore interface so JormungandrNode can replace the plain
    AuditStore in SystemOrchestrator for tamper-resistant audit logging.
"""

from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import secrets
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap

logger = logging.getLogger("SentinelJormungandr")


# =============================================================================
# Constants / enums
# =============================================================================

class Posture:
    CALM     = "CALM"
    VIGILANT = "VIGILANT"
    HOSTILE  = "HOSTILE"


class Mode:
    FORENSIC = "FORENSIC"   # retain N epochs for decryption
    WARTIME  = "WARTIME"    # purge old KEKs aggressively (forward secrecy)


VALID_SEVERITIES: frozenset[str] = frozenset({"Low", "Medium", "High", "Critical"})

_THREAT_SCORE_MAP: dict[str, int] = {
    "Low": 1, "Medium": 5, "High": 15, "Critical": 50,
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
# Configuration (S43 frozen-dataclass pattern)
# =============================================================================

def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        v = int(raw.strip())
        if not lo <= v <= hi:
            raise ValueError(f"out of [{lo},{hi}]")
        return v
    except ValueError:
        logger.warning("Invalid int for %s=%r, using default %s", name, raw, default)
        return default


@dataclass(frozen=True)
class JormungandrConfig:
    """
    Immutable configuration for JormungandrNode.

    Previously: module-level constants (MAX_FIREWALL_LAYERS, BOUNDED_EVENT_LOG,
    etc.) were computed at import time via unguarded int(os.getenv(...)) casts
    that could crash the module on invalid env values.
    """
    mode: str = Mode.FORENSIC
    retain_epochs: int = 8
    max_firewall_layers: int = 74
    event_log_cap: int = 5_000
    threat_log_cap: int = 5_000

    def __post_init__(self) -> None:
        if self.mode not in {Mode.FORENSIC, Mode.WARTIME}:
            raise JormungandrConfigError(
                f"mode must be FORENSIC or WARTIME, got {self.mode!r}"
            )
        if self.retain_epochs < 1:
            raise JormungandrConfigError("retain_epochs must be >= 1")
        if self.max_firewall_layers < 1:
            raise JormungandrConfigError("max_firewall_layers must be >= 1")

    @classmethod
    def from_env(cls) -> "JormungandrConfig":
        """
        Build config from S43_JORM_* environment variables.

        S43_JORM_MODE            -- FORENSIC (default) | WARTIME
        S43_JORM_RETAIN_EPOCHS   -- int, epochs to retain for decryption (default 8)
        S43_JORM_MAX_LAYERS      -- int, max firewall layers (default 74)
        S43_JORM_EVENT_LOG_CAP   -- int, bounded event log size (default 5000)
        S43_JORM_THREAT_LOG_CAP  -- int, bounded threat log size (default 5000)
        """
        raw_mode = _env("S43_JORM_MODE", Mode.FORENSIC).upper()
        if raw_mode not in {Mode.FORENSIC, Mode.WARTIME}:
            logger.warning("Invalid S43_JORM_MODE=%r, using FORENSIC", raw_mode)
            raw_mode = Mode.FORENSIC

        return cls(
            mode=raw_mode,
            retain_epochs=_env_int("S43_JORM_RETAIN_EPOCHS", 8, 1, 100),
            max_firewall_layers=_env_int("S43_JORM_MAX_LAYERS", 74, 1, 1_000),
            event_log_cap=_env_int("S43_JORM_EVENT_LOG_CAP", 5_000, 100, 100_000),
            threat_log_cap=_env_int("S43_JORM_THREAT_LOG_CAP", 5_000, 100, 100_000),
        )


# =============================================================================
# Key management
# =============================================================================

class KeyManager:
    """
    Derives KEKs per epoch from a root key via HKDF-SHA-256.
    Not externally thread-safe -- callers must hold JormungandrNode._lock.
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

        if self.mode == Mode.FORENSIC:
            cutoff = self.epoch - self.retain_epochs
            for e in list(self._kek_by_epoch):
                if e < cutoff:
                    del self._kek_by_epoch[e]
        elif self.mode == Mode.WARTIME:
            for e in list(self._kek_by_epoch):
                if e != self.epoch:
                    del self._kek_by_epoch[e]

        return self.epoch

    def get_kek(self, epoch: int) -> bytes | None:
        return self._kek_by_epoch.get(epoch)


# =============================================================================
# AEAD helpers
# =============================================================================

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def aead_encrypt(payload: bytes, aad: bytes, kek: bytes) -> dict[str, str]:
    """
    Encrypt payload with a random per-record DEK (AES-256-GCM).
    Wrap the DEK with the epoch KEK (AES Key Wrap, RFC 3394).
    Returns a dict with nonce, wrapped DEK, and ciphertext -- all base64.
    """
    dek = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)  # 96-bit nonce per NIST SP 800-38D
    ct = AESGCM(dek).encrypt(nonce, payload, aad)
    # Fix: explicit keyword arguments for clarity across cryptography versions
    wrapped_dek = aes_key_wrap(wrapping_key=kek, key_to_wrap=dek)
    return {
        "nonce": _b64e(nonce),
        "dek":   _b64e(wrapped_dek),
        "ct":    _b64e(ct),
    }


def aead_decrypt(blob: dict[str, str], aad: bytes, kek: bytes) -> bytes:
    """Reverse of aead_encrypt. Raises on any cryptographic failure."""
    nonce       = _b64d(blob["nonce"])
    wrapped_dek = _b64d(blob["dek"])
    ct          = _b64d(blob["ct"])
    # Fix: explicit keyword arguments
    dek = aes_key_unwrap(wrapping_key=kek, wrapped_key=wrapped_dek)
    return AESGCM(dek).decrypt(nonce, ct, aad)


# =============================================================================
# Audit record
# =============================================================================

@dataclasses.dataclass
class AuditRecord:
    timestamp: str
    kind: str           # EVENT | THREAT | STATUS
    severity: str | None
    posture: str
    epoch: int
    payload: dict[str, Any]  # {"plaintext": str} | {"enc": {nonce, dek, ct}}
    prev_hash: str | None
    # node_uuid at time of encryption: required to reconstruct AAD correctly
    # after a Ship of Theseus identity change rotates self.node_uuid.
    node_uuid: str = ""
    event_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# =============================================================================
# JormungandrNode
# =============================================================================

def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _utc_now_str() -> str:
    return _utc_now().isoformat()


class JormungandrNode:
    """
    Cryptographic security node with posture-driven AEAD audit storage.

    Thread-safe: all public methods and the internal logging call chain
    run under a single RLock. RLock (not Lock) is used because internal
    helpers call each other while the lock is already held.

    Optional MonitoringManager integration: when a manager is supplied,
    HIGH and CRITICAL threats also emit SecurityEvent payloads into the
    S43 monitoring pipeline (Watchtower SECURITY_BASELINE + window store).

    AuditStore compatibility: the append(payload) method provides the same
    interface as core.audit.store.AuditStore so JormungandrNode can replace
    it in SystemOrchestrator for tamper-resistant governance audit logging.
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

        # Fix: RLock because internal helpers call each other recursively
        # while the lock is already held (e.g. _log_threat -> _update_posture
        # -> _status_update -> _event -> _record -> _append).
        self._lock = threading.RLock()

        self.node_uuid: uuid.UUID = uuid.uuid4()
        self.security_mode: str = "Normal"  # Normal | Elevated | Lockdown
        self.posture: str = Posture.CALM
        self.threat_score: int = 0
        self.firewall_layer: int = 0
        self.system_status: dict[str, str] = {}

        # Crypto
        self._keymgr = KeyManager(
            root_key=root_key or os.urandom(32),
            mode=self._config.mode,
            retain_epochs=self._config.retain_epochs,
        )
        self._keymgr.rotate()  # start at epoch 1

        # Fix: deque(maxlen=...) replaces List + del store[:n] (O(n) per trim)
        self._event_log: deque[AuditRecord] = deque(maxlen=self._config.event_log_cap)
        self._threat_log: deque[AuditRecord] = deque(maxlen=self._config.threat_log_cap)

        # Fix: separate hash chains so each log is independently verifiable
        self._last_event_hash: str | None = None
        self._last_threat_hash: str | None = None

        self._status_update("Firewall", f"Inactive (Layer 0/{self._config.max_firewall_layers})")
        self._status_update("Posture", self.posture)
        self._event("Jormungandr node initialized; epoch=1", severity=None, encrypt=False)

        logger.info(
            "JormungandrNode started node_uuid=%s mode=%s max_layers=%d",
            self.node_uuid, self._config.mode, self._config.max_firewall_layers,
        )

    # ------------------------------------------------------------------
    # Internal helpers (all called under self._lock)
    # ------------------------------------------------------------------

    def _aad(
        self,
        severity: str | None,
        ts: dt.datetime,
        *,
        node_uuid_str: str | None = None,
        posture: str | None = None,
    ) -> bytes:
        """
        Build AEAD additional-authenticated data from stable per-record context.
        Time is floored to the minute so the AAD is stable even if the
        timestamp string representation varies slightly.

        node_uuid_str and posture override self.node_uuid / self.posture when
        reconstructing AAD for decryption -- both can change during the node
        lifecycle (Ship of Theseus UUID rotation; posture escalation), so
        decryption must use the VALUES STORED ON THE RECORD, not the current
        node state. Using the wrong values here causes AEAD tag verification
        failure and '[DECRYPTION FAILED]' for every affected record.
        """
        base = {
            "node_uuid": node_uuid_str or str(self.node_uuid),
            "posture": posture or self.posture,
            "severity": severity or "",
            "ts_minute": ts.replace(second=0, microsecond=0).isoformat(),
        }
        return json.dumps(base, sort_keys=True).encode()

    def _chain_hash(
        self,
        rec: AuditRecord,
        prev_hash: str | None,
    ) -> str:
        """Compute the hash-chain link for `rec`."""
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

    def _append(self, store: deque[AuditRecord], rec: AuditRecord, chain: str) -> str:
        """
        Append rec to store, returning the updated chain hash.

        Fix: previously both event_log and threat_log shared a single
        _last_event_hash, making independent forensic verification of
        either log impossible. Now each log maintains its own chain.

        Fix: store is now a deque(maxlen=cap) -- O(1) bounded append.
        Previously List + del store[:n-cap] was O(n) at every trim.
        """
        new_hash = self._chain_hash(rec, chain)
        rec.event_hash = new_hash
        store.append(rec)
        return new_hash

    def _console_log(self, kind: str, message: str, severity: str | None) -> None:
        """
        Fix: CRITICAL/HIGH threats now log at logging.critical/error level.
        In VIGILANT/HOSTILE posture, message content is redacted.
        """
        if self.posture == Posture.CALM:
            out = f"[{kind}] {message}"
        else:
            out = f"[{kind}] (redacted; encrypted) epoch={self._keymgr.epoch}"

        # Fix: map severity to appropriate log level
        if severity == "Critical":
            logger.critical(out)
        elif severity == "High":
            logger.error(out)
        elif kind == "THREAT":
            logger.warning(out)
        else:
            logger.info(out)

    def _record(self, kind: str, message: str, severity: str | None, encrypt: bool) -> None:
        """Core record writer. Must be called with self._lock held."""
        ts = _utc_now()
        aad = self._aad(severity, ts)
        epoch = self._keymgr.epoch

        if encrypt and self.posture != Posture.CALM:
            kek = self._keymgr.get_kek(epoch)
            if kek is None:
                logger.error("No KEK available for epoch %d -- storing plaintext", epoch)
                payload: dict[str, Any] = {"plaintext": message, "encryption_failed": True}
            else:
                try:
                    payload = {"enc": aead_encrypt(message.encode(), aad, kek)}
                except Exception as exc:
                    logger.error("AEAD encrypt failed epoch=%d: %s", epoch, exc)
                    payload = {"plaintext": message, "encryption_failed": True}
        else:
            payload = {"plaintext": message}

        rec = AuditRecord(
            timestamp=ts.isoformat(),
            kind=kind,
            severity=severity,
            posture=self.posture,
            epoch=epoch,
            payload=payload,
            prev_hash=None,  # filled in by _append
            node_uuid=str(self.node_uuid),  # capture for AAD reconstruction
        )

        if kind == "THREAT":
            self._last_threat_hash = self._append(
                self._threat_log, rec, self._last_threat_hash
            )
        else:
            self._last_event_hash = self._append(
                self._event_log, rec, self._last_event_hash
            )

        self._console_log(kind, message, severity)

    def _event(self, message: str, severity: str | None, encrypt: bool = True) -> None:
        self._record("EVENT", message, severity, encrypt)

    def _status_update(self, component: str, status: str) -> None:
        old = self.system_status.get(component, "Unknown")
        self.system_status[component] = status
        self._event(
            f"STATUS UPDATE: {component} changed from {old!r} to {status!r}",
            severity=None,
            encrypt=True,
        )

    def _log_threat(self, source: str, description: str, severity: str) -> None:
        if severity not in VALID_SEVERITIES:
            raise JormungandrError(f"Invalid severity: {severity!r}")

        if self.posture == Posture.CALM:
            msg = f"Source: {source} | {description}"
            encrypt = False
        else:
            msg = f"Source: [REDACTED] | {description}"
            encrypt = True

        self._record("THREAT", msg, severity, encrypt)
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

        if old == Posture.CALM and new_posture in (Posture.VIGILANT, Posture.HOSTILE):
            self._keymgr.rotate()
            self._event(
                f"Key epoch rotated to {self._keymgr.epoch} (posture escalation)",
                severity=None, encrypt=False,
            )
        elif old == Posture.VIGILANT and new_posture == Posture.HOSTILE:
            self._keymgr.rotate()
            self._event(
                f"Key epoch rotated to {self._keymgr.epoch} (HOSTILE entry)",
                severity=None, encrypt=False,
            )
            self._switch_security_mode("Lockdown")

    def _switch_security_mode(self, mode: str) -> None:
        """Internal mode switch -- must be called with _lock held."""
        valid = {"Normal", "Elevated", "Lockdown"}
        if mode not in valid:
            raise JormungandrConfigError(f"Invalid security mode: {mode!r}")
        if self.security_mode == mode:
            return
        old = self.security_mode
        self.security_mode = mode
        if mode in ("Elevated", "Lockdown"):
            self._keymgr.rotate()
            self._event(
                f"Key epoch rotated to {self._keymgr.epoch} (mode change to {mode})",
                severity=None, encrypt=False,
            )
        self._event(f"Security mode changed from {old!r} to {mode!r}", severity=None, encrypt=True)

    def _notify_monitoring(self, severity: str, source: str, description: str) -> None:
        """
        Route HIGH/CRITICAL threats to the S43 monitoring pipeline.
        Runs on a daemon thread so it never blocks the audit path.
        Best-effort: any exception is logged and swallowed.
        """
        if self._monitoring_manager is None:
            return
        if severity not in {"High", "Critical"}:
            return

        event: dict[str, Any] = {
            "kind": "security",
            "secrets_exposed": severity == "Critical",
            "privilege_escalation": severity == "Critical",
            "unsigned_artifact": False,
            "debug_mode_enabled": False,
            "auth_failure": False,
            "jormungandr_severity": severity,
            "jormungandr_posture": self.posture,
            "source": "JormungandrNode",
            "event_category": "jormungandr_threat",
        }

        try:
            import threading as _t
            _t.Thread(
                target=self._monitoring_manager.analyze_event,
                args=(event,),
                daemon=True,
            ).start()
        except Exception as exc:
            logger.debug("JormungandrNode: MonitoringManager notification failed: %s", exc)

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

                # Fix: was encrypt=False -- identity data must be encrypted in HOSTILE posture
                self._event(
                    f"SHIP OF THESEUS: Identity metamorphosed. "
                    f"OLD: {old_id} NEW: {self.node_uuid}",
                    severity=None,
                    encrypt=True,
                )

        # Notify monitoring pipeline outside the lock (daemon thread)
        self._notify_monitoring(severity, source, description)

    def append(self, payload: dict[str, Any]) -> None:
        """
        AuditStore-compatible interface for governance.py's SystemOrchestrator.

        Allows JormungandrNode to replace core.audit.store.AuditStore as the
        tamper-resistant audit backend. The payload dict (from governance.py's
        _best_effort_audit) is JSON-serialised and stored as an encrypted
        EVENT record.
        """
        try:
            message = json.dumps(payload, sort_keys=True, default=str)
        except (TypeError, ValueError) as exc:
            logger.warning("JormungandrNode.append: payload serialization failed: %s", exc)
            message = repr(payload)

        with self._lock:
            self._event(message, severity=None, encrypt=True)

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "node_uuid": str(self.node_uuid),
                "security_mode": self.security_mode,
                "posture": self.posture,
                "threat_score": self.threat_score,
                "firewall_layer": f"{self.firewall_layer}/{self._config.max_firewall_layers}",
                "epoch": self._keymgr.epoch,
                "mode": self._config.mode,
                "total_events_logged": len(self._event_log),
                "total_threats_logged": len(self._threat_log),
                "last_event_hash": self._last_event_hash,
                "last_threat_hash": self._last_threat_hash,
                "timestamp": _utc_now_str(),
            }

    def _decrypt_payload(self, rec: AuditRecord) -> str:
        """Decrypt a single record. Must be called with self._lock held."""
        p = rec.payload
        if "plaintext" in p:
            return p["plaintext"]
        enc = p.get("enc")
        if not enc:
            return "[MALFORMED RECORD]"
        kek = self._keymgr.get_kek(rec.epoch)
        if not kek:
            return f"[KEY RETIRED epoch={rec.epoch}]"
        try:
            ts = dt.datetime.fromisoformat(rec.timestamp)
            # Use stored node_uuid and posture to reconstruct the AAD exactly
            # as it was at encryption time (both can change during lifecycle).
            aad = self._aad(
                rec.severity, ts,
                node_uuid_str=rec.node_uuid or str(self.node_uuid),
                posture=rec.posture,
            )
            return aead_decrypt(enc, aad, kek).decode()
        except Exception as exc:
            logger.debug("Decryption failed epoch=%d: %s", rec.epoch, exc)
            return f"[DECRYPTION FAILED epoch={rec.epoch}]"

    def get_decrypted_logs(self) -> dict[str, Any]:
        """
        Return human-readable decrypted copies of both logs for forensic review.
        Access to this method should be restricted to authorized operators.
        """
        with self._lock:
            events = [
                {
                    "timestamp": r.timestamp,
                    "kind": r.kind,
                    "severity": r.severity,
                    "posture": r.posture,
                    "epoch": r.epoch,
                    "message": self._decrypt_payload(r),
                    "event_hash": r.event_hash,
                }
                for r in self._event_log
            ]
            threats = [
                {
                    "timestamp": r.timestamp,
                    "kind": r.kind,
                    "severity": r.severity,
                    "posture": r.posture,
                    "epoch": r.epoch,
                    "message": self._decrypt_payload(r),
                    "event_hash": r.event_hash,
                }
                for r in self._threat_log
            ]
            return {
                "events": events,
                "threats": threats,
                "system_status": dict(self.system_status),
                "summary": self.get_summary(),
            }

    def verify_chain(self, log: str = "events") -> dict[str, Any]:
        """
        Walk a log's hash chain and verify every link.
        Returns a dict with 'valid', 'length', and 'first_broken_index'.
        """
        with self._lock:
            store = list(self._event_log if log == "events" else self._threat_log)

        prev = None
        for i, rec in enumerate(store):
            expected = self._chain_hash_readonly(rec, prev)
            if rec.event_hash != expected:
                return {
                    "valid": False,
                    "log": log,
                    "length": len(store),
                    "first_broken_index": i,
                    "timestamp": _utc_now_str(),
                }
            prev = rec.event_hash

        return {
            "valid": True,
            "log": log,
            "length": len(store),
            "first_broken_index": None,
            "timestamp": _utc_now_str(),
        }

    def _chain_hash_readonly(self, rec: AuditRecord, prev_hash: str | None) -> str:
        """Recompute the chain hash for verification (no side effects)."""
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


# =============================================================================
# Factory
# =============================================================================

def build_jormungandr(
    *,
    root_key: bytes | None = None,
    monitoring_manager: Any | None = None,
) -> JormungandrNode:
    """
    Build a JormungandrNode from environment configuration.
    In production, supply root_key from KMS/HSM.
    """
    config = JormungandrConfig.from_env()
    node = JormungandrNode(
        config=config,
        root_key=root_key,
        monitoring_manager=monitoring_manager,
    )
    return node


# =============================================================================
# Entry point / demo
# =============================================================================

if __name__ == "__main__":
    import os as _os

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    print("--- INITIALIZING JORMUNGANDR v2.1 ---")
    node = JormungandrNode(JormungandrConfig(mode=Mode.FORENSIC, retain_epochs=6))
    print(json.dumps(node.get_summary(), indent=2))

    print("\n--- SIMULATING LOW/MED THREATS ---")
    node.log_threat_and_react("192.168.1.10", "ICMP Ping Sweep", "Low")
    node.advance_firewall()
    node.log_threat_and_react("192.168.1.15", "UDP Port Scan", "Medium")
    node.advance_firewall()
    print(json.dumps(node.get_summary(), indent=2))

    print("\n--- CRITICAL THREAT & THESEUS ---")
    node.log_threat_and_react("10.20.30.40", "Suspected Rootkit Injection Attempt", "Critical")
    node.advance_firewall()
    print(json.dumps(node.get_summary(), indent=2))

    print("\n--- CHAIN VERIFICATION ---")
    print("Events:", json.dumps(node.verify_chain("events"), indent=2))
    print("Threats:", json.dumps(node.verify_chain("threats"), indent=2))

    print("\n--- DECRYPTED LOGS ---")
    logs = node.get_decrypted_logs()
    for rec in logs["events"]:
        print(f"[EVENT]  {rec['timestamp']} | {rec['posture']} | ep{rec['epoch']} | {rec['message']}")
    for rec in logs["threats"]:
        print(f"[THREAT] {rec['timestamp']} | {rec['severity']} | {rec['posture']} | ep{rec['epoch']} | {rec['message']}")
