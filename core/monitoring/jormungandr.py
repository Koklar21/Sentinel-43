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

"""Jormungandr encrypted append-only audit mirror.

Jormungandr is a cryptographic storage component, not a governance engine.

Responsibilities:
    - encrypt audit payloads with per-record DEKs using AES-256-GCM
    - wrap DEKs with epoch KEKs
    - derive KEKs from a caller-supplied root key
    - maintain bounded tamper-evident hash chains
    - support explicit key rotation and bounded key retention
    - verify retained chain integrity
    - decrypt retained records when the relevant KEK is available

Non-responsibilities:
    - no firewall control
    - no posture escalation
    - no threat scoring
    - no autonomous countermeasures
    - no Watchtower/MonitoringManager calls
    - no environment reads
    - no background threads
    - no process identity mutation
    - no authoritative audit ownership

The canonical authoritative audit store remains outside this module.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import secrets
import threading
import uuid
from collections import deque
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import (
    aes_key_unwrap,
    aes_key_wrap,
)


class JormungandrError(Exception):
    """Base exception for Jormungandr failures."""


class JormungandrConfigError(JormungandrError):
    """Invalid Jormungandr configuration."""


class JormungandrCryptoError(JormungandrError):
    """Cryptographic operation failed."""


class RetentionMode(StrEnum):
    FORENSIC = "FORENSIC"
    MINIMAL = "MINIMAL"


_MIN_ROOT_KEY_BYTES: Final[int] = 32
_MIN_MAX_PAYLOAD_BYTES: Final[int] = 1024
_MAX_MAX_PAYLOAD_BYTES: Final[int] = 10 * 1024 * 1024
_MAX_RETAIN_EPOCHS: Final[int] = 1000
_MAX_RECORD_CAPACITY: Final[int] = 1_000_000


def _utc_now() -> dt.datetime:
    return dt.datetime.now(
        dt.timezone.utc
    )


def _b64e(
    value: bytes,
) -> str:
    return base64.b64encode(
        value
    ).decode(
        "ascii"
    )


def _b64d(
    value: str,
) -> bytes:
    try:
        return base64.b64decode(
            value.encode(
                "ascii"
            ),
            validate=True,
        )
    except Exception as exc:
        raise JormungandrCryptoError(
            "invalid base64 ciphertext field"
        ) from exc


def _canonical_json_bytes(
    value: Any,
) -> bytes:
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(
                ",",
                ":",
            ),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (
        TypeError,
        ValueError,
    ) as exc:
        raise JormungandrConfigError(
            "payload is not JSON serializable"
        ) from exc

    try:
        return text.encode(
            "utf-8"
        )
    except UnicodeEncodeError as exc:
        raise JormungandrConfigError(
            "payload contains invalid Unicode"
        ) from exc


@dataclass(frozen=True, slots=True)
class JormungandrConfig:
    mode: RetentionMode = RetentionMode.FORENSIC
    retain_epochs: int = 8
    record_capacity: int = 5000
    max_append_payload_bytes: int = 262_144

    def __post_init__(self) -> None:
        if not isinstance(
            self.mode,
            RetentionMode,
        ):
            raise JormungandrConfigError(
                "mode must be a RetentionMode"
            )

        if not 1 <= self.retain_epochs <= _MAX_RETAIN_EPOCHS:
            raise JormungandrConfigError(
                f"retain_epochs must be between 1 and {_MAX_RETAIN_EPOCHS}"
            )

        if not 1 <= self.record_capacity <= _MAX_RECORD_CAPACITY:
            raise JormungandrConfigError(
                f"record_capacity must be between 1 and {_MAX_RECORD_CAPACITY}"
            )

        if not (
            _MIN_MAX_PAYLOAD_BYTES
            <= self.max_append_payload_bytes
            <= _MAX_MAX_PAYLOAD_BYTES
        ):
            raise JormungandrConfigError(
                "max_append_payload_bytes is outside the supported range"
            )


@dataclass(frozen=True, slots=True)
class EncryptedBlob:
    nonce_b64: str
    wrapped_dek_b64: str
    ciphertext_b64: str

    def to_dict(
        self,
    ) -> dict[str, str]:
        return {
            "nonce": self.nonce_b64,
            "dek": self.wrapped_dek_b64,
            "ct": self.ciphertext_b64,
        }


@dataclass(frozen=True, slots=True)
class AuditRecord:
    record_id: str
    timestamp: str
    epoch: int
    payload: EncryptedBlob
    prev_hash: str | None
    record_hash: str

    def to_dict(
        self,
    ) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "epoch": self.epoch,
            "payload": self.payload.to_dict(),
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
        }


class KeyManager:
    """Derive and retain epoch KEKs from one caller-supplied root key."""

    def __init__(
        self,
        *,
        root_key: bytes,
        mode: RetentionMode,
        retain_epochs: int,
    ) -> None:
        if not isinstance(
            root_key,
            bytes,
        ):
            raise TypeError(
                "root_key must be bytes"
            )

        if len(
            root_key
        ) < _MIN_ROOT_KEY_BYTES:
            raise JormungandrConfigError(
                "root_key must be at least 32 bytes"
            )

        self._root_key = root_key
        self._mode = mode
        self._retain_epochs = retain_epochs
        self._epoch = 0
        self._keks: dict[
            int,
            bytes,
        ] = {}

    @property
    def epoch(
        self,
    ) -> int:
        return self._epoch

    def _derive_kek(
        self,
        epoch: int,
    ) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=(
                f"sentinel43:jormungandr:kek:{epoch}"
            ).encode(
                "ascii"
            ),
        )

        return hkdf.derive(
            self._root_key
        )

    def rotate(
        self,
    ) -> int:
        self._epoch += 1

        self._keks[
            self._epoch
        ] = self._derive_kek(
            self._epoch
        )

        self._purge()

        return self._epoch

    def _purge(
        self,
    ) -> None:
        if self._mode is RetentionMode.MINIMAL:
            keep = {
                self._epoch
            }

        else:
            first_epoch = max(
                1,
                self._epoch
                - self._retain_epochs
                + 1,
            )

            keep = set(
                range(
                    first_epoch,
                    self._epoch + 1,
                )
            )

        for epoch in tuple(
            self._keks
        ):
            if epoch not in keep:
                self._keks.pop(
                    epoch,
                    None,
                )

    def get(
        self,
        epoch: int,
    ) -> bytes | None:
        return self._keks.get(
            epoch
        )

    def retained_epochs(
        self,
    ) -> tuple[int, ...]:
        return tuple(
            sorted(
                self._keks
            )
        )


def _encrypt(
    *,
    plaintext: bytes,
    aad: bytes,
    kek: bytes,
) -> EncryptedBlob:
    dek = secrets.token_bytes(
        32
    )

    nonce = secrets.token_bytes(
        12
    )

    try:
        ciphertext = AESGCM(
            dek
        ).encrypt(
            nonce,
            plaintext,
            aad,
        )

        wrapped_dek = aes_key_wrap(
            wrapping_key=kek,
            key_to_wrap=dek,
        )

    except Exception as exc:
        raise JormungandrCryptoError(
            "AEAD encryption failed"
        ) from exc

    return EncryptedBlob(
        nonce_b64=_b64e(
            nonce
        ),
        wrapped_dek_b64=_b64e(
            wrapped_dek
        ),
        ciphertext_b64=_b64e(
            ciphertext
        ),
    )


def _decrypt(
    *,
    blob: EncryptedBlob,
    aad: bytes,
    kek: bytes,
) -> bytes:
    try:
        dek = aes_key_unwrap(
            wrapping_key=kek,
            wrapped_key=_b64d(
                blob.wrapped_dek_b64
            ),
        )

        return AESGCM(
            dek
        ).decrypt(
            _b64d(
                blob.nonce_b64
            ),
            _b64d(
                blob.ciphertext_b64
            ),
            aad,
        )

    except JormungandrCryptoError:
        raise

    except Exception as exc:
        raise JormungandrCryptoError(
            "AEAD decryption failed"
        ) from exc


class JormungandrNode:
    """Bounded encrypted audit mirror with a tamper-evident retained chain."""

    def __init__(
        self,
        *,
        root_key: bytes,
        config: JormungandrConfig | None = None,
    ) -> None:
        self._config = (
            config
            or JormungandrConfig()
        )

        self._lock = threading.RLock()

        self._node_id = str(
            uuid.uuid4()
        )

        self._keys = KeyManager(
            root_key=root_key,
            mode=self._config.mode,
            retain_epochs=self._config.retain_epochs,
        )

        self._keys.rotate()

        self._records: deque[
            AuditRecord
        ] = deque(
            maxlen=self._config.record_capacity
        )

        self._last_hash: str | None = None

    @property
    def node_id(
        self,
    ) -> str:
        return self._node_id

    @property
    def epoch(
        self,
    ) -> int:
        with self._lock:
            return self._keys.epoch

    def rotate_key_epoch(
        self,
    ) -> int:
        with self._lock:
            return self._keys.rotate()

    @staticmethod
    def _aad(
        *,
        node_id: str,
        record_id: str,
        timestamp: str,
        epoch: int,
    ) -> bytes:
        return _canonical_json_bytes(
            {
                "node_id": node_id,
                "record_id": record_id,
                "timestamp": timestamp,
                "epoch": epoch,
            }
        )

    @staticmethod
    def _record_hash(
        *,
        record_id: str,
        timestamp: str,
        epoch: int,
        payload: EncryptedBlob,
        prev_hash: str | None,
    ) -> str:
        material = _canonical_json_bytes(
            {
                "record_id": record_id,
                "timestamp": timestamp,
                "epoch": epoch,
                "payload": payload.to_dict(),
                "prev_hash": prev_hash,
            }
        )

        return hashlib.sha256(
            material
        ).hexdigest()

    def append(
        self,
        payload: dict[str, Any],
    ) -> str:
        plaintext = _canonical_json_bytes(
            payload
        )

        if len(
            plaintext
        ) > self._config.max_append_payload_bytes:
            raise JormungandrConfigError(
                "append payload exceeds configured maximum"
            )

        with self._lock:
            epoch = self._keys.epoch

            kek = self._keys.get(
                epoch
            )

            if kek is None:
                raise JormungandrCryptoError(
                    "current KEK is unavailable"
                )

            record_id = str(
                uuid.uuid4()
            )

            timestamp = _utc_now().isoformat()

            aad = self._aad(
                node_id=self._node_id,
                record_id=record_id,
                timestamp=timestamp,
                epoch=epoch,
            )

            encrypted = _encrypt(
                plaintext=plaintext,
                aad=aad,
                kek=kek,
            )

            record_hash = self._record_hash(
                record_id=record_id,
                timestamp=timestamp,
                epoch=epoch,
                payload=encrypted,
                prev_hash=self._last_hash,
            )

            record = AuditRecord(
                record_id=record_id,
                timestamp=timestamp,
                epoch=epoch,
                payload=encrypted,
                prev_hash=self._last_hash,
                record_hash=record_hash,
            )

            self._records.append(
                record
            )

            self._last_hash = record_hash

            return record_id

    def verify_chain(
        self,
    ) -> dict[str, Any]:
        with self._lock:
            records = tuple(
                self._records
            )

        if not records:
            return {
                "valid": True,
                "length": 0,
                "first_broken_index": None,
            }

        previous = records[
            0
        ].prev_hash

        for index, record in enumerate(
            records
        ):
            expected = self._record_hash(
                record_id=record.record_id,
                timestamp=record.timestamp,
                epoch=record.epoch,
                payload=record.payload,
                prev_hash=previous,
            )

            if expected != record.record_hash:
                return {
                    "valid": False,
                    "length": len(
                        records
                    ),
                    "first_broken_index": index,
                }

            previous = record.record_hash

        return {
            "valid": True,
            "length": len(
                records
            ),
            "first_broken_index": None,
        }

    def decrypt_record(
        self,
        record_id: str,
    ) -> dict[str, Any]:
        normalized_id = str(
            record_id
        ).strip()

        if not normalized_id:
            raise ValueError(
                "record_id must not be empty"
            )

        with self._lock:
            record = next(
                (
                    item
                    for item in self._records
                    if item.record_id
                    == normalized_id
                ),
                None,
            )

            if record is None:
                raise KeyError(
                    f"record {normalized_id!r} is not retained"
                )

            kek = self._keys.get(
                record.epoch
            )

            if kek is None:
                raise JormungandrCryptoError(
                    f"KEK for epoch {record.epoch} is not retained"
                )

            aad = self._aad(
                node_id=self._node_id,
                record_id=record.record_id,
                timestamp=record.timestamp,
                epoch=record.epoch,
            )

            plaintext = _decrypt(
                blob=record.payload,
                aad=aad,
                kek=kek,
            )

        try:
            decoded = json.loads(
                plaintext.decode(
                    "utf-8"
                )
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise JormungandrCryptoError(
                "decrypted payload is not valid JSON"
            ) from exc

        if not isinstance(
            decoded,
            dict,
        ):
            raise JormungandrCryptoError(
                "decrypted payload is not an object"
            )

        return decoded

    def retained_records(
        self,
    ) -> tuple[
        AuditRecord,
        ...
    ]:
        with self._lock:
            return tuple(
                self._records
            )

    def summary(
        self,
    ) -> dict[str, Any]:
        with self._lock:
            return {
                "node_id": self._node_id,
                "epoch": self._keys.epoch,
                "retained_key_epochs": self._keys.retained_epochs(),
                "mode": self._config.mode.value,
                "retained_records": len(
                    self._records
                ),
                "record_capacity": self._config.record_capacity,
                "last_record_hash": self._last_hash,
            }


__all__ = [
    "AuditRecord",
    "EncryptedBlob",
    "JormungandrConfig",
    "JormungandrConfigError",
    "JormungandrCryptoError",
    "JormungandrError",
    "JormungandrNode",
    "KeyManager",
    "RetentionMode",
]
