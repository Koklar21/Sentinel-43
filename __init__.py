"""
s34_auth.py — Sentinel-43 Authorization & Key Control
=====================================================

SECURITY-CRITICAL FILE — REPO APPROVAL RULES
--------------------------------------------
This file is part of Sentinel-43's trust perimeter. Any modification
to this file or its execution path is SECURITY-SENSITIVE and subject
to strict review.

REQUIRED CONDITIONS FOR APPROVAL
--------------------------------
- No behavioral changes without explicit maintainer approval.
- 24-hour activation delay is mandatory (NOT-BEFORE gate).
- No plaintext secret persistence (no storing/logging/caching tokens).
- Crypto guarantees are non-negotiable (salt + pepper + PBKDF2, constant-time compare).
- No bypass paths (no debug flags, no env overrides that skip enforcement).
- Scope enforcement must remain explicit (least-privilege; no implicit grants).
- Auditability must be preserved (time gates, revocation, scope decisions).
- No dependency inflation without justification and approval.
- No architectural bleed: keep auth isolated from transport/business logic.
- No license contamination: added code must comply with project licensing model.
- Performance discipline: no expensive behavior without a scaling plan.

AUTO-REJECT CONDITIONS
----------------------
- Hardcoded secrets/keys/credentials
- Obfuscated logic or hidden behavior
- Weakening cryptographic or timing guarantees
- Altering activation timing without approval
- Large refactors without a reviewed plan

This file is an enforcement boundary. Treat it accordingly.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Sequence


logger = logging.getLogger("sentinel43.auth")

_SCOPE_RE = re.compile(r"^[a-z0-9:_\-.]{1,96}$")
_TOKEN_BODY_RE = re.compile(r"^[A-Za-z0-9\-_]{32,}$")


@dataclass(frozen=True)
class AuthKeyConfig:
    """
    Configuration for AuthKeyStore.

    Defaults are intentionally conservative. The 24-hour activation delay is
    part of the trust model and should not be reduced without explicit review.
    """

    activation_delay_seconds: int = 24 * 60 * 60
    default_expires_in_seconds: int = 7 * 24 * 60 * 60

    pepper_env_var: str = "S43_AUTH_PEPPER"

    hash_alg: str = "sha256"
    hash_iters: int = 210_000
    salt_bytes: int = 16

    token_prefix: str = "S43K"
    token_bytes: int = 32

    max_metadata_bytes: int = 8192
    sqlite_timeout_seconds: float = 5.0
    sqlite_busy_timeout_ms: int = 5000

    min_purge_safety_seconds: int = 3600

    def __post_init__(self) -> None:
        if self.activation_delay_seconds < 24 * 60 * 60:
            raise ValueError("activation_delay_seconds must be at least 24 hours")
        if self.default_expires_in_seconds <= 0:
            raise ValueError("default_expires_in_seconds must be > 0")
        if self.hash_iters < 210_000:
            raise ValueError("hash_iters must be >= 210000")
        if self.salt_bytes < 16:
            raise ValueError("salt_bytes must be >= 16")
        if self.token_bytes < 32:
            raise ValueError("token_bytes must be >= 32")
        if self.max_metadata_bytes <= 0:
            raise ValueError("max_metadata_bytes must be > 0")
        if self.sqlite_timeout_seconds <= 0:
            raise ValueError("sqlite_timeout_seconds must be > 0")
        if self.sqlite_busy_timeout_ms <= 0:
            raise ValueError("sqlite_busy_timeout_ms must be > 0")
        if self.min_purge_safety_seconds < 3600:
            raise ValueError("min_purge_safety_seconds must be >= 3600")
        if not self.token_prefix or "_" in self.token_prefix:
            raise ValueError("token_prefix must be non-empty and must not contain '_'")


class AuthKeyStore:
    """
    SQLite-backed authorization key store with delayed activation.

    Security model:
    - plaintext token is returned only once
    - token itself is never stored
    - lookup uses a non-secret SHA256 fingerprint
    - verification still requires salted + peppered PBKDF2
    - comparison uses constant-time compare
    - keys support scopes, expiry, delayed activation, and revocation

    Migration note:
    Rows created before token_fingerprint existed cannot be verified by the
    fingerprint lookup path because the plaintext token was never stored. Reissue
    those keys instead of trying to backfill impossible data. Irritating, yes.
    Correct, also yes.
    """

    def __init__(self, db_path: str, config: AuthKeyConfig | None = None) -> None:
        if not db_path:
            raise ValueError("db_path must not be empty")

        self.db_path = db_path
        self.cfg = config or AuthKeyConfig()
        self._pepper_bytes = self._load_pepper()
        self._ensure_schema()

    def issue_key(
        self,
        subject: str,
        scopes: Sequence[str],
        issued_by: str,
        *,
        expires_in_seconds: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Create a new key and return the plaintext token exactly once.

        The token is never stored. Caller is responsible for secure delivery.
        """

        subject = self._validate_label("subject", subject)
        issued_by = self._validate_label("issued_by", issued_by)
        normalized_scopes = self._normalize_scopes(scopes)
        metadata_json = self._safe_json_metadata(metadata or {})

        now = int(time.time())
        not_before = now + int(self.cfg.activation_delay_seconds)

        exp_in = int(
            expires_in_seconds
            if expires_in_seconds is not None
            else self.cfg.default_expires_in_seconds
        )
        expires_at = now + exp_in if exp_in > 0 else None

        token = self._generate_token()
        token_fingerprint = self._fingerprint_token(token)

        salt = secrets.token_bytes(self.cfg.salt_bytes)
        key_hash = self._hash_token(token=token, salt=salt)

        with self._conn() as cx:
            cur = cx.execute(
                """
                INSERT INTO auth_keys (
                    subject,
                    scopes_json,
                    issued_by,
                    issued_at,
                    not_before,
                    expires_at,
                    revoked_at,
                    revoked_by,
                    metadata_json,
                    token_fingerprint,
                    salt_b64,
                    hash_b64
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    subject,
                    json.dumps(normalized_scopes, separators=(",", ":")),
                    issued_by,
                    now,
                    not_before,
                    expires_at,
                    None,
                    None,
                    metadata_json,
                    token_fingerprint,
                    base64.b64encode(salt).decode("ascii"),
                    base64.b64encode(key_hash).decode("ascii"),
                ),
            )
            key_id = cur.lastrowid

        logger.info(
            "Issued auth key id=%s subject=%s issued_by=%s scopes=%s not_before=%s expires_at=%s",
            key_id,
            subject,
            issued_by,
            normalized_scopes,
            not_before,
            expires_at,
        )

        return token

    def verify_key(
        self,
        token: str,
        *,
        required_scopes: Sequence[str] | None = None,
        now: int | None = None,
    ) -> bool:
        """
        Verify token, activation gate, expiry, revocation, and scope subset.
        """

        if not self._looks_like_token(token):
            logger.warning("Rejected malformed auth token")
            return False

        now_ts = int(now if now is not None else time.time())
        required = set(self._normalize_scopes(required_scopes or []))
        fingerprint = self._fingerprint_token(token)

        with self._conn() as cx:
            rows = cx.execute(
                """
                SELECT id, subject, scopes_json, salt_b64, hash_b64
                FROM auth_keys
                WHERE token_fingerprint = ?
                  AND revoked_at IS NULL
                  AND not_before <= ?
                  AND (expires_at IS NULL OR expires_at > ?)
                """,
                (fingerprint, now_ts, now_ts),
            ).fetchall()

        for row in rows:
            try:
                salt = base64.b64decode(row["salt_b64"].encode("ascii"), validate=True)
                expected = base64.b64decode(row["hash_b64"].encode("ascii"), validate=True)
            except Exception:
                logger.warning("Skipped malformed auth key row id=%s during verification", row["id"])
                continue

            actual = self._hash_token(token=token, salt=salt)

            if not hmac.compare_digest(expected, actual):
                continue

            try:
                scopes = set(json.loads(row["scopes_json"] or "[]"))
            except Exception:
                logger.warning("Auth key matched but scopes_json was malformed id=%s", row["id"])
                scopes = set()

            if required and not required.issubset(scopes):
                logger.warning(
                    "Auth key matched but lacked required scopes id=%s subject=%s required=%s",
                    row["id"],
                    row["subject"],
                    sorted(required),
                )
                continue

            return True

        logger.warning("Auth key verification failed")
        return False

    def revoke_key(
        self,
        token: str,
        revoked_by: str,
        *,
        now: int | None = None,
    ) -> bool:
        """
        Revoke a key by token.

        Returns True only if an unrevoked matching row was updated.
        """

        if not self._looks_like_token(token):
            logger.warning("Rejected malformed auth token during revoke")
            return False

        revoked_by = self._validate_label("revoked_by", revoked_by)
        now_ts = int(now if now is not None else time.time())
        fingerprint = self._fingerprint_token(token)

        cx = self._conn()
        try:
            cx.execute("BEGIN IMMEDIATE")

            rows = cx.execute(
                """
                SELECT id, subject, salt_b64, hash_b64
                FROM auth_keys
                WHERE token_fingerprint = ?
                  AND revoked_at IS NULL
                """,
                (fingerprint,),
            ).fetchall()

            for row in rows:
                try:
                    salt = base64.b64decode(row["salt_b64"].encode("ascii"), validate=True)
                    expected = base64.b64decode(row["hash_b64"].encode("ascii"), validate=True)
                except Exception:
                    logger.warning("Skipped malformed auth key row id=%s during revoke", row["id"])
                    continue

                actual = self._hash_token(token=token, salt=salt)

                if hmac.compare_digest(expected, actual):
                    cur = cx.execute(
                        """
                        UPDATE auth_keys
                        SET revoked_at = ?, revoked_by = ?
                        WHERE id = ? AND revoked_at IS NULL
                        """,
                        (now_ts, revoked_by, row["id"]),
                    )

                    cx.execute("COMMIT")
                    revoked = int(cur.rowcount or 0) > 0

                    if revoked:
                        logger.info(
                            "Revoked auth key id=%s subject=%s revoked_by=%s",
                            row["id"],
                            row["subject"],
                            revoked_by,
                        )

                    return revoked

            cx.execute("ROLLBACK")
            logger.warning("Auth key revoke failed: key not found")
            return False

        except Exception:
            cx.execute("ROLLBACK")
            raise
        finally:
            cx.close()

    def list_keys(self) -> list[dict[str, Any]]:
        """
        List keys without exposing tokens, salts, hashes, or fingerprints.
        """

        with self._conn() as cx:
            rows = cx.execute(
                """
                SELECT
                    id,
                    subject,
                    scopes_json,
                    issued_by,
                    issued_at,
                    not_before,
                    expires_at,
                    revoked_at,
                    revoked_by,
                    metadata_json
                FROM auth_keys
                ORDER BY id DESC
                """
            ).fetchall()

        results: list[dict[str, Any]] = []

        for row in rows:
            try:
                scopes = json.loads(row["scopes_json"] or "[]")
            except Exception:
                scopes = []

            try:
                metadata = json.loads(row["metadata_json"] or "{}")
            except Exception:
                metadata = {}

            results.append(
                {
                    "id": row["id"],
                    "subject": row["subject"],
                    "scopes": scopes,
                    "issued_by": row["issued_by"],
                    "issued_at": row["issued_at"],
                    "not_before": row["not_before"],
                    "expires_at": row["expires_at"],
                    "revoked_at": row["revoked_at"],
                    "revoked_by": row["revoked_by"],
                    "metadata": metadata,
                }
            )

        return results

    def purge_inactive(
        self,
        *,
        older_than_seconds: int,
        now: int | None = None,
    ) -> int:
        """
        Delete expired or revoked keys older than the retention window.
        """

        if older_than_seconds < self.cfg.min_purge_safety_seconds:
            raise ValueError(
                "older_than_seconds must be >= "
                f"{self.cfg.min_purge_safety_seconds}"
            )

        now_ts = int(now if now is not None else time.time())
        cutoff = now_ts - int(older_than_seconds)

        with self._conn() as cx:
            cur = cx.execute(
                """
                DELETE FROM auth_keys
                WHERE
                    (expires_at IS NOT NULL AND expires_at < ?)
                    OR
                    (revoked_at IS NOT NULL AND revoked_at < ?)
                """,
                (cutoff, cutoff),
            )
            deleted = int(cur.rowcount or 0)

        logger.info("Purged inactive auth keys count=%s cutoff=%s", deleted, cutoff)
        return deleted

    def _generate_token(self) -> str:
        raw = secrets.token_bytes(self.cfg.token_bytes)
        b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        return f"{self.cfg.token_prefix}_{b64}"

    def _looks_like_token(self, token: str) -> bool:
        if not isinstance(token, str):
            return False

        prefix = f"{self.cfg.token_prefix}_"

        if not token.startswith(prefix):
            return False

        body = token[len(prefix) :]
        return bool(_TOKEN_BODY_RE.fullmatch(body))

    def _fingerprint_token(self, token: str) -> str:
        """
        Non-secret lookup fingerprint.

        This is not proof of authenticity. It only narrows the DB scan.
        PBKDF2 verification remains authoritative.
        """

        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _load_pepper(self) -> bytes:
        pepper = os.environ.get(self.cfg.pepper_env_var, "").strip()

        if not pepper:
            raise RuntimeError(
                f"{self.cfg.pepper_env_var} is required and not set. "
                "Configure it in your secrets manager before running."
            )

        return pepper.encode("utf-8")

    def _hash_token(self, token: str, salt: bytes) -> bytes:
        material = token.encode("utf-8") + b"|" + self._pepper_bytes

        return hashlib.pbkdf2_hmac(
            self.cfg.hash_alg,
            material,
            salt,
            self.cfg.hash_iters,
            dklen=32,
        )

    def _normalize_scopes(self, scopes: Sequence[str]) -> list[str]:
        normalized: set[str] = set()

        for scope in scopes:
            if not isinstance(scope, str):
                raise TypeError(
                    f"scope values must be str, got {type(scope).__name__}"
                )

            value = scope.strip().lower()

            if not _SCOPE_RE.fullmatch(value):
                raise ValueError(f"invalid scope value: {scope!r}")

            normalized.add(value)

        return sorted(normalized)

    def _validate_label(self, name: str, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError(f"{name} must be str, got {type(value).__name__}")

        cleaned = value.strip()

        if not cleaned:
            raise ValueError(f"{name} must not be empty")

        if len(cleaned) > 256:
            raise ValueError(f"{name} must be <= 256 characters")

        return cleaned

    def _safe_json_metadata(self, metadata: dict[str, Any]) -> str:
        try:
            encoded = json.dumps(
                metadata,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("metadata must be JSON-serializable") from exc

        size = len(encoded.encode("utf-8"))

        if size > self.cfg.max_metadata_bytes:
            raise ValueError(
                f"metadata too large: {size} bytes > "
                f"{self.cfg.max_metadata_bytes} bytes"
            )

        return encoded

    def _conn(self) -> sqlite3.Connection:
        cx = sqlite3.connect(
            self.db_path,
            timeout=float(self.cfg.sqlite_timeout_seconds),
        )
        cx.row_factory = sqlite3.Row
        cx.execute("PRAGMA foreign_keys = ON;")
        cx.execute("PRAGMA journal_mode = WAL;")
        cx.execute("PRAGMA synchronous = FULL;")
        cx.execute(f"PRAGMA busy_timeout = {int(self.cfg.sqlite_busy_timeout_ms)};")
        return cx

    def _ensure_schema(self) -> None:
        with self._conn() as cx:
            cx.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_keys (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject           TEXT    NOT NULL,
                    scopes_json       TEXT    NOT NULL,
                    issued_by         TEXT    NOT NULL,

                    issued_at         INTEGER NOT NULL,
                    not_before        INTEGER NOT NULL,
                    expires_at        INTEGER NULL,

                    revoked_at        INTEGER NULL,
                    revoked_by        TEXT    NULL,

                    metadata_json     TEXT    NOT NULL,

                    token_fingerprint TEXT    NULL,
                    salt_b64          TEXT    NOT NULL,
                    hash_b64          TEXT    NOT NULL
                );
                """
            )

            existing_cols = {
                row["name"]
                for row in cx.execute("PRAGMA table_info(auth_keys)").fetchall()
            }

            if "token_fingerprint" not in existing_cols:
                cx.execute(
                    "ALTER TABLE auth_keys "
                    "ADD COLUMN token_fingerprint TEXT NULL"
                )

            cx.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_auth_keys_fingerprint
                ON auth_keys(token_fingerprint);
                """
            )
            cx.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_auth_keys_subject
                ON auth_keys(subject);
                """
            )
            cx.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_auth_keys_revoked
                ON auth_keys(revoked_at);
                """
            )
            cx.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_auth_keys_not_before
                ON auth_keys(not_before);
                """
            )
            cx.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_auth_keys_expires
                ON auth_keys(expires_at);
                """
            )


__all__ = [
    "AuthKeyConfig",
    "AuthKeyStore",
]
