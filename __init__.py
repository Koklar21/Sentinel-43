"""
s34_auth.py — Sentinel-43 Authorization & Key Control
=====================================================

SECURITY-CRITICAL FILE — REPO APPROVAL RULES
--------------------------------------------
This file is part of Sentinel-43’s trust perimeter. Any modification
to this file or its execution path is SECURITY-SENSITIVE and subject
to strict review.

REQUIRED CONDITIONS FOR APPROVAL
--------------------------------
• No behavioral changes without explicit maintainer approval.
• 24-hour activation delay is mandatory (NOT-BEFORE gate).
• No plaintext secret persistence (no storing/logging/caching tokens).
• Crypto guarantees are non-negotiable (salt + pepper + PBKDF2, constant-time compare).
• No bypass paths (no debug flags, no env overrides that skip enforcement).
• Scope enforcement must remain explicit (least-privilege; no implicit grants).
• Auditability must be preserved (time gates, revocation, scope decisions).
• No dependency inflation without justification and approval.
• No architectural bleed: keep auth isolated from transport/business logic.
• No license contamination: added code must comply with project licensing model.
• Performance discipline: no expensive behavior without a scaling plan.

AUTO-REJECT CONDITIONS
----------------------
• Hardcoded secrets/keys/credentials
• Obfuscated logic or hidden behavior
• Weakening cryptographic or timing guarantees
• Altering activation timing without approval
• Large refactors without a reviewed plan

This file is an enforcement boundary. Treat it accordingly.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Optional, Sequence


# ---------------------------
# Config
# ---------------------------

@dataclass(frozen=True)
class AuthKeyConfig:
    # Hard requirement: 24-hour activation delay
    activation_delay_seconds: int = 24 * 60 * 60

    # Default expiry if not specified (7 days)
    default_expires_in_seconds: int = 7 * 24 * 60 * 60

    # Pepper env var (REQUIRED in production)
    pepper_env_var: str = "S43_AUTH_PEPPER"

    # PBKDF2 settings
    hash_alg: str = "sha256"
    hash_iters: int = 210_000
    salt_bytes: int = 16

    # Token format
    token_prefix: str = "S43K"
    token_bytes: int = 32


# ---------------------------
# Store
# ---------------------------

class AuthKeyStore:
    """
    SQLite-backed authorization key store with delayed activation.

    Design:
    - stores only salted+peppered PBKDF2 hash
    - one-time plaintext token return on issuance
    - constant-time compare for verification
    - supports scopes, expiry, and revocation

    NOTE (scaling):
    verify_key() scans rows because we do not store plaintext or a lookup fingerprint.
    Fine for early use. For large deployments, add a token fingerprint column.
    """

    def __init__(self, db_path: str, config: Optional[AuthKeyConfig] = None) -> None:
        self.db_path = db_path
        self.cfg = config or AuthKeyConfig()
        self._ensure_schema()

    # ---------- Public API ----------

    def issue_key(
        self,
        subject: str,
        scopes: Sequence[str],
        issued_by: str,
        *,
        expires_in_seconds: Optional[int] = None,
        metadata: Optional[dict] = None,
    ) -> str:
        """
        Creates a new key and returns plaintext token ONE TIME.
        """
        now = int(time.time())
        not_before = now + int(self.cfg.activation_delay_seconds)

        exp_in = int(expires_in_seconds or self.cfg.default_expires_in_seconds)
        expires_at = (now + exp_in) if exp_in > 0 else None

        token = self._generate_token()
        salt = secrets.token_bytes(self.cfg.salt_bytes)
        key_hash = self._hash_token(token=token, salt=salt)

        record = (
            subject,
            json.dumps(sorted(set(scopes))),
            issued_by,
            now,
            not_before,
            expires_at,
            None,          # revoked_at
            None,          # revoked_by
            json.dumps(metadata or {}),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(key_hash).decode("ascii"),
        )

        with self._conn() as cx:
            cx.execute(
                """
                INSERT INTO auth_keys (
                    subject, scopes_json, issued_by,
                    issued_at, not_before, expires_at,
                    revoked_at, revoked_by,
                    metadata_json, salt_b64, hash_b64
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                record,
            )

        return token

    def verify_key(
        self,
        token: str,
        *,
        required_scopes: Optional[Sequence[str]] = None,
        now: Optional[int] = None,
    ) -> bool:
        """
        Verifies:
        - token matches stored hash (constant-time compare)
        - not_before gate (24h delay)
        - expires_at gate
        - not revoked
        - scope subset match (if required_scopes set)
        """
        now_ts = int(now or time.time())
        required = set(required_scopes or [])

        if not isinstance(token, str) or len(token) < 20:
            return False

        with self._conn() as cx:
            rows = cx.execute(
                """
                SELECT
                    scopes_json, not_before, expires_at, revoked_at,
                    salt_b64, hash_b64
                FROM auth_keys
                """
            ).fetchall()

        for scopes_json, not_before, expires_at, revoked_at, salt_b64, hash_b64 in rows:
            # Cheap gates first
            if revoked_at is not None:
                continue
            if not_before is not None and now_ts < int(not_before):
                continue
            if expires_at is not None and now_ts > int(expires_at):
                continue

            try:
                salt = base64.b64decode(salt_b64.encode("ascii"))
                expected = base64.b64decode(hash_b64.encode("ascii"))
            except Exception:
                continue

            actual = self._hash_token(token=token, salt=salt)
            if hmac.compare_digest(expected, actual):
                try:
                    scopes = set(json.loads(scopes_json or "[]"))
                except Exception:
                    scopes = set()

                if required and not required.issubset(scopes):
                    return False
                return True

        return False

    def revoke_key(self, token: str, revoked_by: str, *, now: Optional[int] = None) -> bool:
        """
        Revokes a key by matching its token.
        Returns True if revoked, False if not found.
        """
        now_ts = int(now or time.time())

        with self._conn() as cx:
            rows = cx.execute(
                """
                SELECT id, salt_b64, hash_b64
                FROM auth_keys
                WHERE revoked_at IS NULL
                """
            ).fetchall()

            for key_id, salt_b64, hash_b64 in rows:
                try:
                    salt = base64.b64decode(salt_b64.encode("ascii"))
                    expected = base64.b64decode(hash_b64.encode("ascii"))
                except Exception:
                    continue

                actual = self._hash_token(token=token, salt=salt)
                if hmac.compare_digest(expected, actual):
                    cx.execute(
                        """
                        UPDATE auth_keys
                        SET revoked_at = ?, revoked_by = ?
                        WHERE id = ?
                        """,
                        (now_ts, revoked_by, key_id),
                    )
                    return True

        return False

    def list_keys(self) -> list[dict]:
        """
        Lists keys WITHOUT revealing token.
        """
        with self._conn() as cx:
            rows = cx.execute(
                """
                SELECT
                    id, subject, scopes_json, issued_by,
                    issued_at, not_before, expires_at,
                    revoked_at, revoked_by, metadata_json
                FROM auth_keys
                ORDER BY id DESC
                """
            ).fetchall()

        out: list[dict] = []
        for r in rows:
            out.append(
                {
                    "id": r[0],
                    "subject": r[1],
                    "scopes": json.loads(r[2] or "[]"),
                    "issued_by": r[3],
                    "issued_at": r[4],
                    "not_before": r[5],
                    "expires_at": r[6],
                    "revoked_at": r[7],
                    "revoked_by": r[8],
                    "metadata": json.loads(r[9] or "{}"),
                }
            )
        return out

    # ---------- Internals ----------

    def _generate_token(self) -> str:
        raw = secrets.token_bytes(self.cfg.token_bytes)
        b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        return f"{self.cfg.token_prefix}_{b64}"

    def _pepper(self) -> bytes:
        pep = os.environ.get(self.cfg.pepper_env_var, "")
        if not pep:
            # Still functions, but you should NOT ship this into real prod.
            logging.getLogger(__name__).warning(
                "[SECURITY] S43_AUTH_PEPPER not set. Using DEV fallback pepper. "
                "Set S43_AUTH_PEPPER in env/secrets manager for production."
            )
            pep = "DEV_ONLY__SET_S43_AUTH_PEPPER"
        return pep.encode("utf-8")

    def _hash_token(self, token: str, salt: bytes) -> bytes:
        material = token.encode("utf-8") + b"|" + self._pepper()
        return hashlib.pbkdf2_hmac(
            self.cfg.hash_alg,
            material,
            salt,
            self.cfg.hash_iters,
            dklen=32,
        )

    def _conn(self) -> sqlite3.Connection:
        cx = sqlite3.connect(self.db_path)
        cx.execute("PRAGMA foreign_keys = ON;")
        cx.execute("PRAGMA journal_mode = WAL;")
        cx.execute("PRAGMA synchronous = NORMAL;")
        return cx

    def _ensure_schema(self) -> None:
        with self._conn() as cx:
            cx.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    issued_by TEXT NOT NULL,

                    issued_at INTEGER NOT NULL,
                    not_before INTEGER NOT NULL,
                    expires_at INTEGER NULL,

                    revoked_at INTEGER NULL,
                    revoked_by TEXT NULL,

                    metadata_json TEXT NOT NULL,

                    salt_b64 TEXT NOT NULL,
                    hash_b64 TEXT NOT NULL
                );
                """
            )
            cx.execute("CREATE INDEX IF NOT EXISTS idx_auth_keys_subject ON auth_keys(subject);")
            cx.execute("CREATE INDEX IF NOT EXISTS idx_auth_keys_revoked ON auth_keys(revoked_at);")
            cx.execute("CREATE INDEX IF NOT EXISTS idx_auth_keys_not_before ON auth_keys(not_before);")
            cx.execute("CREATE INDEX IF NOT EXISTS idx_auth_keys_expires ON auth_keys(expires_at);")