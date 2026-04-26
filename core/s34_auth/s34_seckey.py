# =============================================================================
# Sentinel-43 Security Platform
# =============================================================================
#
# Copyright (c) 2026 Justin. All rights reserved.
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
#
# Classification: INTERNAL
#
# Component: Identity Core
# File: s34_auth.py
#
# Description:
# Sentinel-43 Authorization & Key Control
#
# =============================================================================

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import warnings
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Optional, Sequence


@dataclass(frozen=True)
class AuthKeyConfig:
    activation_delay_seconds: int = 24 * 60 * 60
    default_expires_in_seconds: int = 7 * 24 * 60 * 60

    pepper_env_var: str = "S43_AUTH_PEPPER"

    hash_alg: str = "sha256"
    hash_iters: int = 210_000
    salt_bytes: int = 16

    token_prefix: str = "S43K"
    token_bytes: int = 32

    sqlite_timeout_seconds: float = 15.0
    max_verify_candidates: int = 500
    schema_version: int = 1


class AuthKeyStore:
    def __init__(self, db_path: str, config: Optional[AuthKeyConfig] = None) -> None:
        self.db_path = db_path
        self.cfg = config or AuthKeyConfig()
        self._ensure_schema()

    def issue_key(
        self,
        subject: str,
        scopes: Sequence[str],
        issued_by: str,
        *,
        expires_in_seconds: Optional[int] = None,
        metadata: Optional[dict] = None,
    ) -> str:
        now = int(time.time())
        not_before = now + int(self.cfg.activation_delay_seconds)

        if expires_in_seconds is None:
            exp_in = int(self.cfg.default_expires_in_seconds)
        else:
            exp_in = int(expires_in_seconds)

        expires_at = now + exp_in if exp_in > 0 else None

        token = self._generate_token()
        salt = secrets.token_bytes(self.cfg.salt_bytes)
        key_hash = self._hash_token(token=token, salt=salt)

        with self._conn() as cx:
            cx.execute(
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
                    salt_b64,
                    hash_b64
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    subject,
                    json.dumps(sorted(set(scopes))),
                    issued_by,
                    now,
                    not_before,
                    expires_at,
                    None,
                    None,
                    json.dumps(metadata or {}),
                    base64.b64encode(salt).decode("ascii"),
                    base64.b64encode(key_hash).decode("ascii"),
                ),
            )

        return token

    def verify_key(
        self,
        token: str,
        *,
        required_scopes: Optional[Sequence[str]] = None,
        now: Optional[int] = None,
    ) -> bool:
        now_ts = int(now if now is not None else time.time())
        required = set(required_scopes or [])

        if not isinstance(token, str):
            return False

        if not token.startswith(f"{self.cfg.token_prefix}_"):
            return False

        if len(token) < 20:
            return False

        with self._conn() as cx:
            rows = cx.execute(
                """
                SELECT
                    id,
                    scopes_json,
                    salt_b64,
                    hash_b64
                FROM auth_keys
                WHERE revoked_at IS NULL
                  AND not_before <= ?
                  AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY id DESC
                LIMIT ?
                """,
                (now_ts, now_ts, int(self.cfg.max_verify_candidates)),
            ).fetchall()

        for _key_id, scopes_json, salt_b64, hash_b64 in rows:
            try:
                salt = base64.b64decode(salt_b64.encode("ascii"))
                expected_hash = base64.b64decode(hash_b64.encode("ascii"))
            except Exception:
                continue

            actual_hash = self._hash_token(token=token, salt=salt)

            if not hmac.compare_digest(expected_hash, actual_hash):
                continue

            try:
                scopes = set(json.loads(scopes_json or "[]"))
            except Exception:
                return False

            if required and not required.issubset(scopes):
                return False

            return True

        return False

    def revoke_key(
        self,
        token: str,
        revoked_by: str,
        *,
        now: Optional[int] = None,
    ) -> bool:
        now_ts = int(now if now is not None else time.time())

        if not isinstance(token, str):
            return False

        with self._conn() as cx:
            rows = cx.execute(
                """
                SELECT
                    id,
                    salt_b64,
                    hash_b64
                FROM auth_keys
                WHERE revoked_at IS NULL
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(self.cfg.max_verify_candidates),),
            ).fetchall()

            for key_id, salt_b64, hash_b64 in rows:
                try:
                    salt = base64.b64decode(salt_b64.encode("ascii"))
                    expected_hash = base64.b64decode(hash_b64.encode("ascii"))
                except Exception:
                    continue

                actual_hash = self._hash_token(token=token, salt=salt)

                if hmac.compare_digest(expected_hash, actual_hash):
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

    def list_keys(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        safe_limit = max(1, min(int(limit), 500))
        safe_offset = max(0, int(offset))

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
                LIMIT ? OFFSET ?
                """,
                (safe_limit, safe_offset),
            ).fetchall()

        out: list[dict] = []

        for row in rows:
            out.append(
                {
                    "id": row[0],
                    "subject": row[1],
                    "scopes": self._safe_json_list(row[2]),
                    "issued_by": row[3],
                    "issued_at": row[4],
                    "not_before": row[5],
                    "expires_at": row[6],
                    "revoked_at": row[7],
                    "revoked_by": row[8],
                    "metadata": self._safe_json_dict(row[9]),
                }
            )

        return out

    def _generate_token(self) -> str:
        raw = secrets.token_bytes(self.cfg.token_bytes)
        b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        return f"{self.cfg.token_prefix}_{b64}"

    def _pepper(self) -> bytes:
        pepper = os.environ.get(self.cfg.pepper_env_var, "")

        if pepper:
            return pepper.encode("utf-8")

        env = os.environ.get("S43_ENV", "").lower().strip()

        if env in {"production", "prod"}:
            raise RuntimeError(
                f"Missing required production secret: {self.cfg.pepper_env_var}"
            )

        warnings.warn(
            f"{self.cfg.pepper_env_var} is not set. Using development-only pepper.",
            RuntimeWarning,
            stacklevel=2,
        )

        return b"DEV_ONLY__SET_S43_AUTH_PEPPER"

    def _hash_token(self, token: str, salt: bytes) -> bytes:
        material = token.encode("utf-8") + b"|" + self._pepper()

        return hashlib.pbkdf2_hmac(
            self.cfg.hash_alg,
            material,
            salt,
            self.cfg.hash_iters,
            dklen=32,
        )

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        cx = sqlite3.connect(
            self.db_path,
            timeout=float(self.cfg.sqlite_timeout_seconds),
        )

        try:
            cx.execute("PRAGMA foreign_keys = ON;")
            cx.execute("PRAGMA journal_mode = WAL;")
            cx.execute("PRAGMA synchronous = NORMAL;")
            yield cx
            cx.commit()
        except Exception:
            cx.rollback()
            raise
        finally:
            cx.close()

    def _ensure_schema(self) -> None:
        with self._conn() as cx:
            cx.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

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

            cx.execute(
                """
                INSERT INTO schema_meta (key, value)
                VALUES ('auth_schema_version', ?)
                ON CONFLICT(key) DO NOTHING
                """,
                (str(self.cfg.schema_version),),
            )

            cx.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_auth_keys_subject
                ON auth_keys(subject);
                """
            )

            cx.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_auth_keys_active_window
                ON auth_keys(revoked_at, not_before, expires_at);
                """
            )

            cx.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_auth_keys_issued_at
                ON auth_keys(issued_at);
                """
            )

    @staticmethod
    def _safe_json_list(value: str) -> list:
        try:
            parsed = json.loads(value or "[]")
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []

    @staticmethod
    def _safe_json_dict(value: str) -> dict:
        try:
            parsed = json.loads(value or "{}")
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}