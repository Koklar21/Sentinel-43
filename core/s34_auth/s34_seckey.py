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
from typing import Any, Iterator, Optional, Sequence


__all__ = [
    "AuthKeyConfig",
    "AuthKeyStore",
]

# Environments in which a missing S43_AUTH_PEPPER is tolerated (with a
# warning) by falling back to a hardcoded development-only pepper.
_DEV_ENVIRONMENTS: frozenset[str] = frozenset({
    "development", "dev", "test", "testing", "local",
})

# Fix #1: safe allowlist for PBKDF2 hash algorithms.
# hashlib.pbkdf2_hmac accepts any digest name without complaint, so an
# operator setting hash_alg = "md5" would silently get 128-bit weak hashing.
_SAFE_HASH_ALGORITHMS: frozenset[str] = frozenset({"sha256", "sha512"})

# Fix #2: allowlist for table names used in PRAGMA table_info.
# PRAGMA statements don't support parameter binding, so the table name is
# interpolated directly. Validating against a known-good set prevents
# injection if the pattern is ever extended beyond "auth_keys".
_KNOWN_TABLE_NAMES: frozenset[str] = frozenset({"auth_keys", "schema_meta"})


@dataclass(frozen=True)
class AuthKeyConfig:
    """
    Configuration for Sentinel-43 authorization keys.

    SQLite WAL mode and synchronous=NORMAL provide a practical balance between
    concurrency, durability, and performance. Use synchronous=FULL for maximum
    durability at the cost of write throughput.
    """

    activation_delay_seconds: int   = 24 * 60 * 60
    default_expires_in_seconds: int = 7 * 24 * 60 * 60

    pepper_env_var: str = "S43_AUTH_PEPPER"

    # Fix #1: must be in _SAFE_HASH_ALGORITHMS (sha256 | sha512).
    hash_alg:   str = "sha256"
    hash_iters: int = 210_000
    salt_bytes: int = 16

    token_prefix: str = "S43K"
    token_bytes:  int = 32

    key_hint_chars: int = 8

    min_token_chars:       int = 20
    max_token_chars:       int = 256
    max_subject_bytes:     int = 512
    max_issued_by_bytes:   int = 512
    max_scope_bytes:       int = 256
    max_scopes:            int = 64
    max_metadata_json_bytes: int = 4 * 1024

    sqlite_timeout_seconds: float = 15.0
    max_verify_candidates:  int   = 16
    schema_version:         int   = 2


class AuthKeyStore:
    """
    SQLite-backed authorization key store.

    Security properties:
    - Raw tokens are returned once at issuance and never stored.
    - Stored hashes use PBKDF2-HMAC with a per-key random salt + env pepper.
    - Token lookup uses a short indexed hint before PBKDF2 runs.
    - Verification and revocation use constant-time hash comparison.
    - Legacy schema-v1 keys are revoked on migration (hints unrecoverable).
    - S43_AUTH_PEPPER required outside _DEV_ENVIRONMENTS; fails closed.
    - Text fields reject control characters against log-injection.
    """

    def __init__(
        self,
        db_path: str,
        config: Optional[AuthKeyConfig] = None,
    ) -> None:
        self.db_path = db_path
        self.cfg = config or AuthKeyConfig()
        self._pepper_cache: bytes | None = None   # Fix #3: cached after first resolve
        self._validate_config()
        self._ensure_schema()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def issue_key(
        self,
        subject: str,
        scopes: Sequence[str],
        issued_by: str,
        *,
        expires_in_seconds: Optional[int] = None,
        not_before_offset_seconds: Optional[int] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> str:
        safe_subject   = self._validate_text(name="subject",   value=subject,    max_bytes=self.cfg.max_subject_bytes)
        safe_issued_by = self._validate_text(name="issued_by", value=issued_by,  max_bytes=self.cfg.max_issued_by_bytes)
        safe_scopes    = self._normalize_scopes(scopes)
        metadata_json  = self._serialize_metadata(metadata)

        exp_in         = self._resolve_expiration_seconds(expires_in_seconds)
        not_before_off = self._resolve_not_before_offset_seconds(not_before_offset_seconds)

        now        = int(time.time())
        not_before = now + not_before_off
        expires_at = now + exp_in if exp_in > 0 else None

        token    = self._generate_token()
        key_hint = self._token_hint(token)
        if key_hint is None:
            raise RuntimeError("Generated authorization token is invalid.")

        salt     = secrets.token_bytes(self.cfg.salt_bytes)
        key_hash = self._hash_token(token=token, salt=salt)

        with self._conn() as cx:
            cx.execute(
                """
                INSERT INTO auth_keys (
                    subject, scopes_json, issued_by,
                    issued_at, not_before, expires_at,
                    revoked_at, revoked_by, metadata_json,
                    key_hint, salt_b64, hash_b64
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    safe_subject,
                    json.dumps(safe_scopes, separators=(",", ":")),
                    safe_issued_by,
                    now, not_before, expires_at,
                    None, None, metadata_json,
                    key_hint,
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
        key_hint = self._token_hint(token)
        if key_hint is None:
            return False

        try:
            required = set(self._normalize_scopes(required_scopes or []))
        except (TypeError, ValueError):
            return False

        now_ts = int(now if now is not None else time.time())

        with self._conn() as cx:
            rows = cx.execute(
                """
                SELECT id, scopes_json, salt_b64, hash_b64
                FROM auth_keys
                WHERE key_hint = ?
                  AND revoked_at IS NULL
                  AND not_before <= ?
                  AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY id DESC LIMIT ?
                """,
                (key_hint, now_ts, now_ts, int(self.cfg.max_verify_candidates)),
            ).fetchall()

        for _key_id, scopes_json, salt_b64, hash_b64 in rows:
            decoded = self._decode_hash_material(salt_b64=salt_b64, hash_b64=hash_b64)
            if decoded is None:
                continue
            salt, expected_hash = decoded
            actual_hash = self._hash_token(token=token, salt=salt)
            if not hmac.compare_digest(expected_hash, actual_hash):
                continue
            scopes = set(self._safe_json_list(scopes_json))
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
        key_hint = self._token_hint(token)
        if key_hint is None:
            return False

        try:
            safe_revoked_by = self._validate_text(
                name="revoked_by", value=revoked_by, max_bytes=self.cfg.max_issued_by_bytes
            )
        except (TypeError, ValueError):
            return False

        now_ts = int(now if now is not None else time.time())

        with self._conn() as cx:
            rows = cx.execute(
                """
                SELECT id, salt_b64, hash_b64 FROM auth_keys
                WHERE key_hint = ? AND revoked_at IS NULL
                ORDER BY id DESC LIMIT ?
                """,
                (key_hint, int(self.cfg.max_verify_candidates)),
            ).fetchall()

            for key_id, salt_b64, hash_b64 in rows:
                decoded = self._decode_hash_material(salt_b64=salt_b64, hash_b64=hash_b64)
                if decoded is None:
                    continue
                salt, expected_hash = decoded
                actual_hash = self._hash_token(token=token, salt=salt)
                if not hmac.compare_digest(expected_hash, actual_hash):
                    continue
                cursor = cx.execute(
                    """
                    UPDATE auth_keys SET revoked_at = ?, revoked_by = ?
                    WHERE id = ? AND revoked_at IS NULL
                    """,
                    (now_ts, safe_revoked_by, key_id),
                )
                return cursor.rowcount == 1

        return False

    def list_keys(self, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        safe_limit  = max(1, min(int(limit), 500))
        safe_offset = max(0, int(offset))

        with self._conn() as cx:
            rows = cx.execute(
                """
                SELECT id, subject, scopes_json, issued_by,
                       issued_at, not_before, expires_at,
                       revoked_at, revoked_by, metadata_json, key_hint
                FROM auth_keys ORDER BY id DESC LIMIT ? OFFSET ?
                """,
                (safe_limit, safe_offset),
            ).fetchall()

        return [
            {
                "id": row[0], "subject": row[1],
                "scopes": self._safe_json_list(row[2]),
                "issued_by": row[3], "issued_at": row[4],
                "not_before": row[5], "expires_at": row[6],
                "revoked_at": row[7], "revoked_by": row[8],
                "metadata": self._safe_json_dict(row[9]),
                "key_hint": row[10],
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Token helpers
    # ------------------------------------------------------------------

    def _generate_token(self) -> str:
        raw  = secrets.token_bytes(self.cfg.token_bytes)
        body = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        return f"{self.cfg.token_prefix}_{body}"

    def _token_hint(self, token: object) -> Optional[str]:
        if not isinstance(token, str):
            return None
        if len(token) < int(self.cfg.min_token_chars):
            return None
        if len(token) > int(self.cfg.max_token_chars):
            return None
        expected_prefix = f"{self.cfg.token_prefix}_"
        if not token.startswith(expected_prefix):
            return None
        body = token[len(expected_prefix):]
        if len(body) < int(self.cfg.key_hint_chars):
            return None
        return body[: int(self.cfg.key_hint_chars)]

    def _pepper(self) -> bytes:
        """
        Resolve the PBKDF2 pepper. Fails closed outside _DEV_ENVIRONMENTS.

        Fix #3: result is cached in self._pepper_cache after first successful
        resolve so os.environ.get is not called on every PBKDF2 invocation.
        """
        if self._pepper_cache is not None:
            return self._pepper_cache

        pepper = os.environ.get(self.cfg.pepper_env_var, "")
        if pepper:
            self._pepper_cache = pepper.encode("utf-8")
            return self._pepper_cache

        env = os.environ.get("S43_ENV", "").lower().strip()
        if env in _DEV_ENVIRONMENTS:
            warnings.warn(
                f"{self.cfg.pepper_env_var} is not set. Using development-only pepper.",
                RuntimeWarning,
                stacklevel=4,
            )
            self._pepper_cache = b"DEV_ONLY__SET_S43_AUTH_PEPPER"
            return self._pepper_cache

        raise RuntimeError(
            f"Missing required secret: {self.cfg.pepper_env_var}. "
            "Required in any environment not in "
            f"{sorted(_DEV_ENVIRONMENTS)!r}. "
            f"Current S43_ENV={os.environ.get('S43_ENV')!r}."
        )

    def _hash_token(self, token: str, salt: bytes) -> bytes:
        material = token.encode("utf-8") + b"|" + self._pepper()
        return hashlib.pbkdf2_hmac(
            self.cfg.hash_alg,
            material,
            salt,
            int(self.cfg.hash_iters),
            dklen=32,
        )

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        cx = sqlite3.connect(self.db_path, timeout=float(self.cfg.sqlite_timeout_seconds))
        try:
            cx.execute("PRAGMA foreign_keys = ON;")
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
            cx.execute("PRAGMA journal_mode = WAL;")
            cx.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL
                );
                """
            )
            if not self._table_exists(cx=cx, table_name="auth_keys"):
                self._create_auth_keys_table(cx)
                cx.execute(
                    """
                    INSERT INTO schema_meta (key, value) VALUES ('auth_schema_version', ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (str(self.cfg.schema_version),),
                )
            else:
                stored = self._read_or_infer_schema_version(cx)
                if stored == 1:
                    self._migrate_v1_to_v2(cx)
                    stored = 2
                if stored != int(self.cfg.schema_version):
                    raise RuntimeError(
                        f"Schema mismatch: stored={stored}, expected={self.cfg.schema_version}."
                    )
            self._create_indexes(cx)

    def _create_auth_keys_table(self, cx: sqlite3.Connection) -> None:
        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_keys (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                subject       TEXT NOT NULL,
                scopes_json   TEXT NOT NULL,
                issued_by     TEXT NOT NULL,
                issued_at     INTEGER NOT NULL,
                not_before    INTEGER NOT NULL,
                expires_at    INTEGER NULL,
                revoked_at    INTEGER NULL,
                revoked_by    TEXT NULL,
                metadata_json TEXT NOT NULL,
                key_hint      TEXT NOT NULL,
                salt_b64      TEXT NOT NULL,
                hash_b64      TEXT NOT NULL
            );
            """
        )

    def _create_indexes(self, cx: sqlite3.Connection) -> None:
        for ddl in [
            "CREATE INDEX IF NOT EXISTS idx_auth_keys_subject ON auth_keys(subject);",
            "CREATE INDEX IF NOT EXISTS idx_auth_keys_active_window ON auth_keys(revoked_at, not_before, expires_at);",
            "CREATE INDEX IF NOT EXISTS idx_auth_keys_issued_at ON auth_keys(issued_at);",
            "CREATE INDEX IF NOT EXISTS idx_auth_keys_key_hint ON auth_keys(key_hint);",
        ]:
            cx.execute(ddl)

    def _migrate_v1_to_v2(self, cx: sqlite3.Connection) -> None:
        columns = self._column_names(cx=cx, table_name="auth_keys")
        if "key_hint" not in columns:
            cx.execute("ALTER TABLE auth_keys ADD COLUMN key_hint TEXT NULL;")
        cx.execute(
            """
            UPDATE auth_keys
            SET revoked_at = COALESCE(revoked_at, ?),
                revoked_by = COALESCE(revoked_by, 'schema-migration-v2')
            WHERE key_hint IS NULL;
            """,
            (int(time.time()),),
        )
        cx.execute(
            """
            INSERT INTO schema_meta (key, value) VALUES ('auth_schema_version', '2')
            ON CONFLICT(key) DO UPDATE SET value = excluded.value;
            """
        )

    def _read_or_infer_schema_version(self, cx: sqlite3.Connection) -> int:
        row = cx.execute(
            "SELECT value FROM schema_meta WHERE key = 'auth_schema_version';"
        ).fetchone()
        if row is not None:
            try:
                return int(row[0])
            except (TypeError, ValueError) as exc:
                raise RuntimeError("Invalid schema version in database.") from exc

        columns = self._column_names(cx=cx, table_name="auth_keys")
        inferred = 2 if "key_hint" in columns else 1
        cx.execute(
            """
            INSERT INTO schema_meta (key, value) VALUES ('auth_schema_version', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value;
            """,
            (str(inferred),),
        )
        return inferred

    # ------------------------------------------------------------------
    # Validation / serialisation helpers
    # ------------------------------------------------------------------

    def _validate_config(self) -> None:
        positive_int_fields = {
            "hash_iters": self.cfg.hash_iters, "salt_bytes": self.cfg.salt_bytes,
            "token_bytes": self.cfg.token_bytes, "key_hint_chars": self.cfg.key_hint_chars,
            "min_token_chars": self.cfg.min_token_chars, "max_token_chars": self.cfg.max_token_chars,
            "max_subject_bytes": self.cfg.max_subject_bytes, "max_issued_by_bytes": self.cfg.max_issued_by_bytes,
            "max_scope_bytes": self.cfg.max_scope_bytes, "max_scopes": self.cfg.max_scopes,
            "max_metadata_json_bytes": self.cfg.max_metadata_json_bytes,
            "max_verify_candidates": self.cfg.max_verify_candidates, "schema_version": self.cfg.schema_version,
        }
        for name, value in positive_int_fields.items():
            if int(value) <= 0:
                raise ValueError(f"{name} must be greater than zero.")

        # Fix #1: reject unsafe hash algorithms at config time.
        if self.cfg.hash_alg not in _SAFE_HASH_ALGORITHMS:
            raise ValueError(
                f"hash_alg {self.cfg.hash_alg!r} is not in the safe algorithm list "
                f"{sorted(_SAFE_HASH_ALGORITHMS)}."
            )

        if int(self.cfg.min_token_chars) > int(self.cfg.max_token_chars):
            raise ValueError("min_token_chars cannot be greater than max_token_chars.")
        if int(self.cfg.activation_delay_seconds) < 0:
            raise ValueError("activation_delay_seconds must be >= 0.")
        if int(self.cfg.default_expires_in_seconds) < 0:
            raise ValueError("default_expires_in_seconds must be >= 0.")
        if not self.cfg.token_prefix.strip():
            raise ValueError("token_prefix cannot be empty.")
        if not self.cfg.pepper_env_var.strip():
            raise ValueError("pepper_env_var cannot be empty.")
        if float(self.cfg.sqlite_timeout_seconds) <= 0:
            raise ValueError("sqlite_timeout_seconds must be greater than zero.")

    def _resolve_expiration_seconds(self, expires_in_seconds: Optional[int]) -> int:
        value = int(self.cfg.default_expires_in_seconds) if expires_in_seconds is None else int(expires_in_seconds)
        if value < 0:
            raise ValueError("expires_in_seconds must be >= 0.")
        return value

    def _resolve_not_before_offset_seconds(self, not_before_offset_seconds: Optional[int]) -> int:
        value = int(self.cfg.activation_delay_seconds) if not_before_offset_seconds is None else int(not_before_offset_seconds)
        if value < 0:
            raise ValueError("not_before_offset_seconds must be >= 0.")
        return value

    def _normalize_scopes(self, scopes: Sequence[str]) -> list[str]:
        if isinstance(scopes, (str, bytes)):
            raise TypeError("scopes must be a sequence of strings.")
        normalized: set[str] = set()
        for scope in scopes:
            normalized.add(self._validate_text(name="scope", value=scope, max_bytes=self.cfg.max_scope_bytes))
        if len(normalized) > int(self.cfg.max_scopes):
            raise ValueError(f"Too many scopes. Maximum allowed: {self.cfg.max_scopes}.")
        return sorted(normalized)

    def _serialize_metadata(self, metadata: Optional[dict[str, Any]]) -> str:
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise TypeError("metadata must be a dictionary.")
        try:
            payload = json.dumps(metadata, separators=(",", ":"), sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("metadata must be JSON serializable.") from exc
        size = len(payload.encode("utf-8"))
        if size > int(self.cfg.max_metadata_json_bytes):
            raise ValueError(f"metadata JSON exceeds limit: {size} > {self.cfg.max_metadata_json_bytes} bytes.")
        return payload

    @staticmethod
    def _validate_text(*, name: str, value: object, max_bytes: int) -> str:
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string.")
        cleaned = value.strip()
        if not cleaned:
            raise ValueError(f"{name} cannot be empty.")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in cleaned):
            raise ValueError(f"{name} contains control characters.")
        size = len(cleaned.encode("utf-8"))
        if size > int(max_bytes):
            raise ValueError(f"{name} exceeds size limit: {size} > {max_bytes} bytes.")
        return cleaned

    @staticmethod
    def _decode_hash_material(*, salt_b64: str, hash_b64: str) -> Optional[tuple[bytes, bytes]]:
        try:
            salt          = base64.b64decode(salt_b64.encode("ascii"), validate=True)
            expected_hash = base64.b64decode(hash_b64.encode("ascii"), validate=True)
            return salt, expected_hash
        except Exception:
            return None

    @staticmethod
    def _table_exists(*, cx: sqlite3.Connection, table_name: str) -> bool:
        row = cx.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1;",
            (table_name,),
        ).fetchone()
        return row is not None

    @staticmethod
    def _column_names(*, cx: sqlite3.Connection, table_name: str) -> set[str]:
        # Fix #2: validate table_name before interpolating into PRAGMA.
        # PRAGMA table_info() does not support parameter binding in SQLite.
        if table_name not in _KNOWN_TABLE_NAMES:
            raise ValueError(f"Unknown table name: {table_name!r}")
        rows = cx.execute(f"PRAGMA table_info({table_name});").fetchall()
        return {str(row[1]) for row in rows}

    @staticmethod
    def _safe_json_list(value: str) -> list[str]:
        try:
            parsed = json.loads(value or "[]")
            return [item for item in parsed if isinstance(item, str)] if isinstance(parsed, list) else []
        except Exception:
            return []

    @staticmethod
    def _safe_json_dict(value: str) -> dict[str, Any]:
        try:
            parsed = json.loads(value or "{}")
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
