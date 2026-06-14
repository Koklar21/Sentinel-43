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
#
# Sentinel-43 is distributed under AGPL/source-available terms, so this
# fallback pepper value is effectively public. Any environment NOT in this
# set - including an unset S43_ENV - is treated as a real deployment and
# will fail closed if S43_AUTH_PEPPER is missing.
_DEV_ENVIRONMENTS: frozenset[str] = frozenset(
    {
        "development",
        "dev",
        "test",
        "testing",
        "local",
    }
)


@dataclass(frozen=True)
class AuthKeyConfig:
    """
    Configuration for Sentinel-43 authorization keys.

    SQLite is configured to use WAL mode and synchronous=NORMAL.

    WAL improves concurrency for mixed read/write workloads.

    synchronous=NORMAL provides a practical balance between durability and
    performance. In the event of an operating-system crash, the most recent
    committed transaction may be lost. Existing database integrity should
    remain intact.

    Use synchronous=FULL if the deployment requires maximum durability and
    can tolerate the additional write cost.
    """

    activation_delay_seconds: int = 24 * 60 * 60
    default_expires_in_seconds: int = 7 * 24 * 60 * 60

    pepper_env_var: str = "S43_AUTH_PEPPER"

    hash_alg: str = "sha256"
    hash_iters: int = 210_000
    salt_bytes: int = 16

    token_prefix: str = "S43K"
    token_bytes: int = 32

    # A non-secret lookup hint prevents an O(n × PBKDF2) verification scan.
    key_hint_chars: int = 8

    # Defensive input limits.
    min_token_chars: int = 20
    max_token_chars: int = 256
    max_subject_bytes: int = 512
    max_issued_by_bytes: int = 512
    max_scope_bytes: int = 256
    max_scopes: int = 64
    max_metadata_json_bytes: int = 4 * 1024

    sqlite_timeout_seconds: float = 15.0

    # This is now a per-hint collision cap, not a global key scan limit.
    max_verify_candidates: int = 16

    schema_version: int = 2


class AuthKeyStore:
    """
    SQLite-backed authorization key store.

    Security properties:
    - Raw tokens are returned once at issuance and are never stored.
    - Stored hashes use PBKDF2-HMAC with a per-key random salt and environment
      pepper.
    - Token lookup uses a short, non-secret indexed hint before PBKDF2 runs.
    - Verification and revocation use constant-time hash comparison.
    - Legacy schema-version-1 keys are revoked during migration because their
      lookup hints cannot be reconstructed from hashes safely.
    - S43_AUTH_PEPPER is required in any environment not explicitly
      recognized as a development environment (see _DEV_ENVIRONMENTS); a
      missing pepper fails closed rather than silently using a known
      development value.
    - Text fields (subject, issued_by, scopes) reject control characters to
      avoid log-injection / display issues when surfaced in dashboards or
      audit logs.
    """

    def __init__(
        self,
        db_path: str,
        config: Optional[AuthKeyConfig] = None,
    ) -> None:
        self.db_path = db_path
        self.cfg = config or AuthKeyConfig()

        self._validate_config()
        self._ensure_schema()

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
        """
        Issue a new authorization key.

        expires_in_seconds:
            None -> use configured default.
            0    -> key does not expire.
            > 0  -> expire after the specified number of seconds.
            < 0  -> rejected.

        not_before_offset_seconds:
            None -> use configured activation delay.
            0    -> activate immediately.
            > 0  -> activate after the specified delay.
            < 0  -> rejected.
        """

        safe_subject = self._validate_text(
            name="subject",
            value=subject,
            max_bytes=self.cfg.max_subject_bytes,
        )

        safe_issued_by = self._validate_text(
            name="issued_by",
            value=issued_by,
            max_bytes=self.cfg.max_issued_by_bytes,
        )

        safe_scopes = self._normalize_scopes(scopes)
        metadata_json = self._serialize_metadata(metadata)

        exp_in = self._resolve_expiration_seconds(expires_in_seconds)
        not_before_offset = self._resolve_not_before_offset_seconds(
            not_before_offset_seconds
        )

        now = int(time.time())
        not_before = now + not_before_offset
        expires_at = now + exp_in if exp_in > 0 else None

        token = self._generate_token()
        key_hint = self._token_hint(token)

        if key_hint is None:
            raise RuntimeError("Generated authorization token is invalid.")

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
                    key_hint,
                    salt_b64,
                    hash_b64
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    safe_subject,
                    json.dumps(safe_scopes, separators=(",", ":")),
                    safe_issued_by,
                    now,
                    not_before,
                    expires_at,
                    None,
                    None,
                    metadata_json,
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
        """
        Verify a key without performing a global PBKDF2 scan.

        The indexed, non-secret key_hint narrows the candidate set before any
        expensive password-derived hashing work occurs.
        """

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
                SELECT
                    id,
                    scopes_json,
                    salt_b64,
                    hash_b64
                FROM auth_keys
                WHERE key_hint = ?
                  AND revoked_at IS NULL
                  AND not_before <= ?
                  AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY id DESC
                LIMIT ?
                """,
                (
                    key_hint,
                    now_ts,
                    now_ts,
                    int(self.cfg.max_verify_candidates),
                ),
            ).fetchall()

        for _key_id, scopes_json, salt_b64, hash_b64 in rows:
            decoded = self._decode_hash_material(
                salt_b64=salt_b64,
                hash_b64=hash_b64,
            )

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
        """
        Revoke an active key.

        The lookup hint prevents revocation requests from triggering an
        expensive scan of every active authorization record.
        """

        key_hint = self._token_hint(token)

        if key_hint is None:
            return False

        try:
            safe_revoked_by = self._validate_text(
                name="revoked_by",
                value=revoked_by,
                max_bytes=self.cfg.max_issued_by_bytes,
            )
        except (TypeError, ValueError):
            return False

        now_ts = int(now if now is not None else time.time())

        with self._conn() as cx:
            rows = cx.execute(
                """
                SELECT
                    id,
                    salt_b64,
                    hash_b64
                FROM auth_keys
                WHERE key_hint = ?
                  AND revoked_at IS NULL
                ORDER BY id DESC
                LIMIT ?
                """,
                (
                    key_hint,
                    int(self.cfg.max_verify_candidates),
                ),
            ).fetchall()

            for key_id, salt_b64, hash_b64 in rows:
                decoded = self._decode_hash_material(
                    salt_b64=salt_b64,
                    hash_b64=hash_b64,
                )

                if decoded is None:
                    continue

                salt, expected_hash = decoded
                actual_hash = self._hash_token(token=token, salt=salt)

                if not hmac.compare_digest(expected_hash, actual_hash):
                    continue

                cursor = cx.execute(
                    """
                    UPDATE auth_keys
                    SET revoked_at = ?, revoked_by = ?
                    WHERE id = ?
                      AND revoked_at IS NULL
                    """,
                    (
                        now_ts,
                        safe_revoked_by,
                        key_id,
                    ),
                )

                return cursor.rowcount == 1

        return False

    def list_keys(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        List authorization records without exposing raw tokens or stored hashes.
        """

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
                    metadata_json,
                    key_hint
                FROM auth_keys
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (
                    safe_limit,
                    safe_offset,
                ),
            ).fetchall()

        out: list[dict[str, Any]] = []

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
                    "key_hint": row[10],
                }
            )

        return out

    def _generate_token(self) -> str:
        raw = secrets.token_bytes(self.cfg.token_bytes)
        body = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

        return f"{self.cfg.token_prefix}_{body}"

    def _token_hint(self, token: object) -> Optional[str]:
        """
        Extract the indexed, non-secret lookup hint from a token.

        Invalid or oversized inputs are rejected before database access and
        before PBKDF2 work begins.
        """

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
        Resolve the PBKDF2 pepper.

        Fails CLOSED: S43_AUTH_PEPPER is required unless S43_ENV is
        explicitly one of _DEV_ENVIRONMENTS. An unset, misspelled, or
        unrecognized S43_ENV (e.g. "staging", "internet", "" ) is treated
        as a real deployment, not a development environment - there is no
        silent fallback to the hardcoded development pepper outside of
        S43_ENV values we explicitly recognize as non-production.
        """

        pepper = os.environ.get(self.cfg.pepper_env_var, "")

        if pepper:
            return pepper.encode("utf-8")

        env = os.environ.get("S43_ENV", "").lower().strip()

        if env in _DEV_ENVIRONMENTS:
            warnings.warn(
                f"{self.cfg.pepper_env_var} is not set. "
                "Using development-only pepper.",
                RuntimeWarning,
                stacklevel=4,
            )
            return b"DEV_ONLY__SET_S43_AUTH_PEPPER"

        raise RuntimeError(
            f"Missing required secret: {self.cfg.pepper_env_var}. "
            "This is required in any environment not explicitly recognized "
            f"as a development environment (S43_ENV in "
            f"{sorted(_DEV_ENVIRONMENTS)!r}); current S43_ENV="
            f"{os.environ.get('S43_ENV')!r}."
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

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        cx = sqlite3.connect(
            self.db_path,
            timeout=float(self.cfg.sqlite_timeout_seconds),
        )

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
        """
        Ensure the database matches the current authorization schema.

        Migration from schema version 1 to version 2:
        - Adds the indexed key_hint column.
        - Revokes legacy keys because the original raw tokens are unavailable
          and hints cannot be reconstructed safely from PBKDF2 hashes.
        """

        with self._conn() as cx:
            # journal_mode persists in the SQLite database file after it is set.
            cx.execute("PRAGMA journal_mode = WAL;")

            cx.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

            table_exists = self._table_exists(
                cx=cx,
                table_name="auth_keys",
            )

            if not table_exists:
                self._create_auth_keys_table(cx)

                cx.execute(
                    """
                    INSERT INTO schema_meta (key, value)
                    VALUES ('auth_schema_version', ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (str(self.cfg.schema_version),),
                )
            else:
                stored_version = self._read_or_infer_schema_version(cx)

                if stored_version == 1:
                    self._migrate_v1_to_v2(cx)
                    stored_version = 2

                if stored_version != int(self.cfg.schema_version):
                    raise RuntimeError(
                        "Authorization database schema mismatch: "
                        f"stored={stored_version}, "
                        f"expected={self.cfg.schema_version}. "
                        "Run the required migration before starting."
                    )

            self._create_indexes(cx)

    def _create_auth_keys_table(self, cx: sqlite3.Connection) -> None:
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

                key_hint TEXT NOT NULL,
                salt_b64 TEXT NOT NULL,
                hash_b64 TEXT NOT NULL
            );
            """
        )

    def _create_indexes(self, cx: sqlite3.Connection) -> None:
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

        cx.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_auth_keys_key_hint
            ON auth_keys(key_hint);
            """
        )

    def _migrate_v1_to_v2(self, cx: sqlite3.Connection) -> None:
        columns = self._column_names(
            cx=cx,
            table_name="auth_keys",
        )

        if "key_hint" not in columns:
            cx.execute(
                """
                ALTER TABLE auth_keys
                ADD COLUMN key_hint TEXT NULL;
                """
            )

        now_ts = int(time.time())

        # Legacy hints cannot be recreated because raw tokens were never stored.
        # Revoke old keys and require clean reissuance.
        cx.execute(
            """
            UPDATE auth_keys
            SET revoked_at = COALESCE(revoked_at, ?),
                revoked_by = COALESCE(revoked_by, 'schema-migration-v2')
            WHERE key_hint IS NULL;
            """,
            (now_ts,),
        )

        cx.execute(
            """
            INSERT INTO schema_meta (key, value)
            VALUES ('auth_schema_version', '2')
            ON CONFLICT(key) DO UPDATE SET value = excluded.value;
            """
        )

    def _read_or_infer_schema_version(self, cx: sqlite3.Connection) -> int:
        row = cx.execute(
            """
            SELECT value
            FROM schema_meta
            WHERE key = 'auth_schema_version';
            """
        ).fetchone()

        if row is not None:
            try:
                return int(row[0])
            except (TypeError, ValueError) as exc:
                raise RuntimeError(
                    "Authorization database schema version is invalid."
                ) from exc

        columns = self._column_names(
            cx=cx,
            table_name="auth_keys",
        )

        inferred_version = 2 if "key_hint" in columns else 1

        cx.execute(
            """
            INSERT INTO schema_meta (key, value)
            VALUES ('auth_schema_version', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value;
            """,
            (str(inferred_version),),
        )

        return inferred_version

    def _resolve_expiration_seconds(
        self,
        expires_in_seconds: Optional[int],
    ) -> int:
        if expires_in_seconds is None:
            value = int(self.cfg.default_expires_in_seconds)
        else:
            value = int(expires_in_seconds)

        if value < 0:
            raise ValueError("expires_in_seconds must be >= 0.")

        return value

    def _resolve_not_before_offset_seconds(
        self,
        not_before_offset_seconds: Optional[int],
    ) -> int:
        if not_before_offset_seconds is None:
            value = int(self.cfg.activation_delay_seconds)
        else:
            value = int(not_before_offset_seconds)

        if value < 0:
            raise ValueError("not_before_offset_seconds must be >= 0.")

        return value

    def _normalize_scopes(
        self,
        scopes: Sequence[str],
    ) -> list[str]:
        if isinstance(scopes, (str, bytes)):
            raise TypeError("scopes must be a sequence of strings.")

        normalized: set[str] = set()

        for scope in scopes:
            safe_scope = self._validate_text(
                name="scope",
                value=scope,
                max_bytes=self.cfg.max_scope_bytes,
            )

            normalized.add(safe_scope)

        if len(normalized) > int(self.cfg.max_scopes):
            raise ValueError(
                f"Too many scopes. Maximum allowed: {self.cfg.max_scopes}."
            )

        return sorted(normalized)

    def _serialize_metadata(
        self,
        metadata: Optional[dict[str, Any]],
    ) -> str:
        if metadata is None:
            metadata = {}

        if not isinstance(metadata, dict):
            raise TypeError("metadata must be a dictionary.")

        try:
            payload = json.dumps(
                metadata,
                separators=(",", ":"),
                sort_keys=True,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("metadata must be JSON serializable.") from exc

        size = len(payload.encode("utf-8"))

        if size > int(self.cfg.max_metadata_json_bytes):
            raise ValueError(
                "metadata JSON exceeds the configured size limit: "
                f"{size} > {self.cfg.max_metadata_json_bytes} bytes."
            )

        return payload

    def _validate_config(self) -> None:
        positive_int_fields = {
            "hash_iters": self.cfg.hash_iters,
            "salt_bytes": self.cfg.salt_bytes,
            "token_bytes": self.cfg.token_bytes,
            "key_hint_chars": self.cfg.key_hint_chars,
            "min_token_chars": self.cfg.min_token_chars,
            "max_token_chars": self.cfg.max_token_chars,
            "max_subject_bytes": self.cfg.max_subject_bytes,
            "max_issued_by_bytes": self.cfg.max_issued_by_bytes,
            "max_scope_bytes": self.cfg.max_scope_bytes,
            "max_scopes": self.cfg.max_scopes,
            "max_metadata_json_bytes": self.cfg.max_metadata_json_bytes,
            "max_verify_candidates": self.cfg.max_verify_candidates,
            "schema_version": self.cfg.schema_version,
        }

        for name, value in positive_int_fields.items():
            if int(value) <= 0:
                raise ValueError(f"{name} must be greater than zero.")

        if int(self.cfg.min_token_chars) > int(self.cfg.max_token_chars):
            raise ValueError(
                "min_token_chars cannot be greater than max_token_chars."
            )

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

    @staticmethod
    def _validate_text(
        *,
        name: str,
        value: object,
        max_bytes: int,
    ) -> str:
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string.")

        cleaned = value.strip()

        if not cleaned:
            raise ValueError(f"{name} cannot be empty.")

        # Reject control characters (including DEL) to prevent log
        # injection and dashboard-rendering issues when these fields are
        # later surfaced via list_keys(), audit logs, or AlertPanel.
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in cleaned):
            raise ValueError(f"{name} contains control characters, which are not allowed.")

        size = len(cleaned.encode("utf-8"))

        if size > int(max_bytes):
            raise ValueError(
                f"{name} exceeds the configured size limit: "
                f"{size} > {max_bytes} bytes."
            )

        return cleaned

    @staticmethod
    def _decode_hash_material(
        *,
        salt_b64: str,
        hash_b64: str,
    ) -> Optional[tuple[bytes, bytes]]:
        try:
            salt = base64.b64decode(
                salt_b64.encode("ascii"),
                validate=True,
            )

            expected_hash = base64.b64decode(
                hash_b64.encode("ascii"),
                validate=True,
            )

            return salt, expected_hash
        except Exception:
            return None

    @staticmethod
    def _table_exists(
        *,
        cx: sqlite3.Connection,
        table_name: str,
    ) -> bool:
        row = cx.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table'
              AND name = ?
            LIMIT 1;
            """,
            (table_name,),
        ).fetchone()

        return row is not None

    @staticmethod
    def _column_names(
        *,
        cx: sqlite3.Connection,
        table_name: str,
    ) -> set[str]:
        rows = cx.execute(
            f"PRAGMA table_info({table_name});"
        ).fetchall()

        return {str(row[1]) for row in rows}

    @staticmethod
    def _safe_json_list(value: str) -> list[str]:
        try:
            parsed = json.loads(value or "[]")

            if not isinstance(parsed, list):
                return []

            return [
                item
                for item in parsed
                if isinstance(item, str)
            ]
        except Exception:
            return []

    @staticmethod
    def _safe_json_dict(value: str) -> dict[str, Any]:
        try:
            parsed = json.loads(value or "{}")

            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
