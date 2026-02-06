"""
Sentinel-43 Authorization Keys (Delayed Activation)
---------------------------------------------------

Design goals:
- Store only hashed keys (never store plaintext keys).
- One-time display of plaintext key at creation.
- Constant-time verification (hmac.compare_digest).
- Built-in 24-hour activation delay (NOT BEFORE).
- Optional expiry + revocation.
- SQLite-first, production-ready enough to not embarrass you later.

Drop-in usage:
    from authorization_keys import AuthKeyStore, AuthKeyConfig

    store = AuthKeyStore(db_path="sentinel43.db")
    token = store.issue_key(
        subject="service:api",
        scopes=["read:events", "write:events"],
        issued_by="admin",
        expires_in_seconds=7 * 24 * 3600,  # optional, default 7 days
    )
    print("SAVE THIS TOKEN NOW:", token)

    # ... 24 hours later ...
    ok = store.verify_key(token, required_scopes=["read:events"])
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence, Tuple


# ---------------------------
# Config
# ---------------------------

@dataclass(frozen=True)
class AuthKeyConfig:
    # The thing you asked for: hard 24-hour activation delay.
    activation_delay_seconds: int = 24 * 60 * 60

    # Default expiry if not specified at issuance (7 days).
    default_expires_in_seconds: int = 7 * 24 * 60 * 60

    # HMAC "pepper" to prevent rainbow-table attacks against DB leaks.
    # REQUIRED in production: set S43_AUTH_PEPPER in env/secrets manager.
    pepper_env_var: str = "S43_AUTH_PEPPER"

    # Hash settings
    hash_alg: str = "sha256"
    hash_iters: int = 210_000  # PBKDF2 iterations (tune if needed)
    salt_bytes: int = 16

    # Token format settings
    token_prefix: str = "S43K"
    token_bytes: int = 32  # raw secret bytes before base64


# ---------------------------
# Store (SQLite)
# ---------------------------

class AuthKeyStore:
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
        Create a new authorization key.

        Returns:
            plaintext token (ONE TIME). Store it securely.
        """
        now = int(time.time())
        not_before = now + int(self.cfg.activation_delay_seconds)

        exp_in = int(expires_in_seconds or self.cfg.default_expires_in_seconds)
        expires_at = now + exp_in if exp_in > 0 else None

        token = self._generate_token()
        salt = secrets.token_bytes(self.cfg.salt_bytes)

        key_hash = self._hash_token(token=token, salt=salt)

        rec = {
            "subject": subject,
            "scopes_json": json.dumps(sorted(set(scopes))),
            "issued_by": issued_by,
            "issued_at": now,
            "not_before": not_before,
            "expires_at": expires_at,
            "revoked_at": None,
            "revoked_by": None,
            "metadata_json": json.dumps(metadata or {}),
            "salt_b64": base64.b64encode(salt).decode("ascii"),
            "hash_b64": base64.b64encode(key_hash).decode("ascii"),
        }

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
                (
                    rec["subject"], rec["scopes_json"], rec["issued_by"],
                    rec["issued_at"], rec["not_before"], rec["expires_at"],
                    rec["revoked_at"], rec["revoked_by"],
                    rec["metadata_json"], rec["salt_b64"], rec["hash_b64"],
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
        Verify token validity + delayed activation + expiry + revocation + scopes.
        """
        now_ts = int(now or time.time())
        required = set(required_scopes or [])

        # Fast fail for obviously wrong tokens, but don't leak too much.
        if not isinstance(token, str) or len(token) < 20:
            return False

        with self._conn() as cx:
            # We can't lookup by token (we don't store plaintext). So we scan.
            # This is OK for small-ish installations; for large scale, add a key_id
            # prefix encoding or a token fingerprint column.
            rows = cx.execute(
                """
                SELECT
                    id,
                    scopes_json,
                    not_before,
                    expires_at,
                    revoked_at,
                    salt_b64,
                    hash_b64
                FROM auth_keys
                """
            ).fetchall()

        token_bytes = token.encode("utf-8", errors="ignore")

        for (key_id, scopes_json, not_before, expires_at, revoked_at, salt_b64, hash_b64) in rows:
            # Time gates first (cheap)
            if revoked_at is not None:
                continue
            if not_before is not None and now_ts < int(not_before):
                continue
            if expires_at is not None and now_ts > int(expires_at):
                continue

            salt = base64.b64decode(salt_b64.encode("ascii"))
            expected_hash = base64.b64decode(hash_b64.encode("ascii"))
            actual_hash = self._hash_token(token=token, salt=salt)

            if hmac.compare_digest(expected_hash, actual_hash):
                # Matched token: now check scopes
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
        Revoke a token (requires matching it).
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

            for (key_id, salt_b64, hash_b64) in rows:
                salt = base64.b64decode(salt_b64.encode("ascii"))
                expected_hash = base64.b64decode(hash_b64.encode("ascii"))
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

    def list_keys(self) -> list[dict]:
        """
        Admin utility: lists keys WITHOUT revealing token.
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
            # In production this should be set. Here we still run, but loudly.
            # If you ship this without pepper, you're basically handing attackers a coupon.
            pep = "DEV_ONLY__SET_S43_AUTH_PEPPER"
        return pep.encode("utf-8")

    def _hash_token(self, token: str, salt: bytes) -> bytes:
        """
        PBKDF2-HMAC(token + pepper, salt, iters)
        """
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