from __future__ import annotations

import hmac
import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Optional


class AuditEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, Decimal):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def _secret_from_str(raw: str) -> bytes:
    """
    Accept hex or raw text. Return bytes.
    """
    raw = (raw or "").strip()
    if not raw:
        raise RuntimeError("Audit signing key is missing.")
    try:
        if all(c in "0123456789abcdefABCDEF" for c in raw) and len(raw) >= 64 and len(raw) % 2 == 0:
            return bytes.fromhex(raw)
    except Exception:
        pass
    return raw.encode("utf-8")


@dataclass(frozen=True)
class AuditConfig:
    sqlite_path: Path
    jsonl_path: Optional[Path]
    signing_key: str  # required in non-dev strict mode (enforced by caller)


class AuditStore:
    """
    Tamper-resistant append-only audit chain.

    - SQLite WAL + FULL synchronous
    - Anchor row stores current head hash (fork prevention)
    - Each payload hash is HMAC(secret, payload_json + prev_hash)
    - Optional JSONL sink is best-effort (non-fatal)
    """

    def __init__(self, cfg: AuditConfig) -> None:
        self.cfg = cfg
        self._lock = threading.Lock()
        self._key = _secret_from_str(cfg.signing_key)
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(str(self.cfg.sqlite_path), timeout=5.0)
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA synchronous=FULL;")
        return con

    def _ensure_schema(self) -> None:
        self.cfg.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        con = self._connect()
        try:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    decision_time TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_hmac TEXT NOT NULL,
                    prev_hash TEXT NOT NULL
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_anchor (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    prev_hash TEXT NOT NULL
                )
                """
            )
            row = con.execute("SELECT prev_hash FROM audit_anchor WHERE id=1").fetchone()
            if row is None:
                con.execute("INSERT INTO audit_anchor (id, prev_hash) VALUES (1, ?)", ("GENESIS",))
            con.commit()
        finally:
            con.close()

    def get_prev_hash(self) -> str:
        con = self._connect()
        try:
            (prev_hash,) = con.execute("SELECT prev_hash FROM audit_anchor WHERE id=1").fetchone()
            return str(prev_hash)
        finally:
            con.close()

    def compute_payload_hmac(self, payload: Dict[str, Any], prev_hash: str) -> str:
        payload_json = json.dumps(payload, cls=AuditEncoder, sort_keys=True, separators=(",", ":")).encode("utf-8")
        msg = payload_json + prev_hash.encode("utf-8")
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def append(self, payload: Dict[str, Any]) -> str:
        """
        Atomic append:
        - BEGIN IMMEDIATE for write lock
        - Verify anchor head
        - Insert row + update anchor
        Returns the new head hash.
        """
        with self._lock:
            con = self._connect()
            try:
                con.execute("BEGIN IMMEDIATE")
                (current_head,) = con.execute("SELECT prev_hash FROM audit_anchor WHERE id=1").fetchone()
                current_head = str(current_head)

                decision_time = payload.get("decision_time") or datetime.now(timezone.utc).isoformat()
                payload["decision_time"] = decision_time

                payload_json = json.dumps(payload, cls=AuditEncoder, sort_keys=True, separators=(",", ":"))
                payload_hmac = self.compute_payload_hmac(payload, current_head)

                con.execute(
                    "INSERT INTO audit_log (decision_time, payload_json, payload_hmac, prev_hash) VALUES (?, ?, ?, ?)",
                    (decision_time, payload_json, payload_hmac, current_head),
                )
                con.execute("UPDATE audit_anchor SET prev_hash=? WHERE id=1", (payload_hmac,))
                con.commit()
            except Exception:
                con.rollback()
                raise
            finally:
                con.close()

        # Best-effort JSONL sink (non-fatal)
        if self.cfg.jsonl_path:
            try:
                p = self.cfg.jsonl_path
                p.parent.mkdir(parents=True, exist_ok=True)
                line = json.dumps({"payload": payload, "hash": payload_hmac}, cls=AuditEncoder) + "\n"
                with open(p, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception:
                # swallow: audit DB is the source of truth
                pass

        return payload_hmac