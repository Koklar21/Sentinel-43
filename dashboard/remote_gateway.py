from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------
# Paths / Identity
# ---------------------------------------------------------------------
try:
    BASE_DIR = Path(__file__).resolve().parent
except NameError:
    BASE_DIR = Path.cwd()

DB_PATH = Path(os.getenv("SENTINEL_DB_PATH", str(BASE_DIR / "sentinel_secure.db")))
SYSTEM_ID = os.getenv("SENTINEL_SYSTEM_ID", "SENTINEL-43-GATEWAY-01")

# ---------------------------------------------------------------------
# Auth (Prototype JWT HS256)
# ---------------------------------------------------------------------
JWT_SECRET = os.getenv("SENTINEL_JWT_SECRET", "dev-only-change-me")
JWT_ISSUER = os.getenv("SENTINEL_JWT_ISSUER", "sentinel")
JWT_AUDIENCE = os.getenv("SENTINEL_JWT_AUDIENCE", "sentinel-remote")

security = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    sub: str
    role: str  # viewer/operator/admin


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def verify_jwt(token: str) -> Principal:
    """
    Minimal HS256 verification for prototype.
    Production: use RS256 + JWKS (OIDC) + nonce/iat rules.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Bad token format")

    header_b64, payload_b64, sig_b64 = parts

    header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
    if header.get("typ") not in (None, "JWT"):
        raise ValueError("Bad typ")
    if header.get("alg") != "HS256":
        raise ValueError("Unsupported alg")

    signed = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), signed, hashlib.sha256).digest()
    expected_sig_b64 = _b64url_encode(expected_sig)

    # Compare base64url text to avoid subtle decoding quirks
    if not hmac.compare_digest(expected_sig_b64, sig_b64):
        raise ValueError("Bad signature")

    payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))

    if payload.get("iss") != JWT_ISSUER:
        raise ValueError("Bad issuer")

    aud = payload.get("aud")
    if aud != JWT_AUDIENCE:
        raise ValueError("Bad audience")

    exp = payload.get("exp")
    if not isinstance(exp, int) or exp < int(time.time()):
        raise ValueError("Expired token")

    sub = payload.get("sub", "unknown")
    role = payload.get("role", "viewer")
    if role not in ("viewer", "operator", "admin"):
        role = "viewer"

    return Principal(sub=sub, role=role)


def get_principal(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Principal:
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    try:
        return verify_jwt(creds.credentials)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {exc}")


def require_role(*allowed: str):
    def _dep(p: Principal = Depends(get_principal)) -> Principal:
        if p.role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return p

    return _dep


# ---------------------------------------------------------------------
# DB helpers / schema
# ---------------------------------------------------------------------
def db_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def db_init() -> None:
    with db_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS event_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                module TEXT NOT NULL,
                message TEXT NOT NULL,
                context_json TEXT
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_actions (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                action_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL,                -- PENDING/APPROVED/VETOED/EXPIRED
                decided_at TEXT,
                decided_by TEXT,
                decision_reason TEXT
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_actions(status);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pending_created ON pending_actions(created_at);")


def _utc_ts() -> str:
    import datetime as _dt

    return _dt.datetime.utcnow().isoformat(timespec="microseconds") + "Z"


def log_event(level: str, module: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
    ctx = json.dumps(context, default=str) if context else None
    with db_conn() as conn:
        conn.execute(
            """
            INSERT INTO event_logs (timestamp, level, module, message, context_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (_utc_ts(), level, module, message, ctx),
        )


def read_tail(limit: int = 200) -> List[Dict[str, Any]]:
    limit = max(1, min(limit, 1000))
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, timestamp, level, module, message, context_json
            FROM event_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    items: List[Dict[str, Any]] = []
    for r in reversed(rows):
        items.append(
            {
                "id": r["id"],
                "timestamp": r["timestamp"],
                "level": r["level"],
                "module": r["module"],
                "message": r["message"],
                "context": json.loads(r["context_json"]) if r["context_json"] else None,
            }
        )
    return items


# ---------------------------------------------------------------------
# API models
# ---------------------------------------------------------------------
class LogWrite(BaseModel):
    level: str = "INFO"
    module: str = "UI"
    message: str
    context: Optional[Dict[str, Any]] = None


class PendingActionCreate(BaseModel):
    """
    Create a pending action that requires human approval.
    action_type examples: FIREWALL_BLOCK, DISABLE_ACCOUNT, RATE_LIMIT, etc.
    payload is arbitrary JSON.
    """
    id: Optional[str] = None
    action_type: str = Field(..., min_length=1, max_length=80)
    payload: Dict[str, Any] = Field(default_factory=dict)


class PendingActionDecision(BaseModel):
    reason: str = Field(..., min_length=1, max_length=500)


class PendingActionOut(BaseModel):
    id: str
    created_at: str
    created_by: str
    action_type: str
    payload: Dict[str, Any]
    status: str
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
    decision_reason: Optional[str] = None


# ---------------------------------------------------------------------
# App
# ---------------------------------------------------------------------
app = FastAPI(title="Sentinel Pending Actions Gateway", version="0.2.0")


@app.on_event("startup")
def _startup() -> None:
    db_init()
    log_event("INFO", "BOOT", f"[BOOT] {SYSTEM_ID} started", {"db_path": str(DB_PATH)})


@app.get("/api/v1/health")
def health(_: Principal = Depends(require_role("viewer", "operator", "admin"))):
    return {"ok": True, "system_id": SYSTEM_ID, "db_path": str(DB_PATH)}


# -------------------------
# Logs
# -------------------------
@app.get("/api/v1/logs/tail")
def logs_tail(limit: int = 200, _: Principal = Depends(require_role("viewer", "operator", "admin"))):
    try:
        return {"items": read_tail(limit)}
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")


@app.post("/api/v1/logs")
def write_log(entry: LogWrite, p: Principal = Depends(require_role("operator", "admin"))):
    log_event(entry.level, entry.module, entry.message, entry.context or {"operator": p.sub})
    return {"ok": True}


# -------------------------
# Pending Actions (Persistent)
# -------------------------
def _action_id() -> str:
    # Small, readable, collision-resistant enough for prototypes
    raw = os.urandom(16)
    return _b64url_encode(raw)


def _row_to_action(r: sqlite3.Row) -> PendingActionOut:
    return PendingActionOut(
        id=r["id"],
        created_at=r["created_at"],
        created_by=r["created_by"],
        action_type=r["action_type"],
        payload=json.loads(r["payload_json"]),
        status=r["status"],
        decided_at=r["decided_at"],
        decided_by=r["decided_by"],
        decision_reason=r["decision_reason"],
    )


@app.post("/api/v1/actions", response_model=PendingActionOut)
def create_action(body: PendingActionCreate, p: Principal = Depends(require_role("operator", "admin"))):
    action_id = body.id or _action_id()
    created_at = _utc_ts()
    payload_json = json.dumps(body.payload, default=str)

    with db_conn() as conn:
        try:
            conn.execute(
                """
                INSERT INTO pending_actions
                (id, created_at, created_by, action_type, payload_json, status)
                VALUES (?, ?, ?, ?, ?, 'PENDING')
                """,
                (action_id, created_at, p.sub, body.action_type, payload_json),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Action id already exists")

        row = conn.execute("SELECT * FROM pending_actions WHERE id = ?", (action_id,)).fetchone()

    log_event("INFO", "ACTIONS", f"[ACTIONS] CREATED: {action_id} ({body.action_type})", {"id": action_id, "by": p.sub})
    return _row_to_action(row)


@app.get("/api/v1/actions", response_model=List[PendingActionOut])
def list_actions(
    status_filter: str = "PENDING",
    limit: int = 200,
    _: Principal = Depends(require_role("viewer", "operator", "admin")),
):
    limit = max(1, min(limit, 1000))
    status_filter = status_filter.upper()

    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT * FROM pending_actions
            WHERE status = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (status_filter, limit),
        ).fetchall()

    return [_row_to_action(r) for r in rows]


@app.get("/api/v1/actions/{action_id}", response_model=PendingActionOut)
def get_action(action_id: str, _: Principal = Depends(require_role("viewer", "operator", "admin"))):
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM pending_actions WHERE id = ?", (action_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Action not found")
    return _row_to_action(row)


def _decide(action_id: str, p: Principal, new_status: str, reason: str) -> PendingActionOut:
    decided_at = _utc_ts()
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM pending_actions WHERE id = ?", (action_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Action not found")
        if row["status"] != "PENDING":
            raise HTTPException(status_code=409, detail=f"Action is not pending (current: {row['status']})")

        conn.execute(
            """
            UPDATE pending_actions
            SET status = ?, decided_at = ?, decided_by = ?, decision_reason = ?
            WHERE id = ?
            """,
            (new_status, decided_at, p.sub, reason, action_id),
        )
        updated = conn.execute("SELECT * FROM pending_actions WHERE id = ?", (action_id,)).fetchone()

    log_event(
        "INFO",
        "ACTIONS",
        f"[ACTIONS] {new_status}: {action_id} by {p.sub}. Reason: {reason}",
        {"id": action_id, "status": new_status, "by": p.sub, "reason": reason},
    )
    return _row_to_action(updated)


@app.post("/api/v1/actions/{action_id}/approve", response_model=PendingActionOut)
def approve_action(action_id: str, body: PendingActionDecision, p: Principal = Depends(require_role("operator", "admin"))):
    return _decide(action_id, p, "APPROVED", body.reason)


@app.post("/api/v1/actions/{action_id}/veto", response_model=PendingActionOut)
def veto_action(action_id: str, body: PendingActionDecision, p: Principal = Depends(require_role("operator", "admin"))):
    return _decide(action_id, p, "VETOED", body.reason)