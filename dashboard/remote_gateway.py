from __future__ import annotations

import base64
import json
import os
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional

import jwt  # PyJWT
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------
# Paths / Identity
# ---------------------------------------------------------------------
try:
    BASE_DIR = Path(__file__).resolve().parent
except NameError:
    BASE_DIR = Path.cwd()

DB_PATH = Path(os.getenv("SENTINEL_DB_PATH", str(BASE_DIR / "sentinel_secure.db")))
SYSTEM_ID = os.getenv("SENTINEL_SYSTEM_ID", "SENTINEL-43-GATEWAY-01")
VERSION = os.getenv("SENTINEL_GATEWAY_VERSION", "0.3.0")

# ---------------------------------------------------------------------
# Auth (RS256 verification)
# ---------------------------------------------------------------------
JWT_ISSUER = os.getenv("SENTINEL_JWT_ISSUER", "sentinel")
JWT_AUDIENCE = os.getenv("SENTINEL_JWT_AUDIENCE", "sentinel-remote")
JWT_PUBLIC_KEY_PATH = os.getenv("SENTINEL_JWT_PUBLIC_KEY_PATH", "")

JWT_MAX_AGE_SECONDS = int(os.getenv("SENTINEL_JWT_MAX_AGE_SECONDS", "86400"))  # 24h
JWT_CLOCK_SKEW_SECONDS = int(os.getenv("SENTINEL_JWT_CLOCK_SKEW_SECONDS", "60"))

security = HTTPBearer(auto_error=False)

VALID_ROLES = ("viewer", "operator", "admin")
VALID_STATUSES = {"PENDING", "APPROVED", "VETOED", "EXPIRED", "EXECUTED"}
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARN", "ERROR"}

ACTION_ID_RE = re.compile(r"^[A-Z0-9_-]{10,64}$")

# ---------------------------------------------------------------------
# Request correlation
# ---------------------------------------------------------------------
from contextvars import ContextVar

_request_id: ContextVar[str] = ContextVar("request_id", default="")

def get_request_id() -> str:
    return _request_id.get()

# ---------------------------------------------------------------------
# Tiny in-memory rate limiter (single instance; swap later if needed)
# ---------------------------------------------------------------------
_RATE_BUCKET: Dict[str, List[float]] = {}

def _rate_limit(key: str, limit: int, per_seconds: int) -> None:
    now = time.time()
    q = _RATE_BUCKET.setdefault(key, [])
    # keep only timestamps within window
    q[:] = [t for t in q if now - t < per_seconds]
    if len(q) >= limit:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    q.append(now)

# ---------------------------------------------------------------------
# Principal
# ---------------------------------------------------------------------
@dataclass(frozen=True)
class Principal:
    sub: str
    role: Literal["viewer", "operator", "admin"]
    jti: Optional[str] = None

# ---------------------------------------------------------------------
# Key loading / JWT verify
# ---------------------------------------------------------------------
_PUBLIC_KEY_PEM: Optional[bytes] = None

def _load_public_key() -> bytes:
    if not JWT_PUBLIC_KEY_PATH:
        raise ValueError("SENTINEL_JWT_PUBLIC_KEY_PATH not configured")
    p = Path(JWT_PUBLIC_KEY_PATH)
    return p.read_bytes()

try:
    _PUBLIC_KEY_PEM = _load_public_key()
except Exception:
    # Keep service bootable for dev, but auth will fail until configured.
    _PUBLIC_KEY_PEM = None

def is_token_revoked(jti: str) -> bool:
    # Stub for revocation. Implement via DB/cache when ready.
    return False

def verify_jwt(token: str) -> Principal:
    """
    RS256 verification with basic replay/age protections.
    Required claims: exp, iat, sub, role, iss, aud
    Optional: nbf, jti
    """
    if not _PUBLIC_KEY_PEM:
        raise ValueError("Token verification unavailable (public key not loaded)")

    payload = jwt.decode(
        token,
        _PUBLIC_KEY_PEM,
        algorithms=["RS256"],
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
        options={"require": ["exp", "iat", "sub", "role"]},
        leeway=JWT_CLOCK_SKEW_SECONDS,
    )

    sub = payload.get("sub")
    role = payload.get("role")
    iat = payload.get("iat")
    exp = payload.get("exp")
    nbf = payload.get("nbf")
    jti = payload.get("jti")

    if not isinstance(sub, str) or not sub:
        raise ValueError("Invalid sub")
    if role not in VALID_ROLES:
        raise ValueError("Invalid role")
    if not isinstance(iat, int):
        raise ValueError("Missing/invalid iat")
    if not isinstance(exp, int):
        raise ValueError("Missing/invalid exp")

    now = int(time.time())

    # Too old = replay risk (even if still unexpired)
    if now - iat > JWT_MAX_AGE_SECONDS:
        raise ValueError("Token too old")

    # Future token not valid yet (if provided)
    if nbf is not None:
        if not isinstance(nbf, int):
            raise ValueError("Invalid nbf")
        if now < nbf:
            raise ValueError("Token not yet valid")

    if isinstance(jti, str) and jti:
        if is_token_revoked(jti):
            raise ValueError("Token revoked")

    return Principal(sub=sub, role=role, jti=jti)

def get_principal(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Principal:
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    try:
        return verify_jwt(creds.credentials)
    except Exception:
        # Don't leak crypto/config details to clients
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def require_role(*allowed: str):
    allowed_set = set(allowed)

    def _dep(p: Principal = Depends(get_principal)) -> Principal:
        if p.role not in allowed_set:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return p

    return _dep

# ---------------------------------------------------------------------
# DB helpers / schema + migrations (simple version table)
# ---------------------------------------------------------------------
@contextmanager
def db_conn() -> Iterable[sqlite3.Connection]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def _utc_ts() -> str:
    import datetime as _dt
    return _dt.datetime.utcnow().isoformat(timespec="microseconds") + "Z"

def db_init() -> None:
    with db_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );
            """
        )
        vrow = conn.execute("SELECT MAX(version) AS v FROM schema_version;").fetchone()
        current = int(vrow["v"] or 0)

        # v1: base tables
        if current < 1:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS event_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    module TEXT NOT NULL,
                    message TEXT NOT NULL,
                    context_json TEXT,
                    request_id TEXT
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
                    status TEXT NOT NULL,                -- PENDING/APPROVED/VETOED/EXPIRED/EXECUTED
                    decided_at TEXT,
                    decided_by TEXT,
                    decision_reason TEXT,
                    request_id TEXT
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_actions(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pending_created ON pending_actions(created_at);")
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?);",
                (1, _utc_ts()),
            )

def log_event(level: str, module: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
    if level not in VALID_LOG_LEVELS:
        level = "INFO"

    rid = get_request_id() or None
    ctx = json.dumps(context, default=str, separators=(",", ":"), ensure_ascii=False) if context else None

    with db_conn() as conn:
        conn.execute(
            """
            INSERT INTO event_logs (timestamp, level, module, message, context_json, request_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (_utc_ts(), level, module, message, ctx, rid),
        )

def read_tail(limit: int = 200) -> List[Dict[str, Any]]:
    limit = max(1, min(limit, 1000))
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, timestamp, level, module, message, context_json, request_id
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
                "request_id": r["request_id"],
            }
        )
    return items

# ---------------------------------------------------------------------
# API models (validated)
# ---------------------------------------------------------------------
class LogWrite(BaseModel):
    level: Literal["DEBUG", "INFO", "WARN", "ERROR"] = "INFO"
    module: str = Field(default="UI", min_length=1, max_length=50)
    message: str = Field(..., min_length=1, max_length=5000)
    context: Optional[Dict[str, Any]] = None

    @field_validator("context")
    @classmethod
    def validate_context_size(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if v is None:
            return None
        raw = json.dumps(v, default=str, separators=(",", ":"), ensure_ascii=False)
        if len(raw) > 10_000:
            raise ValueError("Context too large")
        return v

class PendingActionCreate(BaseModel):
    """
    Create a pending action that requires human approval.
    action_type examples: FIREWALL_BLOCK, DISABLE_ACCOUNT, RATE_LIMIT, etc.
    payload is arbitrary JSON (size-limited).
    """
    id: Optional[str] = Field(default=None, max_length=64)
    action_type: str = Field(..., min_length=1, max_length=80)
    payload: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not ACTION_ID_RE.match(v):
            raise ValueError("Invalid action id format")
        return v

    @field_validator("payload")
    @classmethod
    def validate_payload_size(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        raw = json.dumps(v, default=str, separators=(",", ":"), ensure_ascii=False)
        if len(raw) > 10_000:
            raise ValueError("Payload too large")
        return v

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
    request_id: Optional[str] = None

# ---------------------------------------------------------------------
# App
# ---------------------------------------------------------------------
app = FastAPI(title="Sentinel Pending Actions Gateway", version=VERSION)

# Optional CORS
cors_origins = [o.strip() for o in os.getenv("SENTINEL_CORS_ORIGINS", "").split(",") if o.strip()]
if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )

@app.middleware("http")
async def request_id_mw(request: Request, call_next):
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    _request_id.set(rid)
    resp = await call_next(request)
    resp.headers["X-Request-ID"] = rid
    return resp

@app.on_event("startup")
def _startup() -> None:
    db_init()
    log_event("INFO", "BOOT", f"[BOOT] {SYSTEM_ID} started", {"db_path": str(DB_PATH), "version": VERSION})

# ---------------------------------------------------------------------
# Health (public) with DB check
# ---------------------------------------------------------------------
@app.get("/api/v1/health", dependencies=[])
def health():
    checks: Dict[str, Any] = {"ok": False, "system_id": SYSTEM_ID, "version": VERSION, "database": False}
    try:
        with db_conn() as conn:
            conn.execute("SELECT 1").fetchone()
        checks["database"] = True
        checks["ok"] = True
        return JSONResponse(status_code=200, content=checks)
    except Exception:
        # Keep details out of client response
        return JSONResponse(status_code=503, content=checks)

# -------------------------
# Logs
# -------------------------
@app.get("/api/v1/logs/tail")
def logs_tail(limit: int = 200, _: Principal = Depends(require_role("viewer", "operator", "admin"))):
    # Rate limit per token subject (viewer read path still bounded)
    _rate_limit(f"logs_tail:{_.sub}", limit=120, per_seconds=60)
    try:
        return {"items": read_tail(limit)}
    except Exception:
        raise HTTPException(status_code=500, detail="Internal database error")

@app.post("/api/v1/logs")
def write_log(entry: LogWrite, p: Principal = Depends(require_role("operator", "admin"))):
    _rate_limit(f"write_log:{p.sub}", limit=60, per_seconds=60)
    ctx = entry.context or {}
    ctx.setdefault("operator", p.sub)
    log_event(entry.level, entry.module, entry.message, ctx)
    return {"ok": True}

# -------------------------
# Pending Actions
# -------------------------
def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

def _action_id() -> str:
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
        request_id=r["request_id"],
    )

@app.post("/api/v1/actions", response_model=PendingActionOut)
def create_action(body: PendingActionCreate, p: Principal = Depends(require_role("operator", "admin"))):
    _rate_limit(f"create_action:{p.sub}", limit=30, per_seconds=60)

    action_id = body.id or _action_id()
    created_at = _utc_ts()
    payload_json = json.dumps(body.payload, default=str, separators=(",", ":"), ensure_ascii=False)

    with db_conn() as conn:
        try:
            conn.execute(
                """
                INSERT INTO pending_actions
                (id, created_at, created_by, action_type, payload_json, status, request_id)
                VALUES (?, ?, ?, ?, ?, 'PENDING', ?)
                """,
                (action_id, created_at, p.sub, body.action_type, payload_json, get_request_id()),
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
    p: Principal = Depends(require_role("viewer", "operator", "admin")),
):
    _rate_limit(f"list_actions:{p.sub}", limit=120, per_seconds=60)

    limit = max(1, min(limit, 1000))
    status_filter = status_filter.upper()
    if status_filter not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status_filter}")

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
def get_action(action_id: str, p: Principal = Depends(require_role("viewer", "operator", "admin"))):
    _rate_limit(f"get_action:{p.sub}", limit=240, per_seconds=60)

    with db_conn() as conn:
        row = conn.execute("SELECT * FROM pending_actions WHERE id = ?", (action_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Action not found")
    return _row_to_action(row)

def _decide(action_id: str, p: Principal, new_status: str, reason: str) -> PendingActionOut:
    decided_at = _utc_ts()

    with db_conn() as conn:
        cur = conn.execute(
            """
            UPDATE pending_actions
            SET status = ?, decided_at = ?, decided_by = ?, decision_reason = ?, request_id = ?
            WHERE id = ? AND status = 'PENDING'
            """,
            (new_status, decided_at, p.sub, reason, get_request_id(), action_id),
        )
        if cur.rowcount == 0:
            row = conn.execute("SELECT id, status FROM pending_actions WHERE id = ?", (action_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Action not found")
            raise HTTPException(status_code=409, detail=f"Action is not pending (current: {row['status']})")

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
    _rate_limit(f"approve:{p.sub}", limit=60, per_seconds=60)
    return _decide(action_id, p, "APPROVED", body.reason)

@app.post("/api/v1/actions/{action_id}/veto", response_model=PendingActionOut)
def veto_action(action_id: str, body: PendingActionDecision, p: Principal = Depends(require_role("operator", "admin"))):
    _rate_limit(f"veto:{p.sub}", limit=60, per_seconds=60)
    return _decide(action_id, p, "VETOED", body.reason)