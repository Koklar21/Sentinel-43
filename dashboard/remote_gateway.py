from __future__ import annotations

import base64
import json
import os
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional

import jwt  # PyJWT
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
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
VERSION = os.getenv("SENTINEL_GATEWAY_VERSION", "0.4.0")

# ---------------------------------------------------------------------
# Auth (RS256 verification)
# ---------------------------------------------------------------------
JWT_ISSUER = os.getenv("SENTINEL_JWT_ISSUER", "sentinel")
JWT_AUDIENCE = os.getenv("SENTINEL_JWT_AUDIENCE", "sentinel-remote")
JWT_PUBLIC_KEY_PATH = os.getenv("SENTINEL_JWT_PUBLIC_KEY_PATH", "")
JWT_MAX_AGE_SECONDS = int(os.getenv("SENTINEL_JWT_MAX_AGE_SECONDS", "86400"))
JWT_CLOCK_SKEW_SECONDS = int(os.getenv("SENTINEL_JWT_CLOCK_SKEW_SECONDS", "60"))

security = HTTPBearer(auto_error=False)

VALID_ROLES = ("viewer", "operator", "admin")
VALID_STATUSES = {"PENDING", "STAGED", "APPROVED", "VETOED", "EXPIRED", "EXECUTED"}
ACTIONABLE_STATUSES = {"PENDING", "STAGED"}
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARN", "ERROR"}
ACTION_ID_RE = re.compile(r"^[A-Z0-9_-]{10,64}$")

_request_id: ContextVar[str] = ContextVar("request_id", default="")


def get_request_id() -> str:
    return _request_id.get()


# ---------------------------------------------------------------------
# Small in-memory rate limiter with cleanup
# ---------------------------------------------------------------------
_RATE_BUCKET: Dict[str, List[float]] = {}
_RATE_LAST_SWEEP = 0.0


def _rate_limit(key: str, limit: int, per_seconds: int) -> None:
    global _RATE_LAST_SWEEP
    now = time.time()

    # Avoid unbounded key growth. Single-process limiter, not a fortress.
    if now - _RATE_LAST_SWEEP > 60:
        stale_before = now - max(per_seconds, 300)
        for bucket_key in list(_RATE_BUCKET.keys()):
            _RATE_BUCKET[bucket_key] = [t for t in _RATE_BUCKET[bucket_key] if t >= stale_before]
            if not _RATE_BUCKET[bucket_key]:
                del _RATE_BUCKET[bucket_key]
        _RATE_LAST_SWEEP = now

    q = _RATE_BUCKET.setdefault(key, [])
    q[:] = [t for t in q if now - t < per_seconds]
    if len(q) >= limit:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    q.append(now)


# ---------------------------------------------------------------------
# Principal / JWT
# ---------------------------------------------------------------------
@dataclass(frozen=True)
class Principal:
    sub: str
    role: Literal["viewer", "operator", "admin"]
    jti: Optional[str] = None


_PUBLIC_KEY_PEM: Optional[bytes] = None


def _load_public_key() -> bytes:
    if not JWT_PUBLIC_KEY_PATH:
        raise ValueError("SENTINEL_JWT_PUBLIC_KEY_PATH not configured")
    return Path(JWT_PUBLIC_KEY_PATH).read_bytes()


try:
    _PUBLIC_KEY_PEM = _load_public_key()
except Exception:
    _PUBLIC_KEY_PEM = None


def verify_jwt(token: str) -> Principal:
    if not _PUBLIC_KEY_PEM:
        raise ValueError("Token verification unavailable")

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
    if not isinstance(iat, int) or not isinstance(exp, int):
        raise ValueError("Missing/invalid iat or exp")

    now = int(time.time())
    if now - iat > JWT_MAX_AGE_SECONDS:
        raise ValueError("Token too old")
    if nbf is not None:
        if not isinstance(nbf, int):
            raise ValueError("Invalid nbf")
        if now < nbf:
            raise ValueError("Token not yet valid")
    if isinstance(jti, str) and jti and is_token_revoked(jti):
        raise ValueError("Token revoked")

    return Principal(sub=sub, role=role, jti=jti if isinstance(jti, str) else None)


def get_principal(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Principal:
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    try:
        return verify_jwt(creds.credentials)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


def require_role(*allowed: str):
    allowed_set = set(allowed)

    def _dep(p: Principal = Depends(get_principal)) -> Principal:
        if p.role not in allowed_set:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return p

    return _dep


# ---------------------------------------------------------------------
# DB helpers / migrations
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

    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


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
                    status TEXT NOT NULL,
                    decided_at TEXT,
                    decided_by TEXT,
                    decision_reason TEXT,
                    request_id TEXT
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_actions(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pending_created ON pending_actions(created_at);")
            conn.execute("INSERT INTO schema_version (version, applied_at) VALUES (?, ?);", (1, _utc_ts()))
            current = 1

        if current < 2:
            # Token revocation table. This is not a full auth server, thank the silicon gods.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS revoked_tokens (
                    jti TEXT PRIMARY KEY,
                    revoked_at TEXT NOT NULL,
                    revoked_by TEXT NOT NULL,
                    reason TEXT
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_revoked_at ON revoked_tokens(revoked_at);")
            conn.execute("INSERT INTO schema_version (version, applied_at) VALUES (?, ?);", (2, _utc_ts()))
            current = 2

        # Defensive migration support for old hand-edited DBs.
        if "pending_actions" in {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}:
            cols = _table_columns(conn, "pending_actions")
            if "staged_at" not in cols:
                conn.execute("ALTER TABLE pending_actions ADD COLUMN staged_at TEXT;")
            if "staged_by" not in cols:
                conn.execute("ALTER TABLE pending_actions ADD COLUMN staged_by TEXT;")


def is_token_revoked(jti: str) -> bool:
    try:
        with db_conn() as conn:
            row = conn.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)).fetchone()
        return row is not None
    except Exception:
        # Fail closed if the revocation store is broken.
        return True


# ---------------------------------------------------------------------
# Log helpers
# ---------------------------------------------------------------------
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

    return [
        {
            "id": r["id"],
            "timestamp": r["timestamp"],
            "level": r["level"],
            "module": r["module"],
            "message": r["message"],
            "context": json.loads(r["context_json"]) if r["context_json"] else None,
            "request_id": r["request_id"],
        }
        for r in reversed(rows)
    ]


# ---------------------------------------------------------------------
# API models
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
    id: Optional[str] = Field(default=None, max_length=64)
    action_type: str = Field(..., min_length=1, max_length=80)
    payload: Dict[str, Any] = Field(default_factory=dict)
    stage_immediately: bool = False

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
    reason: str = Field(..., min_length=10, max_length=500)


class PendingActionOut(BaseModel):
    id: str
    created_at: str
    created_by: str
    action_type: str
    payload: Dict[str, Any]
    status: str
    staged_at: Optional[str] = None
    staged_by: Optional[str] = None
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
    decision_reason: Optional[str] = None
    request_id: Optional[str] = None


class ActionListOut(BaseModel):
    items: List[PendingActionOut]
    total: int
    limit: int
    offset: int
    status_filter: Optional[str] = None


class RevokeTokenIn(BaseModel):
    jti: str = Field(..., min_length=8, max_length=256)
    reason: Optional[str] = Field(default=None, max_length=500)


# ---------------------------------------------------------------------
# App
# ---------------------------------------------------------------------
app = FastAPI(title="Sentinel Pending Actions Gateway", version=VERSION)

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
    token = _request_id.set(rid)
    try:
        resp = await call_next(request)
        resp.headers["X-Request-ID"] = rid
        return resp
    finally:
        _request_id.reset(token)


@app.on_event("startup")
def _startup() -> None:
    db_init()
    log_event("INFO", "BOOT", f"[BOOT] {SYSTEM_ID} started", {"db_path": str(DB_PATH), "version": VERSION})


# ---------------------------------------------------------------------
# Health / readiness / dashboard support
# ---------------------------------------------------------------------
def _db_ok() -> bool:
    try:
        with db_conn() as conn:
            conn.execute("SELECT 1").fetchone()
        return True
    except Exception:
        return False


@app.get("/api/v1/health", dependencies=[])
def health():
    db_good = _db_ok()
    return JSONResponse(
        status_code=200 if db_good else 503,
        content={"ok": db_good, "system_id": SYSTEM_ID, "version": VERSION, "database": db_good},
    )


@app.get("/api/v1/ready", dependencies=[])
def ready():
    db_good = _db_ok()
    auth_configured = _PUBLIC_KEY_PEM is not None
    ready_state = db_good and auth_configured
    return JSONResponse(
        status_code=200 if ready_state else 503,
        content={
            "ready": ready_state,
            "database": db_good,
            "auth_configured": auth_configured,
            "system_id": SYSTEM_ID,
            "version": VERSION,
        },
    )


@app.get("/api/v1/vault/stats")
def vault_stats(_: Principal = Depends(require_role("viewer", "operator", "admin"))):
    try:
        with db_conn() as conn:
            action_count = conn.execute("SELECT COUNT(*) AS c FROM pending_actions").fetchone()["c"]
            log_count = conn.execute("SELECT COUNT(*) AS c FROM event_logs").fetchone()["c"]
            revoked_count = conn.execute("SELECT COUNT(*) AS c FROM revoked_tokens").fetchone()["c"]
        return {
            "records": int(action_count) + int(log_count) + int(revoked_count),
            "actions": int(action_count),
            "logs": int(log_count),
            "revoked_tokens": int(revoked_count),
        }
    except Exception:
        raise HTTPException(status_code=500, detail="Internal database error")


# ---------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------
@app.get("/api/v1/logs/tail")
def logs_tail(limit: int = 200, p: Principal = Depends(require_role("viewer", "operator", "admin"))):
    _rate_limit(f"logs_tail:{p.sub}", limit=120, per_seconds=60)
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


# ---------------------------------------------------------------------
# Pending actions
# ---------------------------------------------------------------------
def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _action_id() -> str:
    return _b64url_encode(os.urandom(16)).upper()


def _row_to_action(r: sqlite3.Row) -> PendingActionOut:
    return PendingActionOut(
        id=r["id"],
        created_at=r["created_at"],
        created_by=r["created_by"],
        action_type=r["action_type"],
        payload=json.loads(r["payload_json"]),
        status=r["status"],
        staged_at=r["staged_at"] if "staged_at" in r.keys() else None,
        staged_by=r["staged_by"] if "staged_by" in r.keys() else None,
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
    initial_status = "STAGED" if body.stage_immediately else "PENDING"
    staged_at = created_at if body.stage_immediately else None
    staged_by = p.sub if body.stage_immediately else None

    with db_conn() as conn:
        try:
            conn.execute(
                """
                INSERT INTO pending_actions
                (id, created_at, created_by, action_type, payload_json, status, staged_at, staged_by, request_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (action_id, created_at, p.sub, body.action_type, payload_json, initial_status, staged_at, staged_by, get_request_id()),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Action id already exists")
        row = conn.execute("SELECT * FROM pending_actions WHERE id = ?", (action_id,)).fetchone()

    log_event("INFO", "ACTIONS", f"[ACTIONS] CREATED: {action_id} ({body.action_type})", {"id": action_id, "by": p.sub, "status": initial_status})
    return _row_to_action(row)


@app.get("/api/v1/actions", response_model=List[PendingActionOut])
def list_actions(
    status_filter: Optional[str] = Query(default=None, description="Optional status filter. Omit for all statuses."),
    status_: Optional[str] = Query(default=None, alias="status", include_in_schema=False),
    limit: int = 250,
    offset: int = 0,
    p: Principal = Depends(require_role("viewer", "operator", "admin")),
):
    """Dashboard-compatible list endpoint. Returns a raw list because the current UI expects an array."""
    _rate_limit(f"list_actions:{p.sub}", limit=120, per_seconds=60)
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)

    raw_status = status_filter or status_
    params: list[Any] = []
    where = ""
    if raw_status:
        normalized = raw_status.upper()
        if normalized not in VALID_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid status: {normalized}")
        where = "WHERE status = ?"
        params.append(normalized)

    params.extend([limit, offset])
    with db_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT * FROM pending_actions
            {where}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            params,
        ).fetchall()
    return [_row_to_action(r) for r in rows]


@app.get("/api/v1/actions/page", response_model=ActionListOut)
def list_actions_page(
    status_filter: Optional[str] = None,
    limit: int = 250,
    offset: int = 0,
    p: Principal = Depends(require_role("viewer", "operator", "admin")),
):
    """Paginated endpoint for future UI/API clients that want metadata."""
    _rate_limit(f"list_actions_page:{p.sub}", limit=120, per_seconds=60)
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)

    params: list[Any] = []
    count_params: list[Any] = []
    where = ""
    normalized_status: Optional[str] = None
    if status_filter:
        normalized_status = status_filter.upper()
        if normalized_status not in VALID_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid status: {normalized_status}")
        where = "WHERE status = ?"
        params.append(normalized_status)
        count_params.append(normalized_status)

    params.extend([limit, offset])
    with db_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS c FROM pending_actions {where}", count_params).fetchone()["c"]
        rows = conn.execute(
            f"""
            SELECT * FROM pending_actions
            {where}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            params,
        ).fetchall()

    return ActionListOut(items=[_row_to_action(r) for r in rows], total=int(total), limit=limit, offset=offset, status_filter=normalized_status)


@app.get("/api/v1/actions/{action_id}", response_model=PendingActionOut)
def get_action(action_id: str, p: Principal = Depends(require_role("viewer", "operator", "admin"))):
    _rate_limit(f"get_action:{p.sub}", limit=240, per_seconds=60)
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM pending_actions WHERE id = ?", (action_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Action not found")
    return _row_to_action(row)


def _transition(action_id: str, p: Principal, allowed_from: set[str], new_status: str, reason: Optional[str] = None) -> PendingActionOut:
    now = _utc_ts()
    placeholders = ",".join("?" for _ in allowed_from)

    if new_status == "STAGED":
        sql = f"""
            UPDATE pending_actions
            SET status = ?, staged_at = ?, staged_by = ?, request_id = ?
            WHERE id = ? AND status IN ({placeholders})
        """
        values: list[Any] = [new_status, now, p.sub, get_request_id(), action_id, *allowed_from]
    else:
        sql = f"""
            UPDATE pending_actions
            SET status = ?, decided_at = ?, decided_by = ?, decision_reason = ?, request_id = ?
            WHERE id = ? AND status IN ({placeholders})
        """
        values = [new_status, now, p.sub, reason, get_request_id(), action_id, *allowed_from]

    with db_conn() as conn:
        cur = conn.execute(sql, values)
        if cur.rowcount == 0:
            row = conn.execute("SELECT id, status FROM pending_actions WHERE id = ?", (action_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Action not found")
            raise HTTPException(status_code=409, detail=f"Action cannot transition from {row['status']} to {new_status}")
        updated = conn.execute("SELECT * FROM pending_actions WHERE id = ?", (action_id,)).fetchone()

    log_context = {"id": action_id, "status": new_status, "by": p.sub}
    if reason:
        log_context["reason"] = reason
    log_event("INFO", "ACTIONS", f"[ACTIONS] {new_status}: {action_id} by {p.sub}", log_context)
    return _row_to_action(updated)


@app.post("/api/v1/actions/{action_id}/stage", response_model=PendingActionOut)
def stage_action(action_id: str, p: Principal = Depends(require_role("operator", "admin"))):
    _rate_limit(f"stage:{p.sub}", limit=60, per_seconds=60)
    return _transition(action_id, p, {"PENDING"}, "STAGED")


@app.post("/api/v1/actions/{action_id}/approve", response_model=PendingActionOut)
def approve_action(action_id: str, body: PendingActionDecision, p: Principal = Depends(require_role("operator", "admin"))):
    _rate_limit(f"approve:{p.sub}", limit=60, per_seconds=60)
    return _transition(action_id, p, {"STAGED"}, "APPROVED", body.reason)


@app.post("/api/v1/actions/{action_id}/veto", response_model=PendingActionOut)
def veto_action(action_id: str, body: PendingActionDecision, p: Principal = Depends(require_role("operator", "admin"))):
    _rate_limit(f"veto:{p.sub}", limit=60, per_seconds=60)
    return _transition(action_id, p, ACTIONABLE_STATUSES, "VETOED", body.reason)


@app.post("/api/v1/actions/{action_id}/execute", response_model=PendingActionOut)
def execute_action(action_id: str, body: PendingActionDecision, p: Principal = Depends(require_role("admin"))):
    _rate_limit(f"execute:{p.sub}", limit=30, per_seconds=60)
    return _transition(action_id, p, {"APPROVED"}, "EXECUTED", body.reason)


# ---------------------------------------------------------------------
# Admin revocation support
# ---------------------------------------------------------------------
@app.post("/api/v1/auth/revoke")
def revoke_token(body: RevokeTokenIn, p: Principal = Depends(require_role("admin"))):
    _rate_limit(f"revoke:{p.sub}", limit=30, per_seconds=60)
    with db_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO revoked_tokens (jti, revoked_at, revoked_by, reason)
            VALUES (?, ?, ?, ?)
            """,
            (body.jti, _utc_ts(), p.sub, body.reason),
        )
    log_event("WARN", "AUTH", f"[AUTH] REVOKED JTI: {body.jti}", {"jti": body.jti, "by": p.sub, "reason": body.reason})
    return {"ok": True}


@app.get("/")
def root():
    return {"service": "sentinel-43-gateway", "version": VERSION, "health": "/api/v1/health", "ready": "/api/v1/ready"}
