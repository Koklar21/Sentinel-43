// =============================================================================
// Sentinel-43 Dashboard
// dashboard.js
// UI logic module. WebSocket transport is handled by websocket.js which
// dispatches sentinel:ws:* events consumed here.
//
// Current live SPA behavior:
// - API_BASE defaults to the page origin unless explicitly configured.
// - Session access tokens are read from window.SentinelAuth.
// - Protected polling is gated on authenticated lifecycle events.
// - Cross-origin requests never receive Sentinel authentication headers.
//
// - Added: fetchJson() no longer attaches Authorization/X-S43-Password to
//   cross-origin requests. `credentials` was already gated to same-origin;
//   the auth headers were not, which meant a misconfigured API_BASE could
//   leak the raw operator password (not just a revocable JWT) to the
//   wrong origin.
// - Added: JWT injection modal (authBtn/jwtClear/jwtConfirm) now reads and
//   writes a password field alongside the token, routed through
//   window.SentinelAuth.applyManualCredentials() instead of writing
//   sessionStorage["SENTINEL_JWT"] directly. The old code bypassed
//   password storage entirely, leaving a token that looked valid in the
//   UI but 401'd on the first real request once the backend started
//   requiring both.
// - Added: updateStaticConfig()'s auth-state indicator now reflects
//   password presence too, not just token presence, so it can't tell the
//   operator they're authenticated when a real request would 401.
// - Added: stopProtectedActivity()/startProtectedActivity(), gated on
//   sentinel:auth:locked / sentinel:auth:ready (dispatched by auth.js
//   v1.6.0). Protected polling (actions/vault/watchtower) no longer fires
//   before login completes or continues after auth is lost.
// - Added: sentinel:ws:policy_error / sentinel:ws:protocol_error listeners
//   to surface websocket.js's split 1008/1011 close-code classification
//   in the operator-visible log console.
// - Changed: bottom initialization block replaced with async
//   initializeDashboard(), which awaits window.SentinelAuthReady before
//   starting any protected activity (demo mode is exempt — no real auth
//   applies there).
// =============================================================================
"use strict";

// =============================================================================
// Config
// =============================================================================
const _readMeta = name =>
    document.querySelector(`meta[name="${name}"]`)?.content?.trim() ?? "";

const _runtime = window.SENTINEL_RUNTIME_CONFIG ?? {};

const _locationIsLocal = ["", "localhost", "127.0.0.1", "::1"]
    .includes(location.hostname);

const CONFIG = Object.freeze({
    // Empty / unset => same origin as the page. That is the supported beta
    // setup (SPA served by the API behind the TLS proxy). `||` (not `??`) so
    // an empty meta tag / global also falls through to location.origin.
    API_BASE: String(
        _runtime.apiBase
        || window.SENTINEL_API_BASE_URL
        || _readMeta("sentinel-api-base")
        || location.origin
    ).replace(/\/+$/, ""),
    FALLBACK_POLL_MS: 15_000,
    DATA_STALE_MS:    60_000,
    REASON_MIN:       10,
    REASON_MAX:       500,
    MAX_LOG_LINES:    500,
    MAX_DEMO_ACTIONS: 500,
    DEMO_MODE: new URLSearchParams(location.search).get("demo") === "1",
    LIVE_TEST_MODE:
        _locationIsLocal &&
        new URLSearchParams(location.search).get("test") === "1",
    ALLOW_DEV_JWT_STORAGE: _locationIsLocal,
});

// =============================================================================
// Constants
// =============================================================================
const STATUS_CLASSES = Object.freeze({
    PENDING:  "pending",
    STAGED:   "staged",
    APPROVED: "approved",
    EXECUTED: "executed",
    VETOED:   "vetoed",
    EXPIRED:  "expired",
    UNKNOWN:  "unknown",
});

const SESSION_TOKEN_KEY = "SENTINEL_JWT";

const DEV_JWT_KEYS = Object.freeze([
    "S43_JWT",
    "S43_TOKEN",
    "s43_token",
    "s43_dashboard_token",
    "sentinel_token",
    "jwt",
    "token",
]);

const MODE_ALIASES = Object.freeze({
    SHADOW: "ADVISORY",
});

const WT_PROBE_MS = 30_000;

// =============================================================================
// Demo stubs (used when ?demo=1 is active)
// =============================================================================
const DEMO_WATCHTOWER = Object.freeze({
    overall: "degraded",
    subsystems: Object.freeze([
        { name: "Core Advisory Engine", status: "online",   latencyMs: 11, detail: "Advisory & decision routing" },
        { name: "Fenrir",               status: "online",   latencyMs: 7,  detail: "Threat hunting & behavioral analysis" },
        { name: "Governance Layer",     status: "online",   latencyMs: 5,  detail: "Mode control & gate enforcement" },
        { name: "Audit Layer",          status: "online",   latencyMs: 9,  detail: "Jormungandr audit chain" },
        { name: "WebSocket Bridge",     status: "degraded", latencyMs: 38, detail: "Live transport layer" },
        { name: "Database",             status: "online",   latencyMs: 14, detail: "PostgreSQL persistence" },
    ]),
});

const DEMO_SUMMARY = Object.freeze({
    totalAssessments: 142,
    criticalThreats:  3,
    totalDecisions:   31,
    fenrirSignals:    7,
    mode:             "HUMAN_GATED",
});

// =============================================================================
// Element References
// =============================================================================
const $ = id => document.getElementById(id);
const el = {
    statusDot:    $("statusDot"),
    statusText:   $("statusText"),
    modeText:     $("modeText"),
    modeAlias:    $("modeAlias"),
    queueCount:   $("queueCount"),
    lastSync:     $("lastSync"),
    pollFlash:    $("pollFlash"),
    demoBadge:    $("demoBadge"),
    jwtRiskBadge: $("jwtRiskBadge"),
    liveRegion:   $("liveRegion"),
    wtHeaderChip:   $("wtHeaderChip"),
    wtHeaderDot:    $("wtHeaderDot"),
    wtHeaderStatus: $("wtHeaderStatus"),
    pendingCount:  $("pendingCount"),
    stagedCount:   $("stagedCount"),
    approvedCount: $("approvedCount"),
    vaultCount:    $("vaultCount"),
    criticalThreats:  $("criticalThreats"),
    totalAssessments: $("totalAssessments"),
    totalDecisions:   $("totalDecisions"),
    fenrirSignals:    $("fenrirSignals"),
    apiBaseText:   $("apiBaseText"),
    authStateText: $("authStateText"),
    pollText:      $("pollText"),
    demoText:      $("demoText"),
    authorityStateText: $("authorityStateText"),
    ownerEngineText: $("ownerEngineText"),
    ownerComponentsText: $("ownerComponentsText"),
    externalExecText: $("externalExecText"),
    refreshBtn: $("refreshBtn"),
    injectBtn:  $("injectBtn"),
    exportBtn:  $("exportBtn"),
    themeBtn:   $("themeBtn"),
    authBtn:    $("authBtn"),
    kbHelpBtn:  $("kbHelpBtn"),
    wtGrid:       $("wtGrid"),
    wtOverall:    $("wtOverall"),
    wtProbeTime:  $("wtProbeTime"),
    wtRefreshBtn: $("wtRefreshBtn"),
    userCount:       $("userCount"),
    usersStatus:     $("usersStatus"),
    usersList:       $("usersList"),
    usersRefreshBtn: $("usersRefreshBtn"),
    createUserBtn:   $("createUserBtn"),
    userModal:       $("userModal"),
    userUsername:    $("userUsername"),
    userEmail:       $("userEmail"),
    userPassword:    $("userPassword"),
    userPasswordConfirm: $("userPasswordConfirm"),
    userModalError:  $("userModalError"),
    userCancel:      $("userCancel"),
    userConfirm:     $("userConfirm"),
    passwordResetModal: $("passwordResetModal"),
    passwordResetTitle: $("passwordResetTitle"),
    passwordResetInput: $("passwordResetInput"),
    passwordResetConfirmInput: $("passwordResetConfirmInput"),
    passwordResetError: $("passwordResetError"),
    passwordResetCancel: $("passwordResetCancel"),
    passwordResetConfirm: $("passwordResetConfirm"),
    actionsBody:    $("actionsBody"),
    emptyState:     $("emptyState"),
    searchInput:    $("searchInput"),
    clearSearchBtn: $("clearSearchBtn"),
    selectAll:      $("selectAll"),
    bulkBar:        $("bulkBar"),
    bulkLabel:      $("bulkLabel"),
    bulkApproveBtn: $("bulkApproveBtn"),
    bulkVetoBtn:    $("bulkVetoBtn"),
    bulkClearBtn:   $("bulkClearBtn"),
    logConsole: $("logConsole"),
    clearLogBtn: $("clearLogBtn"),
    reasonModal:    $("reasonModal"),
    modalTitle:     $("modalTitle"),
    modalSubtitle:  $("modalSubtitle"),
    modalInput:     $("modalInput"),
    modalError:     $("modalError"),
    modalCharCount: $("modalCharCount"),
    modalCancel:    $("modalCancel"),
    modalConfirm:   $("modalConfirm"),
    jwtModal:   $("jwtModal"),
    jwtInput:   $("jwtInput"),
    jwtCancel:  $("jwtCancel"),
    jwtClear:   $("jwtClear"),
    jwtConfirm: $("jwtConfirm"),
    injectModal:   $("injectModal"),
    injectCancel:  $("injectCancel"),
    injectConfirm: $("injectConfirm"),
    kbToast: $("kbToast"),
};

// =============================================================================
// State
// =============================================================================
let currentFilter    = "ALL";
let currentLogFilter = "ALL";
let searchQuery      = "";
let allActions       = [];
let selectedIds      = new Set();
let focusedRowIndex  = -1;
let focusedActionId  = null;
let prevCounts       = { pending: null, staged: null, approved: null };
let lastDataSyncAt   = null;
let refreshPromise   = null;
let pollTimer        = null;
let watchtowerTimer  = null;
let watchtowerProbeInFlight = false;
let kbToastTimer     = null;
let injectInFlight   = false;
let wsConnected      = false;
let isLight          = false;
let managedUsers     = [];
let userManagementAvailable = false;
let passwordResetTarget = null;
let userMutationInFlight = false;

// =============================================================================
// Utilities
// =============================================================================
const nowStamp = () =>
    new Date().toLocaleTimeString([], {
        hour:   "2-digit",
        minute: "2-digit",
        second: "2-digit",
    });

const escHtml = value =>
    String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");

const normalizeString = (value, fallback = "") =>
    typeof value === "string" ? value : value == null ? fallback : String(value);

// =============================================================================
// Logging
// =============================================================================
function log(message, type = "info") {
    if (!el.logConsole) return;
    const safeType = ["info", "ok", "warn", "err"].includes(type) ? type : "info";
    const line = document.createElement("div");
    line.className = `log-line ${safeType}`;
    line.dataset.type = safeType;
    const ts = document.createElement("span");
    ts.className = "log-ts";
    ts.textContent = nowStamp();
    const lvl = document.createElement("span");
    lvl.className = "log-lvl";
    lvl.textContent = safeType.toUpperCase();
    const msg = document.createElement("span");
    msg.className = "log-msg";
    msg.textContent = normalizeString(message, "Unknown dashboard event");
    line.append(ts, lvl, msg);
    if (currentLogFilter !== "ALL" && safeType !== currentLogFilter) {
        line.hidden = true;
    }
    el.logConsole.appendChild(line);
    if ((safeType === "warn" || safeType === "err") && el.liveRegion) {
        el.liveRegion.textContent = msg.textContent;
    }
    while (el.logConsole.children.length > CONFIG.MAX_LOG_LINES) {
        el.logConsole.removeChild(el.logConsole.firstElementChild);
    }
    el.logConsole.scrollTop = el.logConsole.scrollHeight;
}

// =============================================================================
// Status / UI Helpers
// =============================================================================
function setStatus(state) {
    const normalized = normalizeString(state, "unknown").toLowerCase();
    if (el.statusText) el.statusText.textContent = normalized.toUpperCase();
    if (!el.statusDot) return;
    el.statusDot.classList.remove("online", "offline");
    if (["online", "live"].includes(normalized)) el.statusDot.classList.add("online");
    if (normalized === "offline") el.statusDot.classList.add("offline");
}

function flashPoll() {
    if (!el.pollFlash) return;
    el.pollFlash.classList.add("flash");
    setTimeout(() => el.pollFlash?.classList.remove("flash"), 600);
}

function bumpStat(node) {
    if (!node) return;
    node.classList.add("bump");
    setTimeout(() => node.classList.remove("bump"), 250);
}

function markDataSync(source) {
    lastDataSyncAt = new Date();
    if (el.lastSync) el.lastSync.textContent = `${source} ${nowStamp()}`;
    flashPoll();
}

function dataIsStale() {
    return !lastDataSyncAt ||
        Date.now() - lastDataSyncAt.getTime() > CONFIG.DATA_STALE_MS;
}

// =============================================================================
// Auth / API Helpers
// =============================================================================
function _readStoredToken(storage, key) {
    try {
        const value = storage.getItem(key);
        return value && value.trim() ? value.trim() : null;
    } catch {
        return null;
    }
}

function getDevTokenInfo() {
    // Real session token: held in memory by auth.js, never persisted.
    try {
        const t = window.SentinelAuth?.getToken?.();
        if (typeof t === "string" && t.trim()) {
            return { token: t.trim(), isRealSession: true };
        }
    } catch {}

    // Back-compat: a token left in sessionStorage by an older auth.js build.
    const sessionToken = _readStoredToken(sessionStorage, SESSION_TOKEN_KEY);
    if (sessionToken) return { token: sessionToken, isRealSession: true };

    if (!CONFIG.ALLOW_DEV_JWT_STORAGE) return { token: null, isRealSession: false };

    for (const key of DEV_JWT_KEYS) {
        const token = _readStoredToken(sessionStorage, key);
        if (token) return { token, isRealSession: false };
    }
    for (const key of DEV_JWT_KEYS) {
        const token = _readStoredToken(localStorage, key);
        if (token) return { token, isRealSession: false };
    }
    try {
        if (typeof window.SENTINEL_JWT === "string" && window.SENTINEL_JWT.trim()) {
            return { token: window.SENTINEL_JWT.trim(), isRealSession: false };
        }
        if (
            typeof window.S43_DASHBOARD_TOKEN === "string" &&
            window.S43_DASHBOARD_TOKEN.trim()
        ) {
            return { token: window.S43_DASHBOARD_TOKEN.trim(), isRealSession: false };
        }
    } catch {
        return { token: null, isRealSession: false };
    }
    return { token: null, isRealSession: false };
}

function getDevToken() {
    return getDevTokenInfo().token;
}

function getAuthHeaders() {
    const headers = { "Content-Type": "application/json" };
    const token = getDevToken();
    if (token) headers.Authorization = `Bearer ${token}`;
    const password = window.SentinelAuth?.getPassword?.();
    if (password) headers["X-S43-Password"] = password;
    return headers;
}

function buildApiUrl(path) {
    if (typeof path !== "string" || !path.startsWith("/")) {
        throw new Error("API path must be relative");
    }
    if (path.includes("\r") || path.includes("\n")) {
        throw new Error("API path contains invalid characters");
    }
    return new URL(`${CONFIG.API_BASE}${path}`, location.href);
}

async function fetchJson(path, opts = {}) {
    const url = buildApiUrl(path);
    const sameOrigin = url.origin === location.origin;

    const authHeaders = sameOrigin
        ? getAuthHeaders()
        : { "Content-Type": "application/json" };

    const response = await fetch(url.toString(), {
        ...opts,
        cache: "no-store",
        credentials: sameOrigin ? "include" : "omit",
        headers: {
            ...authHeaders,
            "Cache-Control": "no-cache",
            ...(opts.headers ?? {}),
        },
    });

    const contentType = response.headers.get("content-type") ?? "";
    const isJson = contentType.includes("application/json");
    if (!response.ok) {
        let detail = "";
        if (isJson) {
            try {
                const body = await response.json();
                detail = normalizeString(
                    body?.detail ?? body?.error ?? body?.message, ""
                ).slice(0, 240);
            } catch {}
        }
        throw new Error(
            `${response.status} ${response.statusText}${detail ? `: ${detail}` : ""}`
        );
    }
    return isJson ? response.json() : null;
}

function unwrapData(value) {
    return value && typeof value === "object" && !Array.isArray(value) && "data" in value
        ? value.data
        : value;
}

function extractActionList(value) {
    const u = unwrapData(value);
    if (Array.isArray(u)) return u;
    if (u && typeof u === "object" && Array.isArray(u.actions)) return u.actions;
    throw new Error("Action endpoint returned an invalid payload shape");
}

function extractVaultRecords(value) {
    const u = unwrapData(value);
    return u && typeof u.records === "number" ? u.records : null;
}

// =============================================================================
// WebSocket Live State
// =============================================================================
function markWebSocketLive(type = "connected") {
    wsConnected = true;
    setStatus("Live");
    log("WebSocket live. Queue updates active.", "ok");
}

// =============================================================================
// Demo Backend (?demo=1 only)
// =============================================================================
const demoBackend = (() => {
    const store = new Map();
    const genId = () =>
        `ACT-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`.toUpperCase();

    function trimStore() {
        while (store.size > CONFIG.MAX_DEMO_ACTIONS) {
            store.delete(store.keys().next().value);
        }
    }

    function make(opts = {}) {
        const item = {
            id:              genId(),
            action_type:     opts.action_type     ?? "THREAT_ACTION",
            status:          opts.status          ?? (Math.random() > 0.5 ? "PENDING" : "STAGED"),
            created_at:      opts.created_at      ?? new Date().toISOString(),
            decision_reason: opts.decision_reason ?? "",
            operator:        opts.operator        ?? "",
            payload: {
                ip:        opts.ip     ?? "203.0.113.10",
                source_ip: opts.ip     ?? "203.0.113.10",
                threat:    opts.threat ?? "Suspicious activity",
            },
        };
        store.set(item.id, item);
        trimStore();
        return item;
    }

    make({ threat: "SQL injection pattern",         ip: "198.51.100.22", status: "PENDING" });
    make({ threat: "Credential stuffing detected",   ip: "203.0.113.77",  status: "STAGED" });
    make({
        threat: "High-rate port probe",
        ip: "192.0.2.41",
        status: "APPROVED",
        decision_reason: "Confirmed scanner - allowlisted",
        operator: "ops@sentinel",
    });
    make({ threat: "XSS payload in user-agent", ip: "198.51.100.9", status: "PENDING" });
    make({
        threat: "Tor exit-node connection",
        ip: "10.0.0.7",
        status: "VETOED",
        decision_reason: "Internal test - false positive",
        operator: "sec@sentinel",
    });

    return {
        listActions: async () =>
            Array.from(store.values())
                .sort((a, b) => new Date(b.created_at) - new Date(a.created_at)),
        approve: async (id, reason) => {
            const item = store.get(id);
            if (!item) throw new Error("Not found");
            if (item.status !== "STAGED") throw new Error("Only staged actions can be approved");
            item.status = "APPROVED";
            item.decision_reason = reason;
            item.operator = "operator";
            return { ok: true };
        },
        veto: async (id, reason) => {
            const item = store.get(id);
            if (!item) throw new Error("Not found");
            if (!["PENDING", "STAGED"].includes(item.status)) {
                throw new Error("Only pending/staged actions can be vetoed");
            }
            item.status = "VETOED";
            item.decision_reason = reason;
            item.operator = "operator";
            return { ok: true };
        },
        inject: async () => {
            make({
                threat: "Injected test incident",
                ip: "203.0.113.88",
                status: Math.random() > 0.5 ? "PENDING" : "STAGED",
            });
            return { ok: true };
        },
        vaultStats: async () => ({ records: 12487 }),
    };
})();

// =============================================================================
// API
// =============================================================================
const api = {
    listActions: () =>
        CONFIG.DEMO_MODE
            ? demoBackend.listActions()
            : fetchJson("/actions?limit=250"),
    vaultStats: () =>
        CONFIG.DEMO_MODE
            ? demoBackend.vaultStats()
            : fetchJson("/vault/stats"),
    approve: (id, reason) =>
        CONFIG.DEMO_MODE
            ? demoBackend.approve(id, reason)
            : fetchJson(`/actions/${encodeURIComponent(id)}/approve`, {
                method: "POST",
                body: JSON.stringify({ reason }),
            }),
    veto: (id, reason) =>
        CONFIG.DEMO_MODE
            ? demoBackend.veto(id, reason)
            : fetchJson(`/actions/${encodeURIComponent(id)}/veto`, {
                method: "POST",
                body: JSON.stringify({ reason }),
            }),
    inject: () =>
        CONFIG.DEMO_MODE
            ? demoBackend.inject()
            : CONFIG.LIVE_TEST_MODE
                ? fetchJson("/actions/test-inject", { method: "POST" })
                : Promise.reject(new Error("Inject requires demo or local test mode")),
    watchtowerStatus: () =>
        CONFIG.DEMO_MODE
            ? Promise.resolve({ ...DEMO_WATCHTOWER, subsystems: [...DEMO_WATCHTOWER.subsystems] })
            : fetchJson("/watchtower/status"),
    dashboardSummary: () =>
        CONFIG.DEMO_MODE
            ? Promise.resolve({ ...DEMO_SUMMARY })
            : Promise.resolve(null),
    systemStatus: () =>
        CONFIG.DEMO_MODE
            ? Promise.resolve(null)
            : fetchJson("/system/status"),
    listUsers: () =>
        CONFIG.DEMO_MODE
            ? Promise.resolve([])
            : fetchJson("/users?limit=500"),
    createUser: payload =>
        fetchJson("/users", {
            method: "POST",
            body: JSON.stringify(payload),
        }),
    updateUser: (userId, payload) =>
        fetchJson(`/users/${encodeURIComponent(userId)}`, {
            method: "PATCH",
            body: JSON.stringify(payload),
        }),
    resetUserPassword: (userId, newPassword) =>
        fetchJson(`/users/${encodeURIComponent(userId)}/password`, {
            method: "POST",
            body: JSON.stringify({ new_password: newPassword }),
        }),
};

// =============================================================================
// Action Normalization
// =============================================================================
function normalizeAction(raw) {
    const payload =
        raw?.payload && typeof raw.payload === "object" && !Array.isArray(raw.payload)
            ? raw.payload
            : {};
    const id = normalizeString(raw?.id, "").trim();
    const createdRaw = normalizeString(raw?.created_at, "");
    const parsed = Date.parse(createdRaw);
    const createdBad = !createdRaw || Number.isNaN(parsed);
    if (!id) log("Backend returned action without id.", "warn");
    if (createdBad) {
        log(`Action ${id || "<missing-id>"} has missing or invalid created_at.`, "warn");
    }
    return {
        id,
        threat:         normalizeString(payload.threat ?? raw?.action_type, "UNKNOWN"),
        source:         normalizeString(payload.source_ip ?? payload.ip, "n/a"),
        status:         normalizeString(raw?.status, "UNKNOWN").toUpperCase(),
        createdAt:      createdBad ? null : new Date(parsed).toISOString(),
        createdRaw,
        createdBad,
        decisionReason: normalizeString(raw?.decision_reason, ""),
        operator:       normalizeString(raw?.operator, ""),
        payload,
    };
}

const actionTimeValue = a => a.createdAt ? Date.parse(a.createdAt) : 0;

// =============================================================================
// Action Store Operations
// =============================================================================
function reconcileSelectedIds() {
    const validIds = new Set(allActions.map(a => a.id).filter(Boolean));
    const before = selectedIds.size;
    selectedIds = new Set([...selectedIds].filter(id => validIds.has(id)));
    if (selectedIds.size !== before) {
        log("Removed stale selections no longer in the live queue.", "info");
    }
}

function replaceActions(rawActions, source) {
    allActions = extractActionList(rawActions)
        .map(normalizeAction)
        .sort((a, b) => actionTimeValue(b) - actionTimeValue(a));
    reconcileSelectedIds();
    updateStats();
    renderActions();
    markDataSync(source);
}

function upsertAction(rawAction, source = "ws-sync") {
    const action = normalizeAction(rawAction);
    if (!action.id) return;
    const idx = allActions.findIndex(a => a.id === action.id);
    if (idx >= 0) allActions[idx] = action;
    else allActions.push(action);
    allActions.sort((a, b) => actionTimeValue(b) - actionTimeValue(a));
    reconcileSelectedIds();
    updateStats();
    renderActions();
    markDataSync(source);
}

function removeAction(actionId, source = "ws-sync") {
    const cleaned = normalizeString(actionId, "").trim();
    if (!cleaned) return;
    allActions = allActions.filter(a => a.id !== cleaned);
    reconcileSelectedIds();
    updateStats();
    renderActions();
    markDataSync(source);
}

// =============================================================================
// Filters
// =============================================================================
function applyFilters(actions) {
    let out = currentFilter === "ALL"
        ? actions
        : actions.filter(a => a.status === currentFilter);
    const q = searchQuery.trim().toLowerCase();
    if (q) {
        out = out.filter(a =>
            a.id.toLowerCase().includes(q) ||
            a.threat.toLowerCase().includes(q) ||
            a.source.toLowerCase().includes(q)
        );
    }
    return out;
}

function visibleActionIds() {
    return new Set(applyFilters(allActions).map(a => a.id));
}

// =============================================================================
// Stats
// =============================================================================
function updateStats() {
    const pending  = allActions.filter(a => a.status === "PENDING").length;
    const staged   = allActions.filter(a => a.status === "STAGED").length;
    const approved = allActions.filter(a =>
        ["APPROVED", "EXECUTED"].includes(a.status)).length;

    if (pending !== prevCounts.pending && el.pendingCount) {
        bumpStat(el.pendingCount);
        el.pendingCount.textContent = pending;
    }
    if (staged !== prevCounts.staged && el.stagedCount) {
        bumpStat(el.stagedCount);
        el.stagedCount.textContent = staged;
    }
    if (approved !== prevCounts.approved && el.approvedCount) {
        bumpStat(el.approvedCount);
        el.approvedCount.textContent = approved;
    }
    prevCounts = { pending, staged, approved };
    if (el.queueCount) el.queueCount.textContent = pending + staged;

    for (const [key, value] of Object.entries({
        ALL:      allActions.length,
        PENDING:  pending,
        STAGED:   staged,
        APPROVED: approved,
        VETOED:   allActions.filter(a => a.status === "VETOED").length,
    })) {
        const target = $(`fc-${key}`);
        if (target) target.textContent = value > 0 ? ` (${value})` : "";
    }
}

// =============================================================================
// Selection Management
// =============================================================================
function updateSelectAllState() {
    const boxes = Array.from(document.querySelectorAll(".row-cb"));
    const checked = boxes.filter(b => b.checked).length;
    if (el.selectAll) {
        el.selectAll.checked = boxes.length > 0 && checked === boxes.length;
        el.selectAll.indeterminate = checked > 0 && checked < boxes.length;
    }
}

function updateBulkBar() {
    const count = selectedIds.size;
    const visibleIds = visibleActionIds();
    const hidden = [...selectedIds].filter(id => !visibleIds.has(id)).length;
    el.bulkBar?.classList.toggle("visible", count > 0);
    if (el.bulkLabel) {
        el.bulkLabel.textContent = hidden
            ? `${count} selected (${hidden} hidden by filter/search)`
            : `${count} selected`;
    }
    const selected = [...selectedIds]
        .map(id => allActions.find(a => a.id === id))
        .filter(Boolean);
    if (el.bulkApproveBtn) {
        el.bulkApproveBtn.disabled = !selected.some(canApproveAction);
    }
    if (el.bulkVetoBtn) {
        el.bulkVetoBtn.disabled = !selected.some(a =>
            ["PENDING", "STAGED"].includes(a.status));
    }
    updateSelectAllState();
}

function clearSelection() {
    selectedIds.clear();
    document.querySelectorAll(".row-cb").forEach(b => {
        b.checked = false;
        b.closest("tr")?.classList.remove("selected");
    });
    if (el.selectAll) {
        el.selectAll.checked = false;
        el.selectAll.indeterminate = false;
    }
    updateBulkBar();
}

// =============================================================================
// Row Focus Navigation
// =============================================================================
function resetFocus() {
    focusedRowIndex = -1;
    focusedActionId = null;
    document.querySelectorAll("tr.focused").forEach(r => r.classList.remove("focused"));
}

function visibleRows() {
    return Array.from(el.actionsBody?.querySelectorAll("tr[data-id]:not(.expand-row)") ?? []);
}

function setFocusedRow(index) {
    const rows = visibleRows();
    rows.forEach(r => r.classList.remove("focused"));
    if (!rows.length) {
        resetFocus();
        return;
    }
    focusedRowIndex = Math.max(0, Math.min(index, rows.length - 1));
    const row = rows[focusedRowIndex];
    focusedActionId = row.dataset.id ?? null;
    row.classList.add("focused");
    row.scrollIntoView({ block: "nearest" });
}

function restoreFocus(previousId) {
    if (!previousId) {
        resetFocus();
        return;
    }
    const rows = visibleRows();
    const idx = rows.findIndex(r => r.dataset.id === previousId);
    if (idx < 0) {
        resetFocus();
        return;
    }
    setFocusedRow(idx);
}

// =============================================================================
// Approval availability (set by the orchestration core; the server enforces it)
// =============================================================================
function approvalBlock(action) {
    const approval = action?.payload?.approval;
    if (!approval || approval.available !== false) return null;
    const reasons = Array.isArray(approval.reasons) ? approval.reasons : [];
    return reasons.length ? reasons : ["Approval is unavailable for this recommendation."];
}

function canApproveAction(action) {
    return action?.status === "STAGED" && !approvalBlock(action);
}

// =============================================================================
// Render
// =============================================================================
function renderActions() {
    if (!el.actionsBody || !el.emptyState) return;
    const previousFocusId = focusedActionId;
    const actions = applyFilters(allActions);
    el.actionsBody.innerHTML = "";
    el.emptyState.hidden = Boolean(actions.length);
    if (!actions.length) {
        resetFocus();
        updateBulkBar();
        return;
    }
    for (const [index, action] of actions.entries()) {
        const row = document.createElement("tr");
        row.dataset.id = action.id;
        row.dataset.idx = String(index);
        if (selectedIds.has(action.id)) row.classList.add("selected");
        const statusClass = STATUS_CLASSES[action.status] ?? "unknown";
        const created = action.createdAt
            ? new Date(action.createdAt).toLocaleString([], { dateStyle: "short", timeStyle: "short" })
            : "MISSING";
        const createdStyle = action.createdBad
            ? "color:var(--red);font-size:10px;"
            : "color:var(--muted);font-size:10px;";
        const canApprove = canApproveAction(action);
        const blocked = action.status === "STAGED" ? approvalBlock(action) : null;
        const canVeto = ["PENDING", "STAGED"].includes(action.status);
        const controls = canApprove || canVeto
            ? `<div class="act-btns">` +
              (canApprove
                  ? `<button class="btn green" type="button" style="padding:3px 7px" data-approve="${escHtml(action.id)}" aria-label="Approve ${escHtml(action.id)}" title="Approve (A)">✓</button>`
                  : "") +
              (blocked
                  ? `<span class="tag unknown" style="padding:3px 6px;cursor:help" title="${escHtml("Approval unavailable: " + blocked.join(" | "))}" aria-label="Approval unavailable for ${escHtml(action.id)}">no approve</span>`
                  : "") +
              (canVeto
                  ? `<button class="btn red" type="button" style="padding:3px 7px" data-veto="${escHtml(action.id)}" aria-label="Veto ${escHtml(action.id)}" title="Veto (V)">✕</button>`
                  : "") +
              `</div>`
            : `<span style="color:var(--muted);font-size:10px;font-family:var(--font-mono);">${escHtml(action.operator) || "—"}</span>`;
        row.innerHTML =
            `<td><input type="checkbox" class="row-cb" data-id="${escHtml(action.id)}"${selectedIds.has(action.id) ? " checked" : ""} aria-label="Select ${escHtml(action.id)}"></td>` +
            `<td><button class="expand-btn" type="button" data-expand="${escHtml(action.id)}" aria-label="Expand ${escHtml(action.id)}">▶</button></td>` +
            `<td class="mono" style="color:var(--cyan)">${escHtml(action.id || "<missing>")}</td>` +
            `<td>${escHtml(action.threat)}</td>` +
            `<td class="mono" style="color:var(--muted)">${escHtml(action.source)}</td>` +
            `<td><span class="tag ${statusClass}">${escHtml(action.status)}</span></td>` +
            `<td class="mono" style="${createdStyle}">${escHtml(created)}</td>` +
            `<td class="reason-cell" title="${escHtml(action.decisionReason)}">${action.decisionReason ? escHtml(action.decisionReason) : '<span style="color:var(--muted)">—</span>'}</td>` +
            `<td class="sticky-actions">${controls}</td>`;
        el.actionsBody.appendChild(row);
    }
    restoreFocus(previousFocusId);
    updateBulkBar();
}

// =============================================================================
// Expand Rows
// =============================================================================
function renderRecommendationDetail(action) {
    const rec = action?.payload?.recommendation;
    const approval = action?.payload?.approval;
    const incidentId = action?.payload?.incident_id;
    const principal = action?.payload?.principal;
    if (!rec && !approval && !incidentId && !principal) return "";
    const blocked = approvalBlock(action);
    const approvalText = blocked
        ? "UNAVAILABLE — " + blocked.join(" | ")
        : (approval ? "available" : "—");
    const items = Array.isArray(rec?.items) ? rec.items : [];
    const itemsText = items.length
        ? items.map(i => `${i.engine_action}: ${i.status}` + (i.meaning ? ` — ${i.meaning}` : "")).join("\n")
        : "—";
    return `<div class="expand-kv"><div class="k">APPROVAL</div><div class="v">${escHtml(approvalText)}</div></div>` +
        (principal
            ? `<div class="expand-kv"><div class="k">ACCOUNT</div><div class="v">${escHtml(principal)}</div></div>`
            : "") +
        `<div class="expand-kv"><div class="k">RECOMMENDED</div><div class="v" style="white-space:pre-wrap">${escHtml(itemsText)}</div></div>` +
        (incidentId
            ? `<div class="expand-kv"><div class="k">INCIDENT</div><div class="v">${escHtml(incidentId)}</div></div>`
            : "");
}

function toggleExpand(actionId) {
    const existing = el.actionsBody?.querySelector(`.expand-row[data-for="${CSS.escape(actionId)}"]`);
    const button = el.actionsBody?.querySelector(`[data-expand="${CSS.escape(actionId)}"]`);
    if (existing) {
        existing.remove();
        if (button) button.textContent = "▶";
        return;
    }
    const action = allActions.find(a => a.id === actionId);
    const row = el.actionsBody?.querySelector(`tr[data-id="${CSS.escape(actionId)}"]`);
    if (!action || !row) return;
    const expansion = document.createElement("tr");
    expansion.className = "expand-row";
    expansion.dataset.for = actionId;
    expansion.innerHTML =
        `<td colspan="9"><div class="expand-inner">` +
        `<div class="expand-kv"><div class="k">ACTION ID</div><div class="v">${escHtml(action.id)}</div></div>` +
        `<div class="expand-kv"><div class="k">SOURCE IP</div><div class="v">${escHtml(action.source)}</div></div>` +
        `<div class="expand-kv"><div class="k">THREAT</div><div class="v">${escHtml(action.threat)}</div></div>` +
        `<div class="expand-kv"><div class="k">STATUS</div><div class="v">${escHtml(action.status)}</div></div>` +
        `<div class="expand-kv"><div class="k">CREATED</div><div class="v">${escHtml(action.createdAt ?? "MISSING / INVALID")}</div></div>` +
        `<div class="expand-kv"><div class="k">OPERATOR</div><div class="v">${escHtml(action.operator || "—")}</div></div>` +
        `<div class="expand-kv"><div class="k">REASON</div><div class="v">${escHtml(action.decisionReason || "—")}</div></div>` +
        renderRecommendationDetail(action) +
        `</div></td>`;
    row.after(expansion);
    if (button) button.textContent = "▼";
}

// =============================================================================
// Reason Modal
// =============================================================================
function validateReason(value) {
    const cleaned = normalizeString(value, "").trim();
    if (!cleaned) return "Reason is required.";
    if (cleaned.length < CONFIG.REASON_MIN) return `Minimum ${CONFIG.REASON_MIN} characters required.`;
    if (cleaned.length > CONFIG.REASON_MAX) return `Maximum ${CONFIG.REASON_MAX} characters.`;
    return null;
}

function openReasonModal({ title, subtitle, confirmText, confirmClass = "green" }) {
    return new Promise(resolve => {
        if (!el.reasonModal) {
            resolve(null);
            return;
        }
        el.modalTitle.textContent = title;
        el.modalSubtitle.textContent = subtitle;
        el.modalInput.value = "";
        el.modalCharCount.textContent = `0 / ${CONFIG.REASON_MAX}`;
        el.modalError.textContent = "";
        el.modalConfirm.textContent = confirmText;
        el.modalConfirm.className = `btn ${confirmClass}`;
        el.reasonModal.hidden = false;
        el.reasonModal.setAttribute("aria-hidden", "false");
        setTimeout(() => el.modalInput.focus(), 0);

        const close = result => {
            cleanup();
            el.reasonModal.hidden = true;
            el.reasonModal.setAttribute("aria-hidden", "true");
            el.modalError.textContent = "";
            resolve(result);
        };
        const onInput = () => {
            el.modalCharCount.textContent = `${el.modalInput.value.length} / ${CONFIG.REASON_MAX}`;
            if (el.modalError.textContent) el.modalError.textContent = "";
        };
        const onCancel = () => close(null);
        const onConfirm = () => {
            const err = validateReason(el.modalInput.value);
            if (err) {
                el.modalError.textContent = err;
                return;
            }
            close(el.modalInput.value.trim());
        };
        const onBackdrop = e => {
            if (e.target.hasAttribute("data-close")) onCancel();
        };
        const onKey = e => {
            if (e.key === "Escape") onCancel();
            if ((e.ctrlKey || e.metaKey) && e.key === "Enter") onConfirm();
        };
        function cleanup() {
            el.modalInput.removeEventListener("input", onInput);
            el.modalCancel.removeEventListener("click", onCancel);
            el.modalConfirm.removeEventListener("click", onConfirm);
            el.reasonModal.removeEventListener("click", onBackdrop);
            document.removeEventListener("keydown", onKey);
        }
        el.modalInput.addEventListener("input", onInput);
        el.modalCancel.addEventListener("click", onCancel);
        el.modalConfirm.addEventListener("click", onConfirm);
        el.reasonModal.addEventListener("click", onBackdrop);
        document.addEventListener("keydown", onKey);
    });
}

// =============================================================================
// Governance Mode
// =============================================================================
function setGovernanceMode(mode) {
    const normalized = normalizeString(mode, "UNKNOWN").toUpperCase();
    if (el.modeText) el.modeText.textContent = normalized;
    const alias = MODE_ALIASES[normalized] ?? null;
    if (el.modeAlias) {
        el.modeAlias.textContent = alias ?? "";
        el.modeAlias.classList.toggle("visible", alias !== null);
    }
}

function renderAuthorityProvenance(systemStatus) {
    const authority =
        systemStatus &&
        typeof systemStatus === "object" &&
        !Array.isArray(systemStatus)
            ? systemStatus.sentinel43_authority
            : null;

    if (!authority || typeof authority !== "object") {
        if (el.authorityStateText) el.authorityStateText.textContent = "UNAVAILABLE";
        if (el.ownerEngineText) el.ownerEngineText.textContent = "UNAVAILABLE";
        if (el.ownerComponentsText) el.ownerComponentsText.textContent = "UNAVAILABLE";
        if (el.externalExecText) el.externalExecText.textContent = "UNKNOWN";
        return;
    }

    const authorityName = normalizeString(
        authority.authority,
        "Sentinel43RuntimeAuthority"
    );
    const authorityState = normalizeString(authority.state, "").toUpperCase();
    const mode = normalizeString(authority.mode, "").toUpperCase();

    if (el.authorityStateText) {
        el.authorityStateText.textContent = [authorityName, mode || authorityState]
            .filter(Boolean)
            .join(" · ");
        el.authorityStateText.style.color =
            authorityState === "UNAVAILABLE" ? "var(--red)" : "var(--green)";
    }

    const engine =
        authority.owner_engine &&
        typeof authority.owner_engine === "object"
            ? authority.owner_engine
            : {};
    const engineClass = normalizeString(engine.class, "UNAVAILABLE");
    const engineHash = normalizeString(
        engine.sha256 ?? engine.digest ?? engine.hash,
        ""
    );
    if (el.ownerEngineText) {
        el.ownerEngineText.textContent = engineHash
            ? engineClass + " · " + engineHash.slice(0, 12)
            : engineClass;
    }

    const components =
        authority.owner_components &&
        typeof authority.owner_components === "object" &&
        !Array.isArray(authority.owner_components)
            ? authority.owner_components
            : {};
    const names = Object.keys(components).sort();
    if (el.ownerComponentsText) {
        el.ownerComponentsText.textContent = names.length
            ? String(names.length) + " · " + names.join(", ")
            : "NONE";
        el.ownerComponentsText.title = names.map(name => {
            const identity = components[name] ?? {};
            const hash = normalizeString(
                identity.sha256 ?? identity.digest ?? identity.hash,
                ""
            );
            return hash ? name + ": " + hash : name;
        }).join("\n");
    }

    const externalSupported = authority.external_execution_supported === true;
    if (el.externalExecText) {
        el.externalExecText.textContent = externalSupported ? "SUPPORTED" : "DISABLED";
        el.externalExecText.style.color = externalSupported
            ? "var(--red)"
            : "var(--green)";
    }

    if (mode) setGovernanceMode(mode);
}

// =============================================================================
// Assessment Metrics
// =============================================================================
function updateAssessmentMetrics(data) {
    if (data == null || typeof data !== "object") return;
    const pairs = [
        [el.criticalThreats,  data.criticalThreats  ?? data.criticalCount    ?? data.critical_count],
        [el.totalAssessments, data.totalAssessments  ?? data.total_assessments],
        [el.totalDecisions,   data.totalDecisions    ?? data.total_decisions],
        [el.fenrirSignals,    data.fenrirSignals     ?? data.fenrir_signals   ?? data.anomalyCount ?? data.anomaly_count],
    ];
    for (const [node, value] of pairs) {
        if (!node || typeof value !== "number") continue;
        node.textContent = value.toLocaleString();
        bumpStat(node);
    }
    if (data.mode) setGovernanceMode(data.mode);
}

// =============================================================================
// Watchtower
// =============================================================================
function renderWatchtower(data) {
    if (!el.wtGrid) return;
    const overall = normalizeString(data?.overall, "unknown").toLowerCase();
    if (el.wtOverall) {
        el.wtOverall.textContent = overall.toUpperCase();
        el.wtOverall.className =
            overall === "ok"       ? "chip ok"       :
            overall === "degraded" ? "chip degraded" :
            "chip offline";
    }
    if (el.wtHeaderChip) el.wtHeaderChip.hidden = false;
    if (el.wtHeaderStatus) el.wtHeaderStatus.textContent = overall.toUpperCase();
    if (el.wtHeaderDot) {
        el.wtHeaderDot.classList.remove("online", "offline");
        el.wtHeaderDot.classList.add(overall === "ok" ? "online" : "offline");
    }
    const subsystems = Array.isArray(data?.subsystems) ? data.subsystems : [];
    if (!subsystems.length) {
        el.wtGrid.innerHTML =
            `<div style="grid-column:1/-1;padding:18px;text-align:center;font-family:var(--font-mono);font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;">No subsystem data returned.</div>`;
    } else {
        el.wtGrid.innerHTML = subsystems.map(s => {
            const status = normalizeString(s.status, "unknown").toLowerCase();
            const latency = s.latencyMs != null
                ? `${escHtml(String(s.latencyMs))}ms`
                : "—";
            return (
                `<div class="wt-card ${escHtml(status)}" role="status" aria-label="${escHtml(normalizeString(s.name, "Unknown"))}: ${escHtml(status)}">` +
                `<div class="wt-card-name">${escHtml(normalizeString(s.name, "Unknown"))}</div>` +
                `<div class="wt-card-detail">${escHtml(normalizeString(s.detail, ""))}</div>` +
                `<div class="wt-card-footer">` +
                `<span class="wt-latency">${latency}</span>` +
                `<span class="wt-badge ${escHtml(status)}">${escHtml(status)}</span>` +
                `</div></div>`
            );
        }).join("");
    }
    if (el.wtProbeTime) {
        el.wtProbeTime.textContent = `Last probe: ${nowStamp()}`;
    }
}

function normalizeWatchtowerResponse(raw) {
    if (!raw || typeof raw !== "object") return raw;
    if ("subsystems" in raw) return raw;
    if ("watchtower" in raw) {
        const reachable = raw.reachable !== false;
        if (!reachable) {
            return { overall: "offline", subsystems: [] };
        }
        const wt = raw.watchtower ?? {};
        const state = normalizeString(wt.state ?? raw.status, "UNKNOWN").toUpperCase();
        const overall =
            ["ACTIVE", "ONLINE", "OK", "READY", "HEALTHY", "RUNNING"].includes(state)
                ? "ok"
                : ["DEGRADED", "WARN", "WARNING"].includes(state)
                    ? "degraded"
                    : "offline";
        const TOWER_TYPE_LABELS = Object.freeze({
            API_HEALTH:        "api health monitoring",
            EXPECTATION_GUARD: "expectation & contract guard",
            CONFIG_DRIFT:      "configuration drift detection",
            LOGGING_AUDIT:     "audit chain integrity",
            ERROR_RATE:        "runtime error rate",
            DEPENDENCY_HEALTH: "dependency health",
            RESOURCE_PRESSURE: "resource pressure",
            SECURITY_BASELINE: "security baseline",
        });
        const towers = Array.isArray(wt.towers) ? wt.towers : [];
        const subsystems = towers.map(t => {
            let status = "online";
            if (t.enabled === false) {
                status = "offline";
            } else if (typeof t.alert_count === "number" && t.alert_count > 0) {
                status = "degraded";
            }
            const towerType = normalizeString(t.tower_type, "");
            const detail = TOWER_TYPE_LABELS[towerType]
                ?? towerType.toLowerCase().replace(/_/g, " ");
            return {
                name:      normalizeString(t.name, "Unknown Tower"),
                status,
                latencyMs: null,
                detail,
            };
        });
        return { overall, subsystems };
    }
    return raw;
}

async function fetchWatchtower() {
    if (watchtowerProbeInFlight) return;
    watchtowerProbeInFlight = true;
    if (el.wtRefreshBtn) el.wtRefreshBtn.disabled = true;
    try {
        const raw = await api.watchtowerStatus();
        console.debug("[S43 Watchtower raw]", raw);
        const data = normalizeWatchtowerResponse(raw);
        renderWatchtower(data);
        log("Watchtower probe complete.", "ok");
    } catch (err) {
        log(`Watchtower probe failed: ${err.message ?? err}`, "warn");
        if (el.wtOverall) {
            el.wtOverall.textContent = "UNREACHABLE";
            el.wtOverall.className = "chip offline";
        }
        if (el.wtHeaderDot) {
            el.wtHeaderDot.classList.remove("online");
            el.wtHeaderDot.classList.add("offline");
        }
        if (el.wtHeaderStatus) el.wtHeaderStatus.textContent = "UNREACHABLE";
        if (el.wtHeaderChip) el.wtHeaderChip.hidden = false;
    } finally {
        watchtowerProbeInFlight = false;
        if (el.wtRefreshBtn) el.wtRefreshBtn.disabled = false;
    }
}

function startWatchtowerPolling() {
    if (watchtowerTimer) clearInterval(watchtowerTimer);
    watchtowerTimer = setInterval(fetchWatchtower, WT_PROBE_MS);
}

// =============================================================================
// Refresh / Data Sync
// =============================================================================
async function performRefresh(manual = false) {
    document.body.setAttribute("aria-busy", "true");
    if (manual) setStatus("Syncing");
    try {
        updateStaticConfig();
        const [rawActions, vault, summary, systemStatus] = await Promise.all([
            api.listActions(),
            api.vaultStats().catch(() => null),
            api.dashboardSummary().catch(() => null),
            api.systemStatus().catch(() => null),
        ]);
        replaceActions(rawActions, wsConnected ? "live-sync" : "poll-sync");
        const records = extractVaultRecords(vault);
        if (el.vaultCount) {
            el.vaultCount.textContent = typeof records === "number"
                ? records.toLocaleString()
                : "--";
        }
        if (summary) updateAssessmentMetrics(summary);
        if (systemStatus) renderAuthorityProvenance(systemStatus);
        setStatus(wsConnected ? "Live" : "Online");
        if (manual) {
            log(`Refresh complete — ${applyFilters(allActions).length} action(s) visible.`, "ok");
        }
        return true;
    } catch (err) {
        setStatus(wsConnected ? "Degraded" : "Offline");
        log(`Refresh failed: ${err.message ?? err}`, "err");
        return false;
    } finally {
        document.body.removeAttribute("aria-busy");
    }
}

async function refreshDashboard(manual = false, { force = false } = {}) {
    if (refreshPromise) {
        const prior = await refreshPromise;
        if (!force) return prior;
    }
    refreshPromise = performRefresh(manual).finally(() => {
        refreshPromise = null;
    });
    return refreshPromise;
}

// =============================================================================
// Revalidation (TOCTOU guard before approve/veto)
// =============================================================================
async function revalidateAction(actionId, expectedStatuses) {
    const refreshed = await refreshDashboard(false, { force: true });
    if (!refreshed) throw new Error("Unable to refresh live state before submit");
    const latest = allActions.find(a => a.id === actionId);
    if (!latest) throw new Error("Action disappeared before submit");
    if (!expectedStatuses.includes(latest.status)) {
        throw new Error(`Action status changed to ${latest.status}`);
    }
}

// =============================================================================
// Approve / Veto
// =============================================================================
async function doApprove(actionId, button) {
    const blocked = approvalBlock(allActions.find(a => a.id === actionId));
    if (blocked) {
        log(`Approval unavailable — ${actionId}: ${blocked.join(" | ")}`, "warn");
        return false;
    }
    const reason = await openReasonModal({
        title: `Approve ${actionId}`,
        subtitle: "Describe why this action should proceed.",
        confirmText: "Approve",
        confirmClass: "green",
    });
    if (!reason) {
        log(`Approve cancelled — ${actionId}`, "warn");
        return false;
    }
    if (button) button.disabled = true;
    try {
        await revalidateAction(actionId, ["STAGED"]);
        await api.approve(actionId, reason);
        log(`Approved ${actionId}`, "ok");
        return true;
    } catch (err) {
        log(`Approve failed — ${actionId}: ${err.message ?? err}`, "err");
        return false;
    } finally {
        if (button) button.disabled = false;
    }
}

async function doVeto(actionId, button) {
    const reason = await openReasonModal({
        title: `Veto ${actionId}`,
        subtitle: "Explain why this action is being blocked.",
        confirmText: "Veto",
        confirmClass: "red",
    });
    if (!reason) {
        log(`Veto cancelled — ${actionId}`, "warn");
        return false;
    }
    if (button) button.disabled = true;
    try {
        await revalidateAction(actionId, ["PENDING", "STAGED"]);
        await api.veto(actionId, reason);
        log(`Vetoed ${actionId}`, "warn");
        return true;
    } catch (err) {
        log(`Veto failed — ${actionId}: ${err.message ?? err}`, "err");
        return false;
    } finally {
        if (button) button.disabled = false;
    }
}

// =============================================================================
// Bulk Actions
// =============================================================================
async function runBulkAction(kind) {
    const requestedIds = [...selectedIds];
    if (!requestedIds.length) return;
    const isApprove = kind === "approve";
    const reason = await openReasonModal({
        title: `Bulk ${kind} ${requestedIds.length} action(s)`,
        subtitle: "Applies only to currently eligible selections after a fresh server check.",
        confirmText: isApprove ? "Approve All" : "Veto All",
        confirmClass: isApprove ? "green" : "red",
    });
    if (!reason) return;
    const refreshed = await refreshDashboard(false, { force: true });
    if (!refreshed) {
        log(`Bulk ${kind} aborted: live state could not be refreshed.`, "err");
        return;
    }
    const expected = isApprove ? ["STAGED"] : ["PENDING", "STAGED"];
    const eligible = requestedIds.filter(id => {
        const a = allActions.find(x => x.id === id);
        return a && expected.includes(a.status) && (!isApprove || canApproveAction(a));
    });
    if (eligible.length !== requestedIds.length) {
        log(`Bulk ${kind}: skipped ${requestedIds.length - eligible.length} ineligible selection(s).`, "warn");
    }
    if (!eligible.length) {
        clearSelection();
        return;
    }
    const btn = isApprove ? el.bulkApproveBtn : el.bulkVetoBtn;
    if (btn) btn.disabled = true;
    let successes = 0;
    try {
        for (const id of eligible) {
            try {
                if (isApprove) await api.approve(id, reason);
                else await api.veto(id, reason);
                successes += 1;
            } catch (err) {
                log(`Bulk ${kind} failed — ${id}: ${err.message ?? err}`, "err");
            }
        }
        log(
            `Bulk ${kind} complete: ${successes}/${eligible.length} action(s).`,
            isApprove ? "ok" : "warn"
        );
    } finally {
        clearSelection();
        await refreshDashboard(true, { force: true });
        if (btn) btn.disabled = false;
    }
}

// =============================================================================
// Inject
// =============================================================================
let _injectModalOpen = false;

function openInjectModal() {
    if ((!CONFIG.DEMO_MODE && !CONFIG.LIVE_TEST_MODE) || injectInFlight) {
        log("Inject blocked: demo/local-test mode disabled or inject in flight.", "warn");
        return;
    }
    _injectModalOpen = true;
    if (el.injectBtn) el.injectBtn.disabled = true;
    if (el.injectModal) {
        el.injectModal.hidden = false;
        el.injectModal.setAttribute("aria-hidden", "false");
    }
}

function closeInjectModal() {
    if (!_injectModalOpen) return;
    _injectModalOpen = false;
    if (el.injectModal) {
        el.injectModal.hidden = true;
        el.injectModal.setAttribute("aria-hidden", "true");
    }
    updateStaticConfig();
}

el.injectCancel?.addEventListener("click", closeInjectModal);
el.injectModal?.addEventListener("click", e => {
    if (e.target.hasAttribute("data-close-inject")) closeInjectModal();
});
el.injectConfirm?.addEventListener("click", async () => {
    if (injectInFlight) return;
    injectInFlight = true;
    closeInjectModal();
    updateStaticConfig();
    try {
        await api.inject();
        log("Test action injected.", "info");
        await refreshDashboard(true, { force: true });
    } catch (err) {
        log(`Inject failed: ${err.message ?? err}`, "err");
    } finally {
        injectInFlight = false;
        updateStaticConfig();
    }
});

// =============================================================================
// Export
// =============================================================================
function exportVisibleActions() {
    const source = applyFilters(allActions);
    const stale = dataIsStale();
    const payload = {
        exported_at: new Date().toISOString(),
        data_as_of: lastDataSyncAt?.toISOString() ?? null,
        data_stale: stale,
        filter: currentFilter,
        search_query: searchQuery,
        action_count: source.length,
        actions: source.map(a => ({
            id: a.id,
            threat: a.threat,
            source: a.source,
            status: a.status,
            created_at: a.createdAt,
            created_raw: a.createdRaw,
            created_invalid: a.createdBad,
            decision_reason: a.decisionReason,
            operator: a.operator,
        })),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `sentinel43-export-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
    log(
        `Exported ${source.length} action(s)${stale ? " with stale-data warning" : ""}.`,
        stale ? "warn" : "ok"
    );
}

// =============================================================================
// Static Config Display
// =============================================================================
function updateStaticConfig() {
    if (el.apiBaseText) el.apiBaseText.textContent = CONFIG.API_BASE;
    if (el.pollText) el.pollText.textContent = `fallback ${CONFIG.FALLBACK_POLL_MS} ms`;
    setGovernanceMode("HUMAN_GATED");
    const demoActive = CONFIG.DEMO_MODE || CONFIG.LIVE_TEST_MODE;
    if (el.demoText) {
        el.demoText.textContent = CONFIG.DEMO_MODE
            ? "DEMO ENABLED"
            : CONFIG.LIVE_TEST_MODE
                ? "LIVE TEST ENABLED"
                : "DISABLED";
        el.demoText.style.color = demoActive ? "var(--amber)" : "var(--green)";
    }
    if (el.demoBadge) el.demoBadge.hidden = !CONFIG.DEMO_MODE;
    if (el.injectBtn) el.injectBtn.disabled = (!demoActive) || injectInFlight;

    const { token, isRealSession } = getDevTokenInfo();
    const hasPassword = !!(window.SentinelAuth?.getPassword?.());
    const trulyAuthenticated = token && hasPassword;

    if (el.authStateText) {
        el.authStateText.textContent = trulyAuthenticated
            ? (isRealSession ? "SESSION TOKEN PRESENT" : "DEV TOKEN PRESENT")
            : token && !hasPassword
                ? "TOKEN PRESENT, PASSWORD MISSING"
                : CONFIG.ALLOW_DEV_JWT_STORAGE ? "COOKIE / MISSING" : "COOKIE ONLY";
        el.authStateText.style.color = trulyAuthenticated
            ? (isRealSession ? "var(--green)" : "var(--amber)")
            : token && !hasPassword
                ? "var(--red)"
                : "var(--green)";
    }
    if (el.jwtRiskBadge) el.jwtRiskBadge.hidden = !(token && !isRealSession);
    if (el.authBtn) el.authBtn.disabled = !CONFIG.ALLOW_DEV_JWT_STORAGE;
}

// =============================================================================
// Theme
// =============================================================================
function applyTheme(light) {
    isLight = light;
    document.documentElement.classList.toggle("light", light);
    if (el.themeBtn) el.themeBtn.textContent = light ? "☽ Dark" : "☀ Light";
    try {
        localStorage.setItem("s43-theme", light ? "light" : "dark");
    } catch {}
}

function initTheme() {
    try {
        const stored = localStorage.getItem("s43-theme");
        if (stored === "light") { applyTheme(true);  return; }
        if (stored === "dark")  { applyTheme(false); return; }
    } catch {}
    applyTheme(
        window.matchMedia?.("(prefers-color-scheme: light)").matches ?? false
    );
}

// =============================================================================
// JWT Modal (dev-only credential injection)
// =============================================================================
function closeJwtModal() {
    if (!el.jwtModal || el.jwtModal.hidden) return;
    el.jwtModal.hidden = true;
    el.jwtModal.setAttribute("aria-hidden", "true");
}

async function handleAuthChanged() {
    updateStaticConfig();
    if (!CONFIG.DEMO_MODE) {
        window.SentinelWS?.disconnect();
        window.SentinelWS?.connect();
    }
    await refreshDashboard(true, { force: true });
}

function _ensureJwtPasswordField() {
    if (el.jwtPasswordInput) return el.jwtPasswordInput;
    const existing = document.getElementById("s43-jwt-password");
    if (existing) {
        el.jwtPasswordInput = existing;
        return existing;
    }
    if (!el.jwtInput || !el.jwtInput.parentElement) return null;
    const input = document.createElement("input");
    input.type = "password";
    input.id = "s43-jwt-password";
    input.placeholder = "Password (required — backend re-verifies on every request)";
    input.autocomplete = "off";
    input.style.cssText = el.jwtInput.style.cssText || "";
    input.style.marginTop = "8px";
    input.style.width = "100%";
    input.style.boxSizing = "border-box";
    el.jwtInput.insertAdjacentElement("afterend", input);
    el.jwtPasswordInput = input;
    return input;
}

el.authBtn?.addEventListener("click", () => {
    if (!CONFIG.ALLOW_DEV_JWT_STORAGE || !el.jwtModal) {
        log("Browser JWT storage is disabled outside local development.", "warn");
        return;
    }
    if (el.jwtInput) el.jwtInput.value = getDevToken() ?? "";
    const pwField = _ensureJwtPasswordField();
    if (pwField) pwField.value = window.SentinelAuth?.getPassword?.() ?? "";
    el.jwtModal.hidden = false;
    el.jwtModal.setAttribute("aria-hidden", "false");
    setTimeout(() => el.jwtInput?.focus(), 0);
});

el.jwtCancel?.addEventListener("click", closeJwtModal);
el.jwtModal?.addEventListener("click", e => {
    if (e.target.hasAttribute("data-close-jwt")) closeJwtModal();
});

el.jwtClear?.addEventListener("click", async () => {
    try {
        for (const key of DEV_JWT_KEYS) {
            sessionStorage.removeItem(key);
            localStorage.removeItem(key);
        }
    } catch {}
    const pwField = _ensureJwtPasswordField();
    if (pwField) pwField.value = "";
    log("Development JWT cleared.", "warn");
    closeJwtModal();
    await handleAuthChanged();
});

el.jwtConfirm?.addEventListener("click", async () => {
    if (!CONFIG.ALLOW_DEV_JWT_STORAGE) return;
    const token = el.jwtInput?.value.trim() ?? "";
    const pwField = _ensureJwtPasswordField();
    const password = pwField?.value ?? "";

    const applied = token
        ? window.SentinelAuth?.applyManualCredentials?.(token, password)
        : window.SentinelAuth?.applyManualCredentials?.("", "");

    log(
        applied
            ? "Development session token + password stored. Local use only."
            : "Rejected: token/password invalid or missing. Nothing was stored.",
        applied ? "warn" : "err"
    );
    closeJwtModal();
    await handleAuthChanged();
});

// =============================================================================
// Admin Account Management
// =============================================================================
function normalizeUser(raw) {
    return {
        id: normalizeString(raw?.user_id, "").trim(),
        username: normalizeString(raw?.username, "").trim(),
        email: normalizeString(raw?.email, "").trim(),
        role: normalizeString(raw?.role, "observer").trim().toLowerCase(),
        active: raw?.is_active === true,
        createdAt: normalizeString(raw?.created_at, ""),
        lastLoginAt: normalizeString(raw?.last_login_at, ""),
    };
}

function setUsersStatus(message, type = "info") {
    if (!el.usersStatus) return;
    el.usersStatus.hidden = false;
    el.usersStatus.textContent = message;
    el.usersStatus.style.color =
        type === "err" ? "var(--red)" :
        type === "ok" ? "var(--green)" :
        type === "warn" ? "var(--amber)" :
        "var(--muted)";
}

function renderUsers() {
    if (!el.usersList) return;
    if (el.userCount) el.userCount.textContent = String(managedUsers.length);

    if (!userManagementAvailable) {
        el.usersList.hidden = true;
        return;
    }

    if (!managedUsers.length) {
        el.usersList.hidden = true;
        setUsersStatus("No accounts returned.", "warn");
        return;
    }

    if (el.usersStatus) el.usersStatus.hidden = true;
    el.usersList.hidden = false;
    el.usersList.innerHTML = managedUsers.map(user => {
        const created = user.createdAt
            ? new Date(user.createdAt).toLocaleString()
            : "unknown";
        const lastLogin = user.lastLoginAt
            ? new Date(user.lastLoginAt).toLocaleString()
            : "never";
        return (
            `<div class="account-row" data-user-id="${escHtml(user.id)}">` +
              `<div class="account-main">` +
                `<div class="account-name">${escHtml(user.username)} ` +
                  `<span class="tag ${user.active ? "approved" : "vetoed"}">${user.active ? "active" : "disabled"}</span></div>` +
                `<div class="account-meta">${escHtml(user.email || "no email")} · created ${escHtml(created)} · last login ${escHtml(lastLogin)}</div>` +
              `</div>` +
              `<div class="account-actions">` +
                `<span class="tag">${escHtml(user.role === "admin" ? "sole admin" : "observer")}</span>` +
                `<button class="btn ${user.active ? "red" : "green"}" type="button" data-user-active="${escHtml(user.id)}" data-next-active="${user.active ? "false" : "true"}"${user.role === "admin" ? " disabled title=\"The sole administrator cannot be disabled\"" : ""}>${user.active ? "Disable" : "Enable"}</button>` +
                `<button class="btn amber" type="button" data-user-password="${escHtml(user.id)}">Reset PW</button>` +
              `</div>` +
            `</div>`
        );
    }).join("");
}

async function refreshUsers({ quiet = false } = {}) {
    if (CONFIG.DEMO_MODE) {
        userManagementAvailable = false;
        managedUsers = [];
        if (el.userCount) el.userCount.textContent = "—";
        setUsersStatus("Account administration is disabled in demo mode.");
        if (el.createUserBtn) el.createUserBtn.disabled = true;
        if (el.usersRefreshBtn) el.usersRefreshBtn.disabled = true;
        renderUsers();
        return;
    }

    try {
        const raw = await api.listUsers();
        if (!Array.isArray(raw)) throw new Error("User endpoint returned an invalid payload shape");
        managedUsers = raw.map(normalizeUser).filter(user => user.id && user.username);
        userManagementAvailable = true;
        if (el.createUserBtn) el.createUserBtn.disabled = false;
        if (el.usersRefreshBtn) el.usersRefreshBtn.disabled = false;
        renderUsers();
        if (!quiet) log(`Loaded ${managedUsers.length} account(s).`, "ok");
    } catch (err) {
        userManagementAvailable = false;
        managedUsers = [];
        if (el.userCount) el.userCount.textContent = "—";
        const message = normalizeString(err?.message, "Account management unavailable.");
        const forbidden = /^403\b/.test(message);
        setUsersStatus(
            forbidden
                ? "Administrator role required for account management."
                : `Account management unavailable: ${message}`,
            forbidden ? "warn" : "err"
        );
        if (el.createUserBtn) el.createUserBtn.disabled = true;
        renderUsers();
        if (!quiet && !forbidden) log(message, "err");
    }
}

function closeUserModal() {
    if (!el.userModal) return;
    el.userModal.hidden = true;
    el.userModal.setAttribute("aria-hidden", "true");
    if (el.userModalError) el.userModalError.textContent = "";
    for (const node of [el.userUsername, el.userEmail, el.userPassword, el.userPasswordConfirm]) {
        if (node) node.value = "";
    }
}

function openUserModal() {
    if (!userManagementAvailable || !el.userModal) return;
    closeUserModal();
    el.userModal.hidden = false;
    el.userModal.setAttribute("aria-hidden", "false");
    setTimeout(() => el.userUsername?.focus(), 0);
}

async function createManagedUser() {
    if (userMutationInFlight) return;
    const username = el.userUsername?.value.trim() ?? "";
    const email = el.userEmail?.value.trim() ?? "";
    const password = el.userPassword?.value ?? "";
    const confirmation = el.userPasswordConfirm?.value ?? "";

    let error = "";
    if (!username) error = "Username is required.";
    else if (password.length < 12) error = "Password must be at least 12 characters.";
    else if (password !== confirmation) error = "Passwords do not match.";

    if (error) {
        if (el.userModalError) el.userModalError.textContent = error;
        return;
    }

    userMutationInFlight = true;
    if (el.userConfirm) el.userConfirm.disabled = true;
    try {
        const created = await api.createUser({
            username,
            password,
            email: email || null,
        });
        log(`Created observer account ${normalizeString(created?.username, username)}.`, "ok");
        closeUserModal();
        await refreshUsers({ quiet: true });
    } catch (err) {
        const message = normalizeString(err?.message, "User creation failed.");
        if (el.userModalError) el.userModalError.textContent = message;
        log(message, "err");
    } finally {
        userMutationInFlight = false;
        if (el.userConfirm) el.userConfirm.disabled = false;
    }
}

async function updateManagedUser(userId, payload) {
    if (userMutationInFlight) return;
    userMutationInFlight = true;
    try {
        const updated = await api.updateUser(userId, payload);
        log(`Updated account ${normalizeString(updated?.username, userId)}.`, "ok");
        await refreshUsers({ quiet: true });
    } catch (err) {
        const message = normalizeString(err?.message, "Account update failed.");
        log(message, "err");
        await refreshUsers({ quiet: true });
    } finally {
        userMutationInFlight = false;
    }
}

function closePasswordResetModal() {
    if (!el.passwordResetModal) return;
    el.passwordResetModal.hidden = true;
    el.passwordResetModal.setAttribute("aria-hidden", "true");
    passwordResetTarget = null;
    if (el.passwordResetInput) el.passwordResetInput.value = "";
    if (el.passwordResetConfirmInput) el.passwordResetConfirmInput.value = "";
    if (el.passwordResetError) el.passwordResetError.textContent = "";
}

function openPasswordResetModal(userId) {
    const user = managedUsers.find(item => item.id === userId);
    if (!user || !el.passwordResetModal) return;
    passwordResetTarget = user;
    if (el.passwordResetTitle) el.passwordResetTitle.textContent = `Reset Password · ${user.username}`;
    el.passwordResetModal.hidden = false;
    el.passwordResetModal.setAttribute("aria-hidden", "false");
    setTimeout(() => el.passwordResetInput?.focus(), 0);
}

async function resetManagedUserPassword() {
    if (userMutationInFlight || !passwordResetTarget) return;
    const password = el.passwordResetInput?.value ?? "";
    const confirmation = el.passwordResetConfirmInput?.value ?? "";
    if (password.length < 12) {
        if (el.passwordResetError) el.passwordResetError.textContent = "Password must be at least 12 characters.";
        return;
    }
    if (password !== confirmation) {
        if (el.passwordResetError) el.passwordResetError.textContent = "Passwords do not match.";
        return;
    }

    const target = passwordResetTarget;
    userMutationInFlight = true;
    if (el.passwordResetConfirm) el.passwordResetConfirm.disabled = true;
    try {
        await api.resetUserPassword(target.id, password);
        log(`Password reset for ${target.username}; existing sessions revoked.`, "ok");
        closePasswordResetModal();
        await refreshUsers({ quiet: true });
    } catch (err) {
        const message = normalizeString(err?.message, "Password reset failed.");
        if (el.passwordResetError) el.passwordResetError.textContent = message;
        log(message, "err");
    } finally {
        userMutationInFlight = false;
        if (el.passwordResetConfirm) el.passwordResetConfirm.disabled = false;
    }
}

el.usersRefreshBtn?.addEventListener("click", () => refreshUsers());
el.createUserBtn?.addEventListener("click", openUserModal);
el.userCancel?.addEventListener("click", closeUserModal);
el.userConfirm?.addEventListener("click", createManagedUser);
el.userModal?.addEventListener("click", event => {
    if (event.target.hasAttribute("data-close-user")) closeUserModal();
});

el.passwordResetCancel?.addEventListener("click", closePasswordResetModal);
el.passwordResetConfirm?.addEventListener("click", resetManagedUserPassword);
el.passwordResetModal?.addEventListener("click", event => {
    if (event.target.hasAttribute("data-close-password-reset")) closePasswordResetModal();
});


el.usersList?.addEventListener("click", event => {
    const activeButton = event.target.closest?.("[data-user-active]");
    if (activeButton) {
        updateManagedUser(
            activeButton.dataset.userActive,
            { is_active: activeButton.dataset.nextActive === "true" }
        );
        return;
    }
    const passwordButton = event.target.closest?.("[data-user-password]");
    if (passwordButton) openPasswordResetModal(passwordButton.dataset.userPassword);
});

// =============================================================================
// Protected-activity lifecycle
// =============================================================================
function stopProtectedActivity() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    if (watchtowerTimer) { clearInterval(watchtowerTimer); watchtowerTimer = null; }
    wsConnected = false;
    setStatus("Locked");
}

let authenticatedStartupInFlight = false;

async function startProtectedActivity() {
    if (authenticatedStartupInFlight || CONFIG.DEMO_MODE) return;
    authenticatedStartupInFlight = true;
    try {
        startPollingFallback();
        startWatchtowerPolling();
        await Promise.allSettled([
            fetchWatchtower(),
            refreshDashboard(true, { force: true }),
            refreshUsers({ quiet: true }),
        ]);
    } finally {
        authenticatedStartupInFlight = false;
    }
}

window.addEventListener("sentinel:auth:locked", () => {
    stopProtectedActivity();
});

window.addEventListener("sentinel:auth:ready", () => {
    updateStaticConfig();
    startProtectedActivity();
});

// =============================================================================
// Polling Fallback
// =============================================================================
function startPollingFallback() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(() => {
        if (!wsConnected || dataIsStale()) refreshDashboard(false);
    }, CONFIG.FALLBACK_POLL_MS);
}

// =============================================================================
// WebSocket Event Listeners
// =============================================================================
window.addEventListener("sentinel:ws:open", () => {
    setStatus("Authenticating");
    log("WebSocket connected. Awaiting auth handshake.", "info");
});
window.addEventListener("sentinel:ws:auth_required", () => {
    log("WebSocket auth challenge received.", "info");
});
window.addEventListener("sentinel:ws:auth_sent", () => {
    log("WebSocket auth frame sent.", "info");
});
window.addEventListener("sentinel:ws:subscribed_all", event => {
    const count = Array.isArray(event.detail?.channels) ? event.detail.channels.length : 0;
    log(`WebSocket subscribed to ${count} channel(s).`, "ok");
});
window.addEventListener("sentinel:ws:close", () => {
    wsConnected = false;
    setStatus("Reconnecting");
    log("WebSocket disconnected. Polling fallback remains active.", "warn");
});
window.addEventListener("sentinel:ws:reconnecting", event => {
    setStatus("Reconnecting");
    log(`WebSocket reconnecting (attempt ${event.detail?.attempt ?? "?"})…`, "info");
});
window.addEventListener("sentinel:ws:disconnected", () => {
    wsConnected = false;
    setStatus("Offline");
});
window.addEventListener("sentinel:ws:connecting", () => {
    setStatus("Reconnecting");
});
window.addEventListener("sentinel:ws:error", event => {
    log(`WebSocket error: ${event.detail?.error ?? "unknown"}`, "warn");
});
window.addEventListener("sentinel:ws:frame_error", event => {
    log(`Rejected WebSocket frame: ${event.detail?.error ?? "unknown"}`, "warn");
});
window.addEventListener("sentinel:ws:server_error", event => {
    log(`WebSocket server error: ${event.detail?.error ?? "unknown"}`, "err");
});
window.addEventListener("sentinel:ws:auth_failed", event => {
    log(
        `WebSocket auth failed: ${
            event.detail?.error ??
            event.detail?.reason ??
            event.detail?.message ??
            "unknown"
        }`,
        "err"
    );
});
window.addEventListener("sentinel:ws:policy_error", event => {
    log(`WebSocket policy rejection: ${event.detail?.reason ?? "unknown"}`, "err");
});
window.addEventListener("sentinel:ws:protocol_error", event => {
    log(`WebSocket protocol rejection: ${event.detail?.reason ?? "unknown"}`, "err");
});
window.addEventListener("sentinel:ws:stale", () => {
    log("WebSocket connection stale — forcing reconnect.", "warn");
});
window.addEventListener("sentinel:ws:message", event => {
    const { type, payload } = event.detail;
    switch (type) {
        case "authenticated":
        case "auth_ok":
        case "connected":
            markWebSocketLive(type);
            break;
        case "subscribed":
            log(`Subscription active: ${normalizeString(payload.channel, "unknown")}`, "ok");
            break;
        case "actions_snapshot":
            replaceActions(payload.actions ?? payload, "ws-sync");
            break;
        case "action_created":
        case "action_updated":
        case "action_status_changed":
        case "action":
            upsertAction(payload.action ?? payload);
            break;
        case "action_deleted":
        case "action_removed":
            removeAction(payload.id ?? payload.action_id);
            break;
        case "vault_stats": {
            const records = extractVaultRecords(payload);
            if (el.vaultCount) {
                el.vaultCount.textContent =
                    typeof records === "number" ? records.toLocaleString() : "--";
            }
            markDataSync("ws-sync");
            break;
        }
        case "governance_pending_snapshot":
            log(`Governance pending queue: ${(payload.pending ?? []).length} item(s).`, "info");
            break;
        case "governance_mode":
        case "mode_changed":
            setGovernanceMode(normalizeString(payload.mode, "UNKNOWN"));
            log(`Governance mode: ${normalizeString(payload.mode, "UNKNOWN")}`, "info");
            break;
        case "watchtower_state":
            log(
                `Watchtower ${payload.reachable ? "reachable" : "unreachable"}.`,
                payload.reachable ? "ok" : "warn"
            );
            if ("reachable" in payload && !("watchtower" in payload) && !("subsystems" in payload)) {
                if (el.wtHeaderChip) el.wtHeaderChip.hidden = false;
                if (el.wtHeaderStatus) {
                    el.wtHeaderStatus.textContent = payload.reachable ? "REACHABLE" : "UNREACHABLE";
                }
                if (el.wtHeaderDot) {
                    el.wtHeaderDot.classList.toggle("online",  !!payload.reachable);
                    el.wtHeaderDot.classList.toggle("offline", !payload.reachable);
                }
                break;
            }
            if (payload.subsystems || payload.overall || "watchtower" in payload) {
                renderWatchtower(normalizeWatchtowerResponse(payload));
            }
            break;
        case "dependency_state":
            log(
                `Dependency ${normalizeString(payload.name, "unknown")}: ${normalizeString(payload.status, "unknown")}`,
                "info"
            );
            break;
        case "error":
            log(`WebSocket server error: ${normalizeString(payload.error, "unknown")}`, "err");
            break;
        case "pong":
        case "unsubscribed":
            break;
        default:
            log(`Ignored unhandled WebSocket event type: ${type}`, "info");
    }
});

// =============================================================================
// DOM Event Wiring
// =============================================================================
el.refreshBtn?.addEventListener("click", () => refreshDashboard(true, { force: true }));
el.exportBtn?.addEventListener("click", exportVisibleActions);
el.injectBtn?.addEventListener("click", openInjectModal);
el.themeBtn?.addEventListener("click", () => applyTheme(!isLight));
el.clearLogBtn?.addEventListener("click", () => {
    if (el.logConsole) el.logConsole.innerHTML = "";
    log("Console cleared.", "info");
});
el.wtRefreshBtn?.addEventListener("click", () => fetchWatchtower());
el.searchInput?.addEventListener("input", () => {
    searchQuery = el.searchInput.value;
    clearSelection();
    renderActions();
});
el.clearSearchBtn?.addEventListener("click", () => {
    if (el.searchInput) el.searchInput.value = "";
    searchQuery = "";
    clearSelection();
    renderActions();
    el.searchInput?.focus();
});
el.selectAll?.addEventListener("change", () => {
    document.querySelectorAll(".row-cb").forEach(box => {
        box.checked = el.selectAll.checked;
        if (box.checked) {
            selectedIds.add(box.dataset.id);
            box.closest("tr")?.classList.add("selected");
        } else {
            selectedIds.delete(box.dataset.id);
            box.closest("tr")?.classList.remove("selected");
        }
    });
    updateBulkBar();
});
document.addEventListener("change", e => {
    const box = e.target.closest?.(".row-cb");
    if (!box) return;
    if (box.checked) {
        selectedIds.add(box.dataset.id);
        box.closest("tr")?.classList.add("selected");
    } else {
        selectedIds.delete(box.dataset.id);
        box.closest("tr")?.classList.remove("selected");
    }
    updateBulkBar();
});
el.bulkClearBtn?.addEventListener("click", clearSelection);
el.bulkApproveBtn?.addEventListener("click", () => runBulkAction("approve"));
el.bulkVetoBtn?.addEventListener("click", () => runBulkAction("veto"));
document.addEventListener("click", async e => {
    const filterBtn = e.target.closest?.("[data-filter]");
    if (filterBtn) {
        currentFilter = filterBtn.dataset.filter;
        document.querySelectorAll("[data-filter]").forEach(b => b.classList.remove("active"));
        filterBtn.classList.add("active");
        clearSelection();
        log(`Filter → ${currentFilter}. Selection cleared.`, "info");
        renderActions();
        return;
    }
    const logFilterBtn = e.target.closest?.("[data-log-filter]");
    if (logFilterBtn) {
        currentLogFilter = logFilterBtn.dataset.logFilter;
        document.querySelectorAll("[data-log-filter]").forEach(b => b.classList.remove("active"));
        logFilterBtn.classList.add("active");
        document.querySelectorAll(".log-line").forEach(line => {
            line.hidden = currentLogFilter !== "ALL" && line.dataset.type !== currentLogFilter;
        });
        return;
    }
    const expandBtn = e.target.closest?.("[data-expand]");
    if (expandBtn) {
        toggleExpand(expandBtn.dataset.expand);
        return;
    }
    const approveBtn = e.target.closest?.("[data-approve]");
    if (approveBtn) {
        const ok = await doApprove(approveBtn.dataset.approve, approveBtn);
        if (ok) await refreshDashboard(true, { force: true });
        return;
    }
    const vetoBtn = e.target.closest?.("[data-veto]");
    if (vetoBtn) {
        const ok = await doVeto(vetoBtn.dataset.veto, vetoBtn);
        if (ok) await refreshDashboard(true, { force: true });
    }
});

// =============================================================================
// Keyboard Shortcuts
// =============================================================================
el.kbHelpBtn?.addEventListener("click", () => {
    el.kbToast?.classList.add("show");
    clearTimeout(kbToastTimer);
    kbToastTimer = setTimeout(() => el.kbToast?.classList.remove("show"), 5000);
});
document.addEventListener("keydown", e => {
    const tag = document.activeElement?.tagName ?? "";
    const inInput = ["INPUT", "TEXTAREA", "SELECT"].includes(tag);
    if (e.key === "Escape") {
        if (!el.reasonModal?.hidden) { el.modalCancel?.click(); return; }
        if (!el.jwtModal?.hidden)    { closeJwtModal();          return; }
        if (!el.injectModal?.hidden) { closeInjectModal();       return; }
        el.kbToast?.classList.remove("show");
        if (selectedIds.size) clearSelection();
        return;
    }
    if (e.key === "/" && !inInput) {
        e.preventDefault();
        el.searchInput?.focus();
        return;
    }
    if (e.key.toLowerCase() === "r" && !inInput) {
        refreshDashboard(true, { force: true });
        return;
    }
    if (inInput) return;
    const rows = visibleRows();
    if (!rows.length) return;
    if (e.key === "ArrowDown") {
        e.preventDefault();
        setFocusedRow(focusedRowIndex < 0 ? 0 : focusedRowIndex + 1);
        return;
    }
    if (e.key === "ArrowUp") {
        e.preventDefault();
        setFocusedRow(focusedRowIndex < 0 ? 0 : focusedRowIndex - 1);
        return;
    }
    if (e.key.toLowerCase() === "a" && focusedRowIndex >= 0 && focusedRowIndex < rows.length) {
        const id = rows[focusedRowIndex].dataset.id;
        const action = allActions.find(a => a.id === id);
        if (action?.status === "STAGED") {
            doApprove(id).then(ok => { if (ok) refreshDashboard(true, { force: true }); });
        }
        return;
    }
    if (e.key.toLowerCase() === "v" && focusedRowIndex >= 0 && focusedRowIndex < rows.length) {
        const id = rows[focusedRowIndex].dataset.id;
        const action = allActions.find(a => a.id === id);
        if (action && ["PENDING", "STAGED"].includes(action.status)) {
            doVeto(id).then(ok => { if (ok) refreshDashboard(true, { force: true }); });
        }
    }
});

// =============================================================================
// Unload Cleanup
// =============================================================================
window.addEventListener("beforeunload", () => {
    if (pollTimer)       clearInterval(pollTimer);
    if (watchtowerTimer) clearInterval(watchtowerTimer);
});

// =============================================================================
// Initialization
// =============================================================================
async function initializeDashboard() {
    log("Dashboard initializing…", "info");
    initTheme();
    updateStaticConfig();
    setStatus("Booting");

    if (CONFIG.DEMO_MODE) {
        window.SentinelWS?.disconnect();
        log("Demo mode active. WebSocket disconnected. Use ?demo=1 for local testing only.", "warn");
        startPollingFallback();
        startWatchtowerPolling();
        await Promise.allSettled([fetchWatchtower(), refreshDashboard(true, { force: true })]);
        return;
    }

    if (!CONFIG.LIVE_TEST_MODE) {
        log("Demo mode disabled. Live API mode active.", "info");
    }

    try {
        await window.SentinelAuthReady;
    } catch {
        setStatus("Locked");
        return;
    }

    await startProtectedActivity();
}

initializeDashboard();
