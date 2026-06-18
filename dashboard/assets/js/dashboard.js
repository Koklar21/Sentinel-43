// =============================================================================
// Sentinel-43 Dashboard
// dashboard.js
// UI logic module. WebSocket transport is handled by websocket.js which
// dispatches sentinel:ws:* events consumed here.
//
// v1.5.2
// Fixes:
// - Removed sendWebSocketAuthFrame(). websocket.js owns the auth exchange
//   entirely: it proactively sends auth on open and responds to auth_required
//   internally before dispatching sentinel:ws:auth_required as a notification.
//   dashboard.js previously called sendWebSocketAuthFrame() from the
//   sentinel:ws:auth_required listener AND from the sentinel:ws:message
//   auth_required case, causing a double auth frame race on every challenge.
// - sentinel:ws:auth_required listener now logs only — no auth send.
// - auth_required removed from sentinel:ws:message switch (dead code: websocket.js
//   handles auth_required internally and returns early, never dispatching it
//   as a general sentinel:ws:message event).
//
// v1.5.1-authfix (prior):
// - Uses a wider dev JWT lookup path matching websocket.js.
// - Handles sentinel:ws:auth_required directly instead of depending only on
//   sentinel:ws:message.
// - Supports both SentinelWS.sendAuth(token) and SentinelWS.auth().
// - Does not log raw JWTs.
// - Treats authenticated/auth_ok/connected as successful live state.
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
    API_BASE: String(
        _runtime.apiBase
        ?? window.SENTINEL_API_BASE_URL
        ?? _readMeta("sentinel-api-base")
        ?? "http://localhost:8000"
    ).replace(/\/+$/, ""),

    FALLBACK_POLL_MS:  15_000,
    DATA_STALE_MS:     60_000,
    REASON_MIN:        10,
    REASON_MAX:        500,
    MAX_LOG_LINES:     500,
    MAX_DEMO_ACTIONS:  500,

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

// Must stay in sync with websocket.js _DEV_JWT_KEYS.
const DEV_JWT_KEYS = Object.freeze([
    "SENTINEL_JWT",
    "S43_JWT",
    "S43_TOKEN",
    "s43_token",
    "s43_dashboard_token",
    "sentinel_token",
    "jwt",
    "token",
]);

// =============================================================================
// Element References
// =============================================================================

const $ = id => document.getElementById(id);

const el = {
    // Header
    statusDot:    $("statusDot"),
    statusText:   $("statusText"),
    modeText:     $("modeText"),
    queueCount:   $("queueCount"),
    lastSync:     $("lastSync"),
    pollFlash:    $("pollFlash"),
    demoBadge:    $("demoBadge"),
    jwtRiskBadge: $("jwtRiskBadge"),
    liveRegion:   $("liveRegion"),

    // Stats
    pendingCount:  $("pendingCount"),
    stagedCount:   $("stagedCount"),
    approvedCount: $("approvedCount"),
    vaultCount:    $("vaultCount"),

    // Config panel
    apiBaseText:   $("apiBaseText"),
    authStateText: $("authStateText"),
    pollText:      $("pollText"),
    demoText:      $("demoText"),

    // Header buttons
    refreshBtn: $("refreshBtn"),
    injectBtn:  $("injectBtn"),
    exportBtn:  $("exportBtn"),
    themeBtn:   $("themeBtn"),
    authBtn:    $("authBtn"),
    kbHelpBtn:  $("kbHelpBtn"),

    // Actions table
    actionsBody:    $("actionsBody"),
    emptyState:     $("emptyState"),
    searchInput:    $("searchInput"),
    clearSearchBtn: $("clearSearchBtn"),
    selectAll:      $("selectAll"),

    // Bulk bar
    bulkBar:        $("bulkBar"),
    bulkLabel:      $("bulkLabel"),
    bulkApproveBtn: $("bulkApproveBtn"),
    bulkVetoBtn:    $("bulkVetoBtn"),
    bulkClearBtn:   $("bulkClearBtn"),

    // Log
    logConsole: $("logConsole"),
    clearLogBtn: $("clearLogBtn"),

    // Reason modal
    reasonModal:    $("reasonModal"),
    modalTitle:     $("modalTitle"),
    modalSubtitle:  $("modalSubtitle"),
    modalInput:     $("modalInput"),
    modalError:     $("modalError"),
    modalCharCount: $("modalCharCount"),
    modalCancel:    $("modalCancel"),
    modalConfirm:   $("modalConfirm"),

    // JWT modal
    jwtModal:   $("jwtModal"),
    jwtInput:   $("jwtInput"),
    jwtCancel:  $("jwtCancel"),
    jwtClear:   $("jwtClear"),
    jwtConfirm: $("jwtConfirm"),

    // Inject modal
    injectModal:   $("injectModal"),
    injectCancel:  $("injectCancel"),
    injectConfirm: $("injectConfirm"),

    // Keyboard shortcut toast
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
let prevCounts       = {pending: null, staged: null, approved: null};
let lastDataSyncAt   = null;
let refreshPromise   = null;
let pollTimer        = null;
let kbToastTimer     = null;
let injectInFlight   = false;
let wsConnected      = false; // true only after server confirms auth/session
let isLight          = false;

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
        .replaceAll("&",  "&amp;")
        .replaceAll("<",  "&lt;")
        .replaceAll(">",  "&gt;")
        .replaceAll('"',  "&quot;")
        .replaceAll("'",  "&#039;");

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

function getDevToken() {
    if (!CONFIG.ALLOW_DEV_JWT_STORAGE) return null;

    for (const key of DEV_JWT_KEYS) {
        const token = _readStoredToken(sessionStorage, key);
        if (token) return token;
    }

    for (const key of DEV_JWT_KEYS) {
        const token = _readStoredToken(localStorage, key);
        if (token) return token;
    }

    try {
        if (typeof window.SENTINEL_JWT === "string" && window.SENTINEL_JWT.trim()) {
            return window.SENTINEL_JWT.trim();
        }

        if (
            typeof window.S43_DASHBOARD_TOKEN === "string" &&
            window.S43_DASHBOARD_TOKEN.trim()
        ) {
            return window.S43_DASHBOARD_TOKEN.trim();
        }
    } catch {
        return null;
    }

    return null;
}

function getAuthHeaders() {
    const headers = {"Content-Type": "application/json"};
    const token = getDevToken();
    if (token) headers.Authorization = `Bearer ${token}`;
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

    const response = await fetch(url.toString(), {
        ...opts,
        cache: "no-store",
        credentials: sameOrigin ? "include" : "omit",
        headers: {
            ...getAuthHeaders(),
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

// Called when the server confirms auth accepted (authenticated/auth_ok/connected).
// wsConnected is only ever set true here — never on socket open — so the
// polling fallback is suppressed only when we're actually live.
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
                ip:         opts.ip     ?? "203.0.113.10",
                source_ip:  opts.ip     ?? "203.0.113.10",
                threat:     opts.threat ?? "Suspicious activity",
            },
        };
        store.set(item.id, item);
        trimStore();
        return item;
    }

    make({threat: "SQL injection pattern",         ip: "198.51.100.22", status: "PENDING"});
    make({threat: "Credential stuffing detected", ip: "203.0.113.77",  status: "STAGED"});
    make({
        threat: "High-rate port probe",
        ip: "192.0.2.41",
        status: "APPROVED",
        decision_reason: "Confirmed scanner - allowlisted",
        operator: "ops@sentinel",
    });
    make({threat: "XSS payload in user-agent",    ip: "198.51.100.9", status: "PENDING"});
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
            return {ok: true};
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
            return {ok: true};
        },
        inject: async () => {
            make({
                threat: "Injected test incident",
                ip: "203.0.113.88",
                status: Math.random() > 0.5 ? "PENDING" : "STAGED",
            });
            return {ok: true};
        },
        vaultStats: async () => ({records: 12487}),
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
                body: JSON.stringify({reason}),
            }),

    veto: (id, reason) =>
        CONFIG.DEMO_MODE
            ? demoBackend.veto(id, reason)
            : fetchJson(`/actions/${encodeURIComponent(id)}/veto`, {
                method: "POST",
                body: JSON.stringify({reason}),
            }),

    inject: () =>
        CONFIG.DEMO_MODE
            ? demoBackend.inject()
            : CONFIG.LIVE_TEST_MODE
                ? fetchJson("/actions/test-inject", {method: "POST"})
                : Promise.reject(new Error("Inject requires demo or local test mode")),
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

    prevCounts = {pending, staged, approved};

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
        el.bulkApproveBtn.disabled = !selected.some(a => a.status === "STAGED");
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
    row.scrollIntoView({block: "nearest"});
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
            ? new Date(action.createdAt).toLocaleString([], {dateStyle: "short", timeStyle: "short"})
            : "MISSING";
        const createdStyle = action.createdBad
            ? "color:var(--red);font-size:10px;"
            : "color:var(--muted);font-size:10px;";

        const canApprove = action.status === "STAGED";
        const canVeto = ["PENDING", "STAGED"].includes(action.status);

        const controls = canApprove || canVeto
            ? `<div class="act-btns">` +
              (canApprove
                  ? `<button class="btn green" type="button" style="padding:3px 7px"` +
                    ` data-approve="${escHtml(action.id)}"` +
                    ` aria-label="Approve ${escHtml(action.id)}" title="Approve (A)">✓</button>`
                  : "") +
              (canVeto
                  ? `<button class="btn red" type="button" style="padding:3px 7px"` +
                    ` data-veto="${escHtml(action.id)}"` +
                    ` aria-label="Veto ${escHtml(action.id)}" title="Veto (V)">✕</button>`
                  : "") +
              `</div>`
            : `<span style="color:var(--muted);font-size:10px;font-family:var(--font-mono);">` +
              `${escHtml(action.operator) || "—"}</span>`;

        row.innerHTML =
            `<td><input type="checkbox" class="row-cb" data-id="${escHtml(action.id)}"` +
            `${selectedIds.has(action.id) ? " checked" : ""} aria-label="Select ${escHtml(action.id)}"></td>` +
            `<td><button class="expand-btn" type="button" data-expand="${escHtml(action.id)}" aria-label="Expand ${escHtml(action.id)}">▶</button></td>` +
            `<td class="mono" style="color:var(--cyan)">${escHtml(action.id || "<missing>")}</td>` +
            `<td>${escHtml(action.threat)}</td>` +
            `<td class="mono" style="color:var(--muted)">${escHtml(action.source)}</td>` +
            `<td><span class="tag ${statusClass}">${escHtml(action.status)}</span></td>` +
            `<td class="mono" style="${createdStyle}">${escHtml(created)}</td>` +
            `<td class="reason-cell" title="${escHtml(action.decisionReason)}">` +
            `${action.decisionReason ? escHtml(action.decisionReason) : '<span style="color:var(--muted)">—</span>'}</td>` +
            `<td class="sticky-actions">${controls}</td>`;

        el.actionsBody.appendChild(row);
    }

    restoreFocus(previousFocusId);
    updateBulkBar();
}

// =============================================================================
// Expand Rows
// =============================================================================

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

function openReasonModal({title, subtitle, confirmText, confirmClass = "green"}) {
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
// Refresh / Data Sync
// =============================================================================

async function performRefresh(manual = false) {
    document.body.setAttribute("aria-busy", "true");
    if (manual) setStatus("Syncing");
    try {
        updateStaticConfig();
        const [rawActions, vault] = await Promise.all([
            api.listActions(),
            api.vaultStats().catch(() => null),
        ]);
        replaceActions(rawActions, wsConnected ? "live-sync" : "poll-sync");
        const records = extractVaultRecords(vault);
        if (el.vaultCount) {
            el.vaultCount.textContent = typeof records === "number"
                ? records.toLocaleString()
                : "--";
        }
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

async function refreshDashboard(manual = false, {force = false} = {}) {
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
    const refreshed = await refreshDashboard(false, {force: true});
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

    const refreshed = await refreshDashboard(false, {force: true});
    if (!refreshed) {
        log(`Bulk ${kind} aborted: live state could not be refreshed.`, "err");
        return;
    }

    const expected = isApprove ? ["STAGED"] : ["PENDING", "STAGED"];
    const eligible = requestedIds.filter(id => {
        const a = allActions.find(x => x.id === id);
        return a && expected.includes(a.status);
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
        await refreshDashboard(true, {force: true});
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
        await refreshDashboard(true, {force: true});
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

    const blob = new Blob([JSON.stringify(payload, null, 2)], {type: "application/json"});
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
    if (el.modeText) el.modeText.textContent = "HUMAN_GATED";

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

    const token = getDevToken();
    if (el.authStateText) {
        el.authStateText.textContent = token
            ? "DEV TOKEN PRESENT"
            : CONFIG.ALLOW_DEV_JWT_STORAGE ? "COOKIE / MISSING" : "COOKIE ONLY";
        el.authStateText.style.color = token ? "var(--amber)" : "var(--green)";
    }
    if (el.jwtRiskBadge) el.jwtRiskBadge.hidden = !token;
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
        if (stored === "light") {
            applyTheme(true);
            return;
        }
        if (stored === "dark") {
            applyTheme(false);
            return;
        }
    } catch {}
    applyTheme(
        window.matchMedia?.("(prefers-color-scheme: light)").matches ?? false
    );
}

// =============================================================================
// JWT Modal
// =============================================================================

function closeJwtModal() {
    if (!el.jwtModal || el.jwtModal.hidden) return;
    el.jwtModal.hidden = true;
    el.jwtModal.setAttribute("aria-hidden", "true");
}

async function handleAuthChanged() {
    updateStaticConfig();
    if (!CONFIG.DEMO_MODE) {
        // Reconnect triggers websocket.js's full auth flow with the new token.
        window.SentinelWS?.disconnect();
        window.SentinelWS?.connect();
    }
    await refreshDashboard(true, {force: true});
}

el.authBtn?.addEventListener("click", () => {
    if (!CONFIG.ALLOW_DEV_JWT_STORAGE || !el.jwtModal) {
        log("Browser JWT storage is disabled outside local development.", "warn");
        return;
    }
    if (el.jwtInput) el.jwtInput.value = getDevToken() ?? "";
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
    log("Development JWT cleared.", "warn");
    closeJwtModal();
    await handleAuthChanged();
});
el.jwtConfirm?.addEventListener("click", async () => {
    if (!CONFIG.ALLOW_DEV_JWT_STORAGE) return;
    const token = el.jwtInput?.value.trim() ?? "";
    try {
        if (token) {
            sessionStorage.setItem("SENTINEL_JWT", token);
            log("Development JWT stored in sessionStorage. Local use only.", "warn");
        } else {
            sessionStorage.removeItem("SENTINEL_JWT");
            log("Development JWT cleared.", "warn");
        }
    } catch {
        log("Unable to update sessionStorage JWT.", "err");
    }
    closeJwtModal();
    await handleAuthChanged();
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

// Fix v1.5.2: auth_required is handled internally by websocket.js before this
// event fires. Do not send a second auth frame here — that causes a double-auth
// race. This listener exists solely for UI notification (log + status).
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

window.addEventListener("sentinel:ws:stale", () => {
    log("WebSocket connection stale — forcing reconnect.", "warn");
});

// All server-to-dashboard messages arrive here after websocket.js has
// validated the frame, checked the byte limit, and parsed the JSON.
window.addEventListener("sentinel:ws:message", event => {
    const {type, payload} = event.detail;

    switch (type) {

        // Fix v1.5.2: auth_required is handled internally by websocket.js and
        // never re-dispatched to sentinel:ws:message. This case is dead code
        // and is removed to avoid confusion. The auth flow is:
        //   open → proactive auth (websocket.js)
        //   OR server sends auth_required → websocket.js responds internally
        //       → dispatches sentinel:ws:auth_required for UI notification only

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

        case "watchtower_state":
            log(
                `Watchtower ${payload.reachable ? "reachable" : "unreachable"}.`,
                payload.reachable ? "ok" : "warn"
            );
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

el.refreshBtn?.addEventListener("click", () => refreshDashboard(true, {force: true}));
el.exportBtn?.addEventListener("click", exportVisibleActions);
el.injectBtn?.addEventListener("click", openInjectModal);
el.themeBtn?.addEventListener("click", () => applyTheme(!isLight));
el.clearLogBtn?.addEventListener("click", () => {
    if (el.logConsole) el.logConsole.innerHTML = "";
    log("Console cleared.", "info");
});

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
        if (ok) await refreshDashboard(true, {force: true});
        return;
    }

    const vetoBtn = e.target.closest?.("[data-veto]");
    if (vetoBtn) {
        const ok = await doVeto(vetoBtn.dataset.veto, vetoBtn);
        if (ok) await refreshDashboard(true, {force: true});
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
        if (!el.reasonModal?.hidden) {
            el.modalCancel?.click();
            return;
        }
        if (!el.jwtModal?.hidden) {
            closeJwtModal();
            return;
        }
        if (!el.injectModal?.hidden) {
            closeInjectModal();
            return;
        }
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
        refreshDashboard(true, {force: true});
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
            doApprove(id).then(ok => {
                if (ok) refreshDashboard(true, {force: true});
            });
        }
        return;
    }
    if (e.key.toLowerCase() === "v" && focusedRowIndex >= 0 && focusedRowIndex < rows.length) {
        const id = rows[focusedRowIndex].dataset.id;
        const action = allActions.find(a => a.id === id);
        if (action && ["PENDING", "STAGED"].includes(action.status)) {
            doVeto(id).then(ok => {
                if (ok) refreshDashboard(true, {force: true});
            });
        }
    }
});

// =============================================================================
// Unload Cleanup
// =============================================================================

window.addEventListener("beforeunload", () => {
    if (pollTimer) clearInterval(pollTimer);
});

// =============================================================================
// Initialization
// =============================================================================

log("Dashboard initializing…", "info");

if (CONFIG.DEMO_MODE) {
    // websocket.js auto-connects on load; cut it immediately in demo mode.
    window.SentinelWS?.disconnect();
    log("Demo mode active. WebSocket disconnected. Use ?demo=1 for local testing only.", "warn");
} else if (!CONFIG.LIVE_TEST_MODE) {
    log("Demo mode disabled. Live API mode active.", "info");
}

initTheme();
updateStaticConfig();
setStatus("Booting");
startPollingFallback();
refreshDashboard(true, {force: true});
