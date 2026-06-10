"use strict";

const readMeta = name => document.querySelector(`meta[name="${name}"]`)?.content?.trim() || "";
const runtime = window.SENTINEL_RUNTIME_CONFIG || {};
const locationIsLocal = ["", "localhost", "127.0.0.1", "::1"].includes(location.hostname);

const CONFIG = Object.freeze({
  API_BASE: String(runtime.apiBase || window.SENTINEL_API_BASE_URL || readMeta("sentinel-api-base") || "http://localhost:8000").replace(/\/+$/, ""),
  WS_URL: String(runtime.wsUrl || window.SENTINEL_WS_URL || readMeta("sentinel-ws-url") || "ws://localhost:8000/ws"),
  FALLBACK_POLL_MS: 15000,
  WS_RECONNECT_MS: 3000,
  WS_HEARTBEAT_MS: 25000,
  DATA_STALE_MS: 60000,
  REASON_MIN: 10,
  REASON_MAX: 500,
  DEMO_MODE: new URLSearchParams(location.search).get("demo") === "1",
  MAX_LOG_LINES: 500,
  MAX_DEMO_ACTIONS: 500,
  MAX_WS_FRAME_BYTES: 64 * 1024,
  ALLOW_DEV_JWT_STORAGE: locationIsLocal
});

const STATUS_CLASSES = Object.freeze({
  PENDING: "pending",
  STAGED: "staged",
  APPROVED: "approved",
  EXECUTED: "executed",
  VETOED: "vetoed",
  EXPIRED: "expired",
  UNKNOWN: "unknown"
});

const $ = id => document.getElementById(id);
const el = {
  statusDot: $("statusDot"), statusText: $("statusText"), modeText: $("modeText"), queueCount: $("queueCount"), lastSync: $("lastSync"), pollFlash: $("pollFlash"), demoBadge: $("demoBadge"), jwtRiskBadge: $("jwtRiskBadge"),
  pendingCount: $("pendingCount"), stagedCount: $("stagedCount"), approvedCount: $("approvedCount"), vaultCount: $("vaultCount"), apiBaseText: $("apiBaseText"), authStateText: $("authStateText"), pollText: $("pollText"), demoText: $("demoText"),
  refreshBtn: $("refreshBtn"), injectBtn: $("injectBtn"), exportBtn: $("exportBtn"), themeBtn: $("themeBtn"), authBtn: $("authBtn"), kbHelpBtn: $("kbHelpBtn"), actionsBody: $("actionsBody"), emptyState: $("emptyState"), logConsole: $("logConsole"), clearLogBtn: $("clearLogBtn"),
  searchInput: $("searchInput"), clearSearchBtn: $("clearSearchBtn"), selectAll: $("selectAll"), bulkBar: $("bulkBar"), bulkLabel: $("bulkLabel"), bulkApproveBtn: $("bulkApproveBtn"), bulkVetoBtn: $("bulkVetoBtn"), bulkClearBtn: $("bulkClearBtn"),
  reasonModal: $("reasonModal"), modalTitle: $("modalTitle"), modalSubtitle: $("modalSubtitle"), modalInput: $("modalInput"), modalError: $("modalError"), modalCharCount: $("modalCharCount"), modalCancel: $("modalCancel"), modalConfirm: $("modalConfirm"),
  jwtModal: $("jwtModal"), jwtInput: $("jwtInput"), jwtCancel: $("jwtCancel"), jwtClear: $("jwtClear"), jwtConfirm: $("jwtConfirm"), injectModal: $("injectModal"), injectCancel: $("injectCancel"), injectConfirm: $("injectConfirm"), kbToast: $("kbToast"), liveRegion: $("liveRegion")
};

let currentFilter = "ALL";
let currentLogFilter = "ALL";
let searchQuery = "";
let allActions = [];
let selectedIds = new Set();
let focusedRowIndex = -1;
let focusedActionId = null;
let prevCounts = {pending: null, staged: null, approved: null};
let lastDataSyncAt = null;
let refreshPromise = null;
let pollTimer = null;
let kbToastTimer = null;
let modalOpenCount = 0;
let injectInFlight = false;
let ws = null;
let wsConnected = false;
let wsReconnectTimer = null;
let wsHeartbeatTimer = null;
let wsClosing = false;

const nowStamp = () => new Date().toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"});
const escHtml = value => String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
const normalizeString = (value, fallback = "") => typeof value === "string" ? value : value == null ? fallback : String(value);

function log(message, type = "info") {
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
  if (currentLogFilter !== "ALL" && safeType !== currentLogFilter) line.hidden = true;
  el.logConsole.appendChild(line);

  if (safeType === "err" || safeType === "warn") el.liveRegion.textContent = msg.textContent;
  while (el.logConsole.children.length > CONFIG.MAX_LOG_LINES) el.logConsole.removeChild(el.logConsole.firstElementChild);
  el.logConsole.scrollTop = el.logConsole.scrollHeight;
}

function setStatus(state) {
  const normalized = normalizeString(state, "unknown").toLowerCase();
  el.statusText.textContent = normalized.toUpperCase();
  el.statusDot.classList.remove("online", "offline");
  if (["online", "live"].includes(normalized)) el.statusDot.classList.add("online");
  if (normalized === "offline") el.statusDot.classList.add("offline");
}

function flashPoll() {
  el.pollFlash.classList.add("flash");
  setTimeout(() => el.pollFlash.classList.remove("flash"), 600);
}

function bumpStat(node) {
  node.classList.add("bump");
  setTimeout(() => node.classList.remove("bump"), 250);
}

function markDataSync(source) {
  lastDataSyncAt = new Date();
  el.lastSync.textContent = `${source} ${nowStamp()}`;
  flashPoll();
}

function dataIsStale() {
  return !lastDataSyncAt || Date.now() - lastDataSyncAt.getTime() > CONFIG.DATA_STALE_MS;
}

function validateRelativePath(path) {
  if (typeof path !== "string" || !path.startsWith("/")) throw new Error("API path must be relative");
  if (path.includes("\r") || path.includes("\n")) throw new Error("API path contains invalid characters");
  return path;
}

function buildApiUrl(path) {
  validateRelativePath(path);
  return new URL(`${CONFIG.API_BASE}${path}`, location.href);
}

function getDevToken() {
  if (!CONFIG.ALLOW_DEV_JWT_STORAGE) return null;
  try { return sessionStorage.getItem("SENTINEL_JWT"); } catch { return null; }
}

function getAuthHeaders() {
  const headers = {"Content-Type": "application/json"};
  const token = getDevToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

function safeServerErrorDetail(body) {
  if (!body || typeof body !== "object") return null;
  for (const key of ["detail", "error", "message"]) {
    const value = body[key];
    if (typeof value === "string" && value.trim()) return value.trim().slice(0, 240);
  }
  return null;
}

async function fetchJson(path, opts = {}) {
  const url = buildApiUrl(path);
  const sameOrigin = url.origin === location.origin;
  const response = await fetch(url.toString(), {
  ...opts,
  cache: "no-store",
  headers: {
    ...getAuthHeaders(),
    "Cache-Control": "no-cache",
    ...(opts.headers || {})
  },
  credentials: sameOrigin ? "include" : "omit"
});

  const contentType = response.headers.get("content-type") || "";
  const isJson = contentType.includes("application/json");

  if (!response.ok) {
    let detail = null;
    if (isJson) {
      try { detail = safeServerErrorDetail(await response.json()); } catch {}
    }
    throw new Error(`${response.status} ${response.statusText}${detail ? `: ${detail}` : ""}`);
  }

  if (!isJson) return null;
  return response.json();
}

function unwrapData(value) {
  if (value && typeof value === "object" && !Array.isArray(value) && "data" in value) return value.data;
  return value;
}

function extractActionList(value) {
  const unwrapped = unwrapData(value);
  if (Array.isArray(unwrapped)) return unwrapped;
  if (unwrapped && typeof unwrapped === "object" && Array.isArray(unwrapped.actions)) return unwrapped.actions;
  throw new Error("Action endpoint returned an invalid payload shape");
}

function extractVaultRecords(value) {
  const unwrapped = unwrapData(value);
  if (unwrapped && typeof unwrapped === "object" && typeof unwrapped.records === "number") return unwrapped.records;
  return null;
}

const demoBackend = (() => {
  const store = new Map();
  const genId = () => `ACT-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`.toUpperCase();

  function trimStore() {
    while (store.size > CONFIG.MAX_DEMO_ACTIONS) store.delete(store.keys().next().value);
  }

  function make(options = {}) {
    const item = {
      id: genId(),
      action_type: options.action_type || "THREAT_ACTION",
      status: options.status || (Math.random() > 0.5 ? "PENDING" : "STAGED"),
      created_at: options.created_at || new Date().toISOString(),
      decision_reason: options.decision_reason || "",
      operator: options.operator || "",
      payload: {
        ip: options.ip || "203.0.113.10",
        source_ip: options.source_ip || options.ip || "203.0.113.10",
        threat: options.threat || "Suspicious activity"
      }
    };
    store.set(item.id, item);
    trimStore();
    return item;
  }

  make({threat: "SQL injection pattern", ip: "198.51.100.22", status: "PENDING"});
  make({threat: "Credential stuffing detected", ip: "203.0.113.77", status: "STAGED"});
  make({threat: "High-rate port probe", ip: "192.0.2.41", status: "APPROVED", decision_reason: "Confirmed scanner - allowlisted", operator: "ops@sentinel"});
  make({threat: "XSS payload in user-agent", ip: "198.51.100.9", status: "PENDING"});
  make({threat: "Tor exit-node connection", ip: "10.0.0.7", status: "VETOED", decision_reason: "Internal test traffic - false positive", operator: "sec@sentinel"});

  return {
    async listActions() { return Array.from(store.values()).sort((a, b) => new Date(b.created_at) - new Date(a.created_at)); },
    async approve(id, reason) { const item = store.get(id); if (!item) throw new Error("Not found"); if (item.status !== "STAGED") throw new Error("Only staged actions can be approved"); item.status = "APPROVED"; item.decision_reason = reason; item.operator = "operator"; return {ok: true}; },
    async veto(id, reason) { const item = store.get(id); if (!item) throw new Error("Not found"); if (!["PENDING", "STAGED"].includes(item.status)) throw new Error("Only pending/staged actions can be vetoed"); item.status = "VETOED"; item.decision_reason = reason; item.operator = "operator"; return {ok: true}; },
    async inject() { make({threat: "Injected test incident", ip: "203.0.113.88", status: Math.random() > 0.5 ? "PENDING" : "STAGED"}); return {ok: true}; },
    async vaultStats() { return {records: 12487}; }
  };
})();

const api = {
  listActions: () => CONFIG.DEMO_MODE ? demoBackend.listActions() : fetchJson("/actions?limit=250"),
  approve: (id, reason) => CONFIG.DEMO_MODE ? demoBackend.approve(id, reason) : fetchJson(`/actions/${encodeURIComponent(id)}/approve`, {method: "POST", body: JSON.stringify({reason})}),
  veto: (id, reason) => CONFIG.DEMO_MODE ? demoBackend.veto(id, reason) : fetchJson(`/actions/${encodeURIComponent(id)}/veto`, {method: "POST", body: JSON.stringify({reason})}),
  inject: () => CONFIG.DEMO_MODE ? demoBackend.inject() : Promise.reject(new Error("Inject is disabled unless demo mode is enabled")),
  vaultStats: () => CONFIG.DEMO_MODE ? demoBackend.vaultStats() : fetchJson("/vault/stats")
};

function normalizeAction(raw) {
  const payload = raw && typeof raw.payload === "object" && raw.payload !== null ? raw.payload : {};
  const id = normalizeString(raw?.id, "").trim();
  const createdRaw = normalizeString(raw?.created_at, "");
  let createdAt = null;
  let createdBad = false;

  if (!createdRaw) {
    createdBad = true;
  } else {
    const parsed = Date.parse(createdRaw);
    if (Number.isNaN(parsed)) createdBad = true;
    else createdAt = new Date(parsed).toISOString();
  }

  if (!id) log("Backend returned action without id; rendering with empty id guard.", "warn");
  if (createdBad) log(`Action ${id || "<missing-id>"} has missing or invalid created_at.`, "warn");

  return {
    id,
    threat: normalizeString(payload.threat || raw?.action_type, "UNKNOWN"),
    source: normalizeString(payload.source_ip || payload.ip, "n/a"),
    status: normalizeString(raw?.status, "UNKNOWN").toUpperCase(),
    createdAt,
    createdRaw,
    createdBad,
    decisionReason: normalizeString(raw?.decision_reason, ""),
    operator: normalizeString(raw?.operator, ""),
    payload
  };
}

const actionTimeValue = action => action.createdAt ? Date.parse(action.createdAt) : 0;

function reconcileSelectedIds() {
  const validIds = new Set(allActions.map(action => action.id).filter(Boolean));
  const before = selectedIds.size;
  selectedIds = new Set([...selectedIds].filter(id => validIds.has(id)));
  if (selectedIds.size !== before) log("Removed stale selections that no longer exist in the live queue.", "info");
}

function replaceActions(rawActions, source) {
  allActions = extractActionList(rawActions).map(normalizeAction).sort((a, b) => actionTimeValue(b) - actionTimeValue(a));
  reconcileSelectedIds();
  updateStats(allActions);
  renderActions(applyFilters(allActions));
  markDataSync(source);
}

function upsertAction(rawAction, source = "ws") {
  const action = normalizeAction(rawAction);
  if (!action.id) return;
  const index = allActions.findIndex(existing => existing.id === action.id);
  if (index >= 0) allActions[index] = action;
  else allActions.push(action);
  allActions.sort((a, b) => actionTimeValue(b) - actionTimeValue(a));
  reconcileSelectedIds();
  updateStats(allActions);
  renderActions(applyFilters(allActions));
  markDataSync(source);
}

function removeAction(actionId, source = "ws") {
  const cleaned = normalizeString(actionId, "").trim();
  if (!cleaned) return;
  allActions = allActions.filter(action => action.id !== cleaned);
  reconcileSelectedIds();
  updateStats(allActions);
  renderActions(applyFilters(allActions));
  markDataSync(source);
}

function applyFilters(actions) {
  let output = currentFilter === "ALL" ? actions : actions.filter(action => action.status === currentFilter);
  const query = searchQuery.trim().toLowerCase();
  if (query) output = output.filter(action => action.id.toLowerCase().includes(query) || action.threat.toLowerCase().includes(query) || action.source.toLowerCase().includes(query));
  return output;
}

function visibleActionIds() {
  return new Set(applyFilters(allActions).map(action => action.id));
}

function updateStats(actions) {
  const pending = actions.filter(action => action.status === "PENDING").length;
  const staged = actions.filter(action => action.status === "STAGED").length;
  const approved = actions.filter(action => action.status === "APPROVED" || action.status === "EXECUTED").length;
  const vetoed = actions.filter(action => action.status === "VETOED").length;

  if (pending !== prevCounts.pending) { bumpStat(el.pendingCount); el.pendingCount.textContent = pending; }
  if (staged !== prevCounts.staged) { bumpStat(el.stagedCount); el.stagedCount.textContent = staged; }
  if (approved !== prevCounts.approved) { bumpStat(el.approvedCount); el.approvedCount.textContent = approved; }
  prevCounts = {pending, staged, approved};
  el.queueCount.textContent = pending + staged;

  for (const [key, value] of Object.entries({ALL: actions.length, PENDING: pending, STAGED: staged, APPROVED: approved, VETOED: vetoed})) {
    const target = $(`fc-${key}`);
    if (target) target.textContent = value > 0 ? ` (${value})` : "";
  }
}

function updateSelectAllState() {
  const checkboxes = Array.from(document.querySelectorAll(".row-cb"));
  const checked = checkboxes.filter(checkbox => checkbox.checked).length;
  el.selectAll.checked = checkboxes.length > 0 && checked === checkboxes.length;
  el.selectAll.indeterminate = checked > 0 && checked < checkboxes.length;
}

function updateBulkBar() {
  const count = selectedIds.size;
  const visibleIds = visibleActionIds();
  const hidden = [...selectedIds].filter(id => !visibleIds.has(id)).length;
  el.bulkBar.classList.toggle("visible", count > 0);
  el.bulkLabel.textContent = hidden ? `${count} selected (${hidden} hidden by filter/search)` : `${count} selected`;

  const selectedActions = [...selectedIds].map(id => allActions.find(action => action.id === id)).filter(Boolean);
  el.bulkApproveBtn.disabled = !selectedActions.some(action => action.status === "STAGED");
  el.bulkVetoBtn.disabled = !selectedActions.some(action => ["PENDING", "STAGED"].includes(action.status));
  updateSelectAllState();
}

function clearSelection() {
  selectedIds.clear();
  document.querySelectorAll(".row-cb").forEach(checkbox => {
    checkbox.checked = false;
    checkbox.closest("tr")?.classList.remove("selected");
  });
  el.selectAll.checked = false;
  el.selectAll.indeterminate = false;
  updateBulkBar();
}

function resetFocus() {
  focusedRowIndex = -1;
  focusedActionId = null;
  document.querySelectorAll("tr.focused").forEach(row => row.classList.remove("focused"));
}

function visibleRows() {
  return Array.from(el.actionsBody.querySelectorAll("tr[data-id]:not(.expand-row)"));
}

function setFocusedRow(index) {
  const rows = visibleRows();
  rows.forEach(row => row.classList.remove("focused"));
  if (!rows.length) { resetFocus(); return; }
  focusedRowIndex = Math.max(0, Math.min(index, rows.length - 1));
  const row = rows[focusedRowIndex];
  focusedActionId = row.dataset.id || null;
  row.classList.add("focused");
  row.scrollIntoView({block: "nearest"});
}

function restoreFocus(previousId) {
  if (!previousId) { resetFocus(); return; }
  const rows = visibleRows();
  const index = rows.findIndex(row => row.dataset.id === previousId);
  if (index < 0) { resetFocus(); return; }
  setFocusedRow(index);
}

function renderActions(actions) {
  const previousFocusId = focusedActionId;
  el.actionsBody.innerHTML = "";
  el.emptyState.hidden = Boolean(actions.length);
  if (!actions.length) { resetFocus(); updateBulkBar(); return; }

  actions.forEach((action, index) => {
    const row = document.createElement("tr");
    row.dataset.id = action.id;
    row.dataset.idx = String(index);
    if (selectedIds.has(action.id)) row.classList.add("selected");

    const statusClass = STATUS_CLASSES[action.status] || "unknown";
    const created = action.createdAt ? new Date(action.createdAt).toLocaleString([], {dateStyle: "short", timeStyle: "short"}) : "MISSING";
    const createdStyle = action.createdBad ? "color:var(--red);font-size:10px;" : "color:var(--muted);font-size:10px;";
    const canVeto = ["PENDING", "STAGED"].includes(action.status);
    const canApprove = action.status === "STAGED";
    const operationCell = canVeto || canApprove
      ? `<div class="act-btns">${canApprove ? `<button class="btn green" type="button" style="padding:3px 7px" data-approve="${escHtml(action.id)}" title="Approve (A)" aria-label="Approve ${escHtml(action.id)}">✓</button>` : ""}${canVeto ? `<button class="btn red" type="button" style="padding:3px 7px" data-veto="${escHtml(action.id)}" title="Veto (V)" aria-label="Veto ${escHtml(action.id)}">✕</button>` : ""}</div>`
      : `<span style="color:var(--muted);font-size:10px;font-family:var(--font-mono);">${escHtml(action.operator) || "—"}</span>`;

    row.innerHTML = `<td><input type="checkbox" class="row-cb" data-id="${escHtml(action.id)}"${selectedIds.has(action.id) ? " checked" : ""} aria-label="Select ${escHtml(action.id)}"></td><td><button class="expand-btn" type="button" data-expand="${escHtml(action.id)}" aria-label="Expand ${escHtml(action.id)}">▶</button></td><td class="mono" style="color:var(--cyan)">${escHtml(action.id || "<missing>")}</td><td>${escHtml(action.threat)}</td><td class="mono" style="color:var(--muted)">${escHtml(action.source)}</td><td><span class="tag ${statusClass}">${escHtml(action.status)}</span></td><td class="mono" style="${createdStyle}">${escHtml(created)}</td><td class="reason-cell" title="${escHtml(action.decisionReason)}">${action.decisionReason ? escHtml(action.decisionReason) : `<span style="color:var(--muted)">—</span>`}</td><td class="sticky-actions">${operationCell}</td>`;
    el.actionsBody.appendChild(row);
  });

  restoreFocus(previousFocusId);
  updateBulkBar();
}

function toggleExpand(actionId) {
  const existing = Array.from(document.querySelectorAll(".expand-row")).find(row => row.dataset.for === actionId);
  const button = Array.from(document.querySelectorAll("[data-expand]")).find(node => node.dataset.expand === actionId);
  if (existing) { existing.remove(); if (button) button.textContent = "▶"; return; }

  const action = allActions.find(candidate => candidate.id === actionId);
  const row = Array.from(document.querySelectorAll("tr[data-id]")).find(candidate => candidate.dataset.id === actionId);
  if (!action || !row) return;

  const expansion = document.createElement("tr");
  expansion.className = "expand-row";
  expansion.dataset.for = actionId;
  expansion.innerHTML = `<td colspan="9"><div class="expand-inner"><div class="expand-kv"><div class="k">ACTION ID</div><div class="v">${escHtml(action.id)}</div></div><div class="expand-kv"><div class="k">SOURCE IP</div><div class="v">${escHtml(action.source)}</div></div><div class="expand-kv"><div class="k">THREAT</div><div class="v">${escHtml(action.threat)}</div></div><div class="expand-kv"><div class="k">STATUS</div><div class="v">${escHtml(action.status)}</div></div><div class="expand-kv"><div class="k">CREATED</div><div class="v">${escHtml(action.createdAt || "MISSING / INVALID")}</div></div><div class="expand-kv"><div class="k">OPERATOR</div><div class="v">${escHtml(action.operator || "—")}</div></div><div class="expand-kv"><div class="k">REASON</div><div class="v">${escHtml(action.decisionReason || "—")}</div></div></div></td>`;
  row.after(expansion);
  if (button) button.textContent = "▼";
}

function validateReason(value) {
  const cleaned = normalizeString(value, "").trim();
  if (!cleaned) return "Reason is required.";
  if (cleaned.length < CONFIG.REASON_MIN) return `Minimum ${CONFIG.REASON_MIN} characters required.`;
  if (cleaned.length > CONFIG.REASON_MAX) return `Maximum ${CONFIG.REASON_MAX} characters.`;
  return null;
}

function setModalOpen(open) {
  modalOpenCount += open ? 1 : -1;
  modalOpenCount = Math.max(0, modalOpenCount);
}

function openReasonModal({title, subtitle, confirmText, confirmClass = "green"}) {
  return new Promise(resolve => {
    setModalOpen(true);
    const close = result => { el.reasonModal.hidden = true; el.reasonModal.setAttribute("aria-hidden", "true"); el.modalError.textContent = ""; setModalOpen(false); resolve(result); };
    el.modalTitle.textContent = title;
    el.modalSubtitle.textContent = subtitle;
    el.modalInput.value = "";
    el.modalCharCount.textContent = `0 / ${CONFIG.REASON_MAX}`;
    el.modalConfirm.textContent = confirmText;
    el.modalConfirm.className = `btn ${confirmClass}`;
    el.reasonModal.hidden = false;
    el.reasonModal.setAttribute("aria-hidden", "false");
    setTimeout(() => el.modalInput.focus(), 0);

    const onInput = () => { el.modalCharCount.textContent = `${el.modalInput.value.length} / ${CONFIG.REASON_MAX}`; if (el.modalError.textContent) el.modalError.textContent = ""; };
    const onCancel = () => { cleanup(); close(null); };
    const onConfirm = () => { const error = validateReason(el.modalInput.value); if (error) { el.modalError.textContent = error; return; } cleanup(); close(el.modalInput.value.trim()); };
    const onBackdrop = event => { if (event.target.hasAttribute("data-close")) onCancel(); };
    const onKey = event => { if (event.key === "Escape") onCancel(); if ((event.ctrlKey || event.metaKey) && event.key === "Enter") onConfirm(); };
    function cleanup() { el.modalInput.removeEventListener("input", onInput); el.modalCancel.removeEventListener("click", onCancel); el.modalConfirm.removeEventListener("click", onConfirm); el.reasonModal.removeEventListener("click", onBackdrop); document.removeEventListener("keydown", onKey); }

    el.modalInput.addEventListener("input", onInput);
    el.modalCancel.addEventListener("click", onCancel);
    el.modalConfirm.addEventListener("click", onConfirm);
    el.reasonModal.addEventListener("click", onBackdrop);
    document.addEventListener("keydown", onKey);
  });
}

async function performRefresh(manual = false) {
  document.body.setAttribute("aria-busy", "true");
  if (manual) setStatus("Syncing");
  try {
    updateStaticConfig();
    const [rawActions, vault] = await Promise.all([
      api.listActions(),
      api.vaultStats().catch(() => null)
    ]);
    replaceActions(rawActions, "http-sync");
    const records = extractVaultRecords(vault);
    el.vaultCount.textContent = typeof records === "number" ? records.toLocaleString() : "--";
    setStatus(wsConnected ? "Live" : "Online");
    if (manual) log(`Refresh complete - ${applyFilters(allActions).length} action(s) visible.`, "ok");
    return true;
  } catch (error) {
    setStatus(wsConnected ? "Degraded" : "Offline");
    log(`Refresh failed: ${error.message || error}`, "err");
    return false;
  } finally {
    document.body.removeAttribute("aria-busy");
  }
}

async function refreshDashboard(manual = false, {force = false} = {}) {
  if (refreshPromise) {
    const priorResult = await refreshPromise;
    if (!force) return priorResult;
  }
  refreshPromise = performRefresh(manual).finally(() => { refreshPromise = null; });
  return refreshPromise;
}

async function revalidateAction(actionId, expectedStatuses) {
  const refreshed = await refreshDashboard(false, {force: true});
  if (!refreshed) throw new Error("Unable to refresh live action state before submit");
  const latest = allActions.find(action => action.id === actionId);
  if (!latest) throw new Error("Action disappeared before submit");
  if (!expectedStatuses.includes(latest.status)) throw new Error(`Action status changed to ${latest.status}`);
}

async function doApprove(actionId, button) {
  const reason = await openReasonModal({title: `Approve ${actionId}`, subtitle: "Describe why this action should proceed.", confirmText: "Approve", confirmClass: "green"});
  if (!reason) { log(`Approve cancelled - ${actionId}`, "warn"); return false; }
  if (button) button.disabled = true;
  try { await revalidateAction(actionId, ["STAGED"]); await api.approve(actionId, reason); log(`Approved ${actionId}`, "ok"); return true; }
  catch (error) { log(`Approve failed - ${actionId}: ${error.message || error}`, "err"); return false; }
  finally { if (button) button.disabled = false; }
}

async function doVeto(actionId, button) {
  const reason = await openReasonModal({title: `Veto ${actionId}`, subtitle: "Explain why this action is being blocked.", confirmText: "Veto", confirmClass: "red"});
  if (!reason) { log(`Veto cancelled - ${actionId}`, "warn"); return false; }
  if (button) button.disabled = true;
  try { await revalidateAction(actionId, ["PENDING", "STAGED"]); await api.veto(actionId, reason); log(`Vetoed ${actionId}`, "warn"); return true; }
  catch (error) { log(`Veto failed - ${actionId}: ${error.message || error}`, "err"); return false; }
  finally { if (button) button.disabled = false; }
}

async function runBulkAction(kind) {
  const requestedIds = [...selectedIds];
  if (!requestedIds.length) return;
  const isApprove = kind === "approve";
  const reason = await openReasonModal({title: `Bulk ${kind} ${requestedIds.length} action(s)`, subtitle: `Applies only to currently eligible selected actions after a fresh server check.`, confirmText: isApprove ? "Approve All" : "Veto All", confirmClass: isApprove ? "green" : "red"});
  if (!reason) return;

  const refreshed = await refreshDashboard(false, {force: true});
  if (!refreshed) { log(`Bulk ${kind} aborted: live state could not be refreshed.`, "err"); return; }

  const expectedStatuses = isApprove ? ["STAGED"] : ["PENDING", "STAGED"];
  const eligibleIds = requestedIds.filter(id => { const action = allActions.find(candidate => candidate.id === id); return action && expectedStatuses.includes(action.status); });
  if (eligibleIds.length !== requestedIds.length) log(`Bulk ${kind}: skipped ${requestedIds.length - eligibleIds.length} stale or ineligible selection(s).`, "warn");
  if (!eligibleIds.length) { clearSelection(); return; }

  const button = isApprove ? el.bulkApproveBtn : el.bulkVetoBtn;
  button.disabled = true;
  let successCount = 0;
  try {
    for (const id of eligibleIds) {
      try {
        if (isApprove) await api.approve(id, reason);
        else await api.veto(id, reason);
        successCount += 1;
      } catch (error) {
        log(`Bulk ${kind} failed - ${id}: ${error.message || error}`, "err");
      }
    }
    log(`Bulk ${kind} completed: ${successCount}/${eligibleIds.length} action(s).`, isApprove ? "ok" : "warn");
  } finally {
    clearSelection();
    await refreshDashboard(true, {force: true});
    button.disabled = false;
  }
}

function safeWsUrl() {
  const url = new URL(CONFIG.WS_URL, location.href);
  if (!["ws:", "wss:"].includes(url.protocol)) throw new Error("WebSocket URL must use ws:// or wss://");
  if (location.protocol === "https:" && url.protocol !== "wss:") throw new Error("Secure pages require wss:// WebSocket URLs");
  if (["token", "access_token", "authorization", "api_key"].some(key => url.searchParams.has(key))) throw new Error("WebSocket credentials must not be placed in the URL");
  return url.toString();
}

function wsSend(type, payload = {}) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return false;
  ws.send(JSON.stringify({type, payload}));
  return true;
}

function startWsHeartbeat() {
  if (wsHeartbeatTimer) clearInterval(wsHeartbeatTimer);
  wsHeartbeatTimer = setInterval(() => wsSend("ping", {timestamp: new Date().toISOString()}), CONFIG.WS_HEARTBEAT_MS);
}

function stopWsHeartbeat() {
  if (wsHeartbeatTimer) clearInterval(wsHeartbeatTimer);
  wsHeartbeatTimer = null;
}

function decodeWsMessage(message) {
  if (typeof message !== "string") throw new Error("WebSocket frame must be text");
  if (new TextEncoder().encode(message).length > CONFIG.MAX_WS_FRAME_BYTES) throw new Error("WebSocket frame exceeds maximum size");
  const decoded = JSON.parse(message);
  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) throw new Error("WebSocket message must be an object");
  if (typeof decoded.type !== "string" || !decoded.type.trim()) throw new Error("WebSocket message type is required");
  if (!decoded.payload || typeof decoded.payload !== "object" || Array.isArray(decoded.payload)) throw new Error("WebSocket payload must be an object");
  return {type: decoded.type.trim(), payload: decoded.payload};
}

function applyWsMessage(message) {
  const {type, payload} = decodeWsMessage(message);
  switch (type) {
    case "actions_snapshot":
      replaceActions(payload.actions || payload, "ws-sync");
      break;
    case "action_created":
    case "action_updated":
    case "action_status_changed":
    case "action":
      upsertAction(payload.action || payload, "ws-sync");
      break;
    case "action_deleted":
    case "action_removed":
      removeAction(payload.id || payload.action_id, "ws-sync");
      break;
    case "vault_stats": {
      const records = extractVaultRecords(payload);
      el.vaultCount.textContent = typeof records === "number" ? records.toLocaleString() : "--";
      markDataSync("ws-sync");
      break;
    }
    case "pong":
      break;
    case "error":
      log(`WebSocket server error: ${normalizeString(payload.error, "unknown error")}`, "err");
      break;
    default:
      log(`Ignored unhandled WebSocket event type: ${type}`, "info");
  }
}

function scheduleWsReconnect() {
  if (CONFIG.DEMO_MODE || wsClosing || wsReconnectTimer) return;
  wsReconnectTimer = setTimeout(() => { wsReconnectTimer = null; connectWebSocket(); }, CONFIG.WS_RECONNECT_MS);
}

function closeWebSocket() {
  wsClosing = true;
  if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
  wsReconnectTimer = null;
  stopWsHeartbeat();
  if (ws) ws.close();
  ws = null;
  wsConnected = false;
}

function reconnectWebSocket() {
  closeWebSocket();
  wsClosing = false;
  connectWebSocket();
}

function connectWebSocket() {
  if (CONFIG.DEMO_MODE || wsClosing || wsConnected || (ws && [WebSocket.OPEN, WebSocket.CONNECTING].includes(ws.readyState))) return;
  let url;
  try { url = safeWsUrl(); }
  catch (error) { log(`WebSocket disabled: ${error.message || error}`, "warn"); setStatus("Degraded"); return; }

  try {
    setStatus("Reconnecting");
    ws = new WebSocket(url);
    ws.addEventListener("open", () => {
      wsConnected = true;
      setStatus("Live");
      log("WebSocket connected. Live queue updates enabled.", "ok");
      wsSend("subscribe", {channel: "actions"});
      wsSend("subscribe", {channel: "vault"});
      startWsHeartbeat();
    });
    ws.addEventListener("message", event => {
      try { applyWsMessage(event.data); }
      catch (error) { log(`Rejected WebSocket message: ${error.message || error}`, "warn"); }
    });
    case "connected":
  log("WebSocket server acknowledged connection.", "ok");
  break;

case "subscribed":
  log(`WebSocket subscription active: ${normalizeString(payload.channel, "unknown")}`, "ok");
  break;
    ws.addEventListener("close", () => {
      wsConnected = false;
      stopWsHeartbeat();
      if (!wsClosing) { setStatus("Reconnecting"); log("WebSocket disconnected. Polling fallback remains active.", "warn"); scheduleWsReconnect(); }
    });
    ws.addEventListener("error", () => log("WebSocket transport error. Polling fallback remains active.", "warn"));
  } catch (error) {
    wsConnected = false;
    log(`WebSocket connection failed: ${error.message || error}`, "warn");
    scheduleWsReconnect();
  }
}

function startPollingFallback() {
  if (pollTimer) clearInterval(pollTimer);

  pollTimer = setInterval(() => {
    refreshDashboard(false);
  }, CONFIG.FALLBACK_POLL_MS);
}

function updateStaticConfig() {
  el.apiBaseText.textContent = CONFIG.API_BASE;
  el.pollText.textContent = `fallback ${CONFIG.FALLBACK_POLL_MS} ms`;
  el.demoText.textContent = CONFIG.DEMO_MODE ? "ENABLED" : "DISABLED";
  el.demoText.style.color = CONFIG.DEMO_MODE ? "var(--amber)" : "var(--green)";
  el.demoBadge.hidden = !CONFIG.DEMO_MODE;
  el.injectBtn.disabled = !CONFIG.DEMO_MODE || injectInFlight;

  const token = getDevToken();
  el.authStateText.textContent = token ? "DEV TOKEN PRESENT" : CONFIG.ALLOW_DEV_JWT_STORAGE ? "COOKIE / MISSING" : "COOKIE ONLY";
  el.authStateText.style.color = token ? "var(--amber)" : "var(--green)";
  el.jwtRiskBadge.hidden = !token;
  el.authBtn.disabled = !CONFIG.ALLOW_DEV_JWT_STORAGE;
}

async function handleAuthChanged() {
  updateStaticConfig();
  reconnectWebSocket();
  await refreshDashboard(true, {force: true});
}

function exportVisibleActions() {
  const source = applyFilters(allActions);
  const stale = dataIsStale();
  const exportedAt = new Date().toISOString();
  const payload = {
    exported_at: exportedAt,
    data_as_of: lastDataSyncAt ? lastDataSyncAt.toISOString() : null,
    data_stale: stale,
    filter: currentFilter,
    search_query: searchQuery,
    action_count: source.length,
    actions: source.map(action => ({id: action.id, threat: action.threat, source: action.source, status: action.status, created_at: action.createdAt, created_raw: action.createdRaw, created_invalid: action.createdBad, decision_reason: action.decisionReason, operator: action.operator}))
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `sentinel43-export-${Date.now()}.json`;
  link.click();
  URL.revokeObjectURL(url);
  log(`Exported ${source.length} visible action(s) as JSON${stale ? " with stale-data warning" : ""}.`, stale ? "warn" : "ok");
}

el.selectAll.addEventListener("change", () => {
  const checkboxes = document.querySelectorAll(".row-cb");
  if (el.selectAll.checked) checkboxes.forEach(checkbox => { selectedIds.add(checkbox.dataset.id); checkbox.checked = true; checkbox.closest("tr")?.classList.add("selected"); });
  else checkboxes.forEach(checkbox => { selectedIds.delete(checkbox.dataset.id); checkbox.checked = false; checkbox.closest("tr")?.classList.remove("selected"); });
  updateBulkBar();
});

document.addEventListener("change", event => {
  const checkbox = event.target.closest?.(".row-cb");
  if (!checkbox) return;
  if (checkbox.checked) { selectedIds.add(checkbox.dataset.id); checkbox.closest("tr")?.classList.add("selected"); }
  else { selectedIds.delete(checkbox.dataset.id); checkbox.closest("tr")?.classList.remove("selected"); }
  updateBulkBar();
});

el.bulkClearBtn.addEventListener("click", clearSelection);
el.bulkApproveBtn.addEventListener("click", () => runBulkAction("approve"));
el.bulkVetoBtn.addEventListener("click", () => runBulkAction("veto"));

document.addEventListener("click", async event => {
  const filterButton = event.target.closest?.("[data-filter]");
  if (filterButton) { currentFilter = filterButton.dataset.filter; document.querySelectorAll("[data-filter]").forEach(button => button.classList.remove("active")); filterButton.classList.add("active"); clearSelection(); log(`Filter -> ${currentFilter}. Selection cleared for safety.`, "info"); renderActions(applyFilters(allActions)); return; }

  const logFilter = event.target.closest?.("[data-log-filter]");
  if (logFilter) { currentLogFilter = logFilter.dataset.logFilter; document.querySelectorAll("[data-log-filter]").forEach(button => button.classList.remove("active")); logFilter.classList.add("active"); document.querySelectorAll(".log-line").forEach(line => { line.hidden = currentLogFilter !== "ALL" && line.dataset.type !== currentLogFilter; }); return; }

  const expandButton = event.target.closest?.("[data-expand]");
  if (expandButton) { toggleExpand(expandButton.dataset.expand); return; }

  const approveButton = event.target.closest?.("[data-approve]");
  if (approveButton) { const ok = await doApprove(approveButton.dataset.approve, approveButton); if (ok) await refreshDashboard(true, {force: true}); return; }

  const vetoButton = event.target.closest?.("[data-veto]");
  if (vetoButton) { const ok = await doVeto(vetoButton.dataset.veto, vetoButton); if (ok) await refreshDashboard(true, {force: true}); }
});

el.searchInput.addEventListener("input", () => { searchQuery = el.searchInput.value; clearSelection(); renderActions(applyFilters(allActions)); });
el.clearSearchBtn.addEventListener("click", () => { el.searchInput.value = ""; searchQuery = ""; clearSelection(); renderActions(applyFilters(allActions)); el.searchInput.focus(); });
el.refreshBtn.addEventListener("click", () => refreshDashboard(true, {force: true}));
el.exportBtn.addEventListener("click", exportVisibleActions);

el.injectBtn.addEventListener("click", () => {
  if (!CONFIG.DEMO_MODE || injectInFlight) { log("Inject blocked: demo mode is disabled or an inject is already in flight.", "warn"); return; }
  el.injectBtn.disabled = true;
  el.injectModal.hidden = false;
  el.injectModal.setAttribute("aria-hidden", "false");
  setModalOpen(true);
});

function closeInject() {
  if (el.injectModal.hidden) return;
  el.injectModal.hidden = true;
  el.injectModal.setAttribute("aria-hidden", "true");
  setModalOpen(false);
  updateStaticConfig();
}

el.injectCancel.addEventListener("click", closeInject);
el.injectModal.addEventListener("click", event => { if (event.target.hasAttribute("data-close-inject")) closeInject(); });
el.injectConfirm.addEventListener("click", async () => {
  if (injectInFlight) return;
  injectInFlight = true;
  closeInject();
  updateStaticConfig();
  try { await api.inject(); log("Test action injected.", "info"); await refreshDashboard(true, {force: true}); }
  catch (error) { log(`Inject failed: ${error.message || error}`, "err"); }
  finally { injectInFlight = false; updateStaticConfig(); }
});

function closeJwt() {
  if (el.jwtModal.hidden) return;
  el.jwtModal.hidden = true;
  el.jwtModal.setAttribute("aria-hidden", "true");
  setModalOpen(false);
}

el.authBtn.addEventListener("click", () => {
  if (!CONFIG.ALLOW_DEV_JWT_STORAGE) { log("Browser JWT storage is disabled outside local development. Use a secure HttpOnly cookie.", "warn"); return; }
  el.jwtInput.value = getDevToken() || "";
  el.jwtModal.hidden = false;
  el.jwtModal.setAttribute("aria-hidden", "false");
  setModalOpen(true);
  setTimeout(() => el.jwtInput.focus(), 0);
});

el.jwtCancel.addEventListener("click", closeJwt);
el.jwtClear.addEventListener("click", async () => { try { sessionStorage.removeItem("SENTINEL_JWT"); } catch {} log("Development JWT cleared.", "warn"); closeJwt(); await handleAuthChanged(); });
el.jwtConfirm.addEventListener("click", async () => {
  if (!CONFIG.ALLOW_DEV_JWT_STORAGE) return;
  const token = el.jwtInput.value.trim();
  try { if (token) { sessionStorage.setItem("SENTINEL_JWT", token); log("Development JWT stored in sessionStorage. Local use only.", "warn"); } else { sessionStorage.removeItem("SENTINEL_JWT"); log("Development JWT cleared.", "warn"); } } catch { log("Unable to update sessionStorage JWT.", "err"); }
  closeJwt();
  await handleAuthChanged();
});
el.jwtModal.addEventListener("click", event => { if (event.target.hasAttribute("data-close-jwt")) closeJwt(); });

el.clearLogBtn.addEventListener("click", () => { el.logConsole.innerHTML = ""; log("Console cleared.", "info"); });

const htmlEl = document.documentElement;
let isLight = false;
function applyTheme(light) { isLight = light; htmlEl.classList.toggle("light", light); el.themeBtn.textContent = light ? "☽ Dark" : "☀ Light"; try { localStorage.setItem("s43-theme", light ? "light" : "dark"); } catch {} }
function initTheme() { try { const stored = localStorage.getItem("s43-theme"); if (stored === "light") return applyTheme(true); if (stored === "dark") return applyTheme(false); } catch {} applyTheme(window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches); }
el.themeBtn.addEventListener("click", () => applyTheme(!isLight));

el.kbHelpBtn.addEventListener("click", () => { el.kbToast.classList.add("show"); clearTimeout(kbToastTimer); kbToastTimer = setTimeout(() => el.kbToast.classList.remove("show"), 5000); });

document.addEventListener("keydown", event => {
  const tag = document.activeElement?.tagName || "";
  const inInput = ["INPUT", "TEXTAREA", "SELECT"].includes(tag);
  if (event.key === "Escape") { if (!el.reasonModal.hidden) { el.modalCancel.click(); return; } if (!el.jwtModal.hidden) { closeJwt(); return; } if (!el.injectModal.hidden) { closeInject(); return; } el.kbToast.classList.remove("show"); if (selectedIds.size) clearSelection(); return; }
  if (event.key === "/" && !inInput) { event.preventDefault(); el.searchInput.focus(); return; }
  if (event.key.toLowerCase() === "r" && !inInput) { refreshDashboard(true, {force: true}); return; }
  if (inInput) return;
  const rows = visibleRows();
  if (!rows.length) return;
  if (event.key === "ArrowDown") { event.preventDefault(); setFocusedRow(focusedRowIndex + 1); return; }
  if (event.key === "ArrowUp") { event.preventDefault(); setFocusedRow(focusedRowIndex < 0 ? 0 : focusedRowIndex - 1); return; }
  if (event.key.toLowerCase() === "a" && focusedRowIndex >= 0 && focusedRowIndex < rows.length) { const id = rows[focusedRowIndex].dataset.id; const action = allActions.find(candidate => candidate.id === id); if (action?.status === "STAGED") doApprove(id).then(ok => { if (ok) refreshDashboard(true, {force: true}); }); return; }
  if (event.key.toLowerCase() === "v" && focusedRowIndex >= 0 && focusedRowIndex < rows.length) { const id = rows[focusedRowIndex].dataset.id; const action = allActions.find(candidate => candidate.id === id); if (action && ["PENDING", "STAGED"].includes(action.status)) doVeto(id).then(ok => { if (ok) refreshDashboard(true, {force: true}); }); }
});

window.addEventListener("beforeunload", () => {
  if (pollTimer) clearInterval(pollTimer);
  closeWebSocket();
});

log("Dashboard initializing...", "info");
if (!CONFIG.DEMO_MODE) log("Demo mode disabled. Use ?demo=1 only for local testing.", "info");
initTheme();
updateStaticConfig();
setStatus("Booting");
startPollingFallback();
connectWebSocket();
refreshDashboard(true, {force: true});
