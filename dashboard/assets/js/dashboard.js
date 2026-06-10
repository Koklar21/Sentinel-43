"use strict";

const $ = id => document.getElementById(id);
const readMeta = name => document.querySelector(`meta[name="${name}"]`)?.content?.trim() || "";
const runtime = window.SENTINEL_RUNTIME_CONFIG || {};
const locationIsLocal = ["", "localhost", "127.0.0.1", "::1"].includes(location.hostname);

const CONFIG = Object.freeze({
API_BASE: String(runtime.apiBase || window.SENTINEL_API_BASE_URL || readMeta("sentinel-api-base") || "[http://localhost:8000").replace(/\/+$/](http://localhost:8000%22%29.replace%28/\/+$/), ""),
WS_URL: String(runtime.wsUrl || window.SENTINEL_WS_URL || readMeta("sentinel-ws-url") || "ws://localhost:8000/ws"),
FALLBACK_POLL_MS: 15000,
WS_RECONNECT_MS: 3000,
WS_HEARTBEAT_MS: 25000,
DATA_STALE_MS: 60000,
REASON_MIN: 10,
REASON_MAX: 500,
MAX_LOG_LINES: 500,
MAX_WS_FRAME_BYTES: 64 * 1024,
DEMO_MODE: new URLSearchParams(location.search).get("demo") === "1",
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

const el = {
statusDot: $("statusDot"),
statusText: $("statusText"),
queueCount: $("queueCount"),
lastSync: $("lastSync"),
pollFlash: $("pollFlash"),
demoBadge: $("demoBadge"),
jwtRiskBadge: $("jwtRiskBadge"),

pendingCount: $("pendingCount"),
stagedCount: $("stagedCount"),
approvedCount: $("approvedCount"),
vaultCount: $("vaultCount"),
apiBaseText: $("apiBaseText"),
authStateText: $("authStateText"),
pollText: $("pollText"),
demoText: $("demoText"),

refreshBtn: $("refreshBtn"),
exportBtn: $("exportBtn"),
themeBtn: $("themeBtn"),
authBtn: $("authBtn"),
clearLogBtn: $("clearLogBtn"),

actionsBody: $("actionsBody"),
emptyState: $("emptyState"),
logConsole: $("logConsole"),
liveRegion: $("liveRegion"),

searchInput: $("searchInput"),
clearSearchBtn: $("clearSearchBtn"),
selectAll: $("selectAll"),
bulkBar: $("bulkBar"),
bulkLabel: $("bulkLabel"),
bulkApproveBtn: $("bulkApproveBtn"),
bulkVetoBtn: $("bulkVetoBtn"),
bulkClearBtn: $("bulkClearBtn"),

reasonModal: $("reasonModal"),
modalTitle: $("modalTitle"),
modalSubtitle: $("modalSubtitle"),
modalInput: $("modalInput"),
modalError: $("modalError"),
modalCharCount: $("modalCharCount"),
modalCancel: $("modalCancel"),
modalConfirm: $("modalConfirm"),

jwtModal: $("jwtModal"),
jwtInput: $("jwtInput"),
jwtCancel: $("jwtCancel"),
jwtClear: $("jwtClear"),
jwtConfirm: $("jwtConfirm")
};

let currentFilter = "ALL";
let currentLogFilter = "ALL";
let searchQuery = "";
let allActions = [];
let selectedIds = new Set();
let lastDataSyncAt = null;
let refreshPromise = null;
let pollTimer = null;
let ws = null;
let wsConnected = false;
let wsReconnectTimer = null;
let wsHeartbeatTimer = null;
let wsClosing = false;
let isLight = false;

const nowStamp = () =>
new Date().toLocaleTimeString([], {
hour: "2-digit",
minute: "2-digit",
second: "2-digit"
});

const escHtml = value =>
String(value ?? "")
.replaceAll("&", "&")
.replaceAll("<", "<")
.replaceAll(">", ">")
.replaceAll('"', """)
.replaceAll("'", "'");

const normalizeString = (value, fallback = "") =>
typeof value === "string"
? value
: value == null
? fallback
: String(value);

function log(message, type = "info") {
if (!el.logConsole) return;

const safeType = ["info", "ok", "warn", "err"].includes(type)
? type
: "info";

const line = document.createElement("div");
line.className = `log-line ${safeType}`;
line.dataset.type = safeType;

line.innerHTML =
`<span class="log-ts">${escHtml(nowStamp())}</span>` +
`<span class="log-lvl">${safeType.toUpperCase()}</span>` +
`<span class="log-msg"></span>`;

line.querySelector(".log-msg").textContent =
normalizeString(message, "Unknown dashboard event");

if (
currentLogFilter !== "ALL" &&
currentLogFilter !== safeType
) {
line.hidden = true;
}

el.logConsole.appendChild(line);

if (
(safeType === "warn" || safeType === "err") &&
el.liveRegion
) {
el.liveRegion.textContent = normalizeString(message);
}

while (el.logConsole.children.length > CONFIG.MAX_LOG_LINES) {
el.logConsole.removeChild(el.logConsole.firstElementChild);
}

el.logConsole.scrollTop = el.logConsole.scrollHeight;
}

function setStatus(state) {
const normalized =
normalizeString(state, "unknown").toLowerCase();

if (el.statusText) {
el.statusText.textContent = normalized.toUpperCase();
}

if (!el.statusDot) return;

el.statusDot.classList.remove("online", "offline");

if (["online", "live"].includes(normalized)) {
el.statusDot.classList.add("online");
}

if (normalized === "offline") {
el.statusDot.classList.add("offline");
}
}

function markDataSync(source) {
lastDataSyncAt = new Date();

if (el.lastSync) {
el.lastSync.textContent = `${source} ${nowStamp()}`;
}

if (el.pollFlash) {
el.pollFlash.classList.add("flash");

```
setTimeout(
  () => el.pollFlash?.classList.remove("flash"),
  600
);
```

}
}

function dataIsStale() {
return (
!lastDataSyncAt ||
Date.now() - lastDataSyncAt.getTime() >
CONFIG.DATA_STALE_MS
);
}

function buildApiUrl(path) {
if (
typeof path !== "string" ||
!path.startsWith("/")
) {
throw new Error("API path must be relative");
}

if (
path.includes("\r") ||
path.includes("\n")
) {
throw new Error("API path contains invalid characters");
}

return new URL(
`${CONFIG.API_BASE}${path}`,
location.href
);
}

function getDevToken() {
if (!CONFIG.ALLOW_DEV_JWT_STORAGE) return null;

try {
return sessionStorage.getItem("SENTINEL_JWT");
} catch {
return null;
}
}

function getAuthHeaders() {
const headers = {
"Content-Type": "application/json"
};

const token = getDevToken();

if (token) {
headers.Authorization = `Bearer ${token}`;
}

return headers;
}

async function fetchJson(path, opts = {}) {
const url = buildApiUrl(path);

const response = await fetch(url.toString(), {
...opts,
cache: "no-store",
credentials:
url.origin === location.origin
? "include"
: "omit",
headers: {
...getAuthHeaders(),
"Cache-Control": "no-cache",
...(opts.headers || {})
}
});

const contentType =
response.headers.get("content-type") || "";

const isJson =
contentType.includes("application/json");

if (!response.ok) {
let detail = "";

```
if (isJson) {
  try {
    const body = await response.json();

    detail = normalizeString(
      body?.detail ||
      body?.error ||
      body?.message,
      ""
    ).slice(0, 240);
  } catch {}
}

throw new Error(
  `${response.status} ${response.statusText}` +
  `${detail ? `: ${detail}` : ""}`
);
```

}

return isJson
? response.json()
: null;
}

function unwrapData(value) {
return (
value &&
typeof value === "object" &&
!Array.isArray(value) &&
"data" in value
)
? value.data
: value;
}

function extractActionList(value) {
const unwrapped = unwrapData(value);

if (Array.isArray(unwrapped)) {
return unwrapped;
}

if (
unwrapped &&
typeof unwrapped === "object" &&
Array.isArray(unwrapped.actions)
) {
return unwrapped.actions;
}

throw new Error(
"Action endpoint returned an invalid payload shape"
);
}

function extractVaultRecords(value) {
const unwrapped = unwrapData(value);

return (
unwrapped &&
typeof unwrapped.records === "number"
)
? unwrapped.records
: null;
}

const api = {
listActions: () =>
fetchJson("/actions?limit=250"),

vaultStats: () =>
fetchJson("/vault/stats"),

approve: (id, reason) =>
fetchJson(
`/actions/${encodeURIComponent(id)}/approve`,
{
method: "POST",
body: JSON.stringify({reason})
}
),

veto: (id, reason) =>
fetchJson(
`/actions/${encodeURIComponent(id)}/veto`,
{
method: "POST",
body: JSON.stringify({reason})
}
)
};

function normalizeAction(raw) {
const payload =
raw &&
typeof raw.payload === "object" &&
raw.payload !== null
? raw.payload
: {};

const createdRaw =
normalizeString(raw?.created_at, "");

const parsed =
Date.parse(createdRaw);

return {
id:
normalizeString(raw?.id, "").trim(),

```
threat:
  normalizeString(
    payload.threat ||
    raw?.action_type,
    "UNKNOWN"
  ),

source:
  normalizeString(
    payload.source_ip ||
    payload.ip,
    "n/a"
  ),

status:
  normalizeString(
    raw?.status,
    "UNKNOWN"
  ).toUpperCase(),

createdAt:
  Number.isNaN(parsed)
    ? null
    : new Date(parsed).toISOString(),

decisionReason:
  normalizeString(
    raw?.decision_reason,
    ""
  ),

operator:
  normalizeString(
    raw?.operator,
    ""
  )
```

};
}

function applyFilters(actions) {
let output =
currentFilter === "ALL"
? actions
: actions.filter(
action =>
action.status === currentFilter
);

const query =
searchQuery.trim().toLowerCase();

if (query) {
output = output.filter(
action =>
[
action.id,
action.threat,
action.source
].some(
value =>
value
.toLowerCase()
.includes(query)
)
);
}

return output;
}

function reconcileSelectedIds() {
const validIds =
new Set(
allActions
.map(action => action.id)
.filter(Boolean)
);

selectedIds =
new Set(
[...selectedIds].filter(
id => validIds.has(id)
)
);
}
function updateStats() {
const pending =
allActions.filter(
action => action.status === "PENDING"
).length;

const staged =
allActions.filter(
action => action.status === "STAGED"
).length;

const approved =
allActions.filter(
action =>
["APPROVED", "EXECUTED"]
.includes(action.status)
).length;

const vetoed =
allActions.filter(
action => action.status === "VETOED"
).length;

if (el.pendingCount) {
el.pendingCount.textContent = pending;
}

if (el.stagedCount) {
el.stagedCount.textContent = staged;
}

if (el.approvedCount) {
el.approvedCount.textContent = approved;
}

if (el.queueCount) {
el.queueCount.textContent =
pending + staged;
}

for (
const [key, value]
of Object.entries({
ALL: allActions.length,
PENDING: pending,
STAGED: staged,
APPROVED: approved,
VETOED: vetoed
})
) {
const target = $(`fc-${key}`);

```
if (target) {
  target.textContent =
    value
      ? ` (${value})`
      : "";
}
```

}
}

function updateBulkBar() {
if (
!el.bulkBar ||
!el.bulkLabel
) {
return;
}

el.bulkBar.classList.toggle(
"visible",
selectedIds.size > 0
);

el.bulkLabel.textContent =
`${selectedIds.size} selected`;

const selected =
[...selectedIds]
.map(
id =>
allActions.find(
action =>
action.id === id
)
)
.filter(Boolean);

if (el.bulkApproveBtn) {
el.bulkApproveBtn.disabled =
!selected.some(
action =>
action.status === "STAGED"
);
}

if (el.bulkVetoBtn) {
el.bulkVetoBtn.disabled =
!selected.some(
action =>
["PENDING", "STAGED"]
.includes(action.status)
);
}
}

function clearSelection() {
selectedIds.clear();

document
.querySelectorAll(".row-cb")
.forEach(
box => {
box.checked = false;

```
    box
      .closest("tr")
      ?.classList
      .remove("selected");
  }
);
```

if (el.selectAll) {
el.selectAll.checked = false;
el.selectAll.indeterminate = false;
}

updateBulkBar();
}

function renderActions() {
if (
!el.actionsBody ||
!el.emptyState
) {
return;
}

const actions =
applyFilters(allActions);

el.actionsBody.innerHTML = "";

el.emptyState.hidden =
Boolean(actions.length);

for (const action of actions) {
const row =
document.createElement("tr");

```
row.dataset.id =
  action.id;

if (
  selectedIds.has(action.id)
) {
  row.classList.add("selected");
}

const statusClass =
  STATUS_CLASSES[action.status] ||
  "unknown";

const created =
  action.createdAt
    ? new Date(
        action.createdAt
      ).toLocaleString(
        [],
        {
          dateStyle: "short",
          timeStyle: "short"
        }
      )
    : "MISSING";

const canApprove =
  action.status === "STAGED";

const canVeto =
  ["PENDING", "STAGED"]
    .includes(action.status);

const controls =
  canApprove || canVeto
    ? (
      `<div class="act-btns">` +
      (
        canApprove
          ? (
            `<button class="btn green" ` +
            `type="button" ` +
            `data-approve="${escHtml(action.id)}">` +
            `✓</button>`
          )
          : ""
      ) +
      (
        canVeto
          ? (
            `<button class="btn red" ` +
            `type="button" ` +
            `data-veto="${escHtml(action.id)}">` +
            `✕</button>`
          )
          : ""
      ) +
      `</div>`
    )
    : (
      `<span class="mono">` +
      `${escHtml(action.operator || "—")}` +
      `</span>`
    );

row.innerHTML =
  `<td>` +
    `<input type="checkbox" ` +
    `class="row-cb" ` +
    `data-id="${escHtml(action.id)}"` +
    `${selectedIds.has(action.id) ? " checked" : ""}>` +
  `</td>` +
  `<td>` +
    `<button class="expand-btn" ` +
    `type="button" ` +
    `data-expand="${escHtml(action.id)}">▶</button>` +
  `</td>` +
  `<td class="mono">${escHtml(action.id || "<missing>")}</td>` +
  `<td>${escHtml(action.threat)}</td>` +
  `<td class="mono">${escHtml(action.source)}</td>` +
  `<td>` +
    `<span class="tag ${statusClass}">` +
      `${escHtml(action.status)}` +
    `</span>` +
  `</td>` +
  `<td class="mono">${escHtml(created)}</td>` +
  `<td class="reason-cell">` +
    `${escHtml(action.decisionReason || "—")}` +
  `</td>` +
  `<td class="sticky-actions">${controls}</td>`;

el.actionsBody.appendChild(row);
```

}

updateBulkBar();
}

function replaceActions(
rawActions,
source
) {
allActions =
extractActionList(rawActions)
.map(normalizeAction)
.sort(
(a, b) =>
Date.parse(b.createdAt || 0) -
Date.parse(a.createdAt || 0)
);

reconcileSelectedIds();
updateStats();
renderActions();
markDataSync(source);
}

function upsertAction(
rawAction,
source = "ws-sync"
) {
const action =
normalizeAction(rawAction);

if (!action.id) return;

const index =
allActions.findIndex(
item =>
item.id === action.id
);

if (index >= 0) {
allActions[index] = action;
} else {
allActions.push(action);
}

allActions.sort(
(a, b) =>
Date.parse(b.createdAt || 0) -
Date.parse(a.createdAt || 0)
);

reconcileSelectedIds();
updateStats();
renderActions();
markDataSync(source);
}

function removeAction(
id,
source = "ws-sync"
) {
const cleaned =
normalizeString(id).trim();

allActions =
allActions.filter(
action =>
action.id !== cleaned
);

reconcileSelectedIds();
updateStats();
renderActions();
markDataSync(source);
}

async function performRefresh(
manual = false
) {
document.body.setAttribute(
"aria-busy",
"true"
);

if (manual) {
setStatus("Syncing");
}

try {
const [actions, vault] =
await Promise.all([
api.listActions(),

```
    api
      .vaultStats()
      .catch(() => null)
  ]);

replaceActions(
  actions,
  "http-sync"
);

const records =
  extractVaultRecords(vault);

if (el.vaultCount) {
  el.vaultCount.textContent =
    typeof records === "number"
      ? records.toLocaleString()
      : "--";
}

setStatus(
  wsConnected
    ? "Live"
    : "Online"
);

if (manual) {
  log(
    `Refresh complete - ` +
    `${applyFilters(allActions).length} ` +
    `action(s) visible.`,
    "ok"
  );
}

return true;
```

} catch (error) {
setStatus(
wsConnected
? "Degraded"
: "Offline"
);

```
log(
  `Refresh failed: ` +
  `${error.message || error}`,
  "err"
);

return false;
```

} finally {
document.body.removeAttribute(
"aria-busy"
);
}
}

async function refreshDashboard(
manual = false,
{force = false} = {}
) {
if (
refreshPromise &&
!force
) {
return refreshPromise;
}

if (
refreshPromise &&
force
) {
await refreshPromise;
}

refreshPromise =
performRefresh(manual)
.finally(
() => {
refreshPromise = null;
}
);

return refreshPromise;
}

function decodeWsMessage(message) {
if (
typeof message !== "string"
) {
throw new Error(
"WebSocket frame must be text"
);
}

if (
new TextEncoder()
.encode(message)
.length >
CONFIG.MAX_WS_FRAME_BYTES
) {
throw new Error(
"WebSocket frame exceeds maximum size"
);
}

const decoded =
JSON.parse(message);

if (
!decoded ||
typeof decoded !== "object" ||
Array.isArray(decoded)
) {
throw new Error(
"WebSocket message must be an object"
);
}

if (
typeof decoded.type !== "string" ||
!decoded.type.trim()
) {
throw new Error(
"WebSocket message type is required"
);
}

return {
type:
decoded.type.trim(),

```
payload:
  decoded.payload &&
  typeof decoded.payload === "object"
    ? decoded.payload
    : {}
```

};
}

function applyWsMessage(message) {
const {
type,
payload
} = decodeWsMessage(message);

switch (type) {
case "connected":
log(
"WebSocket server acknowledged connection.",
"ok"
);
break;

```
case "subscribed":
  log(
    `WebSocket subscription active: ` +
    `${normalizeString(payload.channel, "unknown")}`,
    "ok"
  );
  break;

case "actions_snapshot":
  replaceActions(
    payload.actions || payload,
    "ws-sync"
  );
  break;

case "action_created":
case "action_updated":
case "action_status_changed":
case "action":
  upsertAction(
    payload.action || payload
  );
  break;

case "action_deleted":
case "action_removed":
  removeAction(
    payload.id ||
    payload.action_id
  );
  break;

case "vault_stats": {
  const records =
    extractVaultRecords(payload);

  if (el.vaultCount) {
    el.vaultCount.textContent =
      typeof records === "number"
        ? records.toLocaleString()
        : "--";
  }

  markDataSync("ws-sync");
  break;
}

case "pong":
  break;

case "error":
  log(
    `WebSocket server error: ` +
    `${normalizeString(payload.error, "unknown error")}`,
    "err"
  );
  break;

default:
  log(
    `Ignored unhandled WebSocket event type: ${type}`,
    "info"
  );
```

}
}

function safeWsUrl() {
const url =
new URL(
CONFIG.WS_URL,
location.href
);

if (
!["ws:", "wss:"]
.includes(url.protocol)
) {
throw new Error(
"WebSocket URL must use ws:// or wss://"
);
}

if (
location.protocol === "https:" &&
url.protocol !== "wss:"
) {
throw new Error(
"Secure pages require wss:// WebSocket URLs"
);
}

return url.toString();
}

function wsSend(
type,
payload = {}
) {
if (
!ws ||
ws.readyState !== WebSocket.OPEN
) {
return false;
}

ws.send(
JSON.stringify({
type,
payload
})
);

return true;
}

function connectWebSocket() {
if (
CONFIG.DEMO_MODE ||
wsClosing ||
wsConnected ||
(
ws &&
[
WebSocket.OPEN,
WebSocket.CONNECTING
].includes(ws.readyState)
)
) {
return;
}

try {
ws =
new WebSocket(
safeWsUrl()
);

```
ws.addEventListener(
  "open",
  () => {
    wsConnected = true;

    setStatus("Live");

    log(
      "WebSocket connected. Live queue updates enabled.",
      "ok"
    );

    wsSend(
      "subscribe",
      {channel: "actions"}
    );

    wsSend(
      "subscribe",
      {channel: "vault"}
    );

    clearInterval(
      wsHeartbeatTimer
    );

    wsHeartbeatTimer =
      setInterval(
        () =>
          wsSend(
            "ping",
            {
              timestamp:
                new Date()
                  .toISOString()
            }
          ),

        CONFIG.WS_HEARTBEAT_MS
      );
  }
);

ws.addEventListener(
  "message",
  event => {
    try {
      applyWsMessage(
        event.data
      );
    } catch (error) {
      log(
        `Rejected WebSocket message: ` +
        `${error.message || error}`,
        "warn"
      );
    }
  }
);

ws.addEventListener(
  "close",
  () => {
    wsConnected = false;

    clearInterval(
      wsHeartbeatTimer
    );

    wsHeartbeatTimer = null;

    if (!wsClosing) {
      setStatus(
        "Reconnecting"
      );

      log(
        "WebSocket disconnected. HTTP polling remains active.",
        "warn"
      );

      clearTimeout(
        wsReconnectTimer
      );

      wsReconnectTimer =
        setTimeout(
          connectWebSocket,
          CONFIG.WS_RECONNECT_MS
        );
    }
  }
);

ws.addEventListener(
  "error",
  () =>
    log(
      "WebSocket transport error. HTTP polling remains active.",
      "warn"
    )
);
```

} catch (error) {
log(
`WebSocket connection failed: ` +
`${error.message || error}`,
"warn"
);

```
clearTimeout(
  wsReconnectTimer
);

wsReconnectTimer =
  setTimeout(
    connectWebSocket,
    CONFIG.WS_RECONNECT_MS
  );
```

}
}
function closeWebSocket() {
wsClosing = true;

clearTimeout(
wsReconnectTimer
);

clearInterval(
wsHeartbeatTimer
);

wsReconnectTimer = null;
wsHeartbeatTimer = null;

if (ws) {
ws.close();
}

ws = null;
wsConnected = false;
}

function startPolling() {
clearInterval(
pollTimer
);

pollTimer =
setInterval(
() =>
refreshDashboard(false),

```
  CONFIG.FALLBACK_POLL_MS
);
```

}

function validateReason(value) {
const reason =
normalizeString(value).trim();

if (
reason.length <
CONFIG.REASON_MIN
) {
return (
`Minimum ` +
`${CONFIG.REASON_MIN} ` +
`characters required.`
);
}

if (
reason.length >
CONFIG.REASON_MAX
) {
return (
`Maximum ` +
`${CONFIG.REASON_MAX} ` +
`characters.`
);
}

return null;
}

function openReasonModal(
title,
subtitle,
confirmText,
confirmClass = "green"
) {
return new Promise(
resolve => {
if (!el.reasonModal) {
resolve(null);
return;
}

```
  el.modalTitle.textContent =
    title;

  el.modalSubtitle.textContent =
    subtitle;

  el.modalInput.value = "";

  el.modalError.textContent = "";

  el.modalCharCount.textContent =
    `0 / ${CONFIG.REASON_MAX}`;

  el.modalConfirm.textContent =
    confirmText;

  el.modalConfirm.className =
    `btn ${confirmClass}`;

  el.reasonModal.hidden = false;

  const cleanup = () => {
    el.modalCancel.removeEventListener(
      "click",
      cancel
    );

    el.modalConfirm.removeEventListener(
      "click",
      confirm
    );

    el.modalInput.removeEventListener(
      "input",
      count
    );

    el.reasonModal.hidden = true;
  };

  const cancel = () => {
    cleanup();
    resolve(null);
  };

  const confirm = () => {
    const error =
      validateReason(
        el.modalInput.value
      );

    if (error) {
      el.modalError.textContent =
        error;

      return;
    }

    const value =
      el.modalInput.value.trim();

    cleanup();
    resolve(value);
  };

  const count = () => {
    el.modalCharCount.textContent =
      `${el.modalInput.value.length} / ` +
      `${CONFIG.REASON_MAX}`;
  };

  el.modalCancel.addEventListener(
    "click",
    cancel
  );

  el.modalConfirm.addEventListener(
    "click",
    confirm
  );

  el.modalInput.addEventListener(
    "input",
    count
  );

  setTimeout(
    () => el.modalInput.focus(),
    0
  );
}
```

);
}

async function updateAction(
kind,
id
) {
const isApprove =
kind === "approve";

const reason =
await openReasonModal(
`${isApprove ? "Approve" : "Veto"} ${id}`,
"Provide a reason for this decision.",
isApprove ? "Approve" : "Veto",
isApprove ? "green" : "red"
);

if (!reason) return;

try {
if (isApprove) {
await api.approve(
id,
reason
);
} else {
await api.veto(
id,
reason
);
}

```
log(
  `${isApprove ? "Approved" : "Vetoed"} ${id}`,
  isApprove ? "ok" : "warn"
);

await refreshDashboard(
  true,
  {force: true}
);
```

} catch (error) {
log(
`${kind} failed - ${id}: ` +
`${error.message || error}`,
"err"
);
}
}

function toggleExpand(id) {
const existing =
document.querySelector(
`.expand-row[data-for="${CSS.escape(id)}"]`
);

if (existing) {
existing.remove();
return;
}

const action =
allActions.find(
item =>
item.id === id
);

const row =
document.querySelector(
`tr[data-id="${CSS.escape(id)}"]`
);

if (
!action ||
!row
) {
return;
}

const extra =
document.createElement("tr");

extra.className =
"expand-row";

extra.dataset.for =
id;

extra.innerHTML =
`<td colspan="9">` +
`<div class="expand-inner">` +
`<strong>${escHtml(action.id)}</strong><br>` +
`Source: ${escHtml(action.source)}<br>` +
`Threat: ${escHtml(action.threat)}<br>` +
`Status: ${escHtml(action.status)}<br>` +
`Operator: ${escHtml(action.operator || "—")}<br>` +
`Reason: ${escHtml(action.decisionReason || "—")}` +
`</div>` +
`</td>`;

row.after(extra);
}

function exportVisibleActions() {
const actions =
applyFilters(allActions);

const payload = {
exported_at:
new Date().toISOString(),

```
data_as_of:
  lastDataSyncAt
    ?.toISOString() ||
  null,

data_stale:
  dataIsStale(),

actions
```

};

const blob =
new Blob(
[
JSON.stringify(
payload,
null,
2
)
],
{
type: "application/json"
}
);

const url =
URL.createObjectURL(blob);

const link =
document.createElement("a");

link.href = url;

link.download =
`sentinel43-export-${Date.now()}.json`;

link.click();

URL.revokeObjectURL(url);

log(
`Exported ${actions.length} visible action(s).`,
"ok"
);
}

function updateStaticConfig() {
if (el.apiBaseText) {
el.apiBaseText.textContent =
CONFIG.API_BASE;
}

if (el.pollText) {
el.pollText.textContent =
`every ${CONFIG.FALLBACK_POLL_MS} ms`;
}

if (el.demoText) {
el.demoText.textContent =
CONFIG.DEMO_MODE
? "ENABLED"
: "DISABLED";
}

if (el.demoBadge) {
el.demoBadge.hidden =
!CONFIG.DEMO_MODE;
}

const token =
getDevToken();

if (el.authStateText) {
el.authStateText.textContent =
token
? "DEV TOKEN PRESENT"
: CONFIG.ALLOW_DEV_JWT_STORAGE
? "COOKIE / MISSING"
: "COOKIE ONLY";
}

if (el.jwtRiskBadge) {
el.jwtRiskBadge.hidden =
!token;
}

if (el.authBtn) {
el.authBtn.disabled =
!CONFIG.ALLOW_DEV_JWT_STORAGE;
}
}

el.refreshBtn
?.addEventListener(
"click",
() =>
refreshDashboard(
true,
{force: true}
)
);

el.exportBtn
?.addEventListener(
"click",
exportVisibleActions
);

el.themeBtn
?.addEventListener(
"click",
() => {
isLight = !isLight;

```
  document
    .documentElement
    .classList
    .toggle(
      "light",
      isLight
    );
}
```

);

el.clearLogBtn
?.addEventListener(
"click",
() => {
if (el.logConsole) {
el.logConsole.innerHTML = "";
}
}
);

el.clearSearchBtn
?.addEventListener(
"click",
() => {
if (el.searchInput) {
el.searchInput.value = "";
}

```
  searchQuery = "";

  renderActions();
}
```

);

el.searchInput
?.addEventListener(
"input",
() => {
searchQuery =
el.searchInput.value;

```
  renderActions();
}
```

);

el.bulkClearBtn
?.addEventListener(
"click",
clearSelection
);

el.bulkApproveBtn
?.addEventListener(
"click",
() =>
[...selectedIds]
.forEach(
id =>
updateAction(
"approve",
id
)
)
);

el.bulkVetoBtn
?.addEventListener(
"click",
() =>
[...selectedIds]
.forEach(
id =>
updateAction(
"veto",
id
)
)
);

el.authBtn
?.addEventListener(
"click",
() => {
if (
!CONFIG.ALLOW_DEV_JWT_STORAGE ||
!el.jwtModal
) {
return;
}

```
  el.jwtInput.value =
    getDevToken() || "";

  el.jwtModal.hidden =
    false;
}
```

);

el.jwtCancel
?.addEventListener(
"click",
() => {
el.jwtModal.hidden =
true;
}
);

el.jwtClear
?.addEventListener(
"click",
async () => {
try {
sessionStorage.removeItem(
"SENTINEL_JWT"
);
} catch {}

```
  el.jwtModal.hidden =
    true;

  updateStaticConfig();

  await refreshDashboard(
    true,
    {force: true}
  );
}
```

);

el.jwtConfirm
?.addEventListener(
"click",
async () => {
try {
sessionStorage.setItem(
"SENTINEL_JWT",
el.jwtInput.value.trim()
);
} catch {}

```
  el.jwtModal.hidden =
    true;

  updateStaticConfig();

  await refreshDashboard(
    true,
    {force: true}
  );
}
```

);

el.selectAll
?.addEventListener(
"change",
() => {
document
.querySelectorAll(".row-cb")
.forEach(
box => {
box.checked =
el.selectAll.checked;

```
        if (box.checked) {
          selectedIds.add(
            box.dataset.id
          );
        } else {
          selectedIds.delete(
            box.dataset.id
          );
        }
      }
    );

  updateBulkBar();
}
```

);

document.addEventListener(
"change",
event => {
const box =
event.target.closest
?.(".row-cb");

```
if (!box) return;

if (box.checked) {
  selectedIds.add(
    box.dataset.id
  );
} else {
  selectedIds.delete(
    box.dataset.id
  );
}

updateBulkBar();
```

}
);

document.addEventListener(
"click",
event => {
const filter =
event.target.closest
?.("[data-filter]");

```
if (filter) {
  currentFilter =
    filter.dataset.filter;

  renderActions();
  return;
}

const logFilter =
  event.target.closest
    ?.("[data-log-filter]");

if (logFilter) {
  currentLogFilter =
    logFilter.dataset.logFilter;

  document
    .querySelectorAll(".log-line")
    .forEach(
      line => {
        line.hidden =
          currentLogFilter !== "ALL" &&
          line.dataset.type !== currentLogFilter;
      }
    );

  return;
}

const expand =
  event.target.closest
    ?.("[data-expand]");

if (expand) {
  toggleExpand(
    expand.dataset.expand
  );

  return;
}

const approve =
  event.target.closest
    ?.("[data-approve]");

if (approve) {
  updateAction(
    "approve",
    approve.dataset.approve
  );

  return;
}

const veto =
  event.target.closest
    ?.("[data-veto]");

if (veto) {
  updateAction(
    "veto",
    veto.dataset.veto
  );
}
```

}
);

window.addEventListener(
"beforeunload",
() => {
clearInterval(
pollTimer
);

```
closeWebSocket();
```

}
);

log(
"Dashboard initializing...",
"info"
);

updateStaticConfig();

setStatus("Booting");

startPolling();

connectWebSocket();

refreshDashboard(
true,
{force: true}
);
