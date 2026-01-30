/*
Copyright 2025 Justin

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
  Sentinel-43 Dashboard Script
  ----------------------------
  UI-only control surface.
  - No enforcement logic
  - No backend authority
  - Backend remains source of truth
*/

"use strict";

/* =============================
   DOM Bindings
============================= */
const logConsole = document.getElementById("log-console");
const threatFeed = document.getElementById("threat-feed");
const recordCountEl = document.getElementById("record-count");

/* Optional modal (recommended) */
const reasonModalEl = document.getElementById("reasonModal");

/* =============================
   Runtime Flags
============================= */
const DEMO_MODE = (window.AEGIS_DEMO_MODE ?? true) === true;

/* =============================
   Config
============================= */
const CONFIG = Object.freeze({
  // Polling
  POLL_FAST_MS: 750,
  POLL_IDLE_MS: 2000,
  POLL_DEEP_IDLE_MS: 5000,
  STABLE_TICKS_TO_IDLE: 10,
  STABLE_TICKS_TO_DEEP_IDLE: 60,

  // Vault
  VAULT_POLL_MS: 10000,

  // Cleanup windows (UI tombstones)
  DISMISS_MS: 4500,

  // Demo timings
  DEMO_LOG_MS: 2000,

  // Input validation
  REASON_MAX_LEN: 240,

  // Demo backend cleanup constants
  DEMO_EXECUTED_CLEANUP_MS: 3000,
  DEMO_VETOED_CLEANUP_MS: 4000,
});

/* =============================
   Timer Registry (avoid leaks)
============================= */
const timers = new Set();
function every(ms, fn) {
  const id = setInterval(fn, ms);
  timers.add(id);
  return id;
}
function after(ms, fn) {
  const id = setTimeout(() => {
    timers.delete(id);
    fn();
  }, ms);
  timers.add(id);
  return id;
}
function stopAllTimers() {
  for (const id of timers) {
    clearInterval(id);
    clearTimeout(id);
  }
  timers.clear();
}
window.addEventListener("beforeunload", stopAllTimers);

/* =============================
   Logging + Time Formatting
============================= */
const timeFmt = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  timeZoneName: "short",
});

function ts() {
  return timeFmt.format(new Date());
}

function log(msg, level = "info") {
  if (!logConsole) return;
  const d = document.createElement("div");
  d.className = `log-entry ${level}`;
  d.textContent = `[${ts()}] ${msg}`;
  logConsole.appendChild(d);
  logConsole.scrollTop = logConsole.scrollHeight;
}

function reportErr(context, e, level = "warn") {
  const msg = e instanceof Error ? e.message : String(e);
  // Console for devs, log for operators
  console.error(`[dashboard] ${context}:`, e);
  log(`${context}: ${msg}`, level);
}

/* =============================
   HTML escaping
============================= */
function escapeHtml(v) {
  return String(v)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function fmtMMSS(sec) {
  sec = Math.max(0, sec | 0);
  return `${String(Math.floor(sec / 60)).padStart(2, "0")}:${String(sec % 60).padStart(2, "0")}`;
}

/* =============================
   Auth + API Fetch (thin seam)
   - Supports existing JWT header
   - Also supports cookie-auth (credentials: include)
============================= */
function getCookie(name) {
  return document.cookie
    .split("; ")
    .find((row) => row.startsWith(name + "="))
    ?.split("=")[1];
}

const api = {
  token() {
    // Current approach (keep for compatibility; migrate to httpOnly cookies in backend when ready)
    return sessionStorage.getItem("AEGIS_JWT") || null;
  },

  headers() {
    const h = { "Content-Type": "application/json" };

    // JWT mode (legacy)
    const t = this.token();
    if (t) h.Authorization = `Bearer ${t}`;

    // Optional CSRF header if you move to cookie-auth:
    // backend sets csrf_token cookie (NOT httpOnly), JS echoes it.
    const csrf = getCookie("csrf_token");
    if (csrf) h["X-CSRF-Token"] = decodeURIComponent(csrf);

    return h;
  },

  async fetchJson(path, { method = "GET", body } = {}) {
    const res = await fetch(path, {
      method,
      headers: this.headers(),
      credentials: "include", // safe for cookie-auth; ignored if not used
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status} ${res.statusText}${txt ? `: ${txt}` : ""}`);
    }

    // Some endpoints might return empty response bodies
    const ct = res.headers.get("content-type") || "";
    if (!ct.includes("application/json")) return null;

    return res.json();
  },

  async listPendingActions() {
    if (DEMO_MODE) return demo.listPendingActions();
    return this.fetchJson("/api/v1/actions/pending");
  },

  async veto(actionId, reason) {
    if (DEMO_MODE) return demo.veto(actionId, reason);
    await this.fetchJson("/api/v1/oversight/veto", {
      method: "POST",
      body: { action_id: actionId, reason },
    });
    return true;
  },

  async vaultStats() {
    if (DEMO_MODE) return { records: null };
    try {
      const out = await this.fetchJson("/api/v1/vault/stats");
      return out ?? { records: null };
    } catch {
      return { records: null };
    }
  },
};

/* =============================
   Demo Backend (sandbox only)
============================= */
const demo = (() => {
  const pending = new Map();

  function makeAction(ip, threat, delaySec) {
    const now = Date.now();
    const id = `ACT-${now.toString(36)}-${Math.random().toString(36).slice(2, 8)}`.toUpperCase();

    pending.set(id, {
      action_id: id,
      ip,
      threat_type: threat,
      created_at_ms: now,
      execute_at_ms: now + delaySec * 1000,
      status: "PENDING",
    });
  }

  function listPendingActions() {
    const now = Date.now();

    for (const [id, a] of pending.entries()) {
      if (a.status === "PENDING" && now >= a.execute_at_ms) {
        a.status = "EXECUTED";
      }
      if (a.status === "EXECUTED" && now - a.execute_at_ms > CONFIG.DEMO_EXECUTED_CLEANUP_MS) {
        pending.delete(id);
      }
    }

    return { actions: Array.from(pending.values()) };
  }

  function veto(id, reason) {
    const a = pending.get(id);
    if (!a || a.status !== "PENDING") return false;
    a.status = "VETOED";
    a.veto_reason = reason;
    after(CONFIG.DEMO_VETOED_CLEANUP_MS, () => pending.delete(id));
    return true;
  }

  after(3000, () => makeAction("203.0.113.45", "SQL INJECTION PATTERN", 30));
  after(15000, () => makeAction("198.51.100.12", "DATA EXFILTRATION", 45));

  return { listPendingActions, veto };
})();

/* =============================
   UI Tombstones (fix zombie cards)
============================= */
const dismissed = new Map(); // id -> expiresAtMs
function dismissThreat(id) {
  dismissed.set(id, Date.now() + CONFIG.DISMISS_MS);
  after(CONFIG.DISMISS_MS + 250, () => dismissed.delete(id));
}
function shouldRender(id) {
  const exp = dismissed.get(id);
  return !(exp && exp > Date.now());
}

/* =============================
   Threat Card Renderer
============================= */
function renderThreat(a) {
  const id = a.action_id;
  if (!shouldRender(id)) return;

  let card = document.getElementById(id);

  if (!card) {
    card = document.createElement("div");
    card.className = "threat-card";
    card.id = id;
    threatFeed.appendChild(card);
  }

  if (a.status === "VETOED") {
    card.className = "threat-card vetoed-card";
    card.innerHTML = `
      <h3>Action Aborted</h3>
      <p>${escapeHtml(a.veto_reason || "Operator override")}</p>
      <small>${escapeHtml(id)}</small>
    `;
    return;
  }

  if (a.status === "EXECUTED") {
    // tombstone to prevent brief reappear due to backend lag
    dismissThreat(id);
    card.remove();
    return;
  }

  const remain = Math.ceil((a.execute_at_ms - Date.now()) / 1000);

  card.className = "threat-card";
  card.innerHTML = `
    <div>
      <h3>${escapeHtml(a.threat_type)}</h3>
      <p>Source: ${escapeHtml(a.ip)}</p>
      <small>ID: ${escapeHtml(id)}</small>
    </div>
    <div>
      <span class="countdown">${fmtMMSS(remain)}</span>
      <button class="veto-btn" data-id="${escapeHtml(id)}">Abort</button>
    </div>
  `;
}

/* =============================
   Modal (replaces prompt)
============================= */
function openReasonModal({ title, placeholder = "" }) {
  // Fallback if HTML modal not present
  if (!reasonModalEl) {
    const reason = prompt(`${title}`, "False positive");
    return Promise.resolve(reason?.trim() || null);
  }

  const input = reasonModalEl.querySelector("textarea");
  const ok = reasonModalEl.querySelector("[data-ok]");
  const cancel = reasonModalEl.querySelector("[data-cancel]");
  const titleEl = reasonModalEl.querySelector("[data-title]");
  const errEl = reasonModalEl.querySelector("[data-error]");

  titleEl.textContent = title;
  input.value = "";
  input.placeholder = placeholder;
  errEl.textContent = "";

  reasonModalEl.classList.add("open");
  input.focus();

  const setErr = (m) => (errEl.textContent = m);

  return new Promise((resolve) => {
    const cleanup = () => {
      reasonModalEl.classList.remove("open");
      ok.removeEventListener("click", onOk);
      cancel.removeEventListener("click", onCancel);
      reasonModalEl.removeEventListener("keydown", onKey);
    };

    const onOk = () => {
      const v = input.value?.trim();
      if (!v) return setErr("Reason is required.");
      if (v.length > CONFIG.REASON_MAX_LEN) {
        return setErr(`Reason too long. Max ${CONFIG.REASON_MAX_LEN} characters.`);
      }
      cleanup();
      resolve(v);
    };

    const onCancel = () => {
      cleanup();
      resolve(null);
    };

    const onKey = (e) => {
      if (e.key === "Escape") onCancel();
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") onOk();
    };

    ok.addEventListener("click", onOk);
    cancel.addEventListener("click", onCancel);
    reasonModalEl.addEventListener("keydown", onKey);
  });
}

/* =============================
   Event Wiring
============================= */
threatFeed.addEventListener("click", async (e) => {
  const btn = e.target.closest(".veto-btn");
  if (!btn) return;

  const id = btn.dataset.id;

  const reason = await openReasonModal({
    title: "Veto reason (required)",
    placeholder: "False positive, test traffic, duplicate, etc.",
  });

  if (!reason) {
    log(`Veto cancelled for ${id}: reason required.`, "warn");
    return;
  }

  try {
    const ok = await api.veto(id, reason);
    log(ok ? `Action ${id} vetoed.` : `Veto failed for ${id}.`, ok ? "warn" : "error");
    if (ok) dismissThreat(id); // stop it reappearing while backend propagates
  } catch (err) {
    reportErr(`Veto request failed for ${id}`, err, "error");
  }
});

/* =============================
   Poll Loops (adaptive)
============================= */
let pollMs = CONFIG.POLL_FAST_MS;
let stableTicks = 0;
let lastThreatHash = "";

function hashThreatList(actions) {
  // stable-ish fingerprint (ids + status + execute time)
  return actions
    .map((a) => `${a.action_id}:${a.status}:${a.execute_at_ms}`)
    .sort()
    .join("|");
}

async function refreshThreats() {
  const { actions = [] } = await api.listPendingActions();
  const seen = new Set();

  for (const a of actions) {
    seen.add(a.action_id);
    renderThreat(a);
  }

  // remove unseen cards (unless dismissed tombstone wants it gone anyway)
  [...threatFeed.children].forEach((el) => {
    if (!seen.has(el.id)) el.remove();
  });

  return actions;
}

async function refreshThreatsAdaptive() {
  try {
    const actions = await refreshThreats();
    const h = hashThreatList(actions);

    const changed = h !== lastThreatHash;
    lastThreatHash = h;

    if (changed) {
      stableTicks = 0;
      pollMs = CONFIG.POLL_FAST_MS;
    } else {
      stableTicks++;
      if (stableTicks > CONFIG.STABLE_TICKS_TO_DEEP_IDLE) pollMs = CONFIG.POLL_DEEP_IDLE_MS;
      else if (stableTicks > CONFIG.STABLE_TICKS_TO_IDLE) pollMs = CONFIG.POLL_IDLE_MS;
    }
  } catch (e) {
    reportErr("Threat refresh failed", e, "warn");
    // back off slightly on failures
    pollMs = Math.min(CONFIG.POLL_DEEP_IDLE_MS, pollMs + 500);
  } finally {
    after(pollMs, refreshThreatsAdaptive);
  }
}

async function refreshVault() {
  try {
    const s = await api.vaultStats();
    if (typeof s?.records === "number") {
      recordCountEl.textContent = s.records.toLocaleString();
    }
  } catch (e) {
    if (!DEMO_MODE) reportErr("Vault refresh failed", e, "warn");
  }
}

/* =============================
   Boot
============================= */
after(0, refreshThreatsAdaptive);
every(CONFIG.VAULT_POLL_MS, refreshVault);

if (DEMO_MODE) {
  every(CONFIG.DEMO_LOG_MS, () => {
    const msgs = [
      "[WATCHTOWER] Heartbeat nominal",
      "[AUDIT] Integrity unchanged",
      "[API] Latency < 15ms",
      "[RESOURCE] CPU steady",
    ];
    log(msgs[Math.floor(Math.random() * msgs.length)]);
  });
}

after(0, () => {
  log(`Dashboard online. Mode: ${DEMO_MODE ? "DEMO" : "LIVE"}.`, "info");
  refreshVault();
});

.modal { display:none; position:fixed; inset:0; background:rgba(0,0,0,.6); }
.modal.open { display:flex; align-items:center; justify-content:center; }
.modal-card { background:#111; padding:16px; border-radius:10px; width:min(520px, 92vw); }
.modal-card textarea { width:100%; margin-top:8px; }
.modal-actions { display:flex; gap:8px; justify-content:flex-end; margin-top:10px; }
.modal-error { color:#ff8080; min-height:18px; margin-top:6px; }
