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

/* =============================
   DOM Bindings
============================= */
const logConsole     = document.getElementById("log-console");
const threatFeed    = document.getElementById("threat-feed");
const recordCountEl = document.getElementById("record-count");

/* =============================
   Runtime Flags
============================= */
const DEMO_MODE = (window.AEGIS_DEMO_MODE ?? true) === true;

/* =============================
   Backend Interface (thin seam)
============================= */
const api = {
  token() {
    return sessionStorage.getItem("AEGIS_JWT") || null;
  },

  headers() {
    const h = { "Content-Type": "application/json" };
    const t = this.token();
    if (t) h.Authorization = `Bearer ${t}`;
    return h;
  },

  async listPendingActions() {
    if (DEMO_MODE) return demo.listPendingActions();
    const r = await fetch("/api/v1/actions/pending", { headers: this.headers() });
    if (!r.ok) throw new Error("pending actions fetch failed");
    return r.json();
  },

  async veto(actionId, reason) {
    if (DEMO_MODE) return demo.veto(actionId, reason);
    const r = await fetch("/api/v1/oversight/veto", {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({ action_id: actionId, reason }),
    });
    return r.ok;
  },

  async vaultStats() {
    if (DEMO_MODE) return { records: null };
    const r = await fetch("/api/v1/vault/stats", { headers: this.headers() });
    return r.ok ? r.json() : { records: null };
  },
};

/* =============================
   Demo Backend (sandbox only)
============================= */
const demo = (() => {
  const pending = new Map();

  function makeAction(ip, threat, delaySec) {
    const now = Date.now();
    const id  = `ACT-${now.toString(36)}-${Math.random().toString(36).slice(2,8)}`.toUpperCase();

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
      if (a.status === "EXECUTED" && now - a.execute_at_ms > 3000) {
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
    setTimeout(() => pending.delete(id), 4000);
    return true;
  }

  setTimeout(() => makeAction("203.0.113.45", "SQL INJECTION PATTERN", 30), 3000);
  setTimeout(() => makeAction("198.51.100.12", "DATA EXFILTRATION", 45), 15000);

  return { listPendingActions, veto };
})();

/* =============================
   UI Utilities
============================= */
function ts() {
  return new Date().toISOString().split("T")[1].split(".")[0];
}

function log(msg, level = "info") {
  const d = document.createElement("div");
  d.className = `log-entry ${level}`;
  d.textContent = `[${ts()}] ${msg}`;
  logConsole.appendChild(d);
  logConsole.scrollTop = logConsole.scrollHeight;
}

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
  return `${String(Math.floor(sec/60)).padStart(2,"0")}:${String(sec%60).padStart(2,"0")}`;
}

/* =============================
   Threat Card Renderer
============================= */
function renderThreat(a) {
  const id = a.action_id;
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
    card.remove();
    return;
  }

  const remain = Math.ceil((a.execute_at_ms - Date.now()) / 1000);

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
   Event Wiring
============================= */
threatFeed.addEventListener("click", e => {
  const btn = e.target.closest(".veto-btn");
  if (!btn) return;

  const id = btn.dataset.id;
  const reason = prompt("Veto reason (required):", "False positive");
  if (!reason) return;

  api.veto(id, reason).then(ok => {
    log(ok ? `Action ${id} vetoed.` : `Veto failed for ${id}.`, ok ? "warn" : "error");
  });
});

/* =============================
   Poll Loops
============================= */
async function refreshThreats() {
  try {
    const { actions = [] } = await api.listPendingActions();
    const seen = new Set();

    actions.forEach(a => {
      seen.add(a.action_id);
      renderThreat(a);
    });

    [...threatFeed.children].forEach(el => {
      if (!seen.has(el.id)) el.remove();
    });
  } catch (e) {
    log(`Threat refresh failed: ${e}`, "warn");
  }
}

async function refreshVault() {
  try {
    const s = await api.vaultStats();
    if (typeof s.records === "number") {
      recordCountEl.textContent = s.records.toLocaleString();
    }
  } catch {}
}

/* =============================
   Boot
============================= */
setInterval(refreshThreats, 750);
setInterval(refreshVault, 10000);

if (DEMO_MODE) {
  setInterval(() => {
    const msgs = [
      "[WATCHTOWER] Heartbeat nominal",
      "[AUDIT] Integrity unchanged",
      "[API] Latency < 15ms",
      "[RESOURCE] CPU steady"
    ];
    log(msgs[Math.floor(Math.random() * msgs.length)]);
  }, 2000);
}

refreshThreats();