/* ==========================================================
   Sentinel-43 Dashboard
   websocket.js
   ========================================================== */

"use strict";

/* ==========================================================
   Config
   ========================================================== */

const SentinelWebSocket = {
    wsUrl:
        window.SENTINEL_WS_URL ||
        "ws://localhost:8000/ws",

    reconnectDelayMs: 3000,
    maxReconnectDelayMs: 30000,
    heartbeatIntervalMs: 15000,

    socket: null,
    reconnectAttempts: 0,
    heartbeatTimer: null,
    manuallyClosed: false,
};

/* ==========================================================
   Helpers
   ========================================================== */

function wsSetText(selector, value) {
    const element = document.querySelector(selector);

    if (element) {
        element.textContent = value;
    }
}

function wsSetStatus(state) {
    const statusElement = document.querySelector("[data-ws-status]");

    if (!statusElement) {
        return;
    }

    statusElement.textContent = state;

    statusElement.classList.remove(
        "status-online",
        "status-warning",
        "status-error",
        "status-info",
    );

    const normalized = String(state || "").toLowerCase();

    if (["connected", "online", "open"].includes(normalized)) {
        statusElement.classList.add("status-online");
    } else if (["connecting", "reconnecting"].includes(normalized)) {
        statusElement.classList.add("status-warning");
    } else if (["closed", "error", "offline"].includes(normalized)) {
        statusElement.classList.add("status-error");
    } else {
        statusElement.classList.add("status-info");
    }
}

function wsLogEvent(message, level = "info") {
    const feed = document.querySelector("[data-ws-feed]");

    if (!feed) {
        return;
    }

    const entry = document.createElement("div");
    entry.className = `audit-entry ws-event ws-event-${level}`;

    const timestamp = new Date().toISOString();

    entry.innerHTML = `
        <div class="audit-entry-time">${timestamp}</div>
        <div class="audit-entry-message">${message}</div>
    `;

    feed.prepend(entry);

    const maxEntries = 100;

    while (feed.children.length > maxEntries) {
        feed.removeChild(feed.lastChild);
    }
}

function buildWebSocketUrl() {
    return SentinelWebSocket.wsUrl;
}

/* ==========================================================
   Message Handling
   ========================================================== */

function handleWebSocketMessage(event) {
    let data = null;

    try {
        data = JSON.parse(event.data);
    } catch {
        wsLogEvent(`Non-JSON message received: ${event.data}`, "warning");
        return;
    }

    const eventType = data.event_type || data.type || "unknown";
    const message = data.message || JSON.stringify(data);

    wsSetText("[data-last-event-type]", eventType);
    wsSetText("[data-last-event-time]", new Date().toISOString());

    wsLogEvent(`[${eventType}] ${message}`, "info");

    window.dispatchEvent(
        new CustomEvent("sentinel:ws:event", {
            detail: data,
        }),
    );
}

/* ==========================================================
   Heartbeat
   ========================================================== */

function startHeartbeat() {
    stopHeartbeat();

    SentinelWebSocket.heartbeatTimer = window.setInterval(() => {
        if (
            SentinelWebSocket.socket &&
            SentinelWebSocket.socket.readyState === WebSocket.OPEN
        ) {
            SentinelWebSocket.socket.send(
                JSON.stringify({
                    type: "dashboard_ping",
                    timestamp: new Date().toISOString(),
                }),
            );
        }
    }, SentinelWebSocket.heartbeatIntervalMs);
}

function stopHeartbeat() {
    if (SentinelWebSocket.heartbeatTimer) {
        window.clearInterval(SentinelWebSocket.heartbeatTimer);
        SentinelWebSocket.heartbeatTimer = null;
    }
}

/* ==========================================================
   Connection Lifecycle
   ========================================================== */

function connectSentinelWebSocket() {
    if (
        SentinelWebSocket.socket &&
        (
            SentinelWebSocket.socket.readyState === WebSocket.OPEN ||
            SentinelWebSocket.socket.readyState === WebSocket.CONNECTING
        )
    ) {
        return;
    }

    SentinelWebSocket.manuallyClosed = false;
    wsSetStatus("connecting");

    try {
        SentinelWebSocket.socket = new WebSocket(buildWebSocketUrl());
    } catch (error) {
        wsSetStatus("error");
        wsLogEvent(`WebSocket creation failed: ${error.message}`, "error");
        scheduleReconnect();
        return;
    }

    SentinelWebSocket.socket.addEventListener("open", () => {
        SentinelWebSocket.reconnectAttempts = 0;

        wsSetStatus("connected");
        wsLogEvent("WebSocket connected", "info");

        startHeartbeat();
    });

    SentinelWebSocket.socket.addEventListener("message", handleWebSocketMessage);

    SentinelWebSocket.socket.addEventListener("error", () => {
        wsSetStatus("error");
        wsLogEvent("WebSocket error detected", "error");
    });

    SentinelWebSocket.socket.addEventListener("close", () => {
        stopHeartbeat();

        wsSetStatus("closed");
        wsLogEvent("WebSocket closed", "warning");

        if (!SentinelWebSocket.manuallyClosed) {
            scheduleReconnect();
        }
    });
}

function disconnectSentinelWebSocket() {
    SentinelWebSocket.manuallyClosed = true;

    stopHeartbeat();

    if (SentinelWebSocket.socket) {
        SentinelWebSocket.socket.close();
        SentinelWebSocket.socket = null;
    }

    wsSetStatus("closed");
}

function scheduleReconnect() {
    SentinelWebSocket.reconnectAttempts += 1;

    const delay = Math.min(
        SentinelWebSocket.reconnectDelayMs * SentinelWebSocket.reconnectAttempts,
        SentinelWebSocket.maxReconnectDelayMs,
    );

    wsSetStatus("reconnecting");
    wsLogEvent(`Reconnecting in ${delay}ms`, "warning");

    window.setTimeout(() => {
        if (!SentinelWebSocket.manuallyClosed) {
            connectSentinelWebSocket();
        }
    }, delay);
}

/* ==========================================================
   Public Send Helper
   ========================================================== */

function sendSentinelWebSocketMessage(payload) {
    if (
        !SentinelWebSocket.socket ||
        SentinelWebSocket.socket.readyState !== WebSocket.OPEN
    ) {
        wsLogEvent("Cannot send WebSocket message: socket is not connected", "error");
        return false;
    }

    SentinelWebSocket.socket.send(JSON.stringify(payload));
    return true;
}

/* ==========================================================
   Startup
   ========================================================== */

document.addEventListener("DOMContentLoaded", () => {
    const shouldConnect =
        document.body.dataset.websocket === "true" ||
        document.querySelector("[data-ws-status]") !== null;

    if (shouldConnect) {
        connectSentinelWebSocket();
    }
});
