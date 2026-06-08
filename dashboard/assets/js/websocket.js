/* ==========================================================
   Sentinel-43 Dashboard
   websocket.js
   Hardened WebSocket bridge
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
    maxLogMessageLength: 2000,

    socket: null,
    reconnectAttempts: 0,
    heartbeatTimer: null,
    reconnectTimer: null,
    lastMessageAt: 0,
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

function clampLogMessage(message) {
    const text = String(message ?? "");

    if (text.length <= SentinelWebSocket.maxLogMessageLength) {
        return text;
    }

    return `${text.slice(0, SentinelWebSocket.maxLogMessageLength)}... [truncated]`;
}

function wsLogEvent(message, level = "info") {
    const feed = document.querySelector("[data-ws-feed]");

    if (!feed) {
        return;
    }

    const safeLevel = String(level || "info").replace(/[^a-z0-9_-]/gi, "");
    const entry = document.createElement("div");
    entry.className = `audit-entry ws-event ws-event-${safeLevel}`;

    const timeElement = document.createElement("div");
    timeElement.className = "audit-entry-time";
    timeElement.textContent = new Date().toISOString();

    const messageElement = document.createElement("div");
    messageElement.className = "audit-entry-message";
    messageElement.textContent = clampLogMessage(message);

    entry.appendChild(timeElement);
    entry.appendChild(messageElement);

    feed.prepend(entry);

    const maxEntries = 100;

    while (feed.children.length > maxEntries) {
        feed.removeChild(feed.lastChild);
    }
}

function getDashboardAuthToken() {
    return (
        window.SENTINEL_WS_TOKEN ||
        window.SENTINEL_AUTH_TOKEN ||
        window.localStorage.getItem("sentinel_token") ||
        window.sessionStorage.getItem("sentinel_token") ||
        ""
    );
}

function buildWebSocketUrl() {
    const token = getDashboardAuthToken();

    if (!token) {
        return SentinelWebSocket.wsUrl;
    }

    const url = new URL(SentinelWebSocket.wsUrl, window.location.href);
    url.searchParams.set("token", token);

    return url.toString();
}

function clearReconnectTimer() {
    if (SentinelWebSocket.reconnectTimer) {
        window.clearTimeout(SentinelWebSocket.reconnectTimer);
        SentinelWebSocket.reconnectTimer = null;
    }
}

function getReconnectDelay() {
    const attempt = Math.max(0, SentinelWebSocket.reconnectAttempts - 1);
    const exponential = SentinelWebSocket.reconnectDelayMs * Math.pow(2, attempt);
    const capped = Math.min(exponential, SentinelWebSocket.maxReconnectDelayMs);
    const jitter = Math.floor(Math.random() * 1000);

    return capped + jitter;
}

/* ==========================================================
   Message Handling
   ========================================================== */

function handleWebSocketMessage(event) {
    SentinelWebSocket.lastMessageAt = Date.now();

    let data = null;

    try {
        data = JSON.parse(event.data);
    } catch {
        wsLogEvent(`Non-JSON message received: ${clampLogMessage(event.data)}`, "warning");
        return;
    }

    const eventType = String(data.event_type || data.type || "unknown");
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

    SentinelWebSocket.lastMessageAt = Date.now();

    SentinelWebSocket.heartbeatTimer = window.setInterval(() => {
        const socket = SentinelWebSocket.socket;

        if (!socket || socket.readyState !== WebSocket.OPEN) {
            return;
        }

        const staleMs = Date.now() - SentinelWebSocket.lastMessageAt;
        const staleLimitMs = SentinelWebSocket.heartbeatIntervalMs * 2;

        if (staleMs > staleLimitMs) {
            wsLogEvent("WebSocket heartbeat timeout; forcing reconnect", "warning");
            socket.close();
            return;
        }

        try {
            socket.send(
                JSON.stringify({
                    type: "dashboard_ping",
                    timestamp: new Date().toISOString(),
                }),
            );
        } catch (error) {
            wsLogEvent(`Heartbeat send failed: ${error.message}`, "error");
            socket.close();
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
    if (document.hidden) {
        return;
    }

    if (
        SentinelWebSocket.socket &&
        (
            SentinelWebSocket.socket.readyState === WebSocket.OPEN ||
            SentinelWebSocket.socket.readyState === WebSocket.CONNECTING
        )
    ) {
        return;
    }

    clearReconnectTimer();

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

    const socket = SentinelWebSocket.socket;

    socket.addEventListener("open", () => {
        SentinelWebSocket.reconnectAttempts = 0;
        SentinelWebSocket.lastMessageAt = Date.now();

        wsSetStatus("connected");
        wsLogEvent("WebSocket connected", "info");

        startHeartbeat();
    });

    socket.addEventListener("message", handleWebSocketMessage);

    socket.addEventListener("error", () => {
        wsSetStatus("error");
        wsLogEvent("WebSocket error detected", "error");
    });

    socket.addEventListener("close", () => {
        stopHeartbeat();

        if (SentinelWebSocket.socket === socket) {
            SentinelWebSocket.socket = null;
        }

        wsSetStatus("closed");
        wsLogEvent("WebSocket closed", "warning");

        if (!SentinelWebSocket.manuallyClosed && !document.hidden) {
            scheduleReconnect();
        }
    });
}

function disconnectSentinelWebSocket() {
    SentinelWebSocket.manuallyClosed = true;

    clearReconnectTimer();
    stopHeartbeat();

    if (SentinelWebSocket.socket) {
        SentinelWebSocket.socket.close();
        SentinelWebSocket.socket = null;
    }

    wsSetStatus("closed");
}

function scheduleReconnect() {
    if (SentinelWebSocket.manuallyClosed || document.hidden) {
        return;
    }

    clearReconnectTimer();

    SentinelWebSocket.reconnectAttempts += 1;

    const delay = getReconnectDelay();

    wsSetStatus("reconnecting");
    wsLogEvent(`Reconnecting in ${delay}ms`, "warning");

    SentinelWebSocket.reconnectTimer = window.setTimeout(() => {
        SentinelWebSocket.reconnectTimer = null;

        if (!SentinelWebSocket.manuallyClosed && !document.hidden) {
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

    try {
        SentinelWebSocket.socket.send(JSON.stringify(payload));
        return true;
    } catch (error) {
        wsLogEvent(`WebSocket send failed: ${error.message}`, "error");
        return false;
    }
}

/* ==========================================================
   Page Visibility Handling
   ========================================================== */

document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
        disconnectSentinelWebSocket();
        return;
    }

    const shouldConnect =
        document.body.dataset.websocket === "true" ||
        document.querySelector("[data-ws-status]") !== null;

    if (shouldConnect) {
        connectSentinelWebSocket();
    }
});

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
