/* =============================================================================
   Sentinel-43 Dashboard
   websocket.js — Hardened WebSocket bridge
   Protocol: aligned to core/api/main.py
   ============================================================================= */

"use strict";

/* =============================================================================
   Config
   Reads from the same sources as the inline dashboard CONFIG block so both
   can be driven by the same meta tags or window.SENTINEL_RUNTIME_CONFIG.
   ============================================================================= */

const _readMeta = name =>
    document.querySelector(`meta[name="${name}"]`)?.content?.trim() ?? "";

const _runtime = window.SENTINEL_RUNTIME_CONFIG ?? {};
const _locationIsLocal = ["", "localhost", "127.0.0.1", "::1"]
    .includes(location.hostname);

const WS_CONFIG = Object.freeze({
    // URL resolution order matches the inline dashboard.
    URL: String(
        _runtime.wsUrl
        ?? window.SENTINEL_WS_URL
        ?? _readMeta("sentinel-ws-url")
        ?? "ws://localhost:8000/ws"
    ),

    // Reconnect: starts at 1 s, doubles each failed attempt, caps at 30 s,
    // +20 % jitter — matches the inline dashboard's scheduleWsReconnect().
    RECONNECT_MS:     1_000,
    RECONNECT_MAX_MS: 30_000,

    // Heartbeat: send ping every 25 s, force-reconnect if nothing received
    // in 2× that window (50 s). Matches inline dashboard WS_HEARTBEAT_MS.
    HEARTBEAT_MS: 25_000,

    // Frame size cap in bytes — matches inline dashboard MAX_WS_FRAME_BYTES.
    MAX_FRAME_BYTES: 64 * 1_024,

    // Dev-only JWT read from sessionStorage. Never read localStorage.
    // Only enabled on local hostnames, same gate as the inline dashboard.
    ALLOW_DEV_TOKEN: _locationIsLocal,

    // Channels to subscribe on connect.
    // "watchtower" and "dependencies" can be added once the dashboard
    // has handlers for those event types.
    CHANNELS: Object.freeze(["actions", "vault"]),
});

/* =============================================================================
   Module-scope TextEncoder
   One allocation per page lifetime — hoisted out of the per-frame hot path.
   Matches inline dashboard fix for TEXT_ENCODER.
   ============================================================================= */

const _WS_TEXT_ENCODER = new TextEncoder();

/* =============================================================================
   Module State
   ============================================================================= */

let _ws                = null;   // active WebSocket instance
let _connected         = false;  // true only when OPEN + post-connect setup done
let _manuallyClosed    = false;  // set by disconnect() to suppress auto-reconnect
let _reconnectAttempts = 0;      // resets to 0 on successful open
let _reconnectTimer    = null;
let _heartbeatTimer    = null;
let _lastMessageAt     = 0;      // epoch ms of last received frame

/* =============================================================================
   Token Helper
   sessionStorage only. No localStorage, no window globals, no URL params.
   ============================================================================= */

function _getDevToken() {
    if (!WS_CONFIG.ALLOW_DEV_TOKEN) return null;
    try { return sessionStorage.getItem("SENTINEL_JWT") || null; } catch { return null; }
}

/* =============================================================================
   URL Validation
   Identical rules to safeWsUrl() in the inline dashboard.
   Tokens must never appear in the WebSocket URL — they end up in server logs,
   browser history, and proxy caches.
   ============================================================================= */

function _safeWsUrl() {
    const url = new URL(WS_CONFIG.URL, location.href);

    if (!["ws:", "wss:"].includes(url.protocol))
        throw new Error("WebSocket URL must use ws:// or wss://");

    if (location.protocol === "https:" && url.protocol !== "wss:")
        throw new Error("Secure pages require a wss:// WebSocket URL");

    if (["token", "access_token", "authorization", "api_key"]
            .some(key => url.searchParams.has(key)))
        throw new Error("Credentials must not be placed in the WebSocket URL");

    return url.toString();
}

/* =============================================================================
   Event Dispatch
   Dispatches two events per message so listeners can subscribe either to
   the generic stream or to a specific message type.

     "sentinel:ws:message"        detail = full parsed message object
     "sentinel:ws:<type>"         e.g. "sentinel:ws:actions_snapshot"

   Status-change events (open, close, error, etc.) use named events only.
   ============================================================================= */

function _dispatch(name, detail = {}) {
    window.dispatchEvent(new CustomEvent(name, {detail, bubbles: false}));
}

function _dispatchMessage(parsed) {
    _dispatch("sentinel:ws:message", parsed);
    _dispatch(`sentinel:ws:${parsed.type}`, parsed);
}

/* =============================================================================
   Frame Validation
   Checks byte length before parsing so oversized frames never hit JSON.parse().
   Fast-path: skip encode() when string character count already exceeds the cap
   (UTF-8 byte length >= JS character count, so the cap is definitely breached).
   ============================================================================= */

function _validateFrame(raw) {
    if (typeof raw !== "string")
        throw new Error("WebSocket frame must be a text message");

    if (
        raw.length > WS_CONFIG.MAX_FRAME_BYTES ||
        _WS_TEXT_ENCODER.encode(raw).length > WS_CONFIG.MAX_FRAME_BYTES
    ) throw new Error(`WebSocket frame exceeds the ${WS_CONFIG.MAX_FRAME_BYTES}-byte limit`);

    let parsed;
    try {
        parsed = JSON.parse(raw);
    } catch (err) {
        throw new Error(`Malformed JSON in WebSocket frame: ${err.message}`);
    }

    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
        throw new Error("WebSocket message must be a JSON object");

    if (typeof parsed.type !== "string" || !parsed.type.trim())
        throw new Error("WebSocket message missing required type field");

    if ("payload" in parsed &&
        (parsed.payload === null ||
         typeof parsed.payload !== "object" ||
         Array.isArray(parsed.payload)))
        throw new Error("WebSocket message payload must be an object when present");

    return {
        type:    parsed.type.trim(),
        payload: (parsed.payload && typeof parsed.payload === "object") ? parsed.payload : {},
    };
}

/* =============================================================================
   Heartbeat
   Sends {"type":"ping","payload":{...}} — matches main.py's "ping" handler
   which returns {"type":"pong",...}. The old "dashboard_ping" type is gone.
   ============================================================================= */

function _startHeartbeat() {
    _stopHeartbeat();
    _lastMessageAt = Date.now();

    _heartbeatTimer = setInterval(() => {
        if (!_ws || _ws.readyState !== WebSocket.OPEN) return;

        // Force reconnect if the server has gone silent for 2× the heartbeat window.
        if (Date.now() - _lastMessageAt > WS_CONFIG.HEARTBEAT_MS * 2) {
            _dispatch("sentinel:ws:stale", {
                silentMs: Date.now() - _lastMessageAt,
                timestamp: new Date().toISOString(),
            });
            _ws.close();
            return;
        }

        try {
            _ws.send(JSON.stringify({
                type:    "ping",
                payload: {timestamp: new Date().toISOString()},
            }));
        } catch (err) {
            _dispatch("sentinel:ws:error", {
                error: `Heartbeat send failed: ${err.message}`,
            });
            _ws.close();
        }
    }, WS_CONFIG.HEARTBEAT_MS);
}

function _stopHeartbeat() {
    if (_heartbeatTimer) { clearInterval(_heartbeatTimer); _heartbeatTimer = null; }
}

/* =============================================================================
   Reconnect — exponential backoff with 20 % jitter
   ============================================================================= */

function _clearReconnectTimer() {
    if (_reconnectTimer) { clearTimeout(_reconnectTimer); _reconnectTimer = null; }
}

function _reconnectDelay() {
    const base = Math.min(
        WS_CONFIG.RECONNECT_MAX_MS,
        WS_CONFIG.RECONNECT_MS * Math.pow(2, _reconnectAttempts),
    );
    return Math.floor(base + base * 0.2 * Math.random());
}

function _scheduleReconnect() {
    if (_manuallyClosed || document.hidden || _reconnectTimer) return;
    const delay = _reconnectDelay();
    _reconnectAttempts += 1;
    _dispatch("sentinel:ws:reconnecting", {
        attempt: _reconnectAttempts,
        delayMs: delay,
        timestamp: new Date().toISOString(),
    });
    _reconnectTimer = setTimeout(() => {
        _reconnectTimer = null;
        if (!_manuallyClosed && !document.hidden) connect();
    }, delay);
}

/* =============================================================================
   Message Handler
   ============================================================================= */

function _handleMessage(event) {
    _lastMessageAt = Date.now();

    let parsed;
    try {
        parsed = _validateFrame(event.data);
    } catch (err) {
        // Bad frame — log it but keep the connection alive.
        _dispatch("sentinel:ws:frame_error", {error: err.message});
        return;
    }

    // ── auth_required ────────────────────────────────────────────────────────
    // main.py sends this when S43_WS_REQUIRE_AUTH=true.
    // Respond immediately with the dev token from sessionStorage.
    // If no token is available, dispatch an auth failure event and close.
    if (parsed.type === "auth_required") {
        const token = _getDevToken();
        if (!token) {
            _dispatch("sentinel:ws:auth_failed", {
                error: "Server requires authentication but no token found in sessionStorage. "
                     + "Set a JWT via the JWT button in the dashboard before connecting.",
            });
            _ws?.close();
            return;
        }
        try {
            _ws.send(JSON.stringify({
                type:    "auth",
                payload: {token},
            }));
        } catch (err) {
            _dispatch("sentinel:ws:auth_failed", {
                error: `Auth frame send failed: ${err.message}`,
            });
        }
        // Do not surface auth_required to the dashboard.
        return;
    }

    // ── pong ─────────────────────────────────────────────────────────────────
    // Internal heartbeat acknowledgement. Update timestamp, do not surface.
    if (parsed.type === "pong") {
        _lastMessageAt = Date.now();
        return;
    }

    // ── all other messages ───────────────────────────────────────────────────
    // Dispatch both generic and type-specific events for the dashboard to handle.
    // Expected types from main.py:
    //   connected, subscribed, actions_snapshot,
    //   action_created, action_updated, action_status_changed,
    //   action_deleted, action_removed,
    //   vault_stats, watchtower_state, dependency_state,
    //   error, unsubscribed
    _dispatchMessage(parsed);
}

/* =============================================================================
   Connection Lifecycle
   ============================================================================= */

function connect() {
    if (document.hidden) return;
    if (_ws && [WebSocket.OPEN, WebSocket.CONNECTING].includes(_ws.readyState)) return;

    _clearReconnectTimer();
    _manuallyClosed = false;

    let url;
    try {
        url = _safeWsUrl();
    } catch (err) {
        _dispatch("sentinel:ws:error", {error: err.message});
        return;
    }

    _dispatch("sentinel:ws:connecting", {url, timestamp: new Date().toISOString()});

    try {
        _ws = new WebSocket(url);
    } catch (err) {
        _dispatch("sentinel:ws:error", {
            error: `WebSocket construction failed: ${err.message}`,
        });
        _scheduleReconnect();
        return;
    }

    _ws.addEventListener("open", () => {
        _reconnectAttempts = 0;
        _connected = true;
        _lastMessageAt = Date.now();

        _startHeartbeat();
        _dispatch("sentinel:ws:open", {timestamp: new Date().toISOString()});

        // Subscribe to all configured channels.
        // main.py will respond with "subscribed" + an immediate snapshot per channel.
        for (const channel of WS_CONFIG.CHANNELS) {
            try {
                _ws.send(JSON.stringify({
                    type:    "subscribe",
                    payload: {channel},
                }));
            } catch (err) {
                _dispatch("sentinel:ws:error", {
                    error: `subscribe(${channel}) failed: ${err.message}`,
                });
            }
        }
    });

    _ws.addEventListener("message", _handleMessage);

    _ws.addEventListener("close", () => {
        _connected = false;
        _stopHeartbeat();
        _ws = null;
        _dispatch("sentinel:ws:close", {timestamp: new Date().toISOString()});
        if (!_manuallyClosed && !document.hidden) _scheduleReconnect();
    });

    // The "error" event fires before "close" on transport errors.
    // close always follows, so reconnect is handled there.
    _ws.addEventListener("error", () => {
        _dispatch("sentinel:ws:error", {
            error: "WebSocket transport error",
            timestamp: new Date().toISOString(),
        });
    });
}

function disconnect() {
    _manuallyClosed = true;
    _clearReconnectTimer();
    _stopHeartbeat();
    _connected = false;
    if (_ws) { _ws.close(); _ws = null; }
    _dispatch("sentinel:ws:disconnected", {timestamp: new Date().toISOString()});
}

/* =============================================================================
   Public Send Helper
   ============================================================================= */

function send(type, payload = {}) {
    if (!_ws || _ws.readyState !== WebSocket.OPEN) {
        _dispatch("sentinel:ws:error", {
            error: "Cannot send: socket is not open",
        });
        return false;
    }
    try {
        _ws.send(JSON.stringify({type, payload}));
        return true;
    } catch (err) {
        _dispatch("sentinel:ws:error", {error: `Send failed: ${err.message}`});
        return false;
    }
}

/* =============================================================================
   Page Visibility
   Disconnect when the operator hides the tab — this is a security console and
   an unattended live connection is undesirable.
   Reconnect automatically when the tab becomes visible again.
   ============================================================================= */

document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
        disconnect();
        return;
    }
    // Re-enable auto-reconnect and attempt a fresh connection.
    _manuallyClosed = false;
    connect();
});

/* =============================================================================
   Unload Cleanup
   ============================================================================= */

window.addEventListener("beforeunload", disconnect);

/* =============================================================================
   Public API
   Exposed on window.SentinelWS so the inline dashboard or other scripts
   can drive the connection without duplicating the protocol logic.

   Integration note:
   The inline dashboard currently manages its own WebSocket connection.
   To use this module instead, remove the connectWebSocket / closeWebSocket /
   wsConnected / wsReconnect* / wsHeartbeat* code from the inline script and
   add event listeners for the sentinel:ws:* events documented below.

   Events dispatched by this module:
     sentinel:ws:open              WebSocket opened, subscriptions sent
     sentinel:ws:close             WebSocket closed (reconnect scheduled if unintentional)
     sentinel:ws:disconnected      disconnect() called manually
     sentinel:ws:reconnecting      {attempt, delayMs}
     sentinel:ws:connecting        {url}
     sentinel:ws:error             {error}
     sentinel:ws:frame_error       {error} — bad frame, connection kept alive
     sentinel:ws:auth_failed       {error} — auth_required received but no token
     sentinel:ws:stale             {silentMs} — no data received, forcing reconnect
     sentinel:ws:message           {type, payload} — all server messages (generic)
     sentinel:ws:<type>            type-specific, e.g. sentinel:ws:actions_snapshot
   ============================================================================= */

window.SentinelWS = Object.freeze({
    connect,
    disconnect,
    send,
    get connected()         { return _connected && _ws?.readyState === WebSocket.OPEN; },
    get reconnectAttempts() { return _reconnectAttempts; },
    get lastMessageAt()     { return _lastMessageAt; },
});

/* =============================================================================
   Auto-connect on load
   ============================================================================= */

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", connect);
} else {
    connect();
}
