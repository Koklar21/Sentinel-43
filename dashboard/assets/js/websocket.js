/* =============================================================================
   Sentinel-43 Dashboard
   websocket.js — Hardened WebSocket bridge
   v1.4.0

   Protocol:
     - Backend may send: auth_required
     - Client must answer first with: {"type":"auth","payload":{"token":"..."}}
     - Client must NOT subscribe before auth is accepted.
     - After authenticated/connected, subscribe to configured channels.

   This module exposes window.SentinelWS and dispatches sentinel:ws:* events.
   ============================================================================= */

"use strict";

/* =============================================================================
   Config
   ============================================================================= */

const _readMeta = name =>
    document.querySelector(`meta[name="${name}"]`)?.content?.trim() ?? "";

const _runtime = window.SENTINEL_RUNTIME_CONFIG ?? {};

const _locationIsLocal = ["", "localhost", "127.0.0.1", "::1"]
    .includes(location.hostname);

const WS_CONFIG = Object.freeze({
    URL: String(
        _runtime.wsUrl
        ?? window.SENTINEL_WS_URL
        ?? _readMeta("sentinel-ws-url")
        ?? "ws://localhost:8000/ws"
    ),

    RECONNECT_MS: 1_000,
    RECONNECT_MAX_MS: 30_000,

    HEARTBEAT_MS: 25_000,

    MAX_FRAME_BYTES: 64 * 1_024,

    // Dev token is only read from sessionStorage and only on local hostnames.
    ALLOW_DEV_TOKEN: _locationIsLocal,

    // If true, client may send auth immediately on open when a token exists.
    // This guarantees the first outbound frame is auth.
    AUTH_FIRST_WHEN_TOKEN_PRESENT: true,

    CHANNELS: Object.freeze(["actions", "vault"]),
});

/* =============================================================================
   Module State
   ============================================================================= */

const _WS_TEXT_ENCODER = new TextEncoder();

let _ws = null;

let _socketOpen = false;
let _authenticated = false;
let _connected = false;
let _subscribed = false;

let _manuallyClosed = false;
let _reconnectAttempts = 0;
let _reconnectTimer = null;
let _heartbeatTimer = null;
let _lastMessageAt = 0;

/* =============================================================================
   Helpers
   ============================================================================= */

function _nowIso() {
    return new Date().toISOString();
}

function _dispatch(name, detail = {}) {
    window.dispatchEvent(new CustomEvent(name, { detail, bubbles: false }));
}

function _dispatchMessage(parsed) {
    _dispatch("sentinel:ws:message", parsed);
    _dispatch(`sentinel:ws:${parsed.type}`, parsed);
}

function _getDevToken() {
    if (!WS_CONFIG.ALLOW_DEV_TOKEN) return null;

    try {
        return sessionStorage.getItem("SENTINEL_JWT") || null;
    } catch {
        return null;
    }
}

function _safeWsUrl() {
    const url = new URL(WS_CONFIG.URL, location.href);

    if (!["ws:", "wss:"].includes(url.protocol)) {
        throw new Error("WebSocket URL must use ws:// or wss://");
    }

    if (location.protocol === "https:" && url.protocol !== "wss:") {
        throw new Error("Secure pages require a wss:// WebSocket URL");
    }

    const forbiddenParams = ["token", "access_token", "authorization", "api_key"];
    for (const key of forbiddenParams) {
        if (url.searchParams.has(key)) {
            throw new Error("Credentials must not be placed in the WebSocket URL");
        }
    }

    return url.toString();
}

function _resetConnectionState() {
    _socketOpen = false;
    _authenticated = false;
    _connected = false;
    _subscribed = false;
    _lastMessageAt = 0;
}

/* =============================================================================
   Frame Validation
   ============================================================================= */

function _validateFrame(raw) {
    if (typeof raw !== "string") {
        throw new Error("WebSocket frame must be a text message");
    }

    if (
        raw.length > WS_CONFIG.MAX_FRAME_BYTES ||
        _WS_TEXT_ENCODER.encode(raw).length > WS_CONFIG.MAX_FRAME_BYTES
    ) {
        throw new Error(`WebSocket frame exceeds ${WS_CONFIG.MAX_FRAME_BYTES} bytes`);
    }

    let parsed;
    try {
        parsed = JSON.parse(raw);
    } catch (err) {
        throw new Error(`Malformed JSON in WebSocket frame: ${err.message}`);
    }

    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("WebSocket message must be a JSON object");
    }

    if (typeof parsed.type !== "string" || !parsed.type.trim()) {
        throw new Error("WebSocket message missing required type field");
    }

    if (
        "payload" in parsed &&
        (
            parsed.payload === null ||
            typeof parsed.payload !== "object" ||
            Array.isArray(parsed.payload)
        )
    ) {
        throw new Error("WebSocket payload must be an object when present");
    }

    return {
        type: parsed.type.trim(),
        payload: (
            parsed.payload &&
            typeof parsed.payload === "object" &&
            !Array.isArray(parsed.payload)
        ) ? parsed.payload : {},
    };
}

/* =============================================================================
   Send Helpers
   ============================================================================= */

function _canSend() {
    return _ws && _ws.readyState === WebSocket.OPEN;
}

function _sendRaw(type, payload = {}) {
    if (!_canSend()) return false;

    try {
        _ws.send(JSON.stringify({ type, payload }));
        return true;
    } catch (err) {
        _dispatch("sentinel:ws:error", {
            error: `Send failed: ${err.message}`,
            timestamp: _nowIso(),
        });
        return false;
    }
}

function _sendAuthFrame() {
    const token = _getDevToken();

    if (!token) {
        _dispatch("sentinel:ws:auth_failed", {
            error: "WebSocket authentication required, but no JWT was found in sessionStorage.",
            timestamp: _nowIso(),
        });

        if (_ws) {
            try { _ws.close(); } catch {}
        }

        return false;
    }

    const ok = _sendRaw("auth", { token });

    if (ok) {
        _dispatch("sentinel:ws:auth_sent", {
            timestamp: _nowIso(),
        });
    }

    return ok;
}

function _subscribeConfiguredChannels() {
    if (!_canSend()) return false;
    if (_subscribed) return true;

    for (const channel of WS_CONFIG.CHANNELS) {
        const ok = _sendRaw("subscribe", { channel });
        if (!ok) return false;
    }

    _subscribed = true;

    _dispatch("sentinel:ws:subscribed_all", {
        channels: [...WS_CONFIG.CHANNELS],
        timestamp: _nowIso(),
    });

    return true;
}

/* =============================================================================
   Heartbeat
   ============================================================================= */

function _startHeartbeat() {
    _stopHeartbeat();
    _lastMessageAt = Date.now();

    _heartbeatTimer = setInterval(() => {
        if (!_canSend()) return;

        // Do not ping before backend connection/auth handshake is accepted.
        if (!_connected) return;

        if (Date.now() - _lastMessageAt > WS_CONFIG.HEARTBEAT_MS * 2) {
            _dispatch("sentinel:ws:stale", {
                silentMs: Date.now() - _lastMessageAt,
                timestamp: _nowIso(),
            });

            try { _ws.close(); } catch {}
            return;
        }

        _sendRaw("ping", {
            timestamp: _nowIso(),
        });
    }, WS_CONFIG.HEARTBEAT_MS);
}

function _stopHeartbeat() {
    if (_heartbeatTimer) {
        clearInterval(_heartbeatTimer);
        _heartbeatTimer = null;
    }
}

/* =============================================================================
   Reconnect
   ============================================================================= */

function _clearReconnectTimer() {
    if (_reconnectTimer) {
        clearTimeout(_reconnectTimer);
        _reconnectTimer = null;
    }
}

function _reconnectDelay() {
    const base = Math.min(
        WS_CONFIG.RECONNECT_MAX_MS,
        WS_CONFIG.RECONNECT_MS * Math.pow(2, _reconnectAttempts)
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
        timestamp: _nowIso(),
    });

    _reconnectTimer = setTimeout(() => {
        _reconnectTimer = null;

        if (!_manuallyClosed && !document.hidden) {
            connect();
        }
    }, delay);
}

/* =============================================================================
   Message Handling
   ============================================================================= */

function _handleAuthRequired() {
    _dispatch("sentinel:ws:auth_required", {
        timestamp: _nowIso(),
    });

    _sendAuthFrame();
}

function _markConnected(parsed) {
    _authenticated = true;
    _connected = true;
    _lastMessageAt = Date.now();

    _startHeartbeat();
    _subscribeConfiguredChannels();

    _dispatchMessage(parsed);
}

function _handleMessage(event) {
    _lastMessageAt = Date.now();

    let parsed;
    try {
        parsed = _validateFrame(event.data);
    } catch (err) {
        _dispatch("sentinel:ws:frame_error", {
            error: err.message,
            timestamp: _nowIso(),
        });
        return;
    }

    switch (parsed.type) {
        case "auth_required":
            _handleAuthRequired();
            return;

        case "authenticated":
        case "auth_ok":
        case "connected":
            _markConnected(parsed);
            return;

        case "pong":
            _lastMessageAt = Date.now();
            return;

        case "error":
            _dispatch("sentinel:ws:server_error", {
                error: parsed.payload?.error ?? parsed.payload?.detail ?? "WebSocket server error",
                payload: parsed.payload,
                timestamp: _nowIso(),
            });
            _dispatchMessage(parsed);
            return;

        default:
            _dispatchMessage(parsed);
            return;
    }
}

/* =============================================================================
   Connection Lifecycle
   ============================================================================= */

function connect() {
    if (document.hidden) return;

    if (_ws && [WebSocket.OPEN, WebSocket.CONNECTING].includes(_ws.readyState)) {
        return;
    }

    _clearReconnectTimer();
    _manuallyClosed = false;
    _resetConnectionState();

    let url;
    try {
        url = _safeWsUrl();
    } catch (err) {
        _dispatch("sentinel:ws:error", {
            error: err.message,
            timestamp: _nowIso(),
        });
        return;
    }

    _dispatch("sentinel:ws:connecting", {
        url,
        timestamp: _nowIso(),
    });

    try {
        _ws = new WebSocket(url);
    } catch (err) {
        _dispatch("sentinel:ws:error", {
            error: `WebSocket construction failed: ${err.message}`,
            timestamp: _nowIso(),
        });
        _scheduleReconnect();
        return;
    }

    _ws.addEventListener("open", () => {
        _socketOpen = true;
        _reconnectAttempts = 0;
        _lastMessageAt = Date.now();

        _dispatch("sentinel:ws:open", {
            timestamp: _nowIso(),
        });

        /*
           Critical rule:
           If we send anything immediately after open, it must be auth.
           No subscribe. No ping. No dashboard hello. No vibes.
        */
        if (WS_CONFIG.AUTH_FIRST_WHEN_TOKEN_PRESENT && _getDevToken()) {
            _sendAuthFrame();
        }
    });

    _ws.addEventListener("message", _handleMessage);

    _ws.addEventListener("close", event => {
        const wasManual = _manuallyClosed;

        _stopHeartbeat();
        _resetConnectionState();
        _ws = null;

        _dispatch("sentinel:ws:close", {
            code: event.code,
            reason: event.reason || "",
            clean: event.wasClean,
            timestamp: _nowIso(),
        });

        if (!wasManual && !document.hidden) {
            _scheduleReconnect();
        }
    });

    _ws.addEventListener("error", () => {
        _dispatch("sentinel:ws:error", {
            error: "WebSocket transport error",
            timestamp: _nowIso(),
        });
    });
}

function disconnect() {
    _manuallyClosed = true;
    _clearReconnectTimer();
    _stopHeartbeat();

    if (_ws) {
        try { _ws.close(); } catch {}
        _ws = null;
    }

    _resetConnectionState();

    _dispatch("sentinel:ws:disconnected", {
        timestamp: _nowIso(),
    });
}

/* =============================================================================
   Public Send Helper
   ============================================================================= */

function send(type, payload = {}) {
    if (!_canSend()) {
        _dispatch("sentinel:ws:error", {
            error: "Cannot send: socket is not open",
            timestamp: _nowIso(),
        });
        return false;
    }

    if (!_connected && type !== "auth") {
        _dispatch("sentinel:ws:error", {
            error: `Cannot send '${type}' before WebSocket authentication/connection is complete.`,
            timestamp: _nowIso(),
        });
        return false;
    }

    return _sendRaw(type, payload);
}

/* =============================================================================
   Page Visibility
   ============================================================================= */

document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
        disconnect();
        return;
    }

    _manuallyClosed = false;
    connect();
});

/* =============================================================================
   Unload Cleanup
   ============================================================================= */

window.addEventListener("beforeunload", disconnect);

/* =============================================================================
   Public API
   ============================================================================= */

window.SentinelWS = Object.freeze({
    connect,
    disconnect,
    send,

    subscribe() {
        return _subscribeConfiguredChannels();
    },

    auth() {
        return _sendAuthFrame();
    },

    get socketOpen() {
        return _socketOpen && _ws?.readyState === WebSocket.OPEN;
    },

    get authenticated() {
        return _authenticated;
    },

    get connected() {
        return _connected && _ws?.readyState === WebSocket.OPEN;
    },

    get subscribed() {
        return _subscribed;
    },

    get reconnectAttempts() {
        return _reconnectAttempts;
    },

    get lastMessageAt() {
        return _lastMessageAt;
    },
});

/* =============================================================================
   Auto-connect
   ============================================================================= */

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", connect);
} else {
    connect();
}