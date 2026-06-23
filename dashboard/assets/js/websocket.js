/* =============================================================================
   Sentinel-43 Dashboard
   websocket.js — Hardened WebSocket bridge
   v1.5.2

   Changes from v1.5.1:
     - Fix: _sendAuthFrame() now sets _manuallyClosed = true before closing
       the socket when no token is found. Previously the socket closed with
       code 1000 (normal closure), which is not in NO_RECONNECT_CODES, so
       _scheduleReconnect() fired and produced a tight connect → auth_required
       → no token → close → reconnect loop. Reconnecting without a token is
       pointless; marking the close as manual stops it immediately and lets
       the sentinel:ws:auth_failed event prompt the operator to set a JWT.

   Changes from v1.5.0:
     - Fix: _getDevToken() now searches the same key set as dashboard.js
       (DEV_JWT_KEYS across sessionStorage, localStorage, and window globals).
       Previously only sessionStorage["SENTINEL_JWT"] was checked; tokens
       stored under any other key were invisible to the auth path, causing
       websocket.js to fail the proactive auth-on-open and then re-dispatch
       auth_required to dashboard.js which could also not find the token via
       SentinelWS.auth(). Both sides now see the same token regardless of
       which key or storage mechanism the operator used.

   Changes from v1.4.0 (carried forward from v1.5.0):
     - Fix: no longer reconnects on close code 1008 (auth failure) or 1003
       (unsupported data). These codes mean the server rejected the client;
       reconnecting just repeats the same failure. The client now stops and
       dispatches sentinel:ws:auth_failed so the UI can prompt for re-login.
     - Fix: page-hide no longer disconnects. For an active security hunting
       platform, the operator must receive alerts even when the dashboard is
       in a background tab. Disable RECONNECT_WHEN_VISIBLE if you want the
       old aggressive-disconnect behaviour.
     - Fix: outgoing frame size cap added to _sendRaw(). The server enforces
       64 KB on incoming frames; the client now mirrors that guard before send.
     - Fix: incoming message rate limiter. Server floods (or misbehaving
       connections) no longer exhaust the event loop. MAX_MSGS_PER_SECOND
       frames pass; excess frames are counted and a throttle event dispatched.
     - Fix: _getDevToken() called only once per connection open — token is
       captured in a local variable rather than read from sessionStorage twice.
     - Added: governance, watchtower, dependencies channels to CHANNELS so the
       dashboard receives HUMAN_GATED decision queues, Watchtower state
       transitions, and dependency health events produced by the recoded main.py.
     - Added: explicit handlers for governance_pending_snapshot,
       watchtower_state, and dependency_state message types.
     - Minor: raw.length fast-path in _validateFrame labelled with a comment.

   Protocol:
     - Backend may send: auth_required
     - Client must answer first with: {"type":"auth","payload":{"token":"..."}}
     - Client must NOT subscribe before auth is accepted.
     - After authenticated/connected, subscribe to configured channels.

   Auth ownership:
     - websocket.js owns all auth mechanics. On open it proactively sends an
       auth frame if a token is available (AUTH_FIRST_WHEN_TOKEN_PRESENT).
       If the server still sends auth_required, it responds internally and
       also dispatches sentinel:ws:auth_required as a notification so dashboard
       layers can update their UI. dashboard.js must NOT send a second auth
       frame in response to that event — doing so causes a double-auth race.

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

    RECONNECT_MS:     1_000,
    RECONNECT_MAX_MS: 30_000,

    HEARTBEAT_MS: 25_000,

    // Shared 64 KB limit with the server (main.py MAX_WS_FRAME_BYTES).
    MAX_FRAME_BYTES: 64 * 1_024,

    // Dev token is only read from storage on local hostnames.
    ALLOW_DEV_TOKEN: _locationIsLocal,

    // If true, client sends auth immediately on open when a token exists.
    AUTH_FIRST_WHEN_TOKEN_PRESENT: true,

    // Fix: active hunting context — keep the connection alive in background
    // tabs so operators receive alerts even when the dashboard is not focused.
    // Set to true to restore v1.4.0 behaviour (disconnect on page hide).
    DISCONNECT_ON_PAGE_HIDE: false,

    // Fix: close codes that must NOT trigger a reconnect attempt. 1008 is
    // what main.py sends on auth failure; reconnecting just repeats the same
    // rejected-token cycle indefinitely until the 30s cap is hit every time.
    NO_RECONNECT_CODES: Object.freeze(new Set([
        1008,   // Policy violation (auth failure)
        1003,   // Unsupported data (server rejects message type)
        1011,   // Server error — reconnecting won't fix a server-side crash
    ])),

    // Fix: incoming rate limiter. Excess messages are dropped and a throttle
    // event is dispatched so the UI can display a warning.
    MAX_MSGS_PER_SECOND: 30,

    // Full channel set matching main.py subscriptions including governance
    // (HUMAN_GATED decision queue) and Fenrir hunting event channels.
    CHANNELS: Object.freeze([
    "actions",
    "vault",
    "governance",
    "watchtower",
    "dependencies",
    "security",
]),,
});

/* =============================================================================
   Token Lookup
   ============================================================================= */

// Fix v1.5.1: key list must stay in sync with dashboard.js DEV_JWT_KEYS so
// that any token the UI layer can find is also visible to the auth path here.
// Tokens stored under any other key were previously invisible to this module.
const _DEV_JWT_KEYS = Object.freeze([
    "SENTINEL_JWT",
    "S43_JWT",
    "S43_TOKEN",
    "s43_token",
    "s43_dashboard_token",
    "sentinel_token",
    "jwt",
    "token",
]);

/* =============================================================================
   Module State
   ============================================================================= */

const _WS_TEXT_ENCODER = new TextEncoder();

let _ws = null;

let _socketOpen    = false;
let _authenticated = false;
let _connected     = false;
let _subscribed    = false;

let _manuallyClosed    = false;
let _reconnectAttempts = 0;
let _reconnectTimer    = null;
let _heartbeatTimer    = null;
let _lastMessageAt     = 0;

// Fix: incoming rate limiter state.
let _msgCountThisSecond = 0;
let _msgRateTick = null;

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

// Fix v1.5.1: expanded token lookup. Checks sessionStorage first (shorter-
// lived, more appropriate for session tokens), then localStorage for tokens
// persisted across sessions, then window globals set by server-rendered pages.
function _getDevToken() {
    if (!WS_CONFIG.ALLOW_DEV_TOKEN) return null;

    for (const key of _DEV_JWT_KEYS) {
        try {
            const value = sessionStorage.getItem(key);
            if (value && value.trim()) return value.trim();
        } catch {}
    }

    for (const key of _DEV_JWT_KEYS) {
        try {
            const value = localStorage.getItem(key);
            if (value && value.trim()) return value.trim();
        } catch {}
    }

    try {
        if (typeof window.SENTINEL_JWT === "string" && window.SENTINEL_JWT.trim())
            return window.SENTINEL_JWT.trim();
        if (typeof window.S43_DASHBOARD_TOKEN === "string" && window.S43_DASHBOARD_TOKEN.trim())
            return window.S43_DASHBOARD_TOKEN.trim();
    } catch {}

    return null;
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
    _socketOpen    = false;
    _authenticated = false;
    _connected     = false;
    _subscribed    = false;
    _lastMessageAt = 0;
}

/* =============================================================================
   Incoming Rate Limiter (Fix)
   ============================================================================= */

function _startRateLimitTick() {
    if (_msgRateTick) return;
    _msgCountThisSecond = 0;
    _msgRateTick = setInterval(() => {
        _msgCountThisSecond = 0;
    }, 1_000);
}

function _stopRateLimitTick() {
    if (_msgRateTick) {
        clearInterval(_msgRateTick);
        _msgRateTick = null;
    }
    _msgCountThisSecond = 0;
}

function _isRateLimited() {
    _msgCountThisSecond += 1;
    if (_msgCountThisSecond > WS_CONFIG.MAX_MSGS_PER_SECOND) {
        _dispatch("sentinel:ws:throttled", {
            count: _msgCountThisSecond,
            limit: WS_CONFIG.MAX_MSGS_PER_SECOND,
            timestamp: _nowIso(),
        });
        return true;
    }
    return false;
}

/* =============================================================================
   Frame Validation
   ============================================================================= */

function _validateFrame(raw) {
    if (typeof raw !== "string") {
        throw new Error("WebSocket frame must be a text message");
    }

    // Fast-path: if the JS string length already exceeds the byte cap, we know
    // the UTF-8 byte count will too (UTF-8 bytes >= UTF-16 code units always).
    // This avoids the encode() call for obviously-oversized frames.
    if (raw.length > WS_CONFIG.MAX_FRAME_BYTES) {
        throw new Error(`WebSocket frame exceeds ${WS_CONFIG.MAX_FRAME_BYTES} bytes`);
    }

    // Accurate byte check for frames that might have multi-byte characters
    // within the code-unit budget but exceed the byte budget.
    if (_WS_TEXT_ENCODER.encode(raw).length > WS_CONFIG.MAX_FRAME_BYTES) {
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

    let serialized;
    try {
        serialized = JSON.stringify({ type, payload });
    } catch (err) {
        _dispatch("sentinel:ws:error", {
            error: `Frame serialization failed: ${err.message}`,
            timestamp: _nowIso(),
        });
        return false;
    }

    // Fix: enforce outgoing frame size limit matching the server's incoming cap.
    if (serialized.length > WS_CONFIG.MAX_FRAME_BYTES) {
        _dispatch("sentinel:ws:error", {
            error: `Outgoing frame for '${type}' exceeds ${WS_CONFIG.MAX_FRAME_BYTES} bytes and was not sent`,
            timestamp: _nowIso(),
        });
        return false;
    }

    try {
        _ws.send(serialized);
        return true;
    } catch (err) {
        _dispatch("sentinel:ws:error", {
            error: `Send failed: ${err.message}`,
            timestamp: _nowIso(),
        });
        return false;
    }
}

function _sendAuthFrame(token) {
    if (!token) {
        _dispatch("sentinel:ws:auth_failed", {
            error: "WebSocket authentication required, but no JWT was found.",
            timestamp: _nowIso(),
        });
        // Fix v1.5.2: mark as manually closed BEFORE calling close() so the
        // close event handler sees _manuallyClosed=true and skips
        // _scheduleReconnect(). Without this, the socket closes with code
        // 1000 (not in NO_RECONNECT_CODES) and the reconnect loop fires
        // immediately — pointless when there is no token to authenticate with.
        _manuallyClosed = true;
        if (_ws) {
            try { _ws.close(); } catch {}
        }
        return false;
    }

    const ok = _sendRaw("auth", { token });
    if (ok) {
        _dispatch("sentinel:ws:auth_sent", { timestamp: _nowIso() });
    }
    return ok;
}

function _subscribeConfiguredChannels() {
    if (!_canSend()) return false;
    if (_subscribed) return true;

    // Guard: must be authenticated before subscribing. The server enforces
    // this; subscribing before auth accepted produces an immediate rejection.
    if (!_connected) return false;

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
        if (!_canSend() || !_connected) return;

        if (Date.now() - _lastMessageAt > WS_CONFIG.HEARTBEAT_MS * 2) {
            _dispatch("sentinel:ws:stale", {
                silentMs: Date.now() - _lastMessageAt,
                timestamp: _nowIso(),
            });
            try { _ws.close(); } catch {}
            return;
        }

        _sendRaw("ping", { timestamp: _nowIso() });
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
    if (_manuallyClosed || _reconnectTimer) return;
    if (WS_CONFIG.DISCONNECT_ON_PAGE_HIDE && document.hidden) return;

    const delay = _reconnectDelay();
    _reconnectAttempts += 1;

    _dispatch("sentinel:ws:reconnecting", {
        attempt: _reconnectAttempts,
        delayMs: delay,
        timestamp: _nowIso(),
    });

    _reconnectTimer = setTimeout(() => {
        _reconnectTimer = null;
        if (!_manuallyClosed) connect();
    }, delay);
}

/* =============================================================================
   Message Handling
   ============================================================================= */

// Auth ownership note: this module owns the auth exchange entirely.
// It dispatches sentinel:ws:auth_required as a notification for UI layers
// but also immediately handles it internally. Consumers must NOT send a
// second auth frame in response — that causes a double-auth race.
function _handleAuthRequired() {
    _dispatch("sentinel:ws:auth_required", { timestamp: _nowIso() });
    _sendAuthFrame(_getDevToken());
}

function _markConnected(parsed) {
    _authenticated = true;
    _connected     = true;
    _lastMessageAt = Date.now();

    _startHeartbeat();
    _subscribeConfiguredChannels();
    _dispatchMessage(parsed);
}

function _handleMessage(event) {
    _lastMessageAt = Date.now();

    // Fix: rate limiter — drop excess frames before any parsing work.
    if (_isRateLimited()) return;

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

        // Governance: HUMAN_GATED pending decision queue snapshot.
        case "governance_pending_snapshot":
            _dispatch("sentinel:ws:governance_pending", {
                pending: parsed.payload?.pending ?? [],
                timestamp: _nowIso(),
            });
            _dispatchMessage(parsed);
            return;

        // Watchtower state transition (reachable / unreachable).
        case "watchtower_state":
            _dispatch("sentinel:ws:watchtower_state", {
                reachable: parsed.payload?.reachable ?? false,
                url: parsed.payload?.url ?? "",
                timestamp: _nowIso(),
            });
            _dispatchMessage(parsed);
            return;

        // Dependency health update (core, redis, postgres, etc.).
        case "dependency_state":
            _dispatch("sentinel:ws:dependency_state", {
                name: parsed.payload?.name ?? "unknown",
                status: parsed.payload?.status ?? "unknown",
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
    if (WS_CONFIG.DISCONNECT_ON_PAGE_HIDE && document.hidden) return;

    if (_ws && [WebSocket.OPEN, WebSocket.CONNECTING].includes(_ws.readyState)) {
        return;
    }

    _clearReconnectTimer();
    _manuallyClosed = false;
    _resetConnectionState();
    _startRateLimitTick();

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

    _dispatch("sentinel:ws:connecting", { url, timestamp: _nowIso() });

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
        _socketOpen        = true;
        _reconnectAttempts = 0;
        _lastMessageAt     = Date.now();

        _dispatch("sentinel:ws:open", { timestamp: _nowIso() });

        // Proactively send auth before the server asks for it. Reduces
        // round-trip latency on connect. Token is read once here using the
        // expanded _getDevToken() lookup (sessionStorage → localStorage →
        // window globals). If not found, the server will send auth_required
        // and _handleAuthRequired() will attempt the same lookup again.
        if (WS_CONFIG.AUTH_FIRST_WHEN_TOKEN_PRESENT) {
            const token = _getDevToken();
            if (token) {
                _sendAuthFrame(token);
            }
        }
    });

    _ws.addEventListener("message", _handleMessage);

    _ws.addEventListener("close", event => {
        const wasManual = _manuallyClosed;
        const closeCode = event.code;

        _stopHeartbeat();
        _stopRateLimitTick();
        _resetConnectionState();
        _ws = null;

        _dispatch("sentinel:ws:close", {
            code:   closeCode,
            reason: event.reason || "",
            clean:  event.wasClean,
            timestamp: _nowIso(),
        });

        if (WS_CONFIG.NO_RECONNECT_CODES.has(closeCode)) {
            _dispatch("sentinel:ws:auth_failed", {
                code:    closeCode,
                reason:  event.reason || "Connection rejected by server",
                message: "Re-authentication required. The server rejected this connection.",
                timestamp: _nowIso(),
            });
            return;
        }

        if (!wasManual) {
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
    _stopRateLimitTick();

    if (_ws) {
        try { _ws.close(); } catch {}
        _ws = null;
    }

    _resetConnectionState();
    _dispatch("sentinel:ws:disconnected", { timestamp: _nowIso() });
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
        if (WS_CONFIG.DISCONNECT_ON_PAGE_HIDE) {
            disconnect();
        }
        return;
    }

    if (!_ws || _ws.readyState === WebSocket.CLOSED) {
        _manuallyClosed = false;
        connect();
    }
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
        return _sendAuthFrame(_getDevToken());
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
