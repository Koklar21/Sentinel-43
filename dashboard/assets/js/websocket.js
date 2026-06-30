/* =============================================================================
   Sentinel-43 Dashboard
   websocket.js — Hardened WebSocket bridge
   v1.5.7
   Changes from v1.5.6:
     - Fix: the real session token written by auth.js to
       sessionStorage["SENTINEL_JWT"] after a successful login was being
       gated by ALLOW_DEV_TOKEN (local-hostname-only). That gate was meant
       for legacy/dev fallback keys, not the canonical login token — but
       _getDevToken() was the ONLY function reading any token, dev or real,
       and it refused to look at sessionStorage at all on non-local
       hostnames. Any beta tester not on localhost/127.0.0.1/::1 could log
       in successfully via auth.js and still never get a WebSocket
       connection: the client simply never sent a token. Split into
       _getAuthToken(): always reads SENTINEL_JWT regardless of hostname,
       then falls back to the local-only legacy key scan if that's empty.
       Renamed _getDevToken() -> _getAuthToken() throughout (private,
       no external API change).
     - Fix: double-auth-frame race. On socket open, if a token is present,
       the client proactively sends an auth frame. Separately, the message
       handler unconditionally called _sendAuthFrame() again whenever the
       server's auth_required frame arrived — with no guard against having
       already sent one. The server sends auth_required regardless of
       whether it already received the proactive frame, so in the common
       case both fired: a second "auth" frame landed in the server's main
       message loop (post-auth), which doesn't recognize "auth" as an
       event type there and returned an "Unsupported event" error frame
       right after every successful connect. Harmless to the connection,
       but this is the exact "double-auth race" this file's own comments
       warn dashboard.js not to cause — happening here instead. Added an
       _authSent flag, set on successful send, checked before resending,
       reset on _resetConnectionState().
     - Fix: sentinel:ws:error event name collision. _dispatchMessage()
       dispatches sentinel:ws:${parsed.type} for every server frame, so a
       server-sent {"type":"error",...} frame fired sentinel:ws:error with
       shape {type, payload}. That event name is also used throughout this
       file for client-side failures (_sendRaw, _safeWsUrl, WebSocket
       construction, transport errors) with an incompatible shape:
       {error, timestamp}. Any single listener on sentinel:ws:error had to
       handle two different payload shapes under one name. The "error"
       case now dispatches sentinel:ws:message generically but skips the
       colliding type-specific dispatch; sentinel:ws:server_error remains
       the dedicated, consistently-shaped event for server-originated
       error frames.
   Changes from v1.5.5:
     - Added: explicit proxy_event handler in _handleMessage. Dispatches
       sentinel:ws:proxy_event with { event, timestamp } detail so dashboard.js
       can listen for a clean, stable event name rather than parsing raw frames
       from the generic sentinel:ws:message handler.
     - Added: subscribeChannel(channel) to the public API for targeted
       single-channel subscription. Useful in dev console and for components
       that need one channel without triggering a full re-subscribe.
   Changes from v1.5.4:
     - Added: "proxy" to CHANNELS so the dashboard auto-subscribes to the
       proxy event feed on connect. Required for POST /events/proxy broadcasts
       to reach connected dashboard clients.
   Changes from v1.5.3:
     - Fix: _autoConnect() now awaits window.SentinelAuthReady before
       connecting, so auth.js token verification completes before websocket.js
       auto-connects. Without this, a stored-but-expired token could cause
       websocket.js to attempt auth before auth.js had a chance to clear it.
     - Fix: _sendRaw() outgoing byte check now uses TextEncoder for accurate
       UTF-8 byte counting, matching the inbound _validateFrame() check.
       The previous serialized.length check undercounted multi-byte payloads.
   Changes from v1.5.2:
     - Fix: double comma (,,) after CHANNELS Object.freeze([...]) removed.
       The extra comma was a SyntaxError that prevented the entire module from
       parsing. window.SentinelWS was never defined, connect() was never
       called, and no WebSocket connection was ever established. The dashboard
       fell back silently to HTTP polling only.
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
     - Fix: no longer reconnects on close code 1008 (auth failure) or 1003
       (unsupported data).
     - Fix: page-hide no longer disconnects.
     - Fix: outgoing frame size cap added to _sendRaw().
     - Fix: incoming message rate limiter.
     - Fix: _getDevToken() called only once per connection open.
     - Added: governance, watchtower, dependencies channels to CHANNELS.
     - Added: explicit handlers for governance_pending_snapshot,
       watchtower_state, and dependency_state message types.
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
       (See v1.5.7 changelog above: this file was itself causing that race
       internally; _authSent now prevents it regardless of arrival order.)
   Watchtower note:
     - The server broadcasts watchtower_state over WebSocket with heartbeat
       data only: { reachable, url, timestamp }. No Octagon tower data comes
       through WebSocket. The full tower grid is populated exclusively by the
       HTTP probe in dashboard.js (fetchWatchtower → GET /watchtower/status).
       The watchtower_state WS handler updates the header chip only.
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
    // Gates the LEGACY/DEV fallback key scan only. The real session token
    // (SENTINEL_JWT, written by auth.js on login) is always readable
    // regardless of hostname — see _getAuthToken(). This flag never gates
    // the production login path; gating it there was the v1.5.6 bug.
    ALLOW_DEV_TOKEN: _locationIsLocal,
    // If true, client sends auth immediately on open when a token exists.
    AUTH_FIRST_WHEN_TOKEN_PRESENT: true,
    // Active hunting context — keep the connection alive in background tabs
    // so operators receive alerts even when the dashboard is not focused.
    // Set to true to restore v1.4.0 behaviour (disconnect on page hide).
    DISCONNECT_ON_PAGE_HIDE: false,
    // Close codes that must NOT trigger a reconnect attempt. 1008 is what
    // main.py sends on auth failure; reconnecting just repeats the same
    // rejected-token cycle indefinitely until the 30s cap is hit every time.
    NO_RECONNECT_CODES: Object.freeze(new Set([
        1008,   // Policy violation (auth failure)
        1003,   // Unsupported data (server rejects message type)
        1011,   // Server error — reconnecting won't fix a server-side crash
    ])),
    // Incoming rate limiter. Excess messages are dropped and a throttle
    // event is dispatched so the UI can display a warning.
    MAX_MSGS_PER_SECOND: 30,
    // Full channel set. "proxy" added in v1.5.5 to receive local proxy
    // traffic events broadcast by POST /events/proxy.
    CHANNELS: Object.freeze([
        "actions",
        "vault",
        "governance",
        "watchtower",
        "dependencies",
        "security",
        "proxy",
    ]),
});

/* =============================================================================
   Token Lookup
   ============================================================================= */
// Canonical session token key. This is the ONE auth.js writes to
// sessionStorage on a successful login, and is always checked regardless
// of hostname — it is the production auth path, not a dev convenience.
const SESSION_TOKEN_KEY = "SENTINEL_JWT";

// Legacy/dev fallback keys only. Kept in sync with dashboard.js DEV_JWT_KEYS
// minus SESSION_TOKEN_KEY, which now has its own always-on check above.
// These remain gated to local hostnames — they are guesswork convenience
// lookups for testing without going through the real login flow, not a
// second production path.
const _DEV_JWT_KEYS = Object.freeze([
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
let _authSent          = false;
let _reconnectAttempts = 0;
let _reconnectTimer    = null;
let _heartbeatTimer    = null;
let _lastMessageAt     = 0;

// Incoming rate limiter state.
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

// Generic-stream-only dispatch — used where the type-specific event name
// would collide with an existing, differently-shaped event (see the
// "error" case in _handleMessage and the v1.5.7 changelog above).
function _dispatchGenericOnly(parsed) {
    _dispatch("sentinel:ws:message", parsed);
}

// Always-on read of the real session token, then a local-only fallback
// scan of legacy/dev key names. Called once per connection open; token
// captured in a local variable by the caller.
function _getAuthToken() {
    try {
        const sessionToken = sessionStorage.getItem(SESSION_TOKEN_KEY);
        if (sessionToken && sessionToken.trim()) return sessionToken.trim();
    } catch {}

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
    _authSent      = false;
    _lastMessageAt = 0;
}

/* =============================================================================
   Incoming Rate Limiter
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
    // Enforce outgoing frame size limit matching the server's incoming cap.
    // Use TextEncoder for accurate UTF-8 byte counting, matching _validateFrame().
    // serialized.length undercounts multi-byte characters (e.g. emoji, CJK).
    if (_WS_TEXT_ENCODER.encode(serialized).length > WS_CONFIG.MAX_FRAME_BYTES) {
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
        // Mark as manually closed BEFORE calling close() so the close event
        // handler sees _manuallyClosed=true and skips _scheduleReconnect().
        // Without this, socket closes with code 1000 (not in NO_RECONNECT_CODES)
        // and the reconnect loop fires immediately — pointless with no token.
        _manuallyClosed = true;
        if (_ws) {
            try { _ws.close(); } catch {}
        }
        return false;
    }
    if (_authSent) {
        // Already sent an auth frame this connection (proactive-on-open path
        // and the server's auth_required handler can both reach this point
        // depending on timing). Sending a second one lands in the server's
        // post-auth message loop, which doesn't recognize "auth" there and
        // returns an "Unsupported event" error — harmless, but pointless
        // and confusing in logs. See v1.5.7 changelog.
        return true;
    }
    const ok = _sendRaw("auth", { token });
    if (ok) {
        _authSent = true;
        _dispatch("sentinel:ws:auth_sent", { timestamp: _nowIso() });
    }
    return ok;
}

function _subscribeConfiguredChannels() {
    if (!_canSend()) return false;
    if (_subscribed) return true;
    // Must be authenticated before subscribing. The server enforces this;
    // subscribing before auth accepted produces an immediate rejection.
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
    _sendAuthFrame(_getAuthToken());
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
    // Rate limiter — drop excess frames before any parsing work.
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
            // Dedicated, consistently-shaped event for server-originated
            // errors. Deliberately does NOT use _dispatchMessage() here —
            // that would also fire sentinel:ws:error (parsed.type === "error"),
            // colliding with the differently-shaped client-side error event
            // of the same name used everywhere else in this file. See the
            // v1.5.7 changelog above.
            _dispatch("sentinel:ws:server_error", {
                error: parsed.payload?.error ?? parsed.payload?.detail ?? "WebSocket server error",
                payload: parsed.payload,
                timestamp: _nowIso(),
            });
            _dispatchGenericOnly(parsed);
            return;
        // Governance: HUMAN_GATED pending decision queue snapshot.
        case "governance_pending_snapshot":
            _dispatch("sentinel:ws:governance_pending", {
                pending: parsed.payload?.pending ?? [],
                timestamp: _nowIso(),
            });
            _dispatchMessage(parsed);
            return;
        // Watchtower heartbeat: { reachable, url, timestamp } only.
        // No Octagon tower data comes through WebSocket. The full tower grid
        // is populated by the HTTP probe in dashboard.js (fetchWatchtower).
        // dashboard.js sentinel:ws:message handler updates the header chip.
        case "watchtower_state":
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
        // Proxy traffic event from POST /events/proxy.
        // Dispatches sentinel:ws:proxy_event with a clean { event, timestamp }
        // detail so dashboard.js can bind directly without parsing raw frames.
        case "proxy_event":
            _dispatch("sentinel:ws:proxy_event", {
                event: parsed.payload ?? {},
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
        // Proactively send auth before the server asks for it. Token read once
        // here using the expanded _getAuthToken() lookup. If not found, the
        // server will send auth_required and _handleAuthRequired() retries.
        if (WS_CONFIG.AUTH_FIRST_WHEN_TOKEN_PRESENT) {
            const token = _getAuthToken();
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
    subscribeChannel(channel) {
        const safeChannel = String(channel || "").trim().slice(0, 64);
        if (!safeChannel) return false;
        return send("subscribe", { channel: safeChannel });
    },
    auth() {
        return _sendAuthFrame(_getAuthToken());
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
   Awaits window.SentinelAuthReady (set by auth.js) before connecting so that
   auth.js token verification completes first. If auth.js is not present,
   SentinelAuthReady is undefined; Promise.resolve(undefined) falls through
   immediately — no hard dependency on auth.js being loaded.
   ============================================================================= */
async function _autoConnect() {
    try { await window.SentinelAuthReady; } catch {}
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", connect);
    } else {
        connect();
    }
}

_autoConnect();
