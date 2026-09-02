/* =============================================================================
   Sentinel-43 Dashboard
   websocket.js — Hardened WebSocket bridge
   v1.7.0

   Changes from v1.6.0 (beta-execution Phase 3):
   - The auth frame is {token} only when auth.js holds no in-memory password
     (the session-bound / refresh-on-reload path). {token,password} is still
     sent when a password IS held (legacy env-operator / dual contract). A
     missing password is no longer a hard failure.
   - The backend now passes a meaningful `reason` on every 1008 close
     (invalid_token / invalid_password / session_revoked / token_expired /
     origin_rejected / capacity), so _reasonIndicatesAuthFailure() actually
     classifies auth failures — the backend companion change this file's
     v1.6.0 changelog asked for has landed.

   RECONSTRUCTION NOTE: this file was recovered from a paste that had
   stripped the backticks from every template literal. Backticks have been
   restored based on context. Diff against your real working copy and run
   the linter/test suite before trusting this in production.

   Changes from v1.5.8:
   - Added: _isSecureOrLocalSocket() — refuses to send credentials over a
     plaintext ws:// connection except on an explicit local dev host.
     _safeWsUrl() only enforced wss:// when the PAGE itself is https://;
     if the dashboard is ever misconfigured to serve over plain http:// in
     production, that check alone would not stop a real password going out
     in cleartext over ws://. Checked inside _sendAuthFrame() before the
     password is read.
   - Changed: NO_RECONNECT_CODES no longer includes 1011. A server error
     may be transient and should be allowed to reconnect with the existing
     backoff rather than permanently disconnecting a security-monitoring
     dashboard until manual page refresh.
   - Added: _reasonIndicatesAuthFailure() classifies a 1008 close as
     auth-related vs a generic policy violation by matching event.reason.
     REQUIRES A BACKEND CHANGE: main.py's _ws_safe_close() must be updated
     to pass a meaningful `reason` string at every rejection call site
     (e.g. "invalid_token", "invalid_password" vs "origin_rejected",
     "capacity"). Without that backend change, event.reason is always
     empty and every 1008 close will classify as policy_error, never
     auth_failed — operators will stop being prompted to re-authenticate
     after a real auth rejection. Confirm the backend companion change has
     landed before relying on this classification.
   - Changed: close-handler now dispatches sentinel:ws:policy_error (1008,
     non-auth reason), sentinel:ws:protocol_error (1003), and
     sentinel:ws:server_error (1011, now with reconnect) as distinct
     events instead of conflating all three into "no reconnect, force
     re-auth."
   - Changed: auth frame now also carries the operator's password (read
     via window.SentinelAuth.getPassword(), which as of auth.js v1.6.0
     returns an in-memory-only value, never sessionStorage), matching the
     backend's per-request password re-verification. A JWT with no stored
     password fails the same way a missing JWT does — auth_failed is
     dispatched and the socket closes without reconnecting.

   Changes from v1.5.6 (prior):
   - Fix: the real session token written by auth.js to
     sessionStorage["SENTINEL_JWT"] after a successful login was being
     gated by ALLOW_DEV_TOKEN (local-hostname-only). Split into
     _getAuthToken(): always reads SENTINEL_JWT regardless of hostname,
     then falls back to the local-only legacy key scan if that's empty.
   - Fix: double-auth-frame race — added _authSent flag.
   - Fix: sentinel:ws:error event name collision between client-side
     transport errors and server-sent {"type":"error"} frames. The "error"
     case now dispatches sentinel:ws:message generically and
     sentinel:ws:server_error specifically, skipping the colliding
     type-specific dispatch.

   Changes from v1.5.5 (prior):
   - Added: explicit proxy_event handler.
   - Added: subscribeChannel(channel) to the public API.

   Changes from v1.5.4 (prior):
   - Added: "proxy" to CHANNELS.

   Changes from v1.5.3 (prior):
   - Fix: _autoConnect() now awaits window.SentinelAuthReady before connecting.
   - Fix: _sendRaw() outgoing byte check now uses TextEncoder.

   Changes from v1.5.2 (prior):
   - Fix: double comma syntax error that prevented the entire module from
     parsing, silently falling back to HTTP polling only.
   - Fix: _sendAuthFrame() sets _manuallyClosed = true before closing when
     no token is found, to avoid a tight reconnect loop.

   Changes from v1.5.0 (prior):
   - Fix: _getDevToken() searches the same key set as dashboard.js.
   - Fix: no longer reconnects on 1008/1003 (now revised further above).
   - Fix: page-hide no longer disconnects.
   - Fix: outgoing frame size cap, incoming rate limiter.

   Protocol:
   - Backend may send: auth_required
   - Client must answer first with: {"type":"auth","payload":{"token":"...","password":"..."}}
   - Client must NOT subscribe before auth is accepted.
   - After authenticated/connected, subscribe to configured channels.

   Auth ownership:
   - websocket.js owns all auth mechanics. dashboard.js must NOT send a
     second auth frame in response to sentinel:ws:auth_required.

   Watchtower note:
   - The server broadcasts watchtower_state over WebSocket with heartbeat
     data only: { reachable, url, timestamp }. The full tower grid is
     populated exclusively by the HTTP probe in dashboard.js.

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
    MAX_FRAME_BYTES: 64 * 1_024,
    // Gates the LEGACY/DEV fallback key scan only. The real session token
    // (SENTINEL_JWT, written by auth.js on login) is always readable
    // regardless of hostname — see _getAuthToken().
    ALLOW_DEV_TOKEN: _locationIsLocal,
    AUTH_FIRST_WHEN_TOKEN_PRESENT: true,
    // Keep the connection alive in background tabs so operators receive
    // alerts even when the dashboard is not focused.
    DISCONNECT_ON_PAGE_HIDE: false,
    // Close codes that must NOT trigger a reconnect attempt. 1011 was
    // removed — see changelog: a transient server error should still
    // attempt reconnect with backoff.
    NO_RECONNECT_CODES: Object.freeze(new Set([
        1008, // Policy violation; inspect reason before calling it auth failure.
        1003, // Unsupported data/protocol.
    ])),
    MAX_MSGS_PER_SECOND: 30,
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
const SESSION_TOKEN_KEY = "SENTINEL_JWT";

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

function _dispatchGenericOnly(parsed) {
    _dispatch("sentinel:ws:message", parsed);
}

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

// Password lookup — mirrors _getAuthToken() but reads the credential
// auth.js stores alongside the JWT. The server requires both on every WS
// auth frame; a JWT alone 401s.
function _getAuthPassword() {
    try {
        return window.SentinelAuth?.getPassword?.() ?? null;
    } catch {
        return null;
    }
}

// Refuses to send credentials over a plaintext ws:// connection except on
// an explicit local dev host. _safeWsUrl() only enforces wss:// when the
// PAGE is https:// — if the dashboard is ever misconfigured to serve over
// plain http:// in production, that check alone would not stop a real
// password going out in cleartext over ws://.
function _isSecureOrLocalSocket() {
    if (!_ws || !_ws.url) return false;
    if (_ws.url.startsWith("wss://")) return true;
    return _locationIsLocal;
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
    if (raw.length > WS_CONFIG.MAX_FRAME_BYTES) {
        throw new Error(`WebSocket frame exceeds ${WS_CONFIG.MAX_FRAME_BYTES} bytes`);
    }
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
        _manuallyClosed = true;
        if (_ws) {
            try { _ws.close(); } catch {}
        }
        return false;
    }

    if (!_isSecureOrLocalSocket()) {
        _dispatch("sentinel:ws:auth_failed", {
            error: "Refusing to send credentials over an insecure, non-local WebSocket connection.",
            timestamp: _nowIso(),
        });
        _manuallyClosed = true;
        if (_ws) {
            try { _ws.close(); } catch {}
        }
        return false;
    }

    if (_authSent) {
        return true;
    }
    // Session-bound access tokens (the browser-session redesign) authenticate
    // on their own — the auth frame is {token} only. The password is included
    // only when auth.js still holds one (the legacy env-operator / dual
    // contract path); a session-bound connection never needs it.
    const password = _getAuthPassword();
    const frame = password ? { token, password } : { token };
    const ok = _sendRaw("auth", frame);
    if (ok) {
        _authSent = true;
        _dispatch("sentinel:ws:auth_sent", { timestamp: _nowIso() });
    }
    return ok;
}

function _subscribeConfiguredChannels() {
    if (!_canSend()) return false;
    if (_subscribed) return true;
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
            _dispatchGenericOnly(parsed);
            return;
        case "governance_pending_snapshot":
            _dispatch("sentinel:ws:governance_pending", {
                pending: parsed.payload?.pending ?? [],
                timestamp: _nowIso(),
            });
            _dispatchMessage(parsed);
            return;
        case "watchtower_state":
            _dispatchMessage(parsed);
            return;
        case "dependency_state":
            _dispatch("sentinel:ws:dependency_state", {
                name: parsed.payload?.name ?? "unknown",
                status: parsed.payload?.status ?? "unknown",
                timestamp: _nowIso(),
            });
            _dispatchMessage(parsed);
            return;
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

        if (closeCode === 1008) {
            if (_reasonIndicatesAuthFailure(event.reason)) {
                _dispatch("sentinel:ws:auth_failed", {
                    code: closeCode,
                    reason: event.reason || "Authentication rejected",
                    message: "Re-authentication required.",
                    timestamp: _nowIso(),
                });
            } else {
                _dispatch("sentinel:ws:policy_error", {
                    code: closeCode,
                    reason: event.reason || "WebSocket policy violation",
                    timestamp: _nowIso(),
                });
            }
            return;
        }

        if (closeCode === 1003) {
            _dispatch("sentinel:ws:protocol_error", {
                code: closeCode,
                reason: event.reason || "Unsupported WebSocket message or data",
                timestamp: _nowIso(),
            });
            return;
        }

        if (closeCode === 1011) {
            _dispatch("sentinel:ws:server_error", {
                error: event.reason || "WebSocket server error",
                code: closeCode,
                timestamp: _nowIso(),
            });
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

// Classifies a 1008 close as auth-related vs a generic policy violation
// by matching event.reason. REQUIRES a backend change to main.py's
// _ws_safe_close() to pass a meaningful reason string — see module
// changelog above. Without that, this always returns false (event.reason
// is empty) and every 1008 is treated as a generic policy_error.
function _reasonIndicatesAuthFailure(reason) {
    return /auth|token|password|credential|session|login/i.test(String(reason || ""));
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
   auth.js token verification completes first.
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
