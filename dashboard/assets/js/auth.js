/* =============================================================================
   Sentinel-43 Dashboard
   auth.js — Operator login flow and JWT lifecycle
   v1.8.0

   Changes from v1.7.0 (next-PR Phase C — real-browser + same-origin beta):
   - The bearer access token is now held in module memory ONLY. It is no
     longer written to sessionStorage (init() refreshes it from the HttpOnly
     cookie on every load, so persistence bought nothing and was an XSS
     exfil target). Exposed as window.SentinelAuth.getToken() for
     websocket.js / dashboard.js; an old sessionStorage["SENTINEL_JWT"] is
     cleared on load.
   - No functional change to endpoints (still same-origin /auth/*).

   Changes from v1.6.0 (beta-execution Phase 3 — browser session):
   - Login now also gets an HttpOnly refresh cookie + a JS-readable CSRF
     cookie (s43_csrf) + a sid-bound 15-min access token for DB accounts
     (result.session_bound === true). X-S43-Password is no longer required
     on requests for a session-bound operator — the in-memory password is
     kept only as a fallback for the legacy env-operator (dual contract).
   - init() calls POST /auth/refresh on load: a reload no longer forces a
     fresh login for a DB-account operator (the refresh cookie is exchanged
     for a new access token). No session cookie / rejected refresh => the
     login overlay, as before.
   - logout() calls POST /auth/logout (CSRF double-submit) to revoke the
     server-side session before clearing local state.
   - New: refreshSession() on the public API.

   Changes from v1.5.1:
   - BREAKING (security): password is no longer persisted to sessionStorage
     at all. Held only in a module-scope variable (_sessionPassword). It
     disappears on refresh, navigation, tab close, logout, or auth failure.
     Removed: PASSWORD_KEY, the sessionStorage-backed getPassword/setPassword
     pair, VERIFY_ENDPOINT, VERIFY_TIMEOUT_MS, and verifyStoredToken()
     entirely — a token surviving a page refresh has no matching in-memory
     password and cannot drive any protected route under the current
     backend contract, so verifying it is pointless. A refresh now always
     requires a fresh login. Less convenient; does not leave a reusable
     password sitting in browser storage.
   - Login storage is now atomic: if either the token or the password fails
     to store, clearToken() rolls back whichever half succeeded rather than
     leaving an orphaned token with no password (a state that previously
     looked "logged in" in the UI but 401'd on every real request).
   - Added sentinel:auth:ready / sentinel:auth:locked lifecycle events so
     dashboard.js can gate all protected polling behind actual auth state
     instead of firing protected requests before login completes or after
     auth is lost.
   - applyManualCredentials(token, password) retained from v1.5.1 (the dev
     JWT-injection modal in dashboard.js depends on it), adapted to store
     the password via setSessionPassword() instead of the now-removed
     sessionStorage-backed setPassword().

   LOAD ORDER: auth.js MUST be included BEFORE websocket.js.
   websocket.js must await window.SentinelAuthReady before connecting.
   window.SentinelAuthReady does NOT resolve until auth is confirmed.
   ============================================================================= */

"use strict";

window.SentinelAuth = (() => {

/* =========================================================================
   Config
   ========================================================================= */

const LOGIN_ENDPOINT    = "/auth/login";
const REFRESH_ENDPOINT  = "/auth/refresh";
const LOGOUT_ENDPOINT   = "/auth/logout";
const CSRF_COOKIE       = "s43_csrf";
const CSRF_HEADER       = "X-S43-CSRF";
const TOKEN_KEY         = "SENTINEL_JWT";
const TOKEN_MIN_LEN     = 20;
const TOKEN_MAX_LEN     = 4096;
const USERNAME_MAX_LEN  = 128;
const PASSWORD_MAX_LEN  = 1024;
const LOGIN_TIMEOUT_MS  = 10_000;
const REFRESH_TIMEOUT_MS = 8_000;

function _readCookie(name) {
    const m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
    return m ? decodeURIComponent(m[1]) : null;
}

const JWT_SHAPE_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

let _resolveAuthReady;

// The backend requires the password alongside the JWT on every protected
// HTTP and WebSocket request. Kept in module memory ONLY — never written
// to sessionStorage/localStorage. Cleared on refresh, navigation, tab
// close, logout, or auth failure by construction (it's just a variable).
let _sessionPassword = null;

function _resetAuthReady() {
    window.SentinelAuthReady = new Promise(resolve => {
        _resolveAuthReady = resolve;
    });
}

function _markAuthReady() {
    if (typeof _resolveAuthReady === "function") {
        _resolveAuthReady();
        _resolveAuthReady = null;
    }
    window.dispatchEvent(new CustomEvent("sentinel:auth:ready"));
}

function _markAuthLocked(reason = "Authentication required") {
    window.dispatchEvent(new CustomEvent("sentinel:auth:locked", {
        detail: { reason },
    }));
}

_resetAuthReady();

/* =========================================================================
   Token / password storage
   ========================================================================= */

function _sessionStorageAvailable() {
    try {
        const k = "__s43_probe__";
        sessionStorage.setItem(k, "1");
        sessionStorage.removeItem(k);
        return true;
    } catch {
        return false;
    }
}

// The bearer access token lives in module memory ONLY -- never sessionStorage
// or localStorage. It is short-lived (15 min, sid-bound) and init() exchanges
// the HttpOnly refresh cookie for a fresh one on every page load, so there is
// nothing to gain by persisting it and a stored token is an XSS-exfiltration
// target. Cleared on refresh / navigation / tab close by construction.
let _accessToken = null;

// One-time cleanup of any token left in sessionStorage by an older build.
try { sessionStorage.removeItem(TOKEN_KEY); } catch {}

function getToken() {
    return typeof _accessToken === "string" && _accessToken ? _accessToken : null;
}

function setToken(token) {
    if (typeof token !== "string" || !token) return false;
    _accessToken = token;
    return true;
}

function getPassword() {
    return typeof _sessionPassword === "string" && _sessionPassword
        ? _sessionPassword
        : null;
}

function setSessionPassword(password) {
    if (
        typeof password !== "string" ||
        !password ||
        password.length > PASSWORD_MAX_LEN
    ) {
        return false;
    }
    _sessionPassword = password;
    return true;
}

function clearToken() {
    _sessionPassword = null;
    _accessToken = null;
    try {
        sessionStorage.removeItem(TOKEN_KEY);
    } catch {}
}

/* =========================================================================
   Login API call
   ========================================================================= */

async function attemptLogin(username, password) {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), LOGIN_TIMEOUT_MS);

    let res, body;

    try {
        res = await fetch(LOGIN_ENDPOINT, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
            credentials: "same-origin",
            cache: "no-store",
            signal: controller.signal,
        });

        try { body = await res.json(); } catch { body = {}; }

    } catch (err) {
        if (err.name === "AbortError") {
            throw new Error("Authentication request timed out. Please try again.");
        }
        throw new Error("Unable to reach the authentication server.");
    } finally {
        clearTimeout(t);
    }

    if (!res.ok) {
        console.warn("[S43 Auth] Login rejected:", res.status);
        throw new Error("Invalid username or password.");
    }

    const token = typeof (body.access_token || body.token) === "string"
        ? (body.access_token || body.token).trim()
        : "";

    if (
        token.length < TOKEN_MIN_LEN ||
        token.length > TOKEN_MAX_LEN ||
        !JWT_SHAPE_RE.test(token)
    ) {
        throw new Error("Server returned an invalid session token.");
    }

    return { ...body, token };
}

/* =========================================================================
   Refresh — exchange the HttpOnly refresh cookie for a new access token.
   Called on page load so a reload no longer forces a fresh login for a
   DB-account operator. Returns the new access token, or null.
   ========================================================================= */

async function refreshSession() {
    const csrf = _readCookie(CSRF_COOKIE);
    if (!csrf) return null;  // no session cookie -> nothing to refresh

    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), REFRESH_TIMEOUT_MS);
    try {
        const res = await fetch(REFRESH_ENDPOINT, {
            method: "POST",
            headers: { [CSRF_HEADER]: csrf },
            credentials: "same-origin",
            cache: "no-store",
            signal: controller.signal,
        });
        if (!res.ok) return null;
        const body = await res.json().catch(() => ({}));
        const token = typeof (body.access_token || body.token) === "string"
            ? (body.access_token || body.token).trim() : "";
        if (token.length < TOKEN_MIN_LEN || !JWT_SHAPE_RE.test(token)) return null;
        return token;
    } catch {
        return null;
    } finally {
        clearTimeout(t);
    }
}

/* =========================================================================
   Login overlay
   ========================================================================= */

function buildOverlay() {
    if (!document.getElementById("s43-login-styles")) {
        const style = document.createElement("style");
        style.id = "s43-login-styles";
        style.textContent = `
            #s43-login-overlay {
                position: fixed; inset: 0; z-index: 9999;
                background: rgba(0, 8, 20, 0.97);
                display: flex; align-items: center; justify-content: center;
                font-family: 'Courier New', Courier, monospace;
            }
            #s43-login-box {
                width: 340px; padding: 2rem;
                border: 1px solid rgba(0, 229, 255, 0.2);
                background: #000d1a;
                box-shadow: 0 0 48px rgba(0, 229, 255, 0.07);
            }
            #s43-login-header {
                display: flex; align-items: center; gap: 0.6rem;
                margin-bottom: 0.3rem;
            }
            #s43-login-logo  { font-size: 1.4rem; color: #00e5ff; line-height: 1; }
            #s43-login-title { font-size: 1.05rem; font-weight: bold; color: #00e5ff; letter-spacing: 0.2em; }
            #s43-login-sub   { font-size: 0.6rem; color: rgba(0,229,255,0.45); letter-spacing: 0.2em; margin-bottom: 2rem; }
            .s43lf           { margin-bottom: 1.25rem; }
            .s43lf label     { display: block; font-size: 0.6rem; color: rgba(0,229,255,0.55); letter-spacing: 0.18em; margin-bottom: 0.4rem; }
            .s43lf input     { width: 100%; box-sizing: border-box; background: rgba(0,229,255,0.03); border: 1px solid rgba(0,229,255,0.22); color: #d0f0ff; font-family: inherit; font-size: 0.9rem; padding: 0.5rem 0.65rem; outline: none; transition: border-color 0.15s; }
            .s43lf input:focus { border-color: rgba(0,229,255,0.65); }
            .s43lf input:disabled { opacity: 0.35; cursor: not-allowed; }
            #s43-login-err   { font-size: 0.72rem; color: #ff5252; padding: 0.4rem 0.65rem; margin-bottom: 1rem; border: 1px solid rgba(255,82,82,0.28); background: rgba(255,82,82,0.05); display: none; }
            #s43-login-btn   { width: 100%; padding: 0.65rem; background: rgba(0,229,255,0.07); border: 1px solid rgba(0,229,255,0.35); color: #00e5ff; font-family: inherit; font-size: 0.75rem; letter-spacing: 0.2em; cursor: pointer; transition: background 0.15s; }
            #s43-login-btn:hover:not(:disabled) { background: rgba(0,229,255,0.16); }
            #s43-login-btn:disabled { opacity: 0.42; cursor: not-allowed; }
            #s43-login-foot  { font-size: 0.6rem; color: rgba(0,229,255,0.35); text-align: center; margin-top: 1.25rem; min-height: 0.9rem; letter-spacing: 0.1em; }
        `;
        document.head.appendChild(style);
    }

    if (document.getElementById("s43-login-overlay")) return;

    const overlay = document.createElement("div");
    overlay.id = "s43-login-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-label", "Sentinel-43 Operator Authentication");
    overlay.innerHTML = `
        <div id="s43-login-box">
            <div id="s43-login-header">
                <span id="s43-login-logo">⬡</span>
                <span id="s43-login-title">SENTINEL&#8209;43</span>
            </div>
            <div id="s43-login-sub">OPERATOR AUTHENTICATION REQUIRED</div>
            <form id="s43-login-form" autocomplete="off" novalidate>
                <div class="s43lf">
                    <label for="s43-username">USERNAME</label>
                    <input id="s43-username" type="text"
                           autocomplete="username" spellcheck="false" autocapitalize="none" />
                </div>
                <div class="s43lf">
                    <label for="s43-password">PASSWORD</label>
                    <input id="s43-password" type="password" autocomplete="current-password" />
                </div>
                <div id="s43-login-err" role="alert" aria-live="polite"></div>
                <button id="s43-login-btn" type="submit">AUTHENTICATE</button>
            </form>
            <div id="s43-login-foot"></div>
        </div>
    `;
    document.body.appendChild(overlay);

    const _focusableIds = ["s43-username", "s43-password", "s43-login-btn"];
    overlay.addEventListener("keydown", e => {
        if (e.key !== "Tab") return;
        const focusable = _focusableIds
            .map(id => document.getElementById(id))
            .filter(el => el && !el.disabled);
        if (!focusable.length) return;
        const first = focusable[0];
        const last  = focusable[focusable.length - 1];
        if (e.shiftKey) {
            if (document.activeElement === first) { e.preventDefault(); last.focus(); }
        } else {
            if (document.activeElement === last) { e.preventDefault(); first.focus(); }
        }
    });

    const form  = document.getElementById("s43-login-form");
    const errEl = document.getElementById("s43-login-err");
    const btn   = document.getElementById("s43-login-btn");
    const foot  = document.getElementById("s43-login-foot");

    form.addEventListener("submit", async e => {
        e.preventDefault();

        const username = document.getElementById("s43-username").value.trim();
        const password = document.getElementById("s43-password").value;

        if (!username || !password) {
            _showErr("Username and password are required.");
            return;
        }
        if (username.length > USERNAME_MAX_LEN) {
            _showErr("Username is too long.");
            return;
        }
        if (password.length > PASSWORD_MAX_LEN) {
            _showErr("Password is too long.");
            return;
        }

        errEl.style.display = "none";
        btn.disabled        = true;
        btn.textContent     = "AUTHENTICATING…";
        foot.textContent    = "";

        try {
            const result = await attemptLogin(username, password);

            const tokenStored  = setToken(result.token);
            // For a DB-account operator the backend also set an HttpOnly
            // refresh cookie + a sid-bound token; X-S43-Password is no longer
            // required on requests, so we don't *need* to hold the password.
            // We still keep it (in memory only) as a fallback for the legacy
            // env-operator / dual-contract path. session_bound === false means
            // the legacy path, where the password IS required.
            const passwordHeld = setSessionPassword(password);
            const sessionBound = result.session_bound === true;

            if (!tokenStored || (!passwordHeld && !sessionBound)) {
                clearToken();
                throw new Error(
                    "Unable to establish the authenticated session. Check browser storage settings."
                );
            }

            const passwordInput = document.getElementById("s43-password");
            if (passwordInput) passwordInput.value = "";

            _markAuthReady();

            const subject =
                typeof result.subject === "string" && result.subject.trim()
                    ? result.subject
                    : username;

            foot.textContent = `AUTHENTICATED — ${subject.toUpperCase()}`;
            btn.textContent  = "ACCESS GRANTED";

            await new Promise(r => setTimeout(r, 500));
            hideOverlay();

            if (window.SentinelWS) {
                window.SentinelWS.disconnect();
                window.SentinelWS.connect();
            }

        } catch (err) {
            _showErr(err.message);
            btn.disabled    = false;
            btn.textContent = "AUTHENTICATE";
            document.getElementById("s43-password").value = "";
            document.getElementById("s43-password").focus();
        }
    });

    function _showErr(msg) {
        errEl.textContent   = msg;
        errEl.style.display = "block";
    }
}

function showOverlay(message, locked = false) {
    buildOverlay();

    const overlay = document.getElementById("s43-login-overlay");
    if (overlay) overlay.style.display = "flex";

    const errEl = document.getElementById("s43-login-err");
    if (errEl) {
        if (message) { errEl.textContent = message; errEl.style.display = "block"; }
        else { errEl.style.display = "none"; }
    }

    const uEl = document.getElementById("s43-username");
    const pEl = document.getElementById("s43-password");
    const btn = document.getElementById("s43-login-btn");
    const foot = document.getElementById("s43-login-foot");

    if (uEl) uEl.disabled = locked;
    if (pEl) pEl.disabled = locked;
    if (btn) {
        btn.disabled    = locked;
        btn.textContent = locked ? "UNAVAILABLE" : "AUTHENTICATE";
    }
    if (foot) foot.textContent = "";

    if (!locked) {
        if (pEl) pEl.value = "";
        setTimeout(() => {
            if (uEl && !uEl.value.trim()) uEl.focus();
            else if (pEl) pEl.focus();
        }, 50);
    }
}

function hideOverlay() {
    const overlay = document.getElementById("s43-login-overlay");
    if (overlay) overlay.style.display = "none";
}

/* =========================================================================
   Auth failure handler
   ========================================================================= */

window.addEventListener("sentinel:ws:auth_failed", () => {
    clearToken();
    _resetAuthReady();
    _markAuthLocked("WebSocket authentication rejected");
    showOverlay("Session expired or rejected. Please re-authenticate.");
});

/* =========================================================================
   Init
   On load, try to exchange the HttpOnly refresh cookie for a fresh access
   token (POST /auth/refresh). If it works, the operator stays logged in
   across a reload without re-typing their password (session-bound path).
   If there's no session cookie, or the refresh is rejected, fall back to
   the login overlay. The legacy env-operator has no refresh cookie and
   always lands on the overlay.
   ========================================================================= */

async function init() {
    if (!_sessionStorageAvailable()) {
        const msg = "Session storage is unavailable. Enable cookies or disable "
                  + "private browsing to use this dashboard.";
        if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", () => showOverlay(msg, true));
        } else {
            showOverlay(msg, true);
        }
        return;
    }

    const staleToken = getToken();
    if (staleToken) clearToken();

    const refreshed = await refreshSession();
    if (refreshed && setToken(refreshed)) {
        // session-bound: no in-memory password needed for requests
        _sessionPassword = null;
        _markAuthReady();
        hideOverlay();
        if (window.SentinelWS) {
            window.SentinelWS.disconnect();
            window.SentinelWS.connect();
        }
        return;
    }

    const expiredMsg = staleToken
        ? "Your session ended. Please authenticate again."
        : undefined;

    if (document.readyState === "loading") {
        document.addEventListener(
            "DOMContentLoaded",
            () => showOverlay(expiredMsg),
            { once: true }
        );
    } else {
        showOverlay(expiredMsg);
    }
}

init();

/* =========================================================================
   Public API
   ========================================================================= */

return Object.freeze({
    async logout() {
        // Revoke the server-side session first (best-effort), then clear
        // local state regardless of the result.
        const csrf = _readCookie(CSRF_COOKIE);
        try {
            await fetch(LOGOUT_ENDPOINT, {
                method: "POST",
                headers: csrf ? { [CSRF_HEADER]: csrf } : {},
                credentials: "same-origin",
                cache: "no-store",
            });
        } catch { /* clear locally anyway */ }
        clearToken();
        _resetAuthReady();
        _markAuthLocked("Operator logged out");
        if (window.SentinelWS) window.SentinelWS.disconnect();
        showOverlay("You have been logged out.");
    },
    refreshSession,
    hasToken: () => !!getToken(),
    // In-memory bearer access token for same-origin consumers (websocket.js,
    // dashboard.js). Never persisted; returns null when logged out.
    getToken,
    getPassword,

    applyManualCredentials(token, password) {
        const cleanToken = typeof token === "string" ? token.trim() : "";
        const cleanPassword = typeof password === "string" ? password : "";

        if (!cleanToken || !cleanPassword) {
            clearToken();
            _resetAuthReady();
            return false;
        }

        if (
            cleanToken.length < TOKEN_MIN_LEN ||
            cleanToken.length > TOKEN_MAX_LEN ||
            !JWT_SHAPE_RE.test(cleanToken)
        ) {
            return false;
        }

        const tokenStored  = setToken(cleanToken);
        const passwordHeld = setSessionPassword(cleanPassword);

        if (!tokenStored || !passwordHeld) {
            clearToken();
            return false;
        }

        _markAuthReady();
        return true;
    },
});

})();
