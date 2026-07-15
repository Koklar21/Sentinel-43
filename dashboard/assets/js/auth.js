/* =============================================================================
   Sentinel-43 Dashboard
   auth.js — Operator login flow and JWT lifecycle
   v1.6.0

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
const TOKEN_KEY         = "SENTINEL_JWT";
const TOKEN_MIN_LEN     = 20;
const TOKEN_MAX_LEN     = 4096;
const USERNAME_MAX_LEN  = 128;
const PASSWORD_MAX_LEN  = 1024;
const LOGIN_TIMEOUT_MS  = 10_000;

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

function getToken() {
    try { return sessionStorage.getItem(TOKEN_KEY) || null; } catch { return null; }
}

function setToken(token) {
    try { sessionStorage.setItem(TOKEN_KEY, token); return true; } catch { return false; }
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

    const token = typeof body.token === "string" ? body.token.trim() : "";

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
            const passwordHeld = setSessionPassword(password);

            if (!tokenStored || !passwordHeld) {
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
   Stored-token verification was removed: a token surviving a refresh has
   no matching in-memory password and cannot drive any protected route, so
   there is nothing useful to verify it against. A refresh always requires
   a fresh login.
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

    const token = getToken();

    if (token) {
        clearToken();
    }

    const expiredMsg = token
        ? "Your secure session ended when the page was reloaded. Please authenticate again."
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
    logout() {
        clearToken();
        _resetAuthReady();
        _markAuthLocked("Operator logged out");
        if (window.SentinelWS) window.SentinelWS.disconnect();
        showOverlay("You have been logged out.");
    },
    hasToken: () => !!getToken(),
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
