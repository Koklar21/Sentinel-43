/* =============================================================================
   Sentinel-43 Dashboard
   auth.js — Operator login flow and JWT lifecycle
   v1.1.0

   Changes from v1.0.0:
     - Fix: race condition between async init() and websocket.js auto-connect.
       window.SentinelAuthReady is now a Promise that resolves when the auth
       check is complete. websocket.js waits on it before connecting.
     - Fix: token type and minimum length validated after login response.
     - Fix: result.subject crash when backend omits the field; falls back to
       the username the operator typed.
     - Fix: setToken() return value checked; throws if sessionStorage write fails.
     - Fix: cache: "no-store" added to login and verify fetch calls.
     - Fix: login error shown as generic message; detail logged to console only.
     - Fix: style element guarded separately from overlay element in buildOverlay().

   LOAD ORDER: auth.js MUST be included BEFORE websocket.js.
   websocket.js must await window.SentinelAuthReady before connecting.
   ============================================================================= */

"use strict";

window.SentinelAuth = (() => {

    /* =========================================================================
       Config
       ========================================================================= */

    const LOGIN_ENDPOINT  = "/auth/login";
    const VERIFY_ENDPOINT = "/auth/verify";
    const TOKEN_KEY       = "SENTINEL_JWT";
    const TOKEN_MIN_LEN   = 20;
    const TOKEN_MAX_LEN   = 8192;

    /* =========================================================================
       Token storage
       ========================================================================= */

    function getToken() {
        try { return sessionStorage.getItem(TOKEN_KEY) || null; } catch { return null; }
    }

    function setToken(token) {
        try { sessionStorage.setItem(TOKEN_KEY, token); return true; } catch { return false; }
    }

    function clearToken() {
        try { sessionStorage.removeItem(TOKEN_KEY); } catch {}
    }

    /* =========================================================================
       Token verification
       ========================================================================= */

    async function verifyStoredToken(token) {
        try {
            const res = await fetch(VERIFY_ENDPOINT, {
                headers: { "Authorization": `Bearer ${token}` },
                credentials: "same-origin",
                cache: "no-store",
            });
            return res.ok;
        } catch {
            return false;
        }
    }

    /* =========================================================================
       Login API call
       ========================================================================= */

    async function attemptLogin(username, password) {
        let res, body;
        try {
            res  = await fetch(LOGIN_ENDPOINT, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password }),
                credentials: "same-origin",
                cache: "no-store",
            });
            body = await res.json();
        } catch {
            throw new Error("Unable to reach the authentication server.");
        }

        if (!res.ok) {
            // Log the backend detail for operator debugging; never expose it in the UI.
            console.warn("[S43 Auth] Login rejected:", body?.detail ?? res.status);
            throw new Error("Invalid username or password.");
        }

        // Validate token field before storing it.
        if (
            typeof body.token !== "string" ||
            body.token.length < TOKEN_MIN_LEN ||
            body.token.length > TOKEN_MAX_LEN
        ) {
            throw new Error("Server returned an invalid session token.");
        }

        return body;
    }

    /* =========================================================================
       Login overlay
       ========================================================================= */

    function buildOverlay() {
        // Guard style and overlay independently so neither duplicates.
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
                    <div id="s43-login-err"></div>
                    <button id="s43-login-btn" type="submit">AUTHENTICATE</button>
                </form>
                <div id="s43-login-foot"></div>
            </div>
        `;
        document.body.appendChild(overlay);

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

            errEl.style.display = "none";
            btn.disabled        = true;
            btn.textContent     = "AUTHENTICATING…";
            foot.textContent    = "";

            try {
                const result = await attemptLogin(username, password);

                if (!setToken(result.token)) {
                    throw new Error("Unable to store session token. Check browser storage settings.");
                }

                // Use backend-returned subject if valid string; fall back to typed username.
                const subject =
                    typeof result.subject === "string" && result.subject.trim()
                        ? result.subject
                        : username;

                foot.textContent = `AUTHENTICATED — ${subject.toUpperCase()}`;
                btn.textContent  = "ACCESS GRANTED";

                await new Promise(r => setTimeout(r, 500));
                hideOverlay();

                if (window.SentinelWS) {
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
            errEl.textContent    = msg;
            errEl.style.display = "block";
        }
    }

    function showOverlay(message) {
        buildOverlay();

        const overlay = document.getElementById("s43-login-overlay");
        if (overlay) overlay.style.display = "flex";

        const errEl = document.getElementById("s43-login-err");
        if (errEl) {
            if (message) { errEl.textContent = message; errEl.style.display = "block"; }
            else { errEl.style.display = "none"; }
        }

        const foot = document.getElementById("s43-login-foot");
        if (foot) foot.textContent = "";

        const btn = document.getElementById("s43-login-btn");
        if (btn) { btn.disabled = false; btn.textContent = "AUTHENTICATE"; }

        const pEl = document.getElementById("s43-password");
        const uEl = document.getElementById("s43-username");
        if (pEl) pEl.value = "";
        setTimeout(() => {
            if (uEl && !uEl.value.trim()) uEl.focus();
            else if (pEl) pEl.focus();
        }, 50);
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
        showOverlay("Session expired or rejected. Please re-authenticate.");
    });

    /* =========================================================================
       Init
       Resolves when auth state is confirmed so websocket.js can safely connect.
       Exposed as window.SentinelAuthReady (a Promise) for websocket.js to await.
       ========================================================================= */

    async function init() {
        const token = getToken();

        if (!token) {
            if (document.readyState === "loading") {
                document.addEventListener("DOMContentLoaded", () => showOverlay());
            } else {
                showOverlay();
            }
            return;
        }

        const valid = await verifyStoredToken(token);
        if (!valid) {
            clearToken();
            if (document.readyState === "loading") {
                document.addEventListener("DOMContentLoaded", () =>
                    showOverlay("Previous session expired. Please log in again.")
                );
            } else {
                showOverlay("Previous session expired. Please log in again.");
            }
        }
        // If valid: token stays in sessionStorage, websocket.js connects normally.
    }

    // Expose the init promise so websocket.js can wait on it before auto-connect.
    window.SentinelAuthReady = init();

    /* =========================================================================
       Public API
       ========================================================================= */

    return Object.freeze({
        logout() {
            clearToken();
            if (window.SentinelWS) window.SentinelWS.disconnect();
            showOverlay("You have been logged out.");
        },
        hasToken: () => !!getToken(),
    });

})();
