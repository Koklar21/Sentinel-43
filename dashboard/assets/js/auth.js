/* =============================================================================
   Sentinel-43 Dashboard
   auth.js — Operator login flow and JWT lifecycle
   v1.4.0

   Changes from v1.3.0:
     - Fix: SentinelAuthReady lifecycle was broken after logout or WebSocket
       auth failure. Once _markAuthReady() resolved the Promise, it stayed
       resolved forever. A subsequent logout → relogin cycle left the Promise
       permanently resolved, so any code awaiting it after logout would
       continue immediately rather than waiting for re-authentication.
       _resetAuthReady() now creates a fresh deferred Promise. It is called
       at module init, on logout(), and on sentinel:ws:auth_failed.
     - Fix: AbortController timer was cleared in the finally block immediately
       after fetch() resolved (on headers received), before res.json() ran.
       If a server sent headers but stalled the body, the abort timer had
       already been cancelled and the body read could hang indefinitely.
       res.json() is now inside the try block so clearTimeout() only fires
       after both fetch and body parse complete or abort.
     - Fix: showOverlay() now accepts a locked parameter. When sessionStorage
       is unavailable, the login form is disabled with "UNAVAILABLE" state
       rather than letting the operator submit credentials that cannot be
       stored. Calling showOverlay(message, true) disables username, password,
       and the submit button.

   Changes from v1.2.0:
     - Fix: window.SentinelAuthReady is now a manually-controlled deferred
       Promise. Resolves only on confirmed valid token or successful login.
     - Fix: AbortController timeouts on login (10s) and verify (5s).
     - Fix: Token trimmed before shape validation and storage.
     - Fix: JWT shape regex check (three base64url segments).
     - Fix: Username (128) and password (1024) length caps.
     - Fix: console.warn logs HTTP status only, never backend detail.
     - Fix: disconnect() + connect() after login for clean socket restart.
     - Fix: Focus trap keeps Tab within overlay fields.
     - Fix: aria-modal, role="dialog", role="alert" added.
     - Fix: sessionStorage availability checked at init().

   Changes from v1.1.0:
     - Fix: fetch failure and JSON parse failure handled separately.
     - Fix: TOKEN_MAX_LEN corrected to 4096.

   Changes from v1.0.0:
     - Fix: race condition between async init() and websocket.js auto-connect.
     - Fix: token type and minimum length validated after login response.
     - Fix: result.subject crash when backend omits the field.
     - Fix: setToken() return value checked.
     - Fix: cache: "no-store" on login and verify fetch calls.
     - Fix: generic login error message; detail logged server-side only.
     - Fix: style element guarded separately from overlay in buildOverlay().

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
    const VERIFY_ENDPOINT   = "/auth/verify";
    const TOKEN_KEY         = "SENTINEL_JWT";
    const TOKEN_MIN_LEN     = 20;
    const TOKEN_MAX_LEN     = 4096;   // Matches backend DEFAULT_MAX_TOKEN_CHARS.
    const USERNAME_MAX_LEN  = 128;
    const PASSWORD_MAX_LEN  = 1024;
    const LOGIN_TIMEOUT_MS  = 10_000;
    const VERIFY_TIMEOUT_MS = 5_000;

    // Three-segment base64url shape check. Does NOT decode or trust claims.
    // Backend remains the authority on token validity.
    const JWT_SHAPE_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

    /* =========================================================================
       SentinelAuthReady — resettable deferred Promise
       Resolves only when auth is confirmed:
         (a) Stored token passes /auth/verify on page load, OR
         (b) Operator completes a successful login.
       Must be reset on logout and auth failure so subsequent relogins are
       correctly gated. A permanently-resolved Promise after first login would
       allow websocket.js to connect without waiting for re-authentication.
       ========================================================================= */

    let _resolveAuthReady;

    function _resetAuthReady() {
        window.SentinelAuthReady = new Promise(resolve => {
            _resolveAuthReady = resolve;
        });
    }

    function _markAuthReady() {
        if (typeof _resolveAuthReady === "function") {
            _resolveAuthReady();
            _resolveAuthReady = null;  // Prevent double-resolve on current Promise.
        }
    }

    // Initialize on module load.
    _resetAuthReady();

    /* =========================================================================
       Token storage
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

    function clearToken() {
        try { sessionStorage.removeItem(TOKEN_KEY); } catch {}
    }

    /* =========================================================================
       Token verification
       ========================================================================= */

    async function verifyStoredToken(token) {
        const controller = new AbortController();
        const t = setTimeout(() => controller.abort(), VERIFY_TIMEOUT_MS);
        try {
            const res = await fetch(VERIFY_ENDPOINT, {
                headers: { "Authorization": `Bearer ${token}` },
                credentials: "same-origin",
                cache: "no-store",
                signal: controller.signal,
            });
            return res.ok;
        } catch {
            // Fail-closed: timeout, network failure, and non-OK all treated as
            // invalid. Correct posture for a security dashboard even if it
            // requires re-login on a temporary backend hiccup.
            return false;
        } finally {
            clearTimeout(t);
        }
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

            // JSON parse is inside the try block so the AbortController remains
            // active through the body read. If the server sends headers but stalls
            // the body, the timer fires, controller.abort() is called, and
            // res.json() throws an AbortError caught by the outer handler.
            // clearTimeout(t) in finally only runs after both fetch and parse
            // complete or fail, not prematurely after headers arrive.
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
            // Log status only — never backend detail — for operator debugging.
            console.warn("[S43 Auth] Login rejected:", res.status);
            throw new Error("Invalid username or password.");
        }

        // Trim before validation so whitespace-padded tokens don't pass length
        // checks and then fail silently during the WebSocket auth handshake.
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

        // Focus trap: Tab and Shift+Tab cycle only within overlay fields.
        // Prevents keyboard navigation into hidden dashboard elements below.
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

                if (!setToken(result.token)) {
                    throw new Error("Unable to store session token. Check browser storage settings.");
                }

                // Resolve SentinelAuthReady BEFORE calling SentinelWS so that
                // websocket.js._autoConnect() (if still awaiting) and the explicit
                // connect() call below see a consistent resolved state.
                _markAuthReady();

                const subject =
                    typeof result.subject === "string" && result.subject.trim()
                        ? result.subject
                        : username;

                foot.textContent = `AUTHENTICATED — ${subject.toUpperCase()}`;
                btn.textContent  = "ACCESS GRANTED";

                await new Promise(r => setTimeout(r, 500));
                hideOverlay();

                // Force a clean socket restart. disconnect() sets _manuallyClosed=true;
                // connect() resets it to false and opens a fresh connection with the
                // token now present in sessionStorage.
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

    /**
     * Show the login overlay.
     * @param {string|undefined} message  Optional message shown in the error area.
     * @param {boolean}          locked   If true, disable all form fields and show
     *                                    "UNAVAILABLE". Use when the environment
     *                                    cannot support authentication (e.g. storage
     *                                    unavailable). The operator cannot log in so
     *                                    there is no point letting them try.
     */
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
       Resets SentinelAuthReady so subsequent relogin is properly gated.
       ========================================================================= */

    window.addEventListener("sentinel:ws:auth_failed", () => {
        clearToken();
        _resetAuthReady();
        showOverlay("Session expired or rejected. Please re-authenticate.");
    });

    /* =========================================================================
       Init
       Checks for a stored token and verifies it before resolving
       SentinelAuthReady. If no valid token exists, shows the login overlay
       and holds the Promise open until the operator successfully logs in.
       ========================================================================= */

    async function init() {
        // Storage availability check. Aggressive private mode or enterprise
        // browser policy can disable sessionStorage entirely. Surface this
        // clearly and lock the form rather than letting the operator submit
        // credentials that cannot be stored.
        if (!_sessionStorageAvailable()) {
            const msg = "Session storage is unavailable. Enable cookies or disable "
                      + "private browsing to use this dashboard.";
            if (document.readyState === "loading") {
                document.addEventListener("DOMContentLoaded", () => showOverlay(msg, true));
            } else {
                showOverlay(msg, true);
            }
            // Do not resolve SentinelAuthReady — the operator cannot authenticate.
            return;
        }

        const token = getToken();

        if (token) {
            const valid = await verifyStoredToken(token);
            if (valid) {
                // Valid token confirmed — unblock websocket.js.
                _markAuthReady();
                return;
            }
            clearToken();
        }

        // No token or invalid token: show the login overlay.
        // SentinelAuthReady remains unresolved until the operator logs in.
        const expiredMsg = token
            ? "Previous session expired. Please log in again."
            : undefined;

        if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", () => showOverlay(expiredMsg));
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
            _resetAuthReady();  // Gate websocket.js on next relogin.
            if (window.SentinelWS) window.SentinelWS.disconnect();
            showOverlay("You have been logged out.");
        },
        hasToken: () => !!getToken(),
    });

})();
