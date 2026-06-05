/* ==========================================================
   Sentinel-43 Dashboard
   dashboard.js
   Live backend bridge
   ========================================================== */

"use strict";

console.log("S43 EXTERNAL DASHBOARD.JS LOADED - TEST MARKER");

(() => {
    const API_BASE = window.SENTINEL_API_BASE_URL || "http://localhost:8000";
    const POLL_MS = 15000;

    const $ = (id) => document.getElementById(id);

    async function getJson(path) {
        const response = await fetch(`${API_BASE}${path}`, {
            headers: {
                "Accept": "application/json",
            },
        });

        if (!response.ok) {
            throw new Error(`${response.status} ${response.statusText}`);
        }

        return response.json();
    }

    function setText(id, value) {
        const element = $(id);

        if (element) {
            element.textContent = value;
        }
    }

    function setSystemStatus(state) {
        const dot = $("statusDot");
        const text = $("statusText");

        if (text) {
            text.textContent = state.toUpperCase();
        }

        if (dot) {
            dot.classList.remove("online", "offline");

            if (state === "Online") {
                dot.classList.add("online");
            }

            if (state === "Offline") {
                dot.classList.add("offline");
            }
        }
    }

    function logBridge(message, type = "info") {
        const consoleBox = $("logConsole");

        if (!consoleBox) {
            return;
        }

        const line = document.createElement("div");
        line.className = `log-line ${type}`;

        const timestamp = new Date().toLocaleTimeString();

        line.innerHTML = `
            <span class="log-ts">${timestamp}</span>
            <span class="log-lvl">${type.toUpperCase()}</span>
            <span class="log-msg">${message}</span>
        `;

        consoleBox.appendChild(line);
        consoleBox.scrollTop = consoleBox.scrollHeight;
    }

    async function refreshLiveBackend() {
        try {
            const [
                health,
                ready,
                status,
                routes,
                remoteHealth,
                remoteTargets,
            ] = await Promise.allSettled([
                getJson("/health"),
                getJson("/ready"),
                getJson("/status"),
                getJson("/system/routes"),
                getJson("/remote/health"),
                getJson("/remote/targets"),
            ]);

            if (health.status === "fulfilled") {
                setSystemStatus("Online");
                setText("modeText", "HUMAN_GATED");
            } else {
                setSystemStatus("Offline");
            }

            if (routes.status === "fulfilled") {
                setText("vaultCount", routes.value.route_count ?? "--");
            }

            if (remoteHealth.status === "fulfilled") {
                const gatewayState = remoteHealth.value.state || "unknown";
                const targetCount = remoteHealth.value.registered_targets ?? 0;

                setText("queueCount", targetCount);
                logBridge(`Remote gateway: ${gatewayState}`, "ok");
            }

            if (remoteTargets.status === "fulfilled") {
                const targets = Array.isArray(remoteTargets.value)
                    ? remoteTargets.value.length
                    : 0;

                setText("queueCount", targets);
            }

            setText("apiBaseText", API_BASE);
            setText("lastSync", `sync ${new Date().toLocaleTimeString()}`);

            logBridge("Live backend refresh complete.", "ok");
        } catch (error) {
            setSystemStatus("Offline");
            logBridge(`Live backend refresh failed: ${error.message}`, "err");
        }
    }

   document.addEventListener("DOMContentLoaded", () => {
    logBridge("Sentinel-43 live bridge attached.", "info");

    const refreshBtn = document.getElementById("refreshBtn");

    if (refreshBtn) {
        refreshBtn.addEventListener("click", () => {
            logBridge("Manual refresh requested.", "info");
            refreshLiveBackend();
        });
    }

    const themeBtn = document.getElementById("themeBtn");

    if (themeBtn) {
        themeBtn.addEventListener("click", () => {
            document.documentElement.classList.toggle("light");

            const isLight = document.documentElement.classList.contains("light");

            themeBtn.textContent = isLight ? "☽ Dark" : "☀ Light";

            logBridge(
                `Theme switched to ${isLight ? "light" : "dark"} mode.`,
                "info",
            );
        });
    }

      refreshLiveBackend();
    window.setInterval(refreshLiveBackend, POLL_MS);
});
})();
