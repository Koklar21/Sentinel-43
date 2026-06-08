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

    let pollHandle = null;
    let isRefreshing = false;

    const $ = (id) => document.getElementById(id);

    function getOwnerToken() {
        return (
            window.SENTINEL_REMOTE_OWNER_TOKEN ||
            localStorage.getItem("SENTINEL_REMOTE_OWNER_TOKEN") ||
            ""
        );
    }

    function buildHeaders() {
        const headers = {
            Accept: "application/json",
        };

        const token = getOwnerToken();

        if (token) {
            headers.Authorization = `Bearer ${token}`;
        }

        return headers;
    }

    async function getJson(path) {
        const response = await fetch(`${API_BASE}${path}`, {
            method: "GET",
            headers: buildHeaders(),
        });

        if (!response.ok) {
            throw new Error(`${response.status} ${response.statusText}`);
        }

        return response.json();
    }

    function setText(id, value) {
        const element = $(id);

        if (element) {
            element.textContent = value ?? "--";
        }
    }

    function normalizeState(state) {
        return String(state || "unknown").trim().toLowerCase();
    }

    function setSystemStatus(state) {
        const normalized = normalizeState(state);
        const dot = $("statusDot");
        const text = $("statusText");

        if (text) {
            text.textContent = normalized.toUpperCase();
        }

        if (dot) {
            dot.classList.remove("online", "offline", "degraded", "unknown");

            if (normalized === "online" || normalized === "ok") {
                dot.classList.add("online");
            } else if (normalized === "offline" || normalized === "failed") {
                dot.classList.add("offline");
            } else if (normalized === "degraded" || normalized === "unavailable") {
                dot.classList.add("degraded");
            } else {
                dot.classList.add("unknown");
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

        const timestamp = document.createElement("span");
        timestamp.className = "log-ts";
        timestamp.textContent = new Date().toLocaleTimeString();

        const level = document.createElement("span");
        level.className = "log-lvl";
        level.textContent = type.toUpperCase();

        const msg = document.createElement("span");
        msg.className = "log-msg";
        msg.textContent = String(message);

        line.appendChild(timestamp);
        line.appendChild(level);
        line.appendChild(msg);

        consoleBox.appendChild(line);
        consoleBox.scrollTop = consoleBox.scrollHeight;
    }

    function fulfilled(result) {
        return result.status === "fulfilled";
    }

    function rejected(result) {
        return result.status === "rejected";
    }

    function getModeFromStatus(statusValue) {
        return (
            statusValue?.mode ||
            statusValue?.operation_mode ||
            statusValue?.remote_mode ||
            statusValue?.system_mode ||
            "UNKNOWN"
        );
    }

    async function refreshLiveBackend() {
        if (isRefreshing) {
            return;
        }

        isRefreshing = true;

        const results = await Promise.allSettled([
            getJson("/health"),
            getJson("/ready"),
            getJson("/status"),
            getJson("/system/routes"),
            getJson("/remote/health"),
            getJson("/remote/targets"),
        ]);

        const [
            health,
            ready,
            status,
            routes,
            remoteHealth,
            remoteTargets,
        ] = results;

        if (fulfilled(health)) {
            setSystemStatus("online");
        } else {
            setSystemStatus("offline");
            logBridge(`Health check failed: ${health.reason?.message || health.reason}`, "err");
        }

        if (fulfilled(ready)) {
            setText("readyText", ready.value.ready === true ? "READY" : "NOT READY");
        } else {
            setText("readyText", "NOT READY");
            logBridge(`Ready check failed: ${ready.reason?.message || ready.reason}`, "warn");
        }

        if (fulfilled(status)) {
            setText("modeText", getModeFromStatus(status.value));
        }

        if (fulfilled(routes)) {
            setText("vaultCount", routes.value.route_count ?? "--");
        }

        if (fulfilled(remoteHealth)) {
            const gatewayState = remoteHealth.value.state || remoteHealth.value.status || "unknown";
            const registeredTargets = remoteHealth.value.registered_targets ?? "--";

            setText("remoteGatewayState", gatewayState);
            setText("remoteRegisteredTargets", registeredTargets);

            logBridge(`Remote gateway: ${gatewayState}`, "ok");
        } else {
            setText("remoteGatewayState", "unavailable");
            logBridge(`Remote health failed: ${remoteHealth.reason?.message || remoteHealth.reason}`, "warn");
        }

        if (fulfilled(remoteTargets)) {
            const targets = Array.isArray(remoteTargets.value)
                ? remoteTargets.value.length
                : Array.isArray(remoteTargets.value?.targets)
                    ? remoteTargets.value.targets.length
                    : 0;

            setText("remoteTargetCount", targets);
            setText("queueCount", targets);
        } else {
            setText("remoteTargetCount", "--");
            logBridge(`Remote targets failed: ${remoteTargets.reason?.message || remoteTargets.reason}`, "warn");
        }

        setText("apiBaseText", API_BASE);
        setText("lastSync", `sync ${new Date().toLocaleTimeString()}`);

        const failedCount = results.filter(rejected).length;

        if (failedCount === 0) {
            logBridge("Live backend refresh complete.", "ok");
        } else {
            logBridge(`Live backend refresh completed with ${failedCount} failed check(s).`, "warn");
        }

        isRefreshing = false;
    }

    function startPolling() {
        if (pollHandle) {
            return;
        }

        pollHandle = window.setInterval(refreshLiveBackend, POLL_MS);
    }

    function stopPolling() {
        if (pollHandle) {
            window.clearInterval(pollHandle);
            pollHandle = null;
        }
    }

    document.addEventListener("visibilitychange", () => {
        if (document.hidden) {
            stopPolling();
            logBridge("Polling paused while tab is hidden.", "info");
            return;
        }

        logBridge("Polling resumed.", "info");
        refreshLiveBackend();
        startPolling();
    });

    document.addEventListener("DOMContentLoaded", () => {
        logBridge("Sentinel-43 live bridge attached.", "info");

        const refreshBtn = $("refreshBtn");

        if (refreshBtn) {
            refreshBtn.addEventListener("click", () => {
                logBridge("Manual refresh requested.", "info");
                refreshLiveBackend();
            });
        }

        const themeBtn = $("themeBtn");

        if (themeBtn) {
            themeBtn.addEventListener("click", () => {
                document.documentElement.classList.toggle("light");

                const isLight = document.documentElement.classList.contains("light");

                themeBtn.textContent = isLight ? "☽ Dark" : "☀ Light";

                logBridge(
                    `Theme switched to ${isLight ? "light" : "dark"} mode.`,
                    "info"
                );
            });
        }

        refreshLiveBackend();
        startPolling();
    });

    window.addEventListener("beforeunload", stopPolling);
})();
