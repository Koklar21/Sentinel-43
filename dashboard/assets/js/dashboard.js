/* ==========================================================
   Sentinel-43 Dashboard
   dashboard.js
   ========================================================== */

"use strict";

/* ==========================================================
   Config
   ========================================================== */

const SentinelDashboard = {
    apiBaseUrl: window.SENTINEL_API_BASE_URL || "http://localhost:8000",
    refreshIntervalMs: 15000,
};

/* ==========================================================
   Helpers
   ========================================================== */

function qs(selector, root = document) {
    return root.querySelector(selector);
}

function qsa(selector, root = document) {
    return Array.from(root.querySelectorAll(selector));
}

function setText(selector, value, root = document) {
    const element = qs(selector, root);

    if (element) {
        element.textContent = value;
    }
}

function setStatusClass(element, state) {
    if (!element) {
        return;
    }

    element.classList.remove(
        "status-online",
        "status-warning",
        "status-error",
        "status-info",
    );

    const normalized = String(state || "").toLowerCase();

    if (["ok", "online", "active", "ready", "true"].includes(normalized)) {
        element.classList.add("status-online");
        return;
    }

    if (["warning", "degraded", "unknown"].includes(normalized)) {
        element.classList.add("status-warning");
        return;
    }

    if (["error", "failed", "offline", "false", "disabled"].includes(normalized)) {
        element.classList.add("status-error");
        return;
    }

    element.classList.add("status-info");
}

async function fetchJson(path, options = {}) {
    const url = `${SentinelDashboard.apiBaseUrl}${path}`;

    const response = await fetch(url, {
        headers: {
            "Content-Type": "application/json",
            ...(options.headers || {}),
        },
        ...options,
    });

    const text = await response.text();

    let data = null;

    try {
        data = text ? JSON.parse(text) : null;
    } catch {
        data = { raw: text };
    }

    if (!response.ok) {
        const detail = data?.detail || data?.error || response.statusText;

        throw new Error(`${response.status}: ${detail}`);
    }

    return data;
}

/* ==========================================================
   Page Status
   ========================================================== */

function setPageStatus(message, state = "info") {
    setText("[data-dashboard-status]", message);

    const statusElement = qs("[data-dashboard-status]");

    if (statusElement) {
        setStatusClass(statusElement, state);
    }
}

/* ==========================================================
   Health Loading
   ========================================================== */

async function loadApiHealth() {
    const healthElement = qs("[data-api-health]");

    if (!healthElement) {
        return;
    }

    try {
        const health = await fetchJson("/health");

        healthElement.textContent = health.status || "unknown";
        setStatusClass(healthElement, health.status);

        setText("[data-api-version]", health.version || "unknown");
        setText("[data-api-service]", health.service || "sentinel-43-api");

        setPageStatus("API online", "online");
    } catch (error) {
        healthElement.textContent = "offline";
        setStatusClass(healthElement, "error");

        setPageStatus(`API error: ${error.message}`, "error");
    }
}

/* ==========================================================
   Remote Gateway Loading
   ========================================================== */

async function loadRemoteGatewayHealth() {
    const gatewayElement = qs("[data-remote-gateway-state]");

    if (!gatewayElement) {
        return;
    }

    try {
        const gateway = await fetchJson("/remote/health");

        gatewayElement.textContent = gateway.state || "unknown";
        setStatusClass(gatewayElement, gateway.state);

        setText("[data-remote-gateway-name]", gateway.gateway || "remote-gateway");
        setText("[data-remote-target-count]", gateway.registered_targets ?? "0");
        setText("[data-remote-audit-buffer]", gateway.audit_buffer_max ?? "unknown");
    } catch (error) {
        gatewayElement.textContent = "offline";
        setStatusClass(gatewayElement, "error");

        setText("[data-remote-gateway-error]", error.message);
    }
}

/* ==========================================================
   Routes Loading
   ========================================================== */

async function loadRouteCount() {
    const routeElement = qs("[data-route-count]");

    if (!routeElement) {
        return;
    }

    try {
        const routeData = await fetchJson("/system/routes");

        routeElement.textContent = routeData.route_count ?? "0";
        setStatusClass(routeElement, "online");
    } catch (error) {
        routeElement.textContent = "error";
        setStatusClass(routeElement, "error");
    }
}

/* ==========================================================
   Navigation
   ========================================================== */

function initializeNavigation() {
    const currentPath = window.location.pathname;

    qsa("[data-nav-link]").forEach((link) => {
        const href = link.getAttribute("href");

        if (href && currentPath.endsWith(href)) {
            link.classList.add("active");
        }
    });
}

/* ==========================================================
   Auto Refresh
   ========================================================== */

function startAutoRefresh() {
    loadApiHealth();
    loadRemoteGatewayHealth();
    loadRouteCount();

    window.setInterval(() => {
        loadApiHealth();
        loadRemoteGatewayHealth();
        loadRouteCount();
    }, SentinelDashboard.refreshIntervalMs);
}

/* ==========================================================
   Startup
   ========================================================== */

document.addEventListener("DOMContentLoaded", () => {
    initializeNavigation();
    startAutoRefresh();
});
