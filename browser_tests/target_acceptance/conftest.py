# =============================================================================
# Sentinel-43 -- browser TARGET-ACCEPTANCE fixtures.
#
# These run the shipped SPA against a REAL deployed beta target over ordinary
# trusted-CA HTTPS. Unlike browser_tests/ (the disposable stack), this suite:
#
#   * requires an explicit S43_TARGET_BASE_URL (https://<fqdn>[:port]) and uses
#     that same endpoint for the browser AND every out-of-band API call
#   * does standard certificate-chain + hostname verification (optionally with
#     an approved private CA via S43_TARGET_CA_BUNDLE) -- never CERT_NONE, never
#     an --ignore-certificate-errors / SPKI exception, never host-resolver MAP
#   * never starts, stops, rebuilds, scales, or `down -v`s anything
#   * never bootstraps an admin and never reuses a fixed username to mutate an
#     existing account
#   * reads test-account credentials from files named by env vars; never prints
#     them and never asks for them interactively
#   * treats missing credentials as an ERRORED (incomplete) run, not a green
#     skipped suite
#
# Helpers live in _targetlib.py so `from conftest import ...` in the test files
# never collides with browser_tests/conftest.py.
# =============================================================================

from __future__ import annotations

import os

import pytest

from _targetlib import read_cred, require_https_base


@pytest.fixture(scope="session")
def target_base_url() -> str:
    return require_https_base()


@pytest.fixture(scope="session")
def operator_cred() -> tuple[str, str]:
    """A DESIGNATED beta operator test account -- login / refresh / logout /
    WSS acceptance only, no account mutation."""
    return read_cred("S43_TARGET_OPERATOR_CRED_FILE",
                     purpose="authenticated session acceptance")


@pytest.fixture(scope="session")
def admin_mutation_cred() -> tuple[str, str]:
    """A DEDICATED admin test account for mutation scenarios. Gated on an
    explicit opt-in so these never run against an owner's ordinary account."""
    if os.environ.get("S43_TARGET_ADMIN_SCOPE") != "explicit-dedicated-account":
        pytest.fail(
            "admin-mutation acceptance needs S43_TARGET_ADMIN_SCOPE="
            "explicit-dedicated-account plus S43_TARGET_ADMIN_CRED_FILE pointing "
            "at a throwaway admin account. Not set -> INCOMPLETE, not skipped.",
            pytrace=False,
        )
    return read_cred("S43_TARGET_ADMIN_CRED_FILE",
                     purpose="admin-mutation acceptance")


@pytest.fixture
def target_page(page, target_base_url):
    """A page pointed at the real target. Collects TLS/cert request failures so
    a silent certificate problem fails the test instead of being ignored."""
    tls_errors: list[str] = []

    def _on_failed(r):
        f = str(getattr(r, "failure", "") or "").upper()
        if "CERT" in f or "SSL" in f:
            tls_errors.append(f"{r.url} :: {r.failure}")

    page.on("requestfailed", _on_failed)
    page._s43_tls_errors = tls_errors  # type: ignore[attr-defined]
    return page
