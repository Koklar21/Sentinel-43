# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_package_integrity.py
#
# Repository/package integrity gate. Added after PR #254, which found 9 broken
# import chains and one module (core/audit/store.py) that imported fine but
# had been silently overwritten with unrelated code.
#
# This suite proves, on every commit:
#
#   1. every importable module under core/ (+ dashboard/, migrations/) imports
#      -- catches case-sensitive filename/import mismatches, phantom package
#      names, broken lazy-loader targets, missing modules, syntax corruption.
#   2. known-critical modules define their minimum public contract -- import
#      success alone did NOT catch the audit-store defect.
#   3. no two distinct modules share byte-identical body content -- the exact
#      shape of the audit-store / request_context defects.
#
# Modules that cannot be safely imported during collection (destructive
# side effects, or an execution-context-only module) are listed in
# _IMPORT_EXCLUDE with a reason.
# =============================================================================

from __future__ import annotations

import hashlib
import importlib
import pathlib
import pkgutil

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]

# --------------------------------------------------------------------------- #
# 1. import sweep
# --------------------------------------------------------------------------- #
_IMPORT_ROOTS = ("core", "dashboard", "migrations")

# name -> reason. Documented, not silent.
_IMPORT_EXCLUDE = {
    "migrations.env": "only runs inside Alembic's execution context (uses alembic.context.config)",
}


def _walk_importable() -> list[str]:
    names: list[str] = []
    for root in _IMPORT_ROOTS:
        root_path = _ROOT / root
        if not root_path.is_dir():
            continue
        for m in pkgutil.walk_packages([str(root_path)], prefix=root + "."):
            name = m.name
            if name in _IMPORT_EXCLUDE:
                continue
            if ".tests" in name or ".test_" in name or name.endswith(".conftest"):
                continue
            if name.endswith(".__main__"):
                continue
            names.append(name)
    return sorted(set(names))


_MODULES = _walk_importable()


def test_import_sweep_found_a_reasonable_module_count():
    # A hard floor so a broken walk (empty list) can't make the sweep vacuously pass.
    assert len(_MODULES) > 80, f"only discovered {len(_MODULES)} modules -- walk is broken"


@pytest.mark.parametrize("modname", _MODULES)
def test_module_imports(modname):
    try:
        mod = importlib.import_module(modname)
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"{modname} failed to import: {type(exc).__name__}: {exc}")

    # Belt-and-suspenders for case-sensitive path/import correctness: the file
    # backing the module must match the imported name case-exactly. (Python's
    # own import already enforces this on both Linux and Windows, but assert it
    # so the intent is explicit and a future importlib change can't mask it.)
    f = getattr(mod, "__file__", None)
    if f and pathlib.Path(f).name not in ("__init__.py", "__init__.pyc"):
        assert pathlib.Path(f).stem == modname.rsplit(".", 1)[-1], (
            f"{modname} is backed by {pathlib.Path(f).name} -- case mismatch"
        )


# --------------------------------------------------------------------------- #
# 2. minimum public contract for known-critical modules
#    (import success != the module contains what it is supposed to)
# --------------------------------------------------------------------------- #
_MIN_SYMBOLS = {
    # PR #254 defect list -- cross-checked against the import sweep's own record.
    "core.config": ["get_settings"],
    "core.audit.store": ["AuditStore", "AuditConfig"],
    # core.security.fenrir_auth was rewritten to a principal-based contract.
    "core.security.fenrir_auth": [
        "FenrirPrincipal", "FenrirAuthorizationError", "extract_bearer_token",
        "principal_from_authenticated_claims", "require_fenrir_scope",
    ],
    "core.detection": [
        "ThreatAssessment", "ThreatKind", "ThreatSeverity", "ThreatSourceKind",
        "SentinelThreatDetector", "DetectorConfig", "EventContext",
    ],
    "core.detection.sentinel_threat_types": ["ThreatAssessment", "ThreatKind"],
    "core.detection.sentinel_threat_detector": ["SentinelThreatDetector", "EventContext"],
    "core.guards.exceptions.expectations": [
        "BaseExpectation", "get_default_expectations",
        "get_basic_expectations", "get_hardened_expectations", "get_sentinel43_expectations",
    ],
    "core.guards.exceptions": [
        "BaseExpectation", "CoreStartupExpectation", "get_default_expectations",
        "ExpectationContract", "SentinelError",
    ],
    # core.audit now surfaces the authoritative SQLite/HMAC store + JSONL
    # mirror; the historical AuditEvent/AuditLogger logger API is gone.
    "core.audit": ["AuditStore", "AuditConfig", "AuditJsonlMirror"],
    # The governance composition builder moved to the package root
    # (core.governance / core.governance.composition); orchestrator.py keeps
    # the orchestrator + mode enum.
    "core.governance": ["build_orchestrator_from_settings", "SystemOrchestrator"],
    "core.governance.orchestrator": ["SystemOrchestrator", "GovernanceMode"],
    "core.policy_gate": ["GovernanceMode", "GovernanceAction", "PolicyContext", "evaluate"],
}


@pytest.mark.parametrize("modname,symbols", sorted(_MIN_SYMBOLS.items()))
def test_module_defines_minimum_symbols(modname, symbols):
    mod = importlib.import_module(modname)
    missing = [s for s in symbols if not hasattr(mod, s)]
    assert not missing, f"{modname} is missing expected public symbols: {missing}"


def test_audit_store_is_usable_not_just_importable(tmp_path):
    """The audit-store defect: store.py imported fine while being unrelated
    code. Prove the real contract -- construct and append."""
    from core.audit.store import AuditStore, AuditConfig

    cfg = AuditConfig(
        sqlite_path=tmp_path / "audit.db",
        jsonl_path=None,
        signing_key="integrity-test-signing-key-0123456789abcdef",
    )
    store = AuditStore(cfg)
    # append() is the operation core/governance/orchestrator.py relies on.
    assert hasattr(store, "append")
    # Production lifecycle: core.api.main._start_audit_store() calls
    # initialize() (schema + integrity verification) before any append().
    store.initialize()
    rec = store.append({"event": "integrity_test", "n": 1})
    assert rec is not None


def test_core_monitoring_lazy_exports_resolve():
    """The lazy loader in core/monitoring/__init__.py had two wrong candidate
    module paths (fixed in PR #254)."""
    import core.monitoring as cm

    for name in ("SpartaCore", "IntegrityConfig", "create_node_router",
                 "build_jormungandr", "SentinelWindowStore", "SentinelWindowConfig"):
        assert getattr(cm, name) is not None, f"core.monitoring.{name} did not resolve"


def test_fenrir_auth_exposes_its_canonical_contract():
    """PR #253 deleted core/s34_auth/; fenrir_auth was restored at
    core/security/fenrir_auth.py with the principal-based contract that is the
    canonical Fenrir service-identity surface."""
    import core.security.fenrir_auth as fa

    for name in ("FenrirPrincipal", "FenrirAuthorizationError",
                 "extract_bearer_token", "principal_from_authenticated_claims",
                 "require_fenrir_scope", "require_fenrir_role"):
        assert hasattr(fa, name), f"core.security.fenrir_auth lost {name}"


def test_dashboard_state_singletons_present():
    import dashboard.state as ds

    for name in ("audit_state", "health_state", "remote_state",
                 "watchtower_state", "dashboard_state"):
        assert getattr(ds, name) is not None


def test_runtime_logging_import_path_is_lowercase():
    import core.runtime  # noqa: F401  -- would raise on the old `from Core...`


# --------------------------------------------------------------------------- #
# 3. content-duplication sweep -- permanent, not one-time
# --------------------------------------------------------------------------- #
_DUP_SCAN_ROOTS = ("core", "dashboard", "migrations", "scripts", "browser_tests")
_MIN_BODY_CHARS = 200  # ignore empty __init__.py / trivial stubs


def _stripped_body(path: pathlib.Path) -> str:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    i = 0
    while i < len(lines) and (lines[i].strip().startswith("#") or not lines[i].strip()):
        i += 1
    return "\n".join(lines[i:]).strip()


def test_no_two_modules_share_identical_body():
    """core/audit/store.py was overwritten with a byte-identical copy of
    core/guards/velocity.py and nothing noticed. core/api/middleware/
    request_context.py was a byte-identical copy of core/middleware/
    request_context.py. Neither must recur."""
    by_hash: dict[str, list[str]] = {}
    scanned = 0
    for root in _DUP_SCAN_ROOTS:
        for p in (_ROOT / root).rglob("*.py"):
            if "__pycache__" in p.parts:
                continue
            scanned += 1
            body = _stripped_body(p)
            if len(body) < _MIN_BODY_CHARS:
                continue
            h = hashlib.sha256(body.encode()).hexdigest()
            by_hash.setdefault(h, []).append(str(p.relative_to(_ROOT)))

    assert scanned > 120, f"duplication scan only saw {scanned} files"
    dupes = {h: ps for h, ps in by_hash.items() if len(ps) > 1}
    assert not dupes, (
        "distinct modules share byte-identical body content (header stripped) -- "
        "one has almost certainly been overwritten with the wrong file: "
        + "; ".join(" == ".join(ps) for ps in dupes.values())
    )
