# =============================================================================
# Sentinel-43 -- the architectural non-regression gate
#
# One question per test, answered from the SHIPPED SOURCE rather than from a
# comment, so that a future change which quietly introduces a second decision
# authority, a bypass, or an autonomous path fails here instead of being
# discovered in review:
#
#   1. What component is the sole decision authority?
#   2. What components are evidence/advisory layers only?
#   3. Can the Heart independently stage or approve a governed decision?
#   4. Can a durable-store caller independently authorize or transition one?
#   5. Can an API route bypass SystemOrchestrator?
#   6. Can a recommendation's action set or target change between review and
#      approval?
#   7. Can any approved recommendation cause autonomous enforcement?
#   8. Does failure of audit/auth/governance/engine integrity fail closed?
#   9. Is the owner engine the exact version whose integrity was reviewed?
#  10. Is there any second runtime decision engine?
#
# Behavioural proof of most of these lives in test_heart_recovery.py; this
# file is the structural gate over the source itself. No network, no skips.
# =============================================================================
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE = REPO_ROOT / "core"

#: Every production module (the tests themselves are not the system).
PRODUCTION_SOURCES = sorted(
    path
    for path in CORE.rglob("*.py")
    if "tests" not in path.parts and "__pycache__" not in path.parts
)


def _calls_in(path: Path) -> set[str]:
    """Every attribute/function name called in one module."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                names.add(func.attr)
            elif isinstance(func, ast.Name):
                names.add(func.id)
    return names


def _modules_calling(name: str) -> set[str]:
    return {
        str(path.relative_to(REPO_ROOT)).replace("\\", "/")
        for path in PRODUCTION_SOURCES
        if name in _calls_in(path)
    }


# ---------------------------------------------------------------------------
# 1 + 10. One decision authority, and no second decision engine
# ---------------------------------------------------------------------------
def test_only_the_owner_engines_store_adapter_creates_a_pending_decision():
    """A governed decision comes into existence in exactly one place: the
    engine's own stage_directive, through its ActionStore adapter."""
    assert _modules_calling("insert_pending") == {
        "core/governance/sentinel43_engine.py",
    }


def test_only_the_authority_and_its_engine_transition_a_decision():
    """Nothing else moves a decision between states."""
    assert _modules_calling("transition_status") == {
        "core/governance/orchestrator.py",
        "core/governance/sentinel43_engine.py",
    }


def test_no_second_decision_engine_is_constructed():
    """The historical alternates carry their own pending queues, approval
    paths and executors. Referring to one in a comment is fine; constructing
    one is a second authority."""
    forbidden = (
        "OversightEngine",
        "SentinelNexus",
        "IntegrationHub",
        "SqliteActionStore",
    )
    offenders: list[str] = []
    for path in PRODUCTION_SOURCES:
        called = _calls_in(path)
        for name in forbidden:
            if name in called:
                offenders.append(f"{path.name} constructs {name}")
    assert offenders == []


def test_sentinel43_runtime_authority_owns_engine_construction():
    """The owner engine is constructed by Sentinel-43 itself, never by the
    subordinate SystemOrchestrator."""
    authority_source = (
        CORE / "governance" / "runtime_authority.py"
    ).read_text(encoding="utf-8")
    orchestrator_source = (
        CORE / "governance" / "orchestrator.py"
    ).read_text(encoding="utf-8")

    assert "GovernedEngine(" in authority_source
    assert "GovernedEngine(" not in orchestrator_source
    assert "bind_recommendation_runtime(" in orchestrator_source


def test_api_composition_root_enters_sentinel43_authority():
    """The API hosts Sentinel-43; it does not construct an independent
    SystemOrchestrator as the runtime root."""
    source = (CORE / "api" / "main.py").read_text(encoding="utf-8")
    assert "runtime.sentinel43 = build_runtime_authority_from_settings(" in source
    assert "runtime.orchestrator = runtime.sentinel43.orchestrator" in source
    assert "runtime.orchestrator = build_orchestrator_from_settings(" not in source


def test_runtime_authority_loads_all_owner_components():
    source = (
        CORE / "governance" / "runtime_authority.py"
    ).read_text(encoding="utf-8")
    loader = (
        CORE / "governance" / "owner_components.py"
    ).read_text(encoding="utf-8")

    assert "load_owner_runtime_components(self)" in source
    for filename, class_name in (
        ("Sentienal_Nexus.py", "SentinelNexus"),
        ("Sentienal_core.py", "SentinelNode"),
        ("sentinel_AI_escalation.py", "SentinelAIEscalation"),
    ):
        assert filename in loader
        assert class_name in loader


def test_public_recommendation_path_crosses_the_nexus():
    authority_source = (
        CORE / "governance" / "runtime_authority.py"
    ).read_text(encoding="utf-8")
    nexus_source = (
        REPO_ROOT / "Sentinel-43" / "Sentienal_Nexus.py"
    ).read_text(encoding="utf-8")

    assert "self._owner_components.nexus.submit_recommendation" in authority_source
    assert "self._owner_components.nexus.resolve_recommendation" in authority_source
    assert "_stage_recommendation_from_nexus" in nexus_source
    assert "_resolve_recommendation_from_nexus" in nexus_source


def test_the_only_engine_class_loaded_is_the_owner_response_engine():
    from core.governance.sentinel43_engine import ENGINE_CLASS_NAME

    assert ENGINE_CLASS_NAME == "Sentinel43ResponseEngine"


# ---------------------------------------------------------------------------
# 2 + 3. The Heart and the detection stack are evidence layers only
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "module",
    [
        "core/governance/heart.py",
        "core/detection/sentinel_threat_detector.py",
        "core/detection/feniri_hunter.py",
        "core/monitoring/manager.py",
    ],
)
def test_the_evidence_layers_hold_no_decision_verbs(module):
    """None of them creates, transitions, approves or vetoes a decision, and
    none of them evaluates policy: they report what they saw."""
    called = _calls_in(REPO_ROOT / module)
    forbidden = {
        "insert_pending",
        "transition_status",
        "approve_action",
        "veto_action",
        "insert_pending_action",
        "update_action_status",
        "evaluate",
    }
    assert called & forbidden == set()


def test_the_heart_reaches_the_authority_only_through_its_two_entry_points():
    called = _calls_in(REPO_ROOT / "core/governance/heart.py")
    assert "stage_recommendation" in called
    assert "resolve_recommendation" in called


# ---------------------------------------------------------------------------
# 4. The durable store is not an authorization path
# ---------------------------------------------------------------------------
def test_the_engine_store_refuses_a_transition_outside_a_governed_decision():
    """Calling the adapter directly authorizes nothing: without the decision
    context that only resolve_recommendation opens, it raises."""
    import inspect

    from core.governance.sentinel43_engine import CoreStoreActionStore

    source = inspect.getsource(CoreStoreActionStore.update_action_status)
    assert "_deciding_principal.get() is None" in source
    assert "PermissionError" in source


def test_the_durable_store_itself_holds_no_authorization_logic():
    """core/sentinel43_core_db.py is storage. It must not decide who may
    transition anything -- that belongs to the authority above it."""
    source = (CORE / "sentinel43_core_db.py").read_text(encoding="utf-8")
    for term in ("operator_authenticator", "is_human", "DecisionPrincipal"):
        assert term not in source


# ---------------------------------------------------------------------------
# 5. No API route bypasses the orchestrator
# ---------------------------------------------------------------------------
def test_exactly_one_place_commits_an_action_status():
    source = (CORE / "api" / "main.py").read_text(encoding="utf-8").splitlines()
    writes = [
        line for line in source if line.strip().startswith('action["status"] =')
    ]
    assert len(writes) == 1, writes


def test_that_place_is_reached_only_after_governance_accepts():
    """_commit_action_status has one caller, and that caller has already put
    the decision through the orchestrator."""
    source = (CORE / "api" / "main.py").read_text(encoding="utf-8")
    calls = source.count("_commit_action_status(")
    assert calls == 2, "expected one definition and one call site"

    tree = ast.parse(source)
    callers = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and "_commit_action_status" in _calls_in_node(node)
    ]
    assert callers == ["_resolve_governance_and_commit_action"]


def _calls_in_node(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
            names.add(child.func.id)
    return names


# ---------------------------------------------------------------------------
# 7. No autonomous enforcement behind an approved decision
# ---------------------------------------------------------------------------
def test_no_production_module_starts_an_executor():
    """The engine's executor thread is contained; nothing else may start one
    on its behalf."""
    for path in PRODUCTION_SOURCES:
        source = path.read_text(encoding="utf-8")
        assert "_executor_loop" not in source or path.name == "sentinel43_engine.py"


def test_the_contained_engine_neutralises_both_execution_paths():
    import inspect

    from core.governance.sentinel43_engine import GovernedEngine

    source = inspect.getsource(GovernedEngine)
    assert "_executor_loop" in source and "_execute_approved_now" in source
    # Both are overridden to return None, and nothing calls an integration.
    assert "return None" in source


def test_execution_claims_are_refused_by_the_store_adapter():
    import inspect

    from core.governance.sentinel43_engine import CoreStoreActionStore

    assert "return False" in inspect.getsource(
        CoreStoreActionStore.mark_pending_executing
    )
    assert "execution is not permitted" in inspect.getsource(
        CoreStoreActionStore.finalize_execution
    )


def test_only_shadow_and_human_gated_modes_exist():
    from core.policy_gate import GovernanceMode

    assert {mode.value for mode in GovernanceMode} == {"SHADOW", "HUMAN_GATED"}


# ---------------------------------------------------------------------------
# 8. Failures fail closed
# ---------------------------------------------------------------------------
def test_an_enabled_heart_without_governance_is_refused_at_startup():
    source = (CORE / "api" / "main.py").read_text(encoding="utf-8")
    assert "S43_HEART_ENABLED=true requires S43_GOVERNANCE_ENABLED=true" in source


def test_recovery_can_only_take_a_row_out_of_reach():
    """Restart recovery never manufactures authority: the one transition it
    may perform is to EXPIRED, which makes a row undecidable."""
    import inspect

    from core.governance.orchestrator import SystemOrchestrator

    source = inspect.getsource(SystemOrchestrator.expire_unverifiable_recommendation)
    assert "ActionStatus.EXPIRED" in source
    assert "APPROVED" not in source


# ---------------------------------------------------------------------------
# 9. The owner engine is the reviewed one
# ---------------------------------------------------------------------------
def test_the_shipped_engine_is_the_reviewed_engine():
    from core.governance.sentinel43_engine import (
        EXPECTED_ENGINE_SHA256,
        engine_digest,
        engine_source_path,
    )

    assert engine_digest(engine_source_path().read_bytes()) == EXPECTED_ENGINE_SHA256


def test_the_authority_does_not_hand_out_its_durable_store():
    """The store's own transition_status has no principal check -- that check
    lives in the engine's adapter, on the one path a decision may take. So
    the authority exposes reads, not the store object."""
    from core.governance.orchestrator import SystemOrchestrator

    assert not hasattr(SystemOrchestrator, "recommendation_store")
    assert hasattr(SystemOrchestrator, "list_incidents")

    # No module reads the store off the authority as an attribute.
    tree = ast.parse((CORE / "api" / "main.py").read_text(encoding="utf-8"))
    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert "recommendation_store" not in attributes
