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


def test_recommendation_audit_names_sentinel43_as_authority():
    source = (
        CORE / "governance" / "orchestrator.py"
    ).read_text(encoding="utf-8")

    assert (
        'RECOMMENDATION_AUTHORITY: Final[str] = '
        '"sentinel43_runtime_authority"'
    ) in source
    assert (
        'RECOMMENDATION_AUTHORITY: Final[str] = "system_orchestrator"'
        not in source
    )


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


def test_bounded_audit_reads_use_the_canonical_orchestrator_store():
    """Recovery-facing audit reads must use the store actually owned by the
    subordinate orchestrator, never a nonexistent shadow attribute."""
    source = (
        CORE / "governance" / "orchestrator.py"
    ).read_text(encoding="utf-8")

    assert "self._audit_store" not in source
    assert "self.audit_store.verify_integrity()" in source
    assert "self.audit_store.get_records(" in source
    assert "self.audit_store.get_records_without_component(" in source


def test_api_composition_root_has_only_the_sentinel43_authority_handle():
    """The API hosts one authority and exposes no subordinate orchestrator
    runtime alias that future callers could mistake for a second entry path."""
    source = (CORE / "api" / "main.py").read_text(encoding="utf-8")
    assert "runtime.sentinel43 = build_runtime_authority_from_settings(" in source
    assert "runtime.orchestrator" not in source
    assert "orchestrator: Any | None" not in source


def test_identity_authority_survives_decision_governance_disablement():
    """Disabling recommendation governance must not remove the authority that
    owns first-admin, user-management, and session mutations."""
    api_source = (CORE / "api" / "main.py").read_text(encoding="utf-8")
    authority_source = (
        CORE / "governance" / "runtime_authority.py"
    ).read_text(encoding="utf-8")
    composition_source = (
        CORE / "governance" / "composition.py"
    ).read_text(encoding="utf-8")

    assert "decision_governance_enabled = _env_bool" in api_source
    assert "governance_enabled = decision_governance_enabled" in api_source
    assert "runtime.subsystems.mark_disabled(SUBSYS_GOVERNANCE)" in api_source
    assert "def governance_enabled(self) -> bool" in authority_source
    assert "governance_enabled=bool(_get(settings, \"governance_enabled\", True))" in composition_source
    assert "or not runtime.sentinel43.governance_enabled" in api_source


def test_runtime_authority_loads_all_owner_components():
    source = (
        CORE / "governance" / "runtime_authority.py"
    ).read_text(encoding="utf-8")
    loader = (
        CORE / "governance" / "owner_components.py"
    ).read_text(encoding="utf-8")

    assert "load_owner_runtime_components(self)" in source
    for filename, class_name in (
        ("Sentinel_Nexus.py", "SentinelNexus"),
        ("Sentinel_core.py", "SentinelNode"),
        ("sentinel_AI_escalation.py", "SentinelAIEscalation"),
    ):
        assert filename in loader
        assert class_name in loader


def test_ai_escalation_uses_the_canonical_threat_types():
    source = (
        REPO_ROOT / "Sentinel-43" / "sentinel_AI_escalation.py"
    ).read_text(encoding="utf-8")

    assert "from core.detection.sentinel_threat_types import (" in source
    assert "class ThreatAssessment" not in source
    assert "class ThreatKind" not in source
    assert "class ThreatSeverity" not in source
    assert "class ThreatSourceKind" not in source


def test_ai_escalation_preserves_provenance_without_owning_state_or_execution():
    source = (
        REPO_ROOT / "Sentinel-43" / "sentinel_AI_escalation.py"
    ).read_text(encoding="utf-8")

    assert 'AI_ESCALATION_PROVENANCE_KEY = "ai_escalation"' in source
    assert "assessment_fingerprint" in source
    assert "replace(" in source
    assert "MappingProxyType" in source

    # The owner escalation contract enriches evidence only. Re-introducing
    # its historical private store/executor would create a second authority.
    for forbidden in (
        "import sqlite3",
        "SqliteActionStore",
        "threading.Thread",
        "ExecutorThread",
        "execute_at_ms",
    ):
        assert forbidden not in source


def test_public_recommendation_path_crosses_the_nexus():
    authority_source = (
        CORE / "governance" / "runtime_authority.py"
    ).read_text(encoding="utf-8")
    nexus_source = (
        REPO_ROOT / "Sentinel-43" / "Sentinel_Nexus.py"
    ).read_text(encoding="utf-8")

    assert "self._owner_components.nexus.submit_recommendation" in authority_source
    assert "self._owner_components.nexus.resolve_recommendation" in authority_source
    assert "_stage_recommendation_from_nexus" in nexus_source
    assert "_resolve_recommendation_from_nexus" in nexus_source


def test_nexus_owns_one_fail_closed_integration_boundary():
    nexus_source = (
        REPO_ROOT / "Sentinel-43" / "Sentinel_Nexus.py"
    ).read_text(encoding="utf-8")
    authority_source = (
        CORE / "governance" / "runtime_authority.py"
    ).read_text(encoding="utf-8")

    assert "self._integration = IntegrationHub()" in nexus_source
    assert "def describe_integration_boundary(" in nexus_source
    assert "def execute_external_effect(" in nexus_source
    assert "direct external execution is not supported" in nexus_source

    assert "nexus.describe_integration_boundary()" in authority_source
    assert '"integration_boundary": integration' in authority_source
    assert '"external_execution_supported": False' not in authority_source


def test_owner_components_cannot_reach_the_subordinate_orchestrator():
    """Owner components enter through Sentinel43RuntimeAuthority, including
    read-only mode discovery; the subordinate governor is not exposed."""
    authority_source = (
        CORE / "governance" / "runtime_authority.py"
    ).read_text(encoding="utf-8")

    assert "def orchestrator(" not in authority_source
    assert "def governance_mode(" in authority_source

    for relative in (
        "Sentinel-43/Sentinel_Nexus.py",
        "Sentinel-43/Sentinel_core.py",
        "Sentinel-43/sentinel_AI_escalation.py",
    ):
        source = (REPO_ROOT / relative).read_text(encoding="utf-8")
        assert "authority.orchestrator" not in source
        assert ".governance_mode" in source


def test_the_only_engine_class_loaded_is_the_owner_response_engine():
    from core.governance.sentinel43_engine import ENGINE_CLASS_NAME

    assert ENGINE_CLASS_NAME == "Sentinel43ResponseEngine"


def test_runtime_authority_has_one_canonical_governance_flag():
    source = (
        CORE / "governance" / "runtime_authority.py"
    ).read_text(encoding="utf-8")

    assert "self._governance_enabled = bool(governance_enabled)" in source
    assert "return self._governance_enabled" in source
    assert "if not self._governance_enabled:" in source
    assert "self._decision_governance_enabled" not in source

def test_runtime_authority_owns_the_monitoring_manager():
    authority_source = (
        CORE / "governance" / "runtime_authority.py"
    ).read_text(encoding="utf-8")
    composition_source = (
        CORE / "governance" / "composition.py"
    ).read_text(encoding="utf-8")
    api_source = (
        CORE / "api" / "main.py"
    ).read_text(encoding="utf-8")

    assert "self._monitoring_manager = monitoring_manager" in authority_source
    assert "def monitoring_manager(" in authority_source
    assert "monitoring_manager=monitoring_manager" in composition_source
    assert (
        "runtime.monitoring_manager = runtime.sentinel43.monitoring_manager"
        in api_source
    )
    assert (
        "runtime.sentinel43 is None and runtime.monitoring_manager is not None"
        in api_source
    )


# ---------------------------------------------------------------------------
# 2 + 3. The Heart and the detection stack are evidence layers only
# ---------------------------------------------------------------------------
def test_sigma_detector_has_no_authority_or_enforcement_dependency():
    """Sigma is a deterministic evidence producer, never a control plane."""
    source = (
        CORE / "detection" / "sigma_detector.py"
    ).read_text(encoding="utf-8")

    forbidden_imports = (
        "runtime_authority",
        "governance.heart",
        "governance.orchestrator",
        "sentinel43_engine",
        "monitoring.watchtower",
        "subprocess",
    )
    assert all(name not in source for name in forbidden_imports)
    for verb in (
        "stage_recommendation",
        "resolve_recommendation",
        "approve",
        "veto",
        "quarantine",
        "kill_process",
        "terminate_container",
        "execute_external_effect",
        "transition_status",
        "insert_pending",
    ):
        assert verb not in _calls_in(CORE / "detection" / "sigma_detector.py")


@pytest.mark.parametrize(
    "module",
    [
        "core/governance/heart.py",
        "core/detection/sentinel_threat_detector.py",
        "core/detection/sigma_detector.py",
        "core/detection/fenrir_hunter.py",
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


def test_fenrir_reports_through_s43_authority_not_heart_directly():
    fenrir = (
        CORE / "detection" / "fenrir_hunter.py"
    ).read_text(encoding="utf-8")
    authority = (
        CORE / "governance" / "runtime_authority.py"
    ).read_text(encoding="utf-8")
    api = (
        CORE / "api" / "main.py"
    ).read_text(encoding="utf-8")

    assert "self.heart" not in fenrir
    assert "heart.observe" not in fenrir
    assert "authority.observe_threat" in fenrir

    assert "def attach_heart(" in authority
    assert "def observe_threat(" in authority
    assert "def threat_ingress_available(" in authority
    assert "self._owner_components.ai_escalation.build_envelope(" in authority
    assert "envelope.assessment" in authority
    assert "mode=envelope.requested_mode.value" in authority

    assert "runtime.sentinel43.attach_heart(runtime.heart)" in api
    assert "runtime.fenrir_instance.heart" not in api

    heart_index = api.index("await _start_heart()")
    fenrir_index = api.index("await _start_fenrir()")
    assert heart_index < fenrir_index


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


def test_heart_recovery_reads_audit_through_s43_not_the_store():
    authority_source = (
        CORE / "governance" / "runtime_authority.py"
    ).read_text(encoding="utf-8")
    api_source = (
        CORE / "api" / "main.py"
    ).read_text(encoding="utf-8")

    for method in (
        "def verify_audit_integrity(",
        "def get_audit_records(",
        "def get_legacy_audit_records(",
    ):
        assert method in authority_source

    recovery_start = api_source.index("async def _rehydrate_heart_pending()")
    recovery_end = api_source.index("\nasync def ", recovery_start + 20)
    recovery = api_source[recovery_start:recovery_end]

    assert "authority.verify_audit_integrity" in recovery
    assert "authority.get_audit_records" in recovery
    assert "_legacy_heart_audit_index, authority" in recovery
    assert "authority.audit_store" not in recovery


def test_identity_mutations_enter_the_runtime_authority():
    bootstrap = (
        CORE / "api" / "routers" / "bootstrap.py"
    ).read_text(encoding="utf-8")
    users = (
        CORE / "api" / "routers" / "users.py"
    ).read_text(encoding="utf-8")

    bootstrap_calls = _calls_in(CORE / "api" / "routers" / "bootstrap.py")
    assert "bootstrap_first_admin" in bootstrap_calls
    assert "create_first_admin" not in bootstrap_calls

    for call in (
        "authority.identity.create_account(",
        "authority.identity.update_account(",
        "authority.identity.reset_password(",
    ):
        assert call in users

    for forbidden in (
        "create_user(",
        "set_user_active(",
        "set_user_role(",
        "set_user_password(",
    ):
        assert forbidden not in users


def test_session_mutations_enter_the_runtime_authority():
    auth_path = CORE / "api" / "routers" / "auth.py"
    called = _calls_in(auth_path)
    source = auth_path.read_text(encoding="utf-8")

    for governed in (
        "create_login_session",
        "rotate_session_refresh",
        "logout_session_by_refresh",
    ):
        assert governed in called

    assert "authority.identity.create_login_session(" in source
    assert "authority.identity.rotate_session_refresh(" in source
    assert "authority.identity.logout_session_by_refresh(" in source

    for forbidden in (
        "create_session",
        "rotate_refresh",
        "logout_by_refresh",
    ):
        assert forbidden not in called


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
