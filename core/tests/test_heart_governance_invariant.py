# =============================================================================
# Sentinel-43 -- the Heart requires governance, everywhere it is configured
#
# The Heart reports evidence; the governance orchestrator is the only
# authority that stages or resolves a decision from it. So
#
#     S43_HEART_ENABLED=true  with  S43_GOVERNANCE_ENABLED=false
#
# is a configuration error, not a degraded mode. These tests hold that
# invariant at every layer an operator can get it wrong: the shipped Compose
# and Kubernetes configuration, the deployment preflight (before the deploy
# and again against the running process), and the application itself.
#
# Governance is deliberately never auto-enabled to "fix" the combination:
# enabling an authority is the operator's decision.
#
# No network, no skips.
# =============================================================================
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_preflight():
    spec = importlib.util.spec_from_file_location(
        "deploy_preflight", REPO_ROOT / "scripts" / "deploy_preflight.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # dataclasses resolves annotations through sys.modules, so the module has
    # to be registered before it executes.
    sys.modules["deploy_preflight"] = module
    spec.loader.exec_module(module)
    return module


preflight = _load_preflight()


class _Rep:
    """Minimal stand-in for the preflight Report: records (status, name)."""

    def __init__(self) -> None:
        self.rows: list[tuple[str, str]] = []

    def record(self, status, name, detail="") -> None:
        self.rows.append((status, name))

    def status_of(self, fragment: str):
        for status, name in self.rows:
            if fragment in name:
                return status
        return None


# ---------------------------------------------------------------------------
# The application refuses to start on the invalid combination
# ---------------------------------------------------------------------------
def _validate(monkeypatch, *, heart: str, governance: str):
    """The real _validate_security_config, with the unrelated startup
    requirements satisfied so only this invariant decides the outcome."""
    import core.api.main as main_module

    # Read at import time, so the module attribute is what the check sees.
    # IS_LOCAL_ENV=True takes the non-local production requirements (trusted
    # hosts, TLS assertions, secrets) out of the way: this invariant is NOT
    # one of them -- it holds in every environment, which is what the
    # local-environment cases below prove.
    monkeypatch.setattr(main_module, "JWT_SECRET", "x" * 48, raising=False)
    monkeypatch.setattr(main_module, "IS_LOCAL_ENV", True, raising=False)
    monkeypatch.setenv("S43_HEART_ENABLED", heart)
    monkeypatch.setenv("S43_GOVERNANCE_ENABLED", governance)
    return main_module._validate_security_config


def test_an_enabled_heart_without_governance_refuses_to_start(monkeypatch):
    validate = _validate(monkeypatch, heart="true", governance="false")
    with pytest.raises(RuntimeError) as exc:
        validate()
    message = str(exc.value)
    # The reason must be actionable, naming both flags and the way out.
    assert "S43_HEART_ENABLED" in message
    assert "S43_GOVERNANCE_ENABLED=true" in message
    assert "no decision authority of its own" in message


def test_the_invariant_holds_when_governance_is_merely_unset(monkeypatch):
    validate = _validate(monkeypatch, heart="true", governance="")
    with pytest.raises(RuntimeError, match="S43_GOVERNANCE_ENABLED=true"):
        validate()


@pytest.mark.parametrize(
    "heart,governance",
    [("true", "true"), ("false", "false"), ("false", "true")],
)
def test_every_other_combination_starts(monkeypatch, heart, governance):
    _validate(monkeypatch, heart=heart, governance=governance)()


def test_governance_is_never_auto_enabled_behind_the_operator(monkeypatch):
    """The app refuses; it does not quietly turn governance on."""
    import os

    validate = _validate(monkeypatch, heart="true", governance="false")
    with pytest.raises(RuntimeError):
        validate()
    assert os.environ["S43_GOVERNANCE_ENABLED"] == "false"


# ---------------------------------------------------------------------------
# Preflight detects it BEFORE the deployment goes out (prepare phase)
# ---------------------------------------------------------------------------
_INVARIANT = "S43_HEART_ENABLED=true is accompanied by S43_GOVERNANCE_ENABLED=true"


def _compose_env(**overrides) -> dict[str, str]:
    env = {
        "S43_REJECT_LEGACY_AUTH": "true",
        "S43_HEART_ENABLED": "true",
        "S43_GOVERNANCE_ENABLED": "true",
        "S43_GOVERNANCE_REQUIRED": "true",
    }
    env.update(overrides)
    return env


def test_preflight_fails_the_prepare_phase_on_the_invalid_combination():
    rep = _Rep()
    preflight.check_app_flag_invariants(
        rep, _compose_env(S43_GOVERNANCE_ENABLED="false")
    )
    assert rep.status_of(_INVARIANT) == preflight.FAIL
    assert rep.status_of("S43_GOVERNANCE_ENABLED is true") == preflight.FAIL


def test_preflight_passes_the_prepare_phase_when_both_are_set():
    rep = _Rep()
    preflight.check_app_flag_invariants(rep, _compose_env())
    assert rep.status_of(_INVARIANT) == preflight.PASS
    assert rep.status_of("S43_GOVERNANCE_ENABLED is true") == preflight.PASS


def test_preflight_fails_when_a_governance_failure_would_be_tolerated():
    """S43_GOVERNANCE_REQUIRED=false would let the target serve ungoverned
    with /ready true. That is not a supported beta deployment."""
    rep = _Rep()
    preflight.check_app_flag_invariants(
        rep, _compose_env(S43_GOVERNANCE_REQUIRED="false")
    )
    assert rep.status_of("S43_GOVERNANCE_REQUIRED is not disabled") == preflight.FAIL


def test_preflight_treats_an_unset_required_flag_as_the_safe_default():
    rep = _Rep()
    env = _compose_env()
    env.pop("S43_GOVERNANCE_REQUIRED")
    preflight.check_app_flag_invariants(rep, env)
    assert rep.status_of("S43_GOVERNANCE_REQUIRED is not disabled") == preflight.PASS


def test_the_verify_phase_inspects_the_running_process():
    """Not a file on disk: a target can drift after deploy."""
    assert hasattr(preflight, "check_compose_governance_runtime")
    assert hasattr(preflight, "check_kube_governance_runtime")


# ---------------------------------------------------------------------------
# The shipped deployment configuration satisfies the invariant
# ---------------------------------------------------------------------------
def test_the_beta_kubernetes_overlay_enables_both():
    patch = yaml.safe_load(
        (
            REPO_ROOT
            / "deploy"
            / "kubernetes"
            / "overlays"
            / "beta"
            / "configmap-patch.yaml"
        ).read_text(encoding="utf-8")
    )
    data = patch["data"]
    assert data["S43_HEART_ENABLED"] == "true"
    assert data["S43_GOVERNANCE_ENABLED"] == "true"
    assert data["S43_HEART_REQUIRED"] == "true"
    assert data["S43_GOVERNANCE_REQUIRED"] == "true"


def test_the_base_kubernetes_configmap_disables_both():
    """The base is the non-beta default: neither is on, which is valid."""
    config = yaml.safe_load(
        (REPO_ROOT / "deploy" / "kubernetes" / "base" / "configmap.yaml").read_text(
            encoding="utf-8"
        )
    )
    data = config["data"]
    assert data.get("S43_GOVERNANCE_ENABLED", "false") == "false"
    assert data.get("S43_HEART_ENABLED", "false") == "false"


def test_compose_declares_governance_so_an_env_value_reaches_the_api():
    """Compose passes only DECLARED variables: an undeclared flag in .env
    never reaches the process, which is how this invariant was violated in a
    deployment that looked correctly configured."""
    compose = yaml.safe_load(
        (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    )
    environment = compose["services"]["s43-api"]["environment"]
    for flag in (
        "S43_HEART_ENABLED",
        "S43_GOVERNANCE_ENABLED",
        "S43_GOVERNANCE_REQUIRED",
    ):
        assert flag in environment, f"{flag} is not declared for s43-api"


def test_compose_defaults_are_a_valid_combination():
    """Local dev stays deliberate: both default off, which starts."""
    compose = yaml.safe_load(
        (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    )
    environment = compose["services"]["s43-api"]["environment"]
    assert environment["S43_HEART_ENABLED"] == "${S43_HEART_ENABLED:-false}"
    assert environment["S43_GOVERNANCE_ENABLED"] == "${S43_GOVERNANCE_ENABLED:-false}"


def test_the_env_example_states_the_requirement():
    text = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    assert "REQUIRES S43_GOVERNANCE_ENABLED=true" in text


# ---------------------------------------------------------------------------
# PR #294 review remediation: the invariant must hold for malformed values, must
# not fire when the Heart is off, and must be reached from BOTH deployment paths
# (a parallel per-flag implementation once replaced the shared helper).
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("governance", ["maybe", "tru", "2", "enable", ""])
def test_preflight_fails_a_malformed_or_missing_governance_value_with_the_heart_on(governance):
    rep = _Rep()
    preflight.check_app_flag_invariants(rep, _compose_env(S43_GOVERNANCE_ENABLED=governance))
    assert rep.status_of(_INVARIANT) == preflight.FAIL
    assert rep.status_of("S43_GOVERNANCE_ENABLED is true") == preflight.FAIL


@pytest.mark.parametrize("heart", ["false", "0", "off"])
def test_a_disabled_heart_does_not_fail_the_dependency_alone(heart):
    rep = _Rep()
    preflight.check_app_flag_invariants(
        rep, _compose_env(S43_HEART_ENABLED=heart, S43_GOVERNANCE_ENABLED="false"))
    assert rep.status_of(_INVARIANT) == preflight.PASS
    # ...while the independent beta checks still fail closed on each flag.
    assert rep.status_of("S43_HEART_ENABLED is true") == preflight.FAIL
    assert rep.status_of("S43_GOVERNANCE_ENABLED is true") == preflight.FAIL


def test_both_deployment_paths_enforce_the_invariant_through_the_shared_helper():
    import inspect

    assert "check_app_flag_invariants(rep, env)" in inspect.getsource(preflight.check_compose_config)
    assert "check_app_flag_invariants(rep, data)" in inspect.getsource(preflight.check_kube_prereqs)


def _compose_verify_calls(monkeypatch, argv):
    """Run the REAL parser + run() for `compose --phase verify`, recording the file
    list each Compose runtime check actually receives (no docker involved)."""
    calls: dict[str, object] = {}
    monkeypatch.setattr(preflight, "check_hostname_resolves", lambda rep, host: False)
    for name in ("check_compose_runtime", "check_compose_legacy_auth_runtime",
                 "check_compose_governance_runtime", "check_compose_heart_runtime"):
        monkeypatch.setattr(
            preflight, name,
            lambda rep, project, env_file, files, _n=name: calls.__setitem__(_n, list(files)))
    return calls, preflight.main(argv)


def test_the_compose_file_argument_really_parses_to_compose_files():
    args = preflight.build_parser().parse_args(
        ["compose", "--phase", "verify", "-f", "a.yml", "--compose-file", "b.yml"])
    assert args.compose_files == ["a.yml", "b.yml"]
    assert not hasattr(args, "file")  # the attribute the old code (wrongly) read


def test_compose_verify_passes_the_parsed_file_list_to_every_runtime_check(monkeypatch, capsys):
    calls, _ = _compose_verify_calls(
        monkeypatch, ["compose", "--phase", "verify", "-f", "a.yml", "-f", "b.yml"])
    assert set(calls) == {"check_compose_runtime", "check_compose_legacy_auth_runtime",
                          "check_compose_governance_runtime", "check_compose_heart_runtime"}
    assert all(files == ["a.yml", "b.yml"] for files in calls.values()), calls


def test_compose_verify_never_reads_a_nonexistent_args_file(monkeypatch, capsys):
    # With the old `args.file` this raised AttributeError before reaching the check.
    try:
        _compose_verify_calls(monkeypatch, ["compose", "--phase", "verify"])
    except AttributeError as exc:  # pragma: no cover - the regression being guarded
        pytest.fail(f"compose verify raised AttributeError: {exc}")
