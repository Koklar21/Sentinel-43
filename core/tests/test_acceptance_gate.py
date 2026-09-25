# =============================================================================
# Adversarial tests for the zero-skip acceptance recorder and gate
# (scripts/acceptance_recorder.py, scripts/acceptance_gate.py).
#
# Each scenario builds a small synthetic project, runs the REAL pipeline
# (inventory -> inventory-all -> run-job -> run-check -> verify) through the gate
# CLI, and asserts that verify refuses to produce a PASS -- for
# skip/xfail/xpass/errors/collection problems/config-level deselection or
# omission -- or, for the tampering scenarios, that a doctored copy of an
# otherwise-good evidence directory is rejected.
#
# Limits are stated, not hidden: an adversary who can rewrite every artifact
# AND recompute every hash can forge anything, because the gate is a local
# consistency checker, not a signature scheme. These tests cover accidental and
# careless corruption: missing, empty, stale, mixed, truncated, duplicated,
# narrowed and hand-edited evidence.
# =============================================================================

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
GATE = REPO / "scripts" / "acceptance_gate.py"
GOOD = {
    "tests/test_a.py": "def test_one():\n    assert True\n\ndef test_two():\n    assert 1 + 1 == 2\n",
    "tests/test_b.py": "def test_three():\n    assert True\n",
}
MANIFEST = {
    "test_globs": ["test_*.py"],
    "ignored_dirs": [".git", "__pycache__"],
    "jobs": {
        "unit": {"kind": "pytest", "python": "main", "paths": ["tests"], "ignore": [], "env": {}, "requires_env": []},
        "lint": {"kind": "check", "evidence": {"cmd_contains": ["mycheck"]}},
    },
}


def _run(root: Path, out: Path, *args: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("S43_")}
    env["S43_ACC_ROOT"] = str(root)
    return subprocess.run([sys.executable, str(GATE), *args], cwd=root, env=env,
                          capture_output=True, text=True, encoding="utf-8", errors="replace")


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=root, check=True,
                   capture_output=True)


def build(tmp: Path, files: dict[str, str], *, ini: str | None = None, manifest: dict | None = None,
          run_check: bool = True) -> tuple[Path, Path, subprocess.CompletedProcess]:
    root, out = tmp / "proj", tmp / "out"
    for rel, body in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body, encoding="utf-8")
    if ini:
        (root / "pytest.ini").write_text(ini, encoding="utf-8")
    (root / "acceptance").mkdir(exist_ok=True)
    (root / "acceptance" / "suites.json").write_text(json.dumps(manifest or MANIFEST), encoding="utf-8")
    _git(root.parent if False else root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "x")
    _run(root, out, "inventory", "--out", str(out))
    _run(root, out, "inventory-all", "--out", str(out))
    _run(root, out, "run-job", "unit", "--out", str(out))
    if run_check:
        _run(root, out, "run-check", "--out", str(out), "lint", "--", sys.executable, "-c", "pass", "mycheck")
    return root, out, _run(root, out, "verify", "--out", str(out), "--mode", "final-beta")


@pytest.fixture(scope="module")
def good(tmp_path_factory):
    root, out, result = build(tmp_path_factory.mktemp("good"), GOOD)
    assert result.returncode == 0, result.stdout + result.stderr
    return root, out


def clone(good, tmp_path: Path) -> tuple[Path, Path]:
    root, out = tmp_path / "proj", tmp_path / "out"
    shutil.copytree(good[0], root)
    shutil.copytree(good[1], out)
    return root, out


def verify(root: Path, out: Path, mode: str = "final-beta") -> tuple[bool, str]:
    r = _run(root, out, "verify", "--out", str(out), "--mode", mode)
    return r.returncode == 0, r.stdout + r.stderr


def edit_json(path: Path, fn) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    fn(data)
    path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")


def rebind(out: Path) -> None:
    """A careful forger: recompute the hashes the job meta binds to."""
    meta = out / "jobs" / "unit.meta.json"
    res, inv = out / "jobs" / "unit.results.json", out / "inventory" / "unit.json"
    edit_json(meta, lambda m: m.update(results_sha256=hashlib.sha256(res.read_bytes()).hexdigest(),
                                       inventory_sha256=hashlib.sha256(inv.read_bytes()).hexdigest()))


def test_baseline_passes_and_reports_unique_vs_executions(good):
    root, out = good
    verdict = json.loads((out / "verdict.json").read_text(encoding="utf-8"))
    assert verdict["verdict"] == "FINAL-BETA ACCEPTANCE PASS"
    assert verdict["mode"] == "final-beta" and verdict["final_beta_acceptance"] == "PASS"
    assert verdict["unique_tests_collected"] == verdict["unique_tests_qualified"] == 3
    assert verdict["total_test_executions"] == 3


# ------------------------------------------------------ real pipeline scenarios
@pytest.mark.parametrize("name,files,ini,needle", [
    ("skip", {"tests/test_a.py": "import pytest\n@pytest.mark.skip(reason='r')\ndef test_a(): pass\ndef test_b(): pass\n"}, None, "SKIPPED"),
    ("skipif-env", {"tests/test_a.py": "import os, pytest\n@pytest.mark.skipif(True, reason='env')\ndef test_a(): pass\ndef test_b(): pass\n"}, None, "SKIPPED"),
    ("runtime-skip", {"tests/test_a.py": "import pytest\ndef test_a(): pytest.skip('x')\ndef test_b(): pass\n"}, None, "SKIPPED"),
    ("xfail", {"tests/test_a.py": "import pytest\n@pytest.mark.xfail\ndef test_a(): assert 0\ndef test_b(): pass\n"}, None, "XFAILED"),
    ("xpass", {"tests/test_a.py": "import pytest\n@pytest.mark.xfail\ndef test_a(): pass\ndef test_b(): pass\n"}, None, "XPASSED"),
    ("strict-xpass", {"tests/test_a.py": "import pytest\n@pytest.mark.xfail(strict=True)\ndef test_a(): pass\ndef test_b(): pass\n"}, None, "FAILED"),
    ("setup-error", {"tests/test_a.py": "import pytest\n@pytest.fixture\ndef f(): raise RuntimeError('x')\ndef test_a(f): pass\ndef test_b(): pass\n"}, None, "ERROR"),
    ("teardown-error", {"tests/test_a.py": "import pytest\n@pytest.fixture\ndef f():\n    yield\n    raise RuntimeError('x')\ndef test_a(f): pass\ndef test_b(): pass\n"}, None, "ERROR"),
    ("failing", {"tests/test_a.py": "def test_a(): assert 0\ndef test_b(): pass\n"}, None, "FAILED"),
    ("collection-error", {"tests/test_a.py": "def test_a(:\n"}, None, "collection error"),
    ("module-importorskip", {"tests/test_a.py": "import pytest\npytest.importorskip('no_such_module_xyz')\ndef test_a(): pass\n"}, None, "skipped at collection"),
    ("config-deselect", GOOD, "[pytest]\naddopts = -k test_one\n", "deselected"),
    ("config-maxfail-stops-early", {"tests/test_a.py": "def test_a(): assert 0\ndef test_b(): pass\ndef test_c(): pass\n"}, "[pytest]\naddopts = -x\n", "NOT_RUN"),
    ("config-collect-only", GOOD, "[pytest]\naddopts = --collect-only\n", "not from a real execution"),
    ("config-ignores-a-whole-file", GOOD, "[pytest]\naddopts = --ignore=tests/test_b.py\n", "yielded no passing test"),
    ("conftest-silently-drops-item", dict(GOOD, **{"tests/conftest.py": "def pytest_collection_modifyitems(items):\n    del items[0]\n"}), None, "removed without being reported"),
    ("conftest-skips-everything", dict(GOOD, **{"tests/conftest.py": "import pytest\ndef pytest_runtest_setup(item):\n    pytest.skip('blanket')\n"}), None, "SKIPPED"),
    ("test-file-outside-every-job", dict(GOOD, **{"extra/test_c.py": "def test_c(): pass\n"}), None, "omitted from every required job"),
    ("process-dies-mid-run", {"tests/test_a.py": "import os\ndef test_a(): os._exit(3)\ndef test_b(): pass\n"}, None, "incomplete"),
    ("empty-suite", {"tests/test_a.py": "x = 1\n"}, None, "zero tests"),
])
def test_bad_runs_never_pass(tmp_path, name, files, ini, needle):
    root, out, result = build(tmp_path, files, ini=ini)
    assert result.returncode != 0, f"{name} produced a PASS:\n{result.stdout}"
    assert "FINAL-BETA ACCEPTANCE FAIL" in result.stdout
    assert needle.lower() in (result.stdout + result.stderr).lower(), (name, result.stdout[-1500:])


def test_required_check_never_run_fails(tmp_path):
    _, _, result = build(tmp_path, GOOD, run_check=False)
    assert result.returncode != 0 and "no result" in result.stdout


def test_check_run_with_a_different_command_fails(tmp_path):
    root, out, _ = build(tmp_path, GOOD, run_check=False)
    _run(root, out, "run-check", "--out", str(out), "lint", "--", sys.executable, "-c", "pass")
    ok, text = verify(root, out)
    assert not ok and "not the prescribed check" in text


def test_check_that_exits_nonzero_fails(tmp_path):
    root, out, _ = build(tmp_path, GOOD, run_check=False)
    _run(root, out, "run-check", "--out", str(out), "lint", "--", sys.executable, "-c", "raise SystemExit(2)", "mycheck")
    ok, text = verify(root, out)
    assert not ok and "exit code 2" in text


def test_env_unmet_job_fails_and_is_labelled_env_not_code(tmp_path):
    root, out, _ = build(tmp_path, GOOD)
    _run(root, out, "mark-unmet", "unit", "--out", str(out), "--reason", "no target")
    ok, text = verify(root, out)
    assert not ok and "ENV-UNMET" in text and "no target" in text


def test_ci_success_record_is_required_for_ci_only_checks(tmp_path):
    root, out, _ = build(tmp_path, GOOD, run_check=False)
    for result, expect_ok in (("success", True), ("failure", False), ("cancelled", False), ("skipped", False)):
        _run(root, out, "record-ci", "lint", "--out", str(out), "--result", result)
        ok, text = verify(root, out)
        assert ok is expect_ok, (result, text[-800:])


# -------------------------------------------------------- tampering scenarios
def test_missing_meta_fails(good, tmp_path):
    root, out = clone(good, tmp_path)
    (out / "jobs" / "unit.meta.json").unlink()
    ok, text = verify(root, out)
    assert not ok and "never ran" in text


@pytest.mark.parametrize("content", ["", "{}", "not json", "[]", '{"complete": false}'])
def test_empty_or_garbage_results_fail(good, tmp_path, content):
    root, out = clone(good, tmp_path)
    (out / "jobs" / "unit.results.json").write_text(content, encoding="utf-8")
    ok, text = verify(root, out)
    assert not ok and "incomplete" in text


def test_missing_results_and_inventory_fail(good, tmp_path):
    for victim in ("jobs/unit.results.json", "inventory/unit.json", "inventory/_all-main.json"):
        root, out = clone(good, tmp_path / victim.replace("/", "_"))
        (out / victim).unlink()
        ok, text = verify(root, out)
        assert not ok, victim


def test_hand_edited_results_fail_the_hash_binding(good, tmp_path):
    root, out = clone(good, tmp_path)
    edit_json(out / "jobs" / "unit.results.json", lambda r: r["results"].update({next(iter(r["results"])): "passed"}))
    (out / "jobs" / "unit.results.json").write_text((out / "jobs" / "unit.results.json").read_text() + " ")
    ok, text = verify(root, out)
    assert not ok and "sha256 mismatch" in text


def test_fabricated_results_with_rebound_hash_still_fail_on_args(good, tmp_path):
    root, out = clone(good, tmp_path)
    edit_json(out / "jobs" / "unit.results.json", lambda r: r.update(args=["-k", "one"]))
    rebind(out)
    ok, text = verify(root, out)
    assert not ok and "exact arguments" in text


def test_a_skipped_result_relabelled_passed_is_caught_by_its_own_detail(tmp_path):
    root, out, _ = build(tmp_path, {"tests/test_a.py": "import pytest\ndef test_a(): pytest.skip('x')\ndef test_b(): pass\n"})
    res = out / "jobs" / "unit.results.json"
    edit_json(res, lambda r: r["results"].update({k: "passed" for k in r["results"]}))
    edit_json(out / "jobs" / "unit.meta.json", lambda m: m.update(rc=0))
    rebind(out)
    edit_json(res, lambda r: r.update(pytest_exitstatus=0))
    rebind(out)
    ok, text = verify(root, out)
    assert not ok and "inconsistent" in text


def test_duplicated_ids_fail(good, tmp_path):
    root, out = clone(good, tmp_path)
    edit_json(out / "jobs" / "unit.results.json", lambda r: r["collected"].append(r["collected"][0]))
    rebind(out)
    ok, text = verify(root, out)
    assert not ok and "duplicated" in text


def test_omitted_id_fails_even_when_results_and_inventory_are_both_edited(good, tmp_path):
    root, out = clone(good, tmp_path)
    victim = "tests/test_b.py::test_three"
    for rel in ("jobs/unit.results.json", "inventory/unit.json"):
        def cut(d):
            d["collected"].remove(victim)
            d["collected_count"] -= 1
            d.get("results", {}).pop(victim, None)
        edit_json(out / rel, cut)
    rebind(out)
    ok, text = verify(root, out)
    assert not ok and "NO executed required path" in text


def test_id_missing_from_results_only_fails(good, tmp_path):
    root, out = clone(good, tmp_path)
    edit_json(out / "jobs" / "unit.results.json", lambda r: r["results"].pop("tests/test_b.py::test_three"))
    rebind(out)
    ok, text = verify(root, out)
    assert not ok and "never reported" in text


def test_recorded_deselection_fails(good, tmp_path):
    root, out = clone(good, tmp_path)
    edit_json(out / "jobs" / "unit.results.json", lambda r: r.update(deselected=["tests/test_a.py::test_one"]))
    rebind(out)
    ok, text = verify(root, out)
    assert not ok and "deselected" in text


def test_internal_error_record_fails(good, tmp_path):
    root, out = clone(good, tmp_path)
    edit_json(out / "jobs" / "unit.results.json", lambda r: r.update(internal_errors=["boom"]))
    rebind(out)
    ok, text = verify(root, out)
    assert not ok and "internal errors" in text


def test_stale_evidence_fails(good, tmp_path):
    root, out = clone(good, tmp_path)
    old = time.time() - 4 * 86400
    edit_json(out / "jobs" / "unit.meta.json", lambda m: m.update(started=old, finished=old + 5))
    edit_json(out / "jobs" / "unit.results.json", lambda r: r.update(started=old + 1, finished=old + 4))
    edit_json(out / "inventory" / "unit.json", lambda i: i.update(finished=old - 1))
    rebind(out)
    ok, text = verify(root, out)
    assert not ok and "stale" in text


def test_inventory_recorded_after_execution_fails(good, tmp_path):
    root, out = clone(good, tmp_path)
    edit_json(out / "inventory" / "unit.json", lambda i: i.update(finished=time.time() + 600))
    rebind(out)
    ok, text = verify(root, out)
    assert not ok and "before execution" in text


def test_evidence_from_another_tree_fails(good, tmp_path):
    root, out = clone(good, tmp_path)
    (root / "tests" / "test_a.py").write_text("def test_one(): pass\ndef test_two(): pass\n# changed\n", encoding="utf-8")
    ok, text = verify(root, out)
    assert not ok and "does not match the current" in text


def test_evidence_from_another_commit_fails(good, tmp_path):
    root, out = clone(good, tmp_path)
    (root / "note.txt").write_text("x", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "next")
    ok, text = verify(root, out)
    assert not ok and "does not match the current" in text


def test_mixed_revision_evidence_fails(good, tmp_path):
    root, out = clone(good, tmp_path)
    edit_json(out / "jobs" / "lint.meta.json", lambda m: m["revision"].update(tree_fingerprint="0" * 64))
    ok, text = verify(root, out)
    assert not ok and "different revisions" in text


def test_manifest_changed_after_the_run_fails(good, tmp_path):
    root, out = clone(good, tmp_path)
    edit_json(root / "acceptance" / "suites.json", lambda m: m["jobs"]["unit"].update(description="edited"))
    ok, text = verify(root, out)
    assert not ok and "different acceptance/suites.json" in text


@pytest.mark.parametrize("key,value", [("required", False), ("optional", True), ("allow_skip", True)])
def test_a_job_cannot_be_marked_optional(good, tmp_path, key, value):
    root, out = clone(good, tmp_path)
    edit_json(root / "acceptance" / "suites.json", lambda m: m["jobs"]["lint"].update({key: value}))
    ok, text = verify(root, out)
    assert not ok and "unsupported manifest key" in text


def test_repo_minimum_job_floor_survives_manifest_edits():
    sys.path.insert(0, str(REPO / "scripts"))
    try:
        import importlib
        os.environ.pop("S43_ACC_ROOT", None)
        gate = importlib.import_module("acceptance_gate")
        real = gate.load_manifest()
        assert gate.manifest_errors(real) == []
        for name in gate.MINIMUM_REQUIRED_JOBS:
            trimmed = json.loads(json.dumps(real))
            trimmed["jobs"].pop(name)
            assert any(name in e for e in gate.manifest_errors(trimmed)), name
    finally:
        sys.path.remove(str(REPO / "scripts"))


def test_recorder_flags_real_duplicate_node_ids(tmp_path):
    # Two identical parameter ids that pytest itself de-duplicates cannot be produced, so the
    # recorder's duplicate detector is exercised through a plugin that repeats an item.
    (tmp_path / "test_d.py").write_text("def test_a(): pass\n", encoding="utf-8")
    (tmp_path / "conftest.py").write_text(
        "def pytest_collection_modifyitems(items):\n    items.append(items[0])\n", encoding="utf-8")
    report = tmp_path / "r.json"
    env = dict(os.environ, PYTHONPATH=str(REPO / "scripts"))
    proc = subprocess.run([sys.executable, "-m", "pytest", "-p", "acceptance_recorder", "-p", "no:cacheprovider",
                           "--acc-report", str(report), "-q", str(tmp_path / "test_d.py")],
                          cwd=tmp_path, env=env, capture_output=True, text=True)
    data = json.loads(report.read_text(encoding="utf-8"))
    assert proc.returncode != 0
    assert data["duplicate_ids"] and any("duplicated" in v for v in data["violations"])


# ===================================================================== modes
# `verify --mode pr-ci` verifies only what ordinary PR CI owns; `--mode final-beta`
# is the strict complete gate. The mode is explicit and required, and a PR-CI
# verdict can never stand in for a final-beta one.
TARGET_FILES = dict(GOOD, **{"target_tests/test_t.py": "def test_target():\n    assert True\n"})
TARGET_MANIFEST = json.loads(json.dumps(MANIFEST))
TARGET_MANIFEST["jobs"]["browser-target"] = {
    "kind": "pytest", "python": "main", "paths": ["target_tests"], "ignore": [], "env": {},
    "requires_env": ["S43_TARGET_BASE_URL"],
}


def build_pr_ci(tmp: Path, files: dict[str, str] | None = None, *, ini: str | None = None,
                mark_unmet: bool = False) -> tuple[Path, Path]:
    """PR CI's real situation: everything it owns ran; browser-target could not (no target)."""
    root, out, _ = build(tmp, files or TARGET_FILES, ini=ini, manifest=TARGET_MANIFEST)
    if mark_unmet:
        _run(root, out, "mark-unmet", "browser-target", "--out", str(out), "--reason", "no target")
    return root, out


@pytest.fixture(scope="module")
def pr_ci_good(tmp_path_factory):
    root, out = build_pr_ci(tmp_path_factory.mktemp("prci"))
    ok, text = verify(root, out, "pr-ci")
    assert ok, text
    return root, out


def verdict_of(out: Path) -> dict:
    return json.loads((out / "verdict.json").read_text(encoding="utf-8"))


def test_pr_ci_passes_without_target_and_says_target_acceptance_was_not_performed(pr_ci_good):
    root, out = pr_ci_good
    v = verdict_of(out)
    assert v["verdict"] == "PR-CI PASS" and v["mode"] == "pr-ci"
    assert v["final_beta_acceptance"] == "NOT PERFORMED IN PR CI"
    assert v["not_performed"] == ["browser-target"]
    row = next(r for r in v["jobs"] if r["job"] == "browser-target")
    assert row["status"] == "NOT PERFORMED IN PR CI" and row["status"] != "PASS"
    assert "FINAL-BETA" not in v["verdict"]
    md = (out / "verdict.md").read_text(encoding="utf-8")
    assert "NOT PERFORMED IN PR CI" in md and "FINAL-BETA ACCEPTANCE PASS" not in md


def test_final_beta_on_the_same_evidence_fails_because_browser_target_is_unmet(pr_ci_good, tmp_path):
    root, out = clone(pr_ci_good, tmp_path)
    ok, text = verify(root, out, "final-beta")
    assert not ok and "FINAL-BETA ACCEPTANCE FAIL" in text
    v = verdict_of(out)
    assert v["mode"] == "final-beta" and v["final_beta_acceptance"] == "FAIL" and v["not_performed"] == []
    assert any(f.startswith("browser-target:") for f in v["failures"] + v["env_unmet"])


def test_final_beta_fails_when_browser_target_marked_unmet(tmp_path):
    root, out = build_pr_ci(tmp_path, mark_unmet=True)
    ok, text = verify(root, out, "final-beta")
    assert not ok and "ENV-UNMET" in text and "no target" in text


def test_final_beta_fails_when_any_required_job_is_unexecuted(pr_ci_good, tmp_path):
    root, out = clone(pr_ci_good, tmp_path)
    (out / "jobs" / "unit.meta.json").unlink()
    ok, text = verify(root, out, "final-beta")
    assert not ok and "never ran" in text


def test_verify_requires_an_explicit_mode(pr_ci_good, tmp_path):
    root, out = clone(pr_ci_good, tmp_path)
    r = _run(root, out, "verify", "--out", str(out))
    assert r.returncode != 0 and "--mode" in r.stderr
    bogus = _run(root, out, "verify", "--out", str(out), "--mode", "auto")
    assert bogus.returncode != 0


def test_green_browser_target_evidence_does_not_turn_pr_ci_into_final_beta(pr_ci_good, tmp_path):
    root, out = clone(pr_ci_good, tmp_path)
    env = {k: v for k, v in os.environ.items() if not k.startswith("S43_")}
    env.update(S43_ACC_ROOT=str(root), S43_TARGET_BASE_URL="http://target.invalid")
    subprocess.run([sys.executable, str(GATE), "run-job", "browser-target", "--out", str(out)],
                   cwd=root, env=env, capture_output=True, text=True)
    ok, _ = verify(root, out, "pr-ci")
    v = verdict_of(out)
    assert ok and v["verdict"] == "PR-CI PASS" and v["final_beta_acceptance"] == "NOT PERFORMED IN PR CI"
    row = next(r for r in v["jobs"] if r["job"] == "browser-target")
    assert row["status"] == "NOT PERFORMED IN PR CI"


def test_pr_ci_pass_artifact_is_replaced_never_reused_by_a_failing_final_beta_verify(pr_ci_good, tmp_path):
    root, out = clone(pr_ci_good, tmp_path)
    assert verify(root, out, "pr-ci")[0] and verdict_of(out)["verdict"] == "PR-CI PASS"
    ok, _ = verify(root, out, "final-beta")
    assert not ok
    v = verdict_of(out)
    assert v["verdict"] == "FINAL-BETA ACCEPTANCE FAIL"
    assert "PR-CI PASS" not in (out / "verdict.md").read_text(encoding="utf-8")


def test_a_failed_verify_never_leaves_an_earlier_pass_verdict_behind(pr_ci_good, tmp_path):
    root, out = clone(pr_ci_good, tmp_path)
    assert verify(root, out, "pr-ci")[0]
    (out / "jobs" / "unit.results.json").write_text("{}", encoding="utf-8")
    ok, _ = verify(root, out, "pr-ci")
    assert not ok and verdict_of(out)["verdict"] == "PR-CI FAIL"


def test_pr_ci_exemption_is_a_closed_code_level_set():
    sys.path.insert(0, str(REPO / "scripts"))
    try:
        import importlib
        os.environ.pop("S43_ACC_ROOT", None)
        gate = importlib.import_module("acceptance_gate")
        assert gate.PR_CI_NOT_PERFORMED == frozenset({"browser-target"})
        assert gate.PR_CI_NOT_PERFORMED <= gate.MINIMUM_REQUIRED_JOBS
        trimmed = json.loads(json.dumps(gate.load_manifest()))
        trimmed["jobs"].pop("browser-target")
        assert any("browser-target" in e for e in gate.manifest_errors(trimmed))  # floor holds in both modes
        with pytest.raises(ValueError):
            gate.verify_evidence(Path("."), mode="", write=False)
    finally:
        sys.path.remove(str(REPO / "scripts"))


def _own(body: str) -> dict:
    return dict(TARGET_FILES, **{"tests/test_a.py": body})


# PR-CI is not a weaker gate for the work it owns: every hostile scenario still fails it.
@pytest.mark.parametrize("name,files,ini,needle", [
    ("skip", _own("import pytest\n@pytest.mark.skip(reason='r')\ndef test_one(): pass\ndef test_two(): pass\n"), None, "SKIPPED"),
    ("xfail", _own("import pytest\n@pytest.mark.xfail\ndef test_one(): assert 0\ndef test_two(): pass\n"), None, "XFAILED"),
    ("xpass", _own("import pytest\n@pytest.mark.xfail\ndef test_one(): pass\ndef test_two(): pass\n"), None, "XPASSED"),
    ("failing", _own("def test_one(): assert 0\ndef test_two(): pass\n"), None, "FAILED"),
    ("deselect", TARGET_FILES, "[pytest]\naddopts = -k test_one\n", "deselected"),
    ("omitted-file", dict(TARGET_FILES, **{"extra/test_c.py": "def test_c(): pass\n"}), None, "omitted from every required job"),
    ("ignored-file", TARGET_FILES, "[pytest]\naddopts = --ignore=tests/test_b.py\n", "yielded no passing test"),
])
def test_pr_ci_still_rejects_every_owned_defect(tmp_path, name, files, ini, needle):
    root, out = build_pr_ci(tmp_path, files, ini=ini)
    ok, text = verify(root, out, "pr-ci")
    assert not ok, f"{name} passed PR-CI:\n{text}"
    assert "PR-CI FAIL" in text and needle.lower() in text.lower(), (name, text[-1500:])


def test_pr_ci_fails_when_an_owned_check_was_never_recorded(tmp_path):
    root, out = build_pr_ci(tmp_path)
    (out / "jobs" / "lint.meta.json").unlink()
    ok, text = verify(root, out, "pr-ci")
    assert not ok and "lint" in text


@pytest.mark.parametrize("tamper,needle", [
    ("missing-results", "PR-CI FAIL"),
    ("garbage-results", "incomplete"),
    ("hand-edited", "sha256 mismatch"),
    ("other-commit", "does not match the current"),
    ("stale", "stale"),
    ("manifest-changed", "different acceptance/suites.json"),
])
def test_pr_ci_rejects_missing_tampered_stale_and_mismatched_evidence(pr_ci_good, tmp_path, tamper, needle):
    root, out = clone(pr_ci_good, tmp_path)
    res = out / "jobs" / "unit.results.json"
    if tamper == "missing-results":
        res.unlink()
    elif tamper == "garbage-results":
        res.write_text("not json", encoding="utf-8")
    elif tamper == "hand-edited":
        edit_json(res, lambda d: d.update(tampered=True))
    elif tamper == "other-commit":
        (root / "tests" / "test_a.py").write_text("def test_one(): pass\ndef test_two(): pass\n# drift\n", encoding="utf-8")
    elif tamper == "stale":
        edit_json(out / "jobs" / "unit.meta.json", lambda m: m.update(started=1.0, finished=2.0))
    elif tamper == "manifest-changed":
        edit_json(root / "acceptance" / "suites.json", lambda m: m.update(_note="edited after the run"))
    ok, text = verify(root, out, "pr-ci")
    assert not ok and "PR-CI FAIL" in text and needle.lower() in text.lower(), (tamper, text[-1200:])


# ============================================ browser-disposable evidence wiring
# browser_tests/run.sh used to run plain pytest, so the workflow/campaign's
# S43_ACCEPTANCE_OUT produced no browser-disposable.{results,meta}.json at all.
BROWSER_FILES = dict(GOOD, **{
    "browser_tests/test_flow.py": "def test_flow():\n    assert True\n",
    "target_tests/test_t.py": "def test_target():\n    assert True\n",
})
BROWSER_MANIFEST = json.loads(json.dumps(TARGET_MANIFEST))
BROWSER_MANIFEST["jobs"]["browser-disposable"] = {
    "kind": "pytest", "python": "browser", "paths": ["browser_tests"], "ignore": [], "env": {},
    "requires_env": ["S43_BROWSER_BASE_URL"],
}


def _browser_stack(tmp: Path, flow_body: str | None = None, run_browser: bool = True) -> tuple[Path, Path]:
    files = dict(BROWSER_FILES)
    if flow_body is not None:
        files["browser_tests/test_flow.py"] = flow_body
    root, out, _ = build(tmp, files, manifest=BROWSER_MANIFEST, ini="[pytest]"+chr(10))  # like the real repo: a fixed rootdir
    if run_browser:
        env = {k: v for k, v in os.environ.items() if not k.startswith("S43_")}
        env.update(S43_ACC_ROOT=str(root), S43_BROWSER_BASE_URL="https://disposable.invalid")
        subprocess.run([sys.executable, str(GATE), "inventory", "--out", str(out), "--job", "browser-disposable"],
                       cwd=root, env=env, capture_output=True, text=True)
        subprocess.run([sys.executable, str(GATE), "run-job", "browser-disposable", "--out", str(out)],
                       cwd=root, env=env, capture_output=True, text=True)
    return root, out


def test_browser_disposable_run_writes_results_and_metadata_from_the_real_execution(tmp_path):
    root, out = _browser_stack(tmp_path)
    meta = json.loads((out / "jobs" / "browser-disposable.meta.json").read_text(encoding="utf-8"))
    res = json.loads((out / "jobs" / "browser-disposable.results.json").read_text(encoding="utf-8"))
    assert meta["job"] == "browser-disposable" and meta["classification"] == "executed" and meta["rc"] == 0
    assert meta["results_sha256"] == hashlib.sha256(
        (out / "jobs" / "browser-disposable.results.json").read_bytes()).hexdigest()
    assert res["results"] == {"browser_tests/test_flow.py::test_flow": "passed"}
    assert "acceptance_recorder" in meta["cmd"] and "browser-disposable" in meta["cmd"]


def test_pr_ci_and_final_beta_consume_valid_browser_disposable_evidence(tmp_path):
    root, out = _browser_stack(tmp_path)
    ok, text = verify(root, out, "pr-ci")
    assert ok, text
    row = next(r for r in verdict_of(out)["jobs"] if r["job"] == "browser-disposable")
    assert row["status"] == "PASS"
    ok, text = verify(root, out, "final-beta")  # fails only because browser-target is unmet
    assert not ok
    row = next(r for r in verdict_of(out)["jobs"] if r["job"] == "browser-disposable")
    assert row["status"] == "PASS"
    assert not any(f.startswith("browser-disposable:") for f in verdict_of(out)["failures"] + verdict_of(out)["env_unmet"])


@pytest.mark.parametrize("mode", ["pr-ci", "final-beta"])
def test_a_skipped_browser_test_is_rejected(tmp_path, mode):
    body = "import pytest\n@pytest.mark.skip(reason='x')\ndef test_flow(): pass\n"
    root, out = _browser_stack(tmp_path, flow_body=body)
    ok, text = verify(root, out, mode)
    assert not ok and "skipped" in text.lower()


@pytest.mark.parametrize("mode", ["pr-ci", "final-beta"])
def test_missing_browser_disposable_evidence_is_rejected(tmp_path, mode):
    root, out = _browser_stack(tmp_path, run_browser=False)
    ok, text = verify(root, out, mode)
    assert not ok and "browser-disposable" in text and "never ran" in text


def test_run_sh_routes_acceptance_runs_through_the_gate_and_refuses_extra_pytest_args():
    src = (REPO / "browser_tests" / "run.sh").read_text(encoding="utf-8")
    assert 'S43_ACCEPTANCE_OUT' in src
    assert 'scripts/acceptance_gate.py run-job browser-disposable --out "$S43_ACCEPTANCE_OUT"' in src
    assert "extra pytest arguments are not allowed" in src
    # the developer path is unchanged and still excludes the real-target suite
    assert "--ignore=browser_tests/target_acceptance" in src


# ------------------------------------------- subprocess hardening (PR #294 review)
@pytest.mark.parametrize("field", ["paths", "ignore"])
def test_manifest_entries_that_look_like_pytest_options_are_refused(tmp_path, field):
    manifest = json.loads(json.dumps(MANIFEST))
    manifest["jobs"]["unit"][field] = ["tests", "--rootdir=/elsewhere"] if field == "paths" else ["-p", "evil"]
    root, out, result = build(tmp_path, GOOD, manifest=manifest)
    assert result.returncode != 0
    assert "not options" in result.stdout + result.stderr or "not pytest options" in result.stdout + result.stderr
    # the run itself must be refused, not merely reported afterwards
    run = _run(root, out, "run-job", "unit", "--out", str(out))
    assert run.returncode != 0 and "not options" in run.stderr + run.stdout
