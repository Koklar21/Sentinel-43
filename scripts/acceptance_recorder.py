"""pytest plugin for the zero-skip acceptance run.

Load with ``-p acceptance_recorder`` (PYTHONPATH must include ``scripts/``) and
``--acc-report PATH``. It writes a machine-readable per-test-ID result file and
makes the pytest process itself exit non-zero on anything that is not a clean
PASS: skip, xfail, xpass, setup/teardown error, collection error/skip,
deselection, tests that never ran, or zero collected tests.

The report is written as ``"complete": false`` at session start and rewritten
as ``"complete": true`` only at session finish, so a killed / crashed run is
distinguishable from a finished one by the gate.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import time
from pathlib import Path

import pytest

_STATE: dict = {}


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("acceptance")
    group.addoption("--acc-report", default=None, help="write the acceptance JSON report here")
    group.addoption("--acc-job", default="unnamed", help="acceptance job name recorded in the report")


def _report_path(config: pytest.Config) -> Path | None:
    value = config.getoption("--acc-report", default=None)
    return Path(value) if value else None


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def _payload(config: pytest.Config, *, complete: bool, exitstatus: int | None) -> dict:
    return {
        "schema": 1,
        "job": config.getoption("--acc-job"),
        "complete": complete,
        "pytest_exitstatus": exitstatus,
        "args": list(config.invocation_params.args),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "started": _STATE["started"],
        "finished": time.time() if complete else None,
        "collect_only": bool(config.getoption("collectonly", default=False)),
        "collected": sorted(_STATE["collected"]),
        "collected_count": len(_STATE["collected_list"]),
        "duplicate_ids": sorted({i for i in _STATE["collected_list"] if _STATE["collected_list"].count(i) > 1}),
        "internal_errors": _STATE["internal_errors"],
        "deselected": sorted(_STATE["deselected"]),
        "raw_collected_count": len(_STATE["raw_items"]),
        "collect_errors": _STATE["collect_errors"],
        "collect_skips": _STATE["collect_skips"],
        "results": _STATE.get("results", {}),
        "details": _STATE.get("details", {}),
        "counts": _STATE.get("counts", {}),
        "violations": _STATE.get("violations", []),
    }


def pytest_configure(config: pytest.Config) -> None:
    _STATE.clear()
    _STATE.update(started=time.time(), collected=set(), collected_list=[], raw_items=[], deselected=set(),
                  collect_errors=[], collect_skips=[], phases={}, details={}, internal_errors=[])
    path = _report_path(config)
    if path:
        _write(path, _payload(config, complete=False, exitstatus=None))


def pytest_collectreport(report: pytest.CollectReport) -> None:
    if report.failed:
        _STATE["collect_errors"].append(
            {"id": report.nodeid, "error": str(report.longrepr)[-600:]})
    elif report.skipped:
        _STATE["collect_skips"].append(
            {"id": report.nodeid, "reason": str(report.longrepr)[-300:]})


def pytest_itemcollected(item) -> None:
    # Fires as each item is created, before any modifyitems hook can drop it.
    _STATE["raw_items"].append(item.nodeid)


def pytest_deselected(items) -> None:
    _STATE["deselected"].update(i.nodeid for i in items)


def pytest_collection_finish(session: pytest.Session) -> None:
    _STATE["collected_list"].extend(i.nodeid for i in session.items)
    _STATE["collected"].update(i.nodeid for i in session.items)


def pytest_internalerror(excrepr, excinfo) -> None:
    _STATE["internal_errors"].append(str(excrepr)[-300:])


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    phases = _STATE["phases"].setdefault(report.nodeid, {})
    wasxfail = hasattr(report, "wasxfail")
    phases[report.when] = {"outcome": report.outcome, "wasxfail": wasxfail}
    if report.outcome == "skipped":
        reason = report.longrepr[2] if isinstance(report.longrepr, tuple) else str(report.longrepr)
        _STATE["details"][report.nodeid] = str(reason)[:300]
    elif report.failed:
        _STATE["details"].setdefault(report.nodeid, f"{report.when} failed")


def _classify(phases: dict) -> str:
    if not phases:
        return "not_run"
    setup, call, teardown = (phases.get(k) for k in ("setup", "call", "teardown"))
    if any(p and p["wasxfail"] for p in (setup, call)):
        # xfail: call "skipped"+wasxfail = xfailed; call "passed"+wasxfail = xpassed
        return "xpassed" if call and call["outcome"] == "passed" else "xfailed"
    if setup and setup["outcome"] == "failed":
        return "error"
    if setup and setup["outcome"] == "skipped":
        return "skipped"
    if call is None:
        return "not_run"
    if call["outcome"] == "skipped":
        return "skipped"
    if call["outcome"] == "failed":
        return "failed"
    if teardown and teardown["outcome"] == "failed":
        return "error"
    if teardown is None:
        return "not_run"
    return "passed"


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session: pytest.Session, exitstatus) -> None:
    config = session.config
    collect_only = bool(config.getoption("collectonly", default=False))
    results = {}
    for nodeid in _STATE["collected"]:
        results[nodeid] = "collected" if collect_only else _classify(_STATE["phases"].get(nodeid, {}))
    # Reports for IDs that were never collected (should not happen) still count.
    for nodeid in set(_STATE["phases"]) - _STATE["collected"]:
        results[nodeid] = _classify(_STATE["phases"][nodeid])
    counts: dict[str, int] = {}
    for outcome in results.values():
        counts[outcome] = counts.get(outcome, 0) + 1

    violations = []
    dupes = [i for i in _STATE["collected"] if _STATE["collected_list"].count(i) > 1]
    if dupes:
        violations.append(f"{len(dupes)} duplicated test id(s)")
    if _STATE["internal_errors"]:
        violations.append("pytest internal error")
    silently_removed = sorted(set(_STATE["raw_items"]) - set(_STATE["collected"]) - _STATE["deselected"])
    if silently_removed:
        violations.append(f"{len(silently_removed)} collected item(s) removed without being reported as deselected")
    if not results:
        violations.append("zero tests collected")
    if _STATE["deselected"]:
        violations.append(f"{len(_STATE['deselected'])} deselected")
    if _STATE["collect_errors"]:
        violations.append(f"{len(_STATE['collect_errors'])} collection error(s)")
    if _STATE["collect_skips"]:
        violations.append(f"{len(_STATE['collect_skips'])} module(s) skipped at collection")
    allowed = {"collected"} if collect_only else {"passed", "failed"}
    for outcome, n in sorted(counts.items()):
        if outcome not in allowed:
            violations.append(f"{n} {outcome}")
    _STATE.update(results=results, counts=counts, violations=violations)

    path = _report_path(config)
    if path:
        _write(path, _payload(config, complete=True, exitstatus=int(exitstatus)))
    # Strict: anything short of a clean, complete run must not exit 0.
    if violations and int(exitstatus) == 0:
        session.exitstatus = 1
    if violations:
        print("\nACCEPTANCE VIOLATIONS: " + "; ".join(violations), file=sys.stderr)
