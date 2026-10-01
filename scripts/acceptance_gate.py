#!/usr/bin/env python3
"""Zero-skip acceptance gate for Sentinel-43.

Acceptance rule: every collected test executes and PASSES or FAILS. Any skip,
xfail, xpass, collection/setup error, deselection, missing dependency, missing
required environment, unexecuted required job, or missing/incomplete result
artifact makes the overall result a FAIL (FINAL-BETA ACCEPTANCE FAIL / PR-CI FAIL). A job's own exit status is
never sufficient on its own: ``verify`` re-derives the verdict from the
machine-readable per-test-ID reports and reconciles them against an inventory
recorded before execution.

Sub-commands (all read ``acceptance/suites.json``):

  inventory  --out DIR [--job J ...]   record collected test IDs (collect-only)
  inventory-all --out DIR [--profile P ...]
                                       independent whole-tree collection (omission check),
                                       one per interpreter profile; each profile MUST be
                                       collected by that profile's own interpreter
  run-job    JOB --out DIR             collect (if needed) + run one pytest job
  run-check  JOB --out DIR -- CMD...   run a non-pytest required check
  mark-unmet JOB --out DIR --reason R  record a required job that cannot run
  record-ci  JOB --out DIR --result R  record a CI job's conclusion for a required check
  revision   --out DIR                 write revision.json (host side of a container run)
  verify     --out DIR --mode M        reconcile everything, write the verdict.
                                       --mode is REQUIRED (there is no default):
                                       final-beta = the strict, complete gate;
                                       pr-ci      = only the work ordinary PR CI owns
                                                    (see PR_CI_NOT_PERFORMED)

Verdicts are scoped by mode: ``FINAL-BETA ACCEPTANCE PASS/FAIL`` and ``PR-CI
PASS/FAIL``. A PR-CI PASS never means final beta acceptance passed: it records
deployed-target acceptance as ``NOT PERFORMED IN PR CI``.

Exit codes: 0 PASS (of the requested mode), 1 FAIL (or a job failed), 3 job
environment prerequisite unmet (run-job only).
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
# S43_ACC_ROOT points the gate at a synthetic project (used only by the gate's own
# adversarial tests); it disables the repository-only MINIMUM_REQUIRED_JOBS floor
# because it changes WHAT is being evaluated, not how strictly.
ROOT = Path(os.environ["S43_ACC_ROOT"]).resolve() if os.environ.get("S43_ACC_ROOT") else REPO_ROOT
MANIFEST = ROOT / "acceptance" / "suites.json"
SCRIPTS = REPO_ROOT / "scripts"


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                          check=True).stdout


def revision() -> dict:
    """HEAD + a fingerprint of every modified/untracked (non-ignored) file, so
    evidence can be tied to exactly the tree that was tested."""
    fixed = os.environ.get("S43_ACC_REVISION_FILE")
    if fixed:  # inside a container (no git, no .git): the host's recorded revision
        return json.loads(Path(fixed).read_text(encoding="utf-8"))
    head = git("rev-parse", "HEAD").strip()
    files = sorted(set(git("ls-files", "-m", "-o", "--exclude-standard").splitlines()))
    digest = hashlib.sha256()
    dirty = []
    for rel in files:
        if rel.startswith("acceptance_out/") or "__pycache__/" in rel or rel.endswith(".pyc"):
            continue
        path = ROOT / rel
        dirty.append(rel)
        digest.update(rel.encode())
        digest.update(path.read_bytes() if path.is_file() else b"<deleted>")
    return {"head": head, "branch": git("rev-parse", "--abbrev-ref", "HEAD").strip(),
            "dirty_files": dirty, "tree_fingerprint": digest.hexdigest()}


def python_for(job: dict) -> str:
    if job.get("python") == "browser":
        override = os.environ.get("S43_BROWSER_PYTHON")
        if override:
            return override
        for cand in (ROOT / ".venv-browser" / "Scripts" / "python.exe",
                     ROOT / ".venv-browser" / "bin" / "python"):
            if cand.exists():
                return str(cand)
        if ROOT == REPO_ROOT:
            # The browser venv's pytest-playwright parametrizes node IDs (e.g. "[chromium]");
            # the main interpreter reports the same tests WITHOUT that suffix. Silently
            # collecting or running the browser profile under it yields IDs that can never
            # reconcile, so for this repository the interpreter must be named explicitly.
            raise SystemExit("browser profile needs its own interpreter: set S43_BROWSER_PYTHON or create "
                             ".venv-browser (refusing to fall back to the main interpreter)")
    return sys.executable


def job_env(job: dict) -> dict:
    env = os.environ.copy()
    env.update(job.get("env", {}))
    env["PYTHONPATH"] = os.pathsep.join(
        [str(ROOT), str(SCRIPTS)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    return env


def option_like(entries) -> list[str]:
    """Manifest path/ignore entries that pytest would parse as OPTIONS. The gate runs
    pytest as an argument vector (no shell), so this is not shell injection; it only
    keeps a manifest entry from smuggling in a pytest option (-p, --rootdir, -k, ...)."""
    return [e for e in entries if not isinstance(e, str) or e.startswith("-")]


def pytest_args(name: str, job: dict, report: Path, *, collect_only: bool) -> list[str]:
    """Manifest-owned pytest arguments, independent of the interpreter profile.

    Verification compares already-recorded commands/evidence and must not require
    the interpreter that originally produced them to exist on the verifier host.
    Execution still resolves the real profile through python_for() in pytest_cmd().
    """
    bad = option_like([*job["paths"], *job.get("ignore", [])])
    if bad:
        raise SystemExit(f"{name}: manifest path/ignore entries must be paths, not options: {bad}")
    args = ["-p", "acceptance_recorder", "-p", "no:cacheprovider",
            "--acc-report", str(report), "--acc-job", name, "-q", "-rA", *job["paths"]]
    for ignored in job.get("ignore", []):
        args += ["--ignore", ignored]
    if collect_only:
        args.append("--collect-only")
    return args


def pytest_cmd(name: str, job: dict, report: Path, *, collect_only: bool) -> list[str]:
    return [
        python_for(job),
        "-m",
        "pytest",
        *pytest_args(name, job, report, collect_only=collect_only),
    ]


def missing_env(job: dict, env: dict) -> list[str]:
    missing = [v for v in job.get("requires_env", []) if not env.get(v)]
    return missing + [f"{v} must NOT be set for this job" for v in job.get("forbid_env", []) if env.get(v)]


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=1, sort_keys=True), encoding="utf-8")


def read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------- inventory
def collect(name: str, job: dict, out: Path) -> tuple[int, Path]:
    inv = out / "inventory" / f"{name}.json"
    env = job_env(job)
    proc = subprocess.run(pytest_cmd(name, job, inv, collect_only=True), cwd=ROOT, env=env,
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    (out / "inventory" / f"{name}.log").write_text(proc.stdout + proc.stderr, encoding="utf-8")
    return proc.returncode, inv


def python_profiles(manifest: dict) -> list[str]:
    """Every distinct interpreter profile ("main", "browser", ...) any pytest job uses.

    Different profiles can have different plugins installed (e.g. the browser
    venv's pytest-playwright parametrizes some test IDs by browser name), which
    changes the exact node IDs pytest reports for the SAME test file. A single
    whole-tree collection under one interpreter is therefore not a reliable
    omission/duplicate oracle for a repo with more than one profile -- each
    profile must collect the whole tree itself; see collect_all().
    """
    return sorted({j.get("python", "main") for j in manifest["jobs"].values() if j["kind"] == "pytest"})


def profile_paths(manifest: dict, profile: str) -> list[str]:
    """Every path any job on this interpreter profile declares -- e.g. the
    browser venv lacks core's own dependencies, so its independent recollection
    must stay inside browser_tests/, not sweep the whole repository."""
    return sorted({p for j in manifest["jobs"].values()
                  if j["kind"] == "pytest" and j.get("python", "main") == profile for p in j["paths"]})


def collect_all(out: Path, manifest: dict, only: list[str] | None = None) -> dict[str, int]:
    """Independent, IGNORE-FREE collection of every path used by each interpreter
    profile (one recollection per profile, since plugins differ per venv -- see
    python_profiles()). This is deliberately NOT the same command as any job's own
    collection: no per-job --ignore is applied, so a job that narrowed its own
    collection cannot go unnoticed. ``only`` limits the run to those profiles (a CI job
    that has just one interpreter collects just its own profile; verify still requires
    every profile's recollection). Returns {profile: returncode}."""
    rcs = {}
    known = python_profiles(manifest)
    unknown = sorted(set(only or []) - set(known))
    if unknown:
        raise SystemExit(f"unknown interpreter profile(s) {unknown}; known: {known}")
    for profile in (only or known):
        inv = out / "inventory" / f"_all-{profile}.json"
        env = job_env({"python": profile})
        paths = profile_paths(manifest, profile)
        if option_like(paths):
            raise SystemExit(f"profile {profile!r}: manifest paths must be paths, not options: {option_like(paths)}")
        proc = subprocess.run([python_for({"python": profile}), "-m", "pytest", "-p", "acceptance_recorder",
                               "-p", "no:cacheprovider", "--acc-report", str(inv), "--acc-job", f"_all-{profile}",
                               "-q", "--collect-only", *paths],
                              cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
        (out / "inventory" / f"_all-{profile}.log").write_text(proc.stdout + proc.stderr, encoding="utf-8")
        rcs[profile] = proc.returncode
    write_json(out / "inventory" / "_all.rev.json", revision())
    return rcs


def cmd_inventory_all(args: argparse.Namespace) -> int:
    out = Path(args.out)
    (out / "inventory").mkdir(parents=True, exist_ok=True)
    manifest = load_manifest()
    rcs = collect_all(out, manifest, args.profile)
    ok = True
    union: set[str] = set()
    for profile, rc in rcs.items():
        data = read_json(out / "inventory" / f"_all-{profile}.json") or {}
        union |= set(data.get("collected", []))
        good = rc == 0 and data.get("complete") and not data.get("violations")
        ok = ok and good
        print(f"inventory _all[{profile}]: {len(data.get('collected', []))} test IDs "
              f"[{'ok' if good else 'PROBLEM'}] {data.get('violations', '')}")
    print(f"inventory _all union: {len(union)} test IDs")
    return 0 if ok else 1


def cmd_inventory(args: argparse.Namespace) -> int:
    manifest, out = load_manifest(), Path(args.out)
    (out / "inventory").mkdir(parents=True, exist_ok=True)
    if not os.environ.get("S43_ACC_REVISION_FILE"):
        write_json(out / "revision.json", revision())
    worst, summary = 0, {}
    for name, job in manifest["jobs"].items():
        if job["kind"] != "pytest" or (args.job and name not in args.job):
            continue
        rc, inv = collect(name, job, out)
        write_json(out / "inventory" / f"{name}.rev.json", revision())
        data = read_json(inv) or {}
        summary[name] = len(data.get("collected", []))
        status = "ok" if rc == 0 and data.get("complete") and not data.get("violations") else "PROBLEM"
        print(f"inventory {name}: {summary[name]} test IDs [{status}] {data.get('violations', '')}")
        worst = worst or (0 if status == "ok" else 1)
    return worst


# ---------------------------------------------------------------------- running
def cmd_run_job(args: argparse.Namespace) -> int:
    manifest, out = load_manifest(), Path(args.out)
    job = manifest["jobs"][args.job]
    env = job_env(job)
    started = time.time()
    meta = {"job": args.job, "kind": "pytest", "revision": revision(), "started": started,
            "manifest_sha256": hashlib.sha256(MANIFEST.read_bytes()).hexdigest()}
    missing = missing_env(job, env)
    if missing:
        meta.update(classification="env_unmet", rc=None, missing_env=missing, finished=time.time())
        write_json(out / "jobs" / f"{args.job}.meta.json", meta)
        print(f"ENV UNMET for {args.job}: {missing}", file=sys.stderr)
        return 3
    if not (out / "inventory" / f"{args.job}.json").exists():
        (out / "inventory").mkdir(parents=True, exist_ok=True)
        collect(args.job, job, out)
        write_json(out / "inventory" / f"{args.job}.rev.json", revision())
    meta["started"] = time.time()  # the execution window starts after the inventory exists
    report = out / "jobs" / f"{args.job}.results.json"
    if report.exists():
        report.unlink()
    cmd = pytest_cmd(args.job, job, report, collect_only=False)
    proc = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    (out / "jobs").mkdir(parents=True, exist_ok=True)
    (out / "jobs" / f"{args.job}.log").write_text(proc.stdout + proc.stderr, encoding="utf-8", errors="replace")
    sys.stdout.write(proc.stdout[-500:])
    sys.stderr.write(proc.stderr[-2000:])
    meta.update(classification="executed", rc=proc.returncode, cmd=cmd, finished=time.time())
    rep = out / "jobs" / f"{args.job}.results.json"
    meta["results_sha256"] = hashlib.sha256(rep.read_bytes()).hexdigest() if rep.exists() else None
    meta["inventory_sha256"] = hashlib.sha256((out / "inventory" / f"{args.job}.json").read_bytes()).hexdigest()
    write_json(out / "jobs" / f"{args.job}.meta.json", meta)
    return proc.returncode


def cmd_run_check(args: argparse.Namespace) -> int:
    out = Path(args.out)
    meta = {"job": args.job, "kind": "check", "revision": revision(), "started": time.time()}
    proc = subprocess.run(args.command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    (out / "jobs").mkdir(parents=True, exist_ok=True)
    (out / "jobs" / f"{args.job}.log").write_text(proc.stdout + proc.stderr, encoding="utf-8", errors="replace")
    sys.stdout.write(proc.stdout[-500:])
    sys.stderr.write(proc.stderr[-2000:])
    meta.update(classification="executed", rc=proc.returncode, cmd=args.command, finished=time.time())
    write_json(out / "jobs" / f"{args.job}.meta.json", meta)
    return proc.returncode


def cmd_mark_unmet(args: argparse.Namespace) -> int:
    meta = {"job": args.job, "kind": load_manifest()["jobs"][args.job]["kind"], "revision": revision(),
            "classification": "env_unmet", "rc": None, "missing_env": [args.reason],
            "started": time.time(), "finished": time.time()}
    write_json(Path(args.out) / "jobs" / f"{args.job}.meta.json", meta)
    return 0


def cmd_record_ci(args: argparse.Namespace) -> int:
    """A required non-pytest check whose evidence is a CI job's conclusion.

    Only ``success`` counts. cancelled / skipped / failure / missing all become
    a non-zero rc, so the gate cannot be satisfied by a job that never ran.
    """
    meta = {"job": args.job, "kind": "check", "revision": revision(), "classification": "executed",
            "rc": 0 if args.result == "success" else 1, "ci_result": args.result,
            "started": time.time(), "finished": time.time()}
    write_json(Path(args.out) / "jobs" / f"{args.job}.meta.json", meta)
    return 0


# ----------------------------------------------------------------------- verify
# A floor that lives in reviewed CODE, not only in the manifest: deleting a job
# from (or marking one optional in) acceptance/suites.json cannot drop it from
# the verdict. Only enforced when evaluating this repository itself.
MINIMUM_REQUIRED_JOBS = frozenset({
    "core-isolated", "core-isolated-container", "core-postgres", "core-live",
    "browser-disposable", "browser-target", "check-compose-config", "check-k8s-policy",
    "check-kubeconform", "check-image-scan", "check-kind-smoke",
})
# Jobs ordinary PR CI cannot own because it provisions no authorized deployed
# target or target credentials. Like MINIMUM_REQUIRED_JOBS this lives in reviewed
# CODE, not the manifest, so the manifest cannot widen the exemption. Only
# ``verify --mode pr-ci`` consults it; final-beta ignores it entirely.
PR_CI_NOT_PERFORMED = frozenset({"browser-target"})
MODES = {"pr-ci": "PR-CI", "final-beta": "FINAL-BETA ACCEPTANCE"}
NOT_PERFORMED_STATUS = "NOT PERFORMED IN PR CI"
_JOB_KEYS = {"kind", "python", "description", "paths", "ignore", "env", "forbid_env", "requires_env", "evidence"}
_OUTCOMES = {"passed", "failed", "skipped", "xfailed", "xpassed", "error", "not_run"}
MAX_AGE_SECONDS = 48 * 3600
CLOCK_SLACK = 5.0


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_files(manifest: dict) -> set[str]:
    """Every test file in the working tree (tracked or not, non-ignored dirs)."""
    skip = set(manifest["ignored_dirs"])
    found = set()
    for path in ROOT.rglob("*.py"):
        rel = path.relative_to(ROOT)
        if skip & set(rel.parts):
            continue
        if any(fnmatch.fnmatch(path.name, g) for g in manifest["test_globs"]):
            found.add(rel.as_posix())
    return found


def covered(rel: str, job: dict) -> bool:
    inside = any(rel == p or rel.startswith(p.rstrip("/") + "/") for p in job["paths"])
    return inside and not any(rel == i or rel.startswith(i.rstrip("/") + "/") for i in job.get("ignore", []))


def manifest_errors(manifest: dict) -> list[str]:
    errs = []
    jobs = manifest.get("jobs", {})
    if ROOT == REPO_ROOT:
        errs += [f"required job missing from manifest: {j}" for j in sorted(MINIMUM_REQUIRED_JOBS - set(jobs))]
    for name, job in jobs.items():
        if job.get("kind") not in ("pytest", "check"):
            errs.append(f"{name}: unknown kind {job.get('kind')!r}")
        extra = set(job) - _JOB_KEYS
        if extra:  # e.g. "required": false / "optional" / "allow_skip" -- there is no such thing
            errs.append(f"{name}: unsupported manifest key(s) {sorted(extra)}")
        if job.get("kind") == "pytest" and not job.get("paths"):
            errs.append(f"{name}: pytest job with no paths")
        if job.get("kind") == "pytest" and option_like([*(job.get("paths") or []), *job.get("ignore", [])]):
            errs.append(f"{name}: path/ignore entries must be paths, not pytest options")
    return errs


def normalized_args(cmd: list[str]) -> list[str]:
    """pytest argv with the report path (which differs per host) masked."""
    out, mask_next = [], False
    for tok in cmd:
        if mask_next:
            out.append("<report>")
            mask_next = False
            continue
        out.append(tok)
        mask_next = tok == "--acc-report"
    return out


def check_pytest_job(name, job, out, meta, manifest_sha, bad, now):
    res_path, inv_path = out / "jobs" / f"{name}.results.json", out / "inventory" / f"{name}.json"
    res, inv = read_json(res_path), read_json(inv_path)
    if not isinstance(res, dict) or res.get("complete") is not True:
        bad("result report missing, empty or incomplete")
        return None
    if not isinstance(inv, dict) or inv.get("complete") is not True:
        bad("pre-execution inventory missing, empty or incomplete")
        return None
    if meta.get("results_sha256") != sha256_file(res_path):
        bad("result report changed after the job published it (sha256 mismatch)")
    if meta.get("inventory_sha256") != sha256_file(inv_path):
        bad("inventory changed after the job started (sha256 mismatch)")
    if meta.get("manifest_sha256") != manifest_sha:
        bad("job ran against a different acceptance/suites.json")
    if res.get("job") != name or inv.get("job") != name or res.get("collect_only") or not inv.get("collect_only"):
        bad("report is not from a real execution of this job (job/mode mismatch)")
    # Exactly the manifest-owned pytest arguments: no -k/-m/--deselect/--lf/-x,
    # no narrowed paths. Do not resolve python_for(job) here: verify inspects
    # already-recorded evidence and may run on a host that does not have the
    # producer profile (for example Playwright's browser venv).
    expected = normalized_args(pytest_args(name, job, Path("x"), collect_only=False))
    if normalized_args(list(res.get("args", []))) != expected:
        bad("pytest was not invoked with the manifest's exact arguments")
    if normalized_args(list(meta.get("cmd", []))[3:]) != expected:
        bad("recorded process command differs from the manifest's")
    if normalized_args(list(inv.get("args", []))) != normalized_args(
            pytest_args(name, job, Path("x"), collect_only=True)):
        bad("inventory was not collected with the manifest's exact arguments")
    # Timing: inventory before execution; report inside the job's own window; not stale.
    if not (isinstance(inv.get("finished"), (int, float)) and inv["finished"] <= meta["started"] + CLOCK_SLACK):
        bad("inventory was not recorded before execution began")
    rs, rf = res.get("started"), res.get("finished")
    if not (isinstance(rs, (int, float)) and isinstance(rf, (int, float))
            and meta["started"] - CLOCK_SLACK <= rs <= rf <= meta["finished"] + CLOCK_SLACK):
        bad("result report timestamps fall outside the job's execution window")
    if now - meta["finished"] > MAX_AGE_SECONDS:
        bad("evidence is stale (older than 48h)")
    # Recompute everything from the raw per-test map; never trust counts/violations fields.
    results, collected, inv_collected = res.get("results"), res.get("collected"), inv.get("collected")
    if not (isinstance(results, dict) and isinstance(collected, list) and isinstance(inv_collected, list)):
        bad("malformed result/inventory structure")
        return None
    if len(set(collected)) != len(collected) or len(set(inv_collected)) != len(inv_collected):
        bad("duplicated test IDs in a collected list")
    for rep in (res, inv):
        if rep.get("duplicate_ids"):
            bad(f"duplicated test IDs collected: {rep['duplicate_ids'][:3]}")
        if rep.get("collected_count") != len(rep["collected"]):
            bad("collected_count disagrees with the collected list (duplicates hidden?)")
        for field, label in (("deselected", "deselected tests"), ("collect_errors", "collection errors"),
                             ("collect_skips", "modules skipped at collection"),
                             ("internal_errors", "pytest internal errors")):
            if rep.get(field):
                bad(f"{label} recorded ({len(rep[field])})")
        raw_n = rep.get("raw_collected_count")
        if raw_n is not None and raw_n != len(rep["collected"]) + len(rep.get("deselected", [])):
            bad(f"{raw_n - len(rep['collected']) - len(rep.get('deselected', []))} collected item(s) "
                "removed without being reported as deselected")
    if res.get("pytest_exitstatus") != 0 or meta.get("rc") != 0:
        bad(f"process exit status {meta.get('rc')} / pytest {res.get('pytest_exitstatus')}")
    if not inv_collected:
        bad("inventory declares zero tests")
    declared = set(inv_collected)
    if set(collected) != declared:
        bad("tests collected at execution differ from the pre-execution inventory")
    for missing_id in sorted(declared - set(results)):
        bad(f"declared but never reported: {missing_id}")
    for extra_id in sorted(set(results) - declared):
        bad(f"executed but not in the recorded inventory: {extra_id}")
    counts: dict[str, int] = {}
    for tid, outcome in sorted(results.items()):
        if outcome not in _OUTCOMES:
            bad(f"unrecognised outcome {outcome!r}: {tid}")
            continue
        counts[outcome] = counts.get(outcome, 0) + 1
        if outcome == "passed" and tid in res.get("details", {}):
            bad(f"passed but the report carries a skip/failure detail for it (inconsistent): {tid}")
        if outcome != "passed":
            detail = res.get("details", {}).get(tid, "")[:120]
            bad(f"{outcome.upper()}: {tid}" + (f" ({detail})" if detail else ""))
    return {"counts": counts, "results": results}, inv


def check_check_job(name, job, meta, bad):
    ev = job.get("evidence", {})
    if meta.get("rc") != 0:
        bad(f"process exit code {meta.get('rc')}")
        return
    if meta.get("ci_result") is not None:
        if meta["ci_result"] != "success":
            bad(f"CI job concluded {meta['ci_result']!r}")
        return
    needed = ev.get("cmd_contains") or []
    if not needed:
        bad("this check has no local execution path; it needs its CI job's success record")
    elif not all(any(tok == c or tok.endswith(c) for tok in meta.get("cmd", [])) for c in needed):
        bad("recorded command is not the prescribed check")


def verify_evidence(out: Path, *, mode: str, current: dict | None = None, now: float | None = None,
                    write: bool = True) -> dict:
    if mode not in MODES:  # no default: an unselected/unknown mode must never be guessed
        raise ValueError(f"verification mode must be one of {sorted(MODES)}, got {mode!r}")
    manifest = load_manifest()
    not_performed = PR_CI_NOT_PERFORMED if mode == "pr-ci" else frozenset()
    if write:  # a stale verdict from an earlier run/mode must never survive a failed verify
        for stale in ("verdict.json", "verdict.md", "coverage_map.json"):
            (out / stale).unlink(missing_ok=True)
    manifest_sha = sha256_file(MANIFEST)
    now = time.time() if now is None else now
    current = current or revision()
    failures: list[str] = list(manifest_errors(manifest))
    env_unmet: list[str] = []
    rows, executions, revs = [], {}, set()
    per_id_jobs: dict[str, dict[str, str]] = {}
    inventories: dict[str, set[str]] = {}

    for name, job in manifest["jobs"].items():
        row = {"job": name, "kind": job.get("kind"), "status": "PASS", "why": [], "counts": {}}
        rows.append(row)
        if name in not_performed:
            # Deliberately not evaluated: a PR-CI verdict must not claim this job, so any
            # evidence for it (even a green one) is neither read nor counted.
            row["status"] = NOT_PERFORMED_STATUS
            row["why"].append("deployed-target acceptance is not performed in PR CI")
            continue

        def bad(msg, kind="fail", _row=row, _name=name):
            _row["status"] = "ENV-UNMET" if kind == "env" and _row["status"] != "FAIL" else "FAIL"
            _row["why"].append(msg)
            (env_unmet if kind == "env" else failures).append(f"{_name}: {msg}")

        meta = read_json(out / "jobs" / f"{name}.meta.json")
        if not isinstance(meta, dict) or meta.get("job") != name:
            bad("required job has no result (never ran / artifact missing / wrong job)")
            continue
        rev = meta.get("revision") or {}
        revs.add((rev.get("head"), rev.get("tree_fingerprint")))
        if meta.get("classification") == "env_unmet":
            bad(f"prerequisite unmet: {meta.get('missing_env')}", "env")
            continue
        if (meta.get("classification") != "executed" or not isinstance(meta.get("started"), (int, float))
                or not isinstance(meta.get("finished"), (int, float))):
            bad("job record is incomplete")
            continue
        if job.get("kind") == "check":
            check_check_job(name, job, meta, bad)
            continue
        got = check_pytest_job(name, job, out, meta, manifest_sha, bad, now)
        if got:
            row["counts"] = got[0]["counts"]
            executions[name] = got[0]["results"]
            inventories[name] = set(got[1].get("collected", []))
            for tid, outcome in got[0]["results"].items():
                per_id_jobs.setdefault(tid, {})[name] = outcome

    # Whole-tree reconciliation: an independent collection of the entire repository,
    # once per interpreter profile (see python_profiles() -- different profiles can
    # report different node IDs for the same file, e.g. the browser venv's
    # pytest-playwright parametrizes by browser name). A test ID counts as seen by
    # the whole-tree collection if ANY profile reports it.
    coverage: dict[str, dict] = {}
    performed_jobs = [j for n, j in manifest["jobs"].items() if n not in not_performed and j.get("kind") == "pytest"]
    deferred_jobs = [j for n, j in manifest["jobs"].items() if n in not_performed and j.get("kind") == "pytest"]

    def deferred(tid: str) -> bool:
        """True when the ONLY jobs covering this test are ones PR CI does not perform."""
        rel = tid.split("::")[0]
        return (any(covered(rel, j) for j in deferred_jobs)
                and not any(covered(rel, j) for j in performed_jobs))
    profiles = python_profiles(manifest)
    all_invs = {p: read_json(out / "inventory" / f"_all-{p}.json") for p in profiles}
    missing_profiles = [p for p, d in all_invs.items() if not isinstance(d, dict) or d.get("complete") is not True]
    if missing_profiles:
        failures.append(f"whole-tree inventory missing/incomplete for profile(s): {missing_profiles}")
    else:
        whole_ids: set[str] = set()
        for p, d in all_invs.items():
            if d.get("duplicate_ids") or d.get("collect_errors") or d.get("collect_skips") or d.get("internal_errors"):
                failures.append(f"whole-tree collection under profile {p!r} had duplicates/errors/skips")
            whole_ids |= set(d.get("collected", []))
            # A job's own inventory (collected under ITS OWN profile) must be a
            # subset of that same profile's whole-tree view -- catches a job
            # quietly collecting IDs its interpreter would never really produce.
        if not whole_ids:
            failures.append("whole-tree collection is empty across every profile")
        for name, job in manifest["jobs"].items():
            if job["kind"] != "pytest" or name not in inventories:
                continue
            prof = job.get("python", "main")
            prof_ids = set((all_invs.get(prof) or {}).get("collected", []))
            leaked = inventories[name] - prof_ids
            if leaked:
                failures.append(f"{name}: collected {len(leaked)} ID(s) its own profile's whole-tree "
                                f"collection does not report, e.g. {sorted(leaked)[:2]}")
        for tid in sorted(whole_ids):
            if deferred(tid):
                continue
            jobs_for = per_id_jobs.get(tid, {})
            coverage[tid] = {"jobs": sorted(jobs_for), "outcomes": jobs_for}
            if not jobs_for:
                failures.append(f"collected test has NO executed required path: {tid}")
            elif not any(o == "passed" for o in jobs_for.values()):
                failures.append(f"collected test never passed in any required job: {tid}")
        for tid in sorted(set(per_id_jobs) - whole_ids):
            failures.append(f"a job executed a test no whole-tree profile ever saw: {tid}")

    executed_files = {tid.split("::")[0] for tid, c in coverage.items() if any(o == "passed" for o in c["outcomes"].values())}
    for f in sorted(f for f in test_files(manifest) - executed_files if not deferred(f + "::")):
        failures.append(f"test file yielded no passing test in any job (ignored/deselected by configuration?): {f}")
    pytest_jobs = [j for j in manifest["jobs"].values() if j.get("kind") == "pytest"]
    uncovered = sorted(f for f in test_files(manifest) if not any(covered(f, j) for j in pytest_jobs))
    failures += [f"test file omitted from every required job: {f}" for f in uncovered]

    rev_root = read_json(out / "revision.json")
    if not rev_root:
        failures.append("revision.json missing")
    else:
        revs.add((rev_root.get("head"), rev_root.get("tree_fingerprint")))
    inv_dir = out / "inventory"
    for rev_file in sorted(inv_dir.glob("*.rev.json")) if inv_dir.is_dir() else []:
        r = read_json(rev_file) or {}
        revs.add((r.get("head"), r.get("tree_fingerprint")))
    if len(revs) > 1:
        failures.append(f"evidence spans {len(revs)} different revisions/tree states")
    if revs and revs != {(current["head"], current["tree_fingerprint"])}:
        failures.append("evidence does not match the current HEAD/working tree")

    unique_qualified = sum(1 for c in coverage.values() if any(o == "passed" for o in c["outcomes"].values()))
    outcome_totals: dict[str, int] = {}
    for r in executions.values():
        for o in r.values():
            outcome_totals[o] = outcome_totals.get(o, 0) + 1
    passed_all = not failures and not env_unmet
    label = MODES[mode]
    verdict = {
        "verdict": f"{label} PASS" if passed_all else f"{label} FAIL",
        "mode": mode,
        "final_beta_acceptance": ("PASS" if passed_all else "FAIL") if mode == "final-beta"
                                 else NOT_PERFORMED_STATUS,
        "not_performed": sorted(not_performed),
        "revision": current,
        "unique_tests_collected": len(coverage),
        "unique_tests_qualified": unique_qualified,
        "total_test_executions": sum(len(r) for r in executions.values()),
        "executions_by_job": {k: len(v) for k, v in executions.items()},
        "execution_outcomes": outcome_totals,
        "jobs": rows, "failures": failures, "env_unmet": env_unmet, "uncovered_test_files": uncovered,
    }
    if write:
        write_json(out / "verdict.json", verdict)
        write_json(out / "coverage_map.json", {"revision": current, "tests": coverage})
        lines = [f"# {verdict['verdict']}", "",
                 f"mode: `{mode}`; final beta acceptance: **{verdict['final_beta_acceptance']}**"
                 + (f" (not performed: {', '.join(sorted(not_performed))})" if not_performed else ""), "",
                 f"revision `{current['head']}` (branch {current['branch']}), tree fingerprint "
                 f"`{current['tree_fingerprint'][:16]}`, {len(current['dirty_files'])} uncommitted file(s)", "",
                 f"UNIQUE tests collected: {verdict['unique_tests_collected']}; UNIQUE tests qualified "
                 f"(passed in >=1 required job): {unique_qualified}",
                 f"TOTAL test executions across jobs: {verdict['total_test_executions']} "
                 f"{json.dumps(verdict['executions_by_job'], sort_keys=True)}", "",
                 "| job | status | counts | notes |", "|---|---|---|---|"]
        for r in rows:
            lines.append(f"| {r['job']} | {r['status']} | {json.dumps(r['counts'], sort_keys=True)} | "
                         f"{'; '.join(r['why'])[:200]} |")
        if failures or env_unmet:
            lines += ["", "## Reasons"] + [f"- {f}" for f in (failures + env_unmet)[:200]]
        (out / "verdict.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return verdict


def cmd_verify(args: argparse.Namespace) -> int:
    verdict = verify_evidence(Path(args.out), mode=args.mode)
    print((Path(args.out) / "verdict.md").read_text(encoding="utf-8"))
    if verdict["failures"] or verdict["env_unmet"]:
        print(f"\n{len(verdict['failures'])} failure(s), {len(verdict['env_unmet'])} unmet prerequisite(s)",
              file=sys.stderr)
    return 0 if verdict["verdict"].endswith(" PASS") else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("inventory"); p.add_argument("--out", required=True); p.add_argument("--job", action="append")
    p.set_defaults(fn=cmd_inventory)
    p = sub.add_parser("run-job"); p.add_argument("job"); p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_run_job)
    p = sub.add_parser("inventory-all"); p.add_argument("--out", required=True)
    p.add_argument("--profile", action="append"); p.set_defaults(fn=cmd_inventory_all)
    p = sub.add_parser("run-check"); p.add_argument("job"); p.add_argument("--out", required=True)
    p.add_argument("command", nargs=argparse.REMAINDER); p.set_defaults(fn=cmd_run_check)
    p = sub.add_parser("mark-unmet"); p.add_argument("job"); p.add_argument("--out", required=True)
    p.add_argument("--reason", required=True); p.set_defaults(fn=cmd_mark_unmet)
    p = sub.add_parser("record-ci"); p.add_argument("job"); p.add_argument("--out", required=True)
    p.add_argument("--result", required=True); p.set_defaults(fn=cmd_record_ci)
    p = sub.add_parser("revision"); p.add_argument("--out", required=True)
    p.set_defaults(fn=lambda a: write_json(Path(a.out) / "revision.json", revision()) or 0)
    p = sub.add_parser("verify"); p.add_argument("--out", required=True)
    p.add_argument("--mode", required=True, choices=sorted(MODES)); p.set_defaults(fn=cmd_verify)
    args = ap.parse_args()
    if getattr(args, "command", None) and args.command[:1] == ["--"]:
        args.command = args.command[1:]
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
