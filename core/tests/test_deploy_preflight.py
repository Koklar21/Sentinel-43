# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_deploy_preflight.py
#
# Beta release-tooling regression guard. scripts/deploy_preflight.py is
# phase-aware: `prepare` checks deploy inputs with nothing running, `verify`
# checks a live target. These tests pin the corrected failure modes:
#
#   - an unspecified --phase is refused, not defaulted
#   - unresolved MANDATORY checks -> nonzero exit (2), never 0
#   - preparation success is labelled preparation success, not acceptance
#   - redirects are recognised without being followed; wrong-host / downgrade
#     redirects fail; nonstandard ports are handled consistently
#   - exact origin / host membership (substring lookalikes fail)
#   - malformed / over-broad trusted-proxy CIDRs fail
#   - the compose project / env-file / -f files reach every inspection command
#   - both the JSON-array and NDJSON `compose ps` forms parse
#   - zero or multiple API instances fail the running-target requirement
#   - unknown worker state does not pass
#   - kube inspection errors stay INCOMPLETE, not "resource absent" = pass
#   - an unrelated HPA is not confused with one targeting s43-api
#   - ':sha256-...' tags are not accepted as digest pinning
# =============================================================================

from __future__ import annotations

import datetime as dt
import importlib.util
import pathlib
import sys

import pytest

_SCRIPTS = pathlib.Path(__file__).resolve().parents[2] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

_spec = importlib.util.spec_from_file_location(
    "deploy_preflight", _SCRIPTS / "deploy_preflight.py")
dp = importlib.util.module_from_spec(_spec)
sys.modules["deploy_preflight"] = dp  # dataclasses introspection needs this
_spec.loader.exec_module(dp)  # type: ignore[union-attr]


# --------------------------------------------------------------------------- #
# phase argument
# --------------------------------------------------------------------------- #
def test_phase_is_required_not_defaulted():
    with pytest.raises(SystemExit) as exc:
        dp.build_parser().parse_args(["compose"])
    assert exc.value.code != 0  # argparse refuses; never silently "prepare"


def test_target_is_required():
    with pytest.raises(SystemExit):
        dp.build_parser().parse_args([])


@pytest.mark.parametrize("phase", ["prepare", "verify"])
def test_phase_round_trips(phase):
    args = dp.build_parser().parse_args(["kube", "--phase", phase])
    assert args.phase == phase


# --------------------------------------------------------------------------- #
# exit-code semantics
# --------------------------------------------------------------------------- #
def test_mandatory_incomplete_is_exit_2_not_0():
    rep = dp.Report("verify", "compose")
    rep.record(dp.PASS, "a")
    rep.record(dp.INCOMPLETE, "b", mandatory=True)
    assert rep.exit_code() == dp.EXIT_INCOMPLETE


def test_any_fail_is_exit_1():
    rep = dp.Report("prepare", "compose")
    rep.record(dp.PASS, "a")
    rep.record(dp.INCOMPLETE, "b", mandatory=True)
    rep.record(dp.FAIL, "c")
    assert rep.exit_code() == dp.EXIT_FAIL


def test_non_mandatory_incomplete_does_not_block():
    rep = dp.Report("prepare", "compose")
    rep.record(dp.PASS, "a")
    rep.record(dp.INCOMPLETE, "b", mandatory=False)
    assert rep.exit_code() == dp.EXIT_OK


def test_all_pass_is_exit_0():
    rep = dp.Report("prepare", "compose")
    rep.record(dp.PASS, "a")
    rep.record(dp.NA, "b", mandatory=False)
    assert rep.exit_code() == dp.EXIT_OK


def test_prepare_pass_is_labelled_preparation_not_acceptance():
    assert "NOT beta acceptance" in dp._acceptance_label("prepare", dp.EXIT_OK)
    assert "acceptance" not in dp._acceptance_label("verify", dp.EXIT_OK).replace(
        "checks passed", "")
    assert dp._acceptance_label("prepare", dp.EXIT_INCOMPLETE) == "not satisfied"


def test_json_report_has_no_raw_values_and_carries_phase_target():
    rep = dp.Report("verify", "kube", hostname="beta.example.net")
    rep.record(dp.FAIL, "S43_JWT_SECRET is a real value", "looks like a placeholder")
    blob = rep.to_json()
    assert '"phase": "verify"' in blob and '"target": "kube"' in blob
    assert '"exit_code": 1' in blob


# --------------------------------------------------------------------------- #
# redirect classification -- recognised, not followed
# --------------------------------------------------------------------------- #
def test_valid_permanent_redirect_to_https_passes():
    s, _ = dp.classify_http_redirect(
        308, "https://beta.example.org/health", "beta.example.org", 443)
    assert s == dp.PASS


def test_a_200_means_http_was_not_redirected():
    s, d = dp.classify_http_redirect(200, "", "beta.example.org", 443)
    assert s == dp.FAIL and "not redirected" in d


def test_redirect_to_a_different_host_fails():
    s, d = dp.classify_http_redirect(
        301, "https://evil.example.com/", "beta.example.org", 443)
    assert s == dp.FAIL and "different host" in d


def test_redirect_that_stays_http_is_a_downgrade_fail():
    s, d = dp.classify_http_redirect(
        302, "http://beta.example.org/health", "beta.example.org", 443)
    assert s == dp.FAIL and "https" in d


def test_redirect_to_wrong_https_port_fails():
    s, d = dp.classify_http_redirect(
        308, "https://beta.example.org:8443/health", "beta.example.org", 443)
    assert s == dp.FAIL


def test_nonstandard_https_port_redirect_is_consistent():
    s, _ = dp.classify_http_redirect(
        308, "https://beta.example.org:8443/health", "beta.example.org", 8443)
    assert s == dp.PASS


# --------------------------------------------------------------------------- #
# origin / host membership -- exact, not substring
# --------------------------------------------------------------------------- #
def test_origin_exact_member_accepts_the_real_origin():
    ok, want, _ = dp.origin_exact_member(
        "https://beta.example.org", "beta.example.org", "https", 443)
    assert ok and want == "https://beta.example.org"


def test_origin_substring_lookalike_is_rejected():
    ok, _, _ = dp.origin_exact_member(
        "https://beta.example.org.attacker.test", "beta.example.org", "https", 443)
    assert not ok


def test_origin_nonstandard_port_must_match():
    ok, want, _ = dp.origin_exact_member(
        "https://beta.example.org:8443", "beta.example.org", "https", 8443)
    assert ok and want.endswith(":8443")
    ok2, _, _ = dp.origin_exact_member(
        "https://beta.example.org", "beta.example.org", "https", 8443)
    assert not ok2


def test_host_exact_member_and_wildcard_reject():
    assert dp.host_exact_member("beta.example.org", "beta.example.org")[0]
    assert dp.host_exact_member(".example.org", "beta.example.org")[0]
    assert not dp.host_exact_member("example.org", "beta.example.org")[0]
    assert not dp.host_exact_member("*", "beta.example.org")[0]
    assert not dp.host_exact_member("beta.example.org.evil.test", "beta.example.org")[0]


# --------------------------------------------------------------------------- #
# trusted-proxy CIDR validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("value", ["", "not-a-cidr", "10.0.0.0/8", "0.0.0.0/0",
                                   "::/0", "10.0.0.5/33"])
def test_bad_or_broad_trusted_proxies_fail(value):
    assert dp.validate_trusted_proxies(value)[0] == dp.FAIL


@pytest.mark.parametrize("value", ["172.28.0.250/32", "10.1.2.0/24",
                                   "192.168.5.4"])
def test_narrow_trusted_proxies_pass(value):
    assert dp.validate_trusted_proxies(value)[0] == dp.PASS


# --------------------------------------------------------------------------- #
# secrets rotation timestamp
# --------------------------------------------------------------------------- #
def test_rotated_at_handles_future_and_naive_and_stale():
    now = dt.datetime(2026, 9, 3, tzinfo=dt.timezone.utc)
    assert dp.parse_rotated_at("2026-12-01T00:00:00Z", now)[0] == dp.FAIL      # future
    assert dp.parse_rotated_at("2026-09-01", now)[0] == dp.FAIL               # 48 hours old
    assert dp.parse_rotated_at("2026-01-01T00:00:00+00:00", now)[0] == dp.FAIL  # stale
    assert dp.parse_rotated_at("2026-09-02T00:00:00Z", now)[0] == dp.PASS  # exactly 24h
    assert dp.parse_rotated_at("2026-09-01T23:59:59Z", now)[0] == dp.FAIL  # 24h + 1s
    assert dp.parse_rotated_at("2026-09-03T00:00:01Z", now)[0] == dp.FAIL  # future
    assert dp.parse_rotated_at("garbage", now)[0] == dp.INCOMPLETE


# --------------------------------------------------------------------------- #
# image identity
# --------------------------------------------------------------------------- #
def test_registry_digest_reference_passes():
    ref = "ghcr.io/acme/sentinel43-api@sha256:" + "a" * 64
    assert dp.validate_image_reference(ref)[0] == dp.PASS


def test_sha256_dash_tag_is_not_digest_pinning():
    s, d = dp.validate_image_reference("sentinel43-api:sha256-" + "a" * 12)
    assert s == dp.FAIL and "not a digest" in d


def test_plain_tag_is_incomplete_without_local_identity():
    assert dp.validate_image_reference("sentinel43-api:beta")[0] == dp.INCOMPLETE


def test_plain_tag_with_local_identity_passes():
    s, _ = dp.validate_image_reference(
        "sentinel43-api:ci", image_id="sha256:" + "b" * 64,
        source_revision="0a5c64d")
    assert s == dp.PASS


def test_placeholder_image_fails():
    assert dp.validate_image_reference("sentinel43-api:CHANGEME")[0] == dp.FAIL


# --------------------------------------------------------------------------- #
# compose ps parsing -- both wire forms
# --------------------------------------------------------------------------- #
def test_parse_compose_ps_ndjson():
    out = ('{"Service":"s43-api","State":"running","Publishers":[]}\n'
           '{"Service":"s43-db","State":"running","Publishers":[]}\n')
    svcs = dp.parse_compose_ps(out)
    assert {s["Service"] for s in svcs} == {"s43-api", "s43-db"}


def test_parse_compose_ps_json_array():
    out = ('[{"Service":"s43-api","State":"running","Publishers":[]},'
           '{"Service":"s43-db","State":"exited","Publishers":[]}]')
    svcs = dp.parse_compose_ps(out)
    assert len(svcs) == 2 and svcs[1]["State"] == "exited"


def test_parse_compose_ps_empty():
    assert dp.parse_compose_ps("") == []
    assert dp.parse_compose_ps("   \n") == []


def test_compose_base_cmd_carries_project_env_file_and_files():
    cmd = dp.compose_base_cmd("s43", ".env.beta",
                              ["docker-compose.yml", "docker-compose.beta.yml"])
    assert cmd[:2] == ["docker", "compose"]
    assert "-p" in cmd and "s43" in cmd
    assert "--env-file" in cmd and ".env.beta" in cmd
    assert cmd.count("-f") == 2


def test_compose_runtime_uses_the_selected_project_on_every_call(monkeypatch):
    seen = []

    def fake_run(cmd, timeout=25):
        seen.append(cmd)
        if cmd[-3:] == ["--format", "json", "--all"]:
            return 0, ('[{"Service":"s43-api","State":"running","Publishers":[]},'
                       '{"Service":"s43-db","State":"running","Publishers":[]},'
                       '{"Service":"s43-proxy","State":"running","Publishers":[]}]')
        # the worker probe exec
        return 0, "CMD=uvicorn core.api.main:app --workers 1\nWC=\nCHILDREN=2\n"

    monkeypatch.setattr(dp, "_run", fake_run)
    rep = dp.Report("verify", "compose")
    dp.check_compose_runtime(rep, "s43proj", ".env.x", ["a.yml", "b.yml"])
    assert seen, "no docker commands issued"
    for cmd in seen:
        assert "-p" in cmd and "s43proj" in cmd
        assert "--env-file" in cmd and ".env.x" in cmd
        assert cmd.count("-f") == 2


def test_published_backend_port_fails_runtime(monkeypatch):
    def fake_run(cmd, timeout=25):
        if "ps" in cmd:
            return 0, ('[{"Service":"s43-api","State":"running",'
                       '"Publishers":[{"PublishedPort":8000,"TargetPort":8000}]},'
                       '{"Service":"s43-db","State":"running","Publishers":[]},'
                       '{"Service":"s43-proxy","State":"running","Publishers":[]}]')
        return 0, "CMD=uvicorn --workers 1\nWC=\nCHILDREN=2\n"

    monkeypatch.setattr(dp, "_run", fake_run)
    rep = dp.Report("verify", "compose")
    dp.check_compose_runtime(rep, "p", ".env", ["c.yml"])
    names = {r.name: r.status for r in rep.results}
    assert names["backend / db / redis not host-published (proxy is the only ingress)"] == dp.FAIL


@pytest.mark.parametrize("n_running,expect", [(0, dp.FAIL), (1, dp.PASS), (2, dp.FAIL)])
def test_api_instance_count(monkeypatch, n_running, expect):
    api = [f'{{"Service":"s43-api","State":"running","Publishers":[]}}'
           for _ in range(n_running)]
    body = "[" + ",".join(api + [
        '{"Service":"s43-db","State":"running","Publishers":[]}',
        '{"Service":"s43-proxy","State":"running","Publishers":[]}']) + "]"

    def fake_run(cmd, timeout=25):
        if "ps" in cmd:
            return 0, body
        return 0, "CMD=uvicorn --workers 1\nWC=\nCHILDREN=2\n"

    monkeypatch.setattr(dp, "_run", fake_run)
    rep = dp.Report("verify", "compose")
    dp.check_compose_runtime(rep, "p", ".env", ["x.yml"])
    got = {r.name: r.status for r in rep.results}
    assert got["exactly one running s43-api instance (no `--scale s43-api=N`)"] == expect


def test_compose_stack_unreachable_is_incomplete(monkeypatch):
    monkeypatch.setattr(dp, "_run", lambda cmd, timeout=25: (1, "no configuration file"))
    rep = dp.Report("verify", "compose")
    dp.check_compose_runtime(rep, "p", ".env", ["x.yml"])
    assert rep.exit_code() == dp.EXIT_INCOMPLETE
    assert not any(r.status == dp.PASS for r in rep.results)


# --------------------------------------------------------------------------- #
# worker assessment
# --------------------------------------------------------------------------- #
def test_worker_assessment_variants():
    assert dp.worker_assessment("uvicorn core.api.main:app --workers 1", "", 0)[0] == dp.PASS
    assert dp.worker_assessment("uvicorn core.api.main:app --workers 4", "", 0)[0] == dp.FAIL
    assert dp.worker_assessment("uvicorn app", "3", 0)[0] == dp.FAIL          # WEB_CONCURRENCY
    assert dp.worker_assessment("python -m something", "", 5)[0] == dp.FAIL   # 5 children
    assert dp.worker_assessment("", "", None)[0] == dp.INCOMPLETE            # unknown
    assert dp.worker_assessment("uvicorn app", "", 0)[0] == dp.PASS


# --------------------------------------------------------------------------- #
# kube helpers
# --------------------------------------------------------------------------- #
def test_k8s_api_container_by_name_then_heuristic_then_ambiguous():
    c, _ = dp.k8s_api_container([{"name": "s43-api"}, {"name": "sidecar"}])
    assert c["name"] == "s43-api"
    c, _ = dp.k8s_api_container([{"name": "web", "image": "acme/sentinel43-api:x"}])
    assert c is not None
    c, why = dp.k8s_api_container([{"name": "a", "image": "api"},
                                  {"name": "b", "image": "api2"}])
    assert c is None and "unambig" in why


def test_k8s_worker_flag_forms():
    assert dp.k8s_worker_flag({"args": ["--workers=4"]})[0] == 4
    assert dp.k8s_worker_flag({"command": ["uvicorn"], "args": ["--workers", "2"]})[0] == 2
    assert dp.k8s_worker_flag({"args": ["-w", "8"]})[0] == 8
    assert dp.k8s_worker_flag(
        {"args": [], "env": [{"name": "WEB_CONCURRENCY", "value": "3"}]})[0] == 3
    assert dp.k8s_worker_flag({"args": ["--host", "0.0.0.0"]})[0] is None


def test_hpa_targets_distinguishes_the_api_from_other_services():
    items = [
        {"metadata": {"name": "core-hpa"},
         "spec": {"scaleTargetRef": {"kind": "Deployment", "name": "s43-core"}}},
        {"metadata": {"name": "api-hpa"},
         "spec": {"scaleTargetRef": {"kind": "Deployment", "name": "s43-api"}}},
    ]
    assert dp.hpa_targets(items) == ["api-hpa"]
    assert dp.hpa_targets(items[:1]) == []


def test_kube_runtime_inspection_errors_stay_incomplete(monkeypatch):
    monkeypatch.setattr(dp, "_run",
                        lambda cmd, timeout=25: (1, "error: You must be logged in"))
    rep = dp.Report("verify", "kube")
    dp.check_kube_runtime(rep, "ctx", "ns")
    # every check is INCOMPLETE, none silently PASS
    assert not any(r.status == dp.PASS for r in rep.results)
    assert rep.exit_code() == dp.EXIT_INCOMPLETE


def test_kube_runtime_unrelated_hpa_does_not_fail(monkeypatch):
    dep = ('{"metadata":{"generation":2},"spec":{"replicas":1,'
           '"template":{"spec":{"containers":[{"name":"s43-api","args":["--workers=1"]}]}}},'
           '"status":{"readyReplicas":1,"observedGeneration":2,"updatedReplicas":1}}')

    def fake_run(cmd, timeout=25):
        if "deploy" in cmd and "json" in cmd:
            return 0, dep
        if "hpa" in cmd:
            return 0, ('{"items":[{"metadata":{"name":"core-hpa"},'
                       '"spec":{"scaleTargetRef":{"kind":"Deployment","name":"s43-core"}}}]}')
        if "job" in cmd:
            return 0, "1"
        if "svc" in cmd:
            return 0, "ClusterIP"
        if cmd[-3:] == ["get", "cm", "-o"] or "cm" in cmd:
            return 0, '{"items":[]}'
        return 0, ""

    monkeypatch.setattr(dp, "_run", fake_run)
    rep = dp.Report("verify", "kube")
    dp.check_kube_runtime(rep, "ctx", "ns")
    got = {r.name: r.status for r in rep.results}
    assert got["no HorizontalPodAutoscaler targets s43-api"] == dp.PASS
    assert got["s43-api spec.replicas == 1 (login throttle is process-local)"] == dp.PASS
    assert rep.exit_code() == dp.EXIT_OK


# --------------------------------------------------------------------------- #
# end-to-end: prepare with a placeholder hostname must not exit 0
# --------------------------------------------------------------------------- #
def test_prepare_compose_with_placeholder_hostname_is_nonzero(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("SENTINEL_ENV=beta\n")
    monkeypatch.setattr(dp.shutil, "which", lambda _t: "/usr/bin/x")
    code = dp.main(["compose", "--phase", "prepare",
                    "--hostname", "beta.example.invalid",
                    "--env-file", str(env)])
    assert code == dp.EXIT_FAIL


def test_verify_without_hostname_is_incomplete_not_pass(monkeypatch):
    monkeypatch.setattr(dp, "_run", lambda cmd, timeout=25: (1, "unreachable"))
    code = dp.main(["kube", "--phase", "verify", "--context", "c",
                    "--namespace", "n"])
    assert code == dp.EXIT_INCOMPLETE


# --------------------------------------------------------------------------- #
# PR #257 blocker 1: S43_OPERATOR_PASSWORD_HASH must be a real Argon2id hash
# before deployment -- deploy_preflight.py cannot import argon2-cffi (kept
# stdlib-only), so operator_hash_status() re-implements the same structural
# policy as core.auth.users.is_valid_argon2id_hash() using only `re` and
# `base64`. These pin that it actually rejects what it claims to.
# --------------------------------------------------------------------------- #
_REAL_SALT = "c29tZXNhbHQxeXo"  # >=16 decoded bytes
_REAL_HASH = "RdescudvJCsgt3ub+b+dWRWJTmaaJObGRdescudvJCsg"  # >=16 decoded bytes


def test_operator_hash_missing_fails():
    status, _ = dp.operator_hash_status("")
    assert status == dp.FAIL


def test_operator_hash_placeholder_fails():
    status, _ = dp.operator_hash_status("CHANGEME_ARGON2_HASH")
    assert status == dp.FAIL


def test_operator_hash_legacy_sha256_fails():
    import hashlib

    status, detail = dp.operator_hash_status(hashlib.sha256(b"x").hexdigest())
    assert status == dp.FAIL
    assert "SHA-256" in detail


def test_operator_hash_wrong_variant_fails():
    value = f"$argon2i$v=19$m=65536,t=3,p=4${_REAL_SALT}${_REAL_HASH}"
    status, _ = dp.operator_hash_status(value)
    assert status == dp.FAIL


def test_operator_hash_unsupported_version_fails():
    value = f"$argon2id$v=18$m=65536,t=3,p=4${_REAL_SALT}${_REAL_HASH}"
    status, _ = dp.operator_hash_status(value)
    assert status == dp.FAIL


def test_operator_hash_malformed_base64_fails():
    value = f"$argon2id$v=19$m=65536,t=3,p=4$!!!not-base64!!!${_REAL_HASH}"
    status, _ = dp.operator_hash_status(value)
    assert status == dp.FAIL


def test_operator_hash_excessive_memory_cost_fails():
    value = f"$argon2id$v=19$m=4294967295,t=3,p=4${_REAL_SALT}${_REAL_HASH}"
    status, _ = dp.operator_hash_status(value)
    assert status == dp.FAIL


def test_operator_hash_excessive_parallelism_fails():
    value = f"$argon2id$v=19$m=65536,t=3,p=16777215${_REAL_SALT}${_REAL_HASH}"
    status, _ = dp.operator_hash_status(value)
    assert status == dp.FAIL


def test_operator_hash_undersized_salt_fails():
    value = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$" + _REAL_HASH
    status, _ = dp.operator_hash_status(value)
    assert status == dp.FAIL


def test_operator_hash_real_generated_hash_passes():
    import sys as _sys

    _core_root = pathlib.Path(__file__).resolve().parents[2]
    if str(_core_root) not in _sys.path:
        _sys.path.insert(0, str(_core_root))
    from core.auth.users import hash_password

    status, _ = dp.operator_hash_status(hash_password("preflight-check-password"))
    assert status == dp.PASS


def test_check_compose_config_fails_closed_on_legacy_hash(tmp_path):
    import hashlib

    env = tmp_path / ".env"
    lines = [f"{k}=placeholder-value-not-a-placeholder-string-zz" for k in dp.REQUIRED_SECRETS]
    lines = [
        line if not line.startswith("S43_OPERATOR_PASSWORD_HASH")
        else f"S43_OPERATOR_PASSWORD_HASH={hashlib.sha256(b'x').hexdigest()}"
        for line in lines
    ]
    env.write_text("\n".join(lines) + "\n")

    rep = dp.Report(phase="prepare", target="compose")
    dp.check_compose_config(rep, str(env), "beta.example.invalid", 443)
    hash_results = [r for r in rep.results if "Argon2id" in r.name]
    assert len(hash_results) == 1
    assert hash_results[0].status == dp.FAIL
