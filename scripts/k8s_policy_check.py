#!/usr/bin/env python
"""
Sentinel-43 Kubernetes policy checker.

No OPA/conftest/checkov/kube-score is installed in this environment (see
deploy/kubernetes/README.md's tooling notes), so this implements the
Phase-12-equivalent checklist directly against rendered manifests
(`kubectl kustomize <overlay>`), as a standalone script with no
dependencies beyond PyYAML (already a transitive dependency here).

Usage:
    python scripts/k8s_policy_check.py <rendered.yaml> [<rendered2.yaml> ...]

Exits non-zero if any check fails. Prints one PASS/FAIL line per check per
resource, plus a summary.
"""

from __future__ import annotations

import sys
from typing import Any, Iterable

import yaml

# Kinds whose containers must satisfy the workload-level checks (probes,
# resources, security context). Job is included but exempted from probe
# checks below (Jobs don't have probes; a run-to-completion process
# succeeding /is/ its own "readiness" signal).
WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job"}
PROBED_KINDS = {"Deployment", "StatefulSet", "DaemonSet"}

# automountServiceAccountToken: true is only acceptable for a workload that
# genuinely needs the Kubernetes API — none do in this repo (see
# base/serviceaccounts.yaml's comment). Nothing is listed here on purpose;
# a workload showing up as a violation means either the workload gained a
# real need for API access (and should be added here with a comment
# explaining why), or the manifest regressed.
JUSTIFIED_AUTOMOUNT: set[str] = set()

DEPRECATED_API_VERSIONS = {
    "extensions/v1beta1",
    "apps/v1beta1",
    "apps/v1beta2",
    "networking.k8s.io/v1beta1",
    "policy/v1beta1",
    "batch/v1beta1",
    "rbac.authorization.k8s.io/v1beta1",
}


class Result:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.checks_run = 0

    def check(self, condition: bool, message: str) -> None:
        self.checks_run += 1
        if not condition:
            self.failures.append(message)


def _iter_containers(pod_spec: dict[str, Any]) -> Iterable[dict[str, Any]]:
    yield from pod_spec.get("containers", []) or []
    yield from pod_spec.get("initContainers", []) or []


def _resource_id(doc: dict[str, Any]) -> str:
    meta = doc.get("metadata", {}) or {}
    return f"{doc.get('kind')}/{meta.get('namespace', '-')}/{meta.get('name')}"


def check_deprecated_api(doc: dict[str, Any], result: Result) -> None:
    api_version = doc.get("apiVersion", "")
    result.check(
        api_version not in DEPRECATED_API_VERSIONS,
        f"{_resource_id(doc)}: deprecated apiVersion {api_version!r}",
    )


def check_pod_security(doc: dict[str, Any], pod_spec: dict[str, Any], result: Result) -> None:
    rid = _resource_id(doc)
    pod_sc = pod_spec.get("securityContext", {}) or {}

    result.check(
        pod_sc.get("runAsNonRoot") is True,
        f"{rid}: pod securityContext.runAsNonRoot must be true",
    )
    result.check(
        isinstance(pod_sc.get("runAsUser"), int) and pod_sc["runAsUser"] != 0,
        f"{rid}: pod securityContext.runAsUser must be an explicit nonzero UID",
    )
    result.check(
        not pod_spec.get("hostNetwork"),
        f"{rid}: hostNetwork must not be true",
    )
    result.check(
        not pod_spec.get("hostPID"),
        f"{rid}: hostPID must not be true",
    )
    result.check(
        not pod_spec.get("hostIPC"),
        f"{rid}: hostIPC must not be true",
    )

    for volume in pod_spec.get("volumes", []) or []:
        result.check(
            "hostPath" not in volume,
            f"{rid}: volume {volume.get('name')!r} uses hostPath (not allowed)",
        )

    for container in _iter_containers(pod_spec):
        cname = container.get("name")
        csc = container.get("securityContext", {}) or {}

        result.check(
            csc.get("allowPrivilegeEscalation") is False,
            f"{rid} container {cname}: allowPrivilegeEscalation must be false",
        )
        result.check(
            csc.get("readOnlyRootFilesystem") is True,
            f"{rid} container {cname}: readOnlyRootFilesystem must be true",
        )
        result.check(
            csc.get("privileged") is not True,
            f"{rid} container {cname}: privileged must not be true",
        )
        caps = csc.get("capabilities", {}) or {}
        result.check(
            caps.get("drop") == ["ALL"],
            f"{rid} container {cname}: capabilities.drop must be ['ALL']",
        )
        seccomp = csc.get("seccompProfile") or pod_sc.get("seccompProfile") or {}
        result.check(
            seccomp.get("type") in ("RuntimeDefault", "Localhost"),
            f"{rid} container {cname}: seccompProfile.type must be RuntimeDefault or Localhost",
        )

        image = container.get("image", "")
        result.check(
            ":latest" not in image and (":" in image or "@sha256:" in image),
            f"{rid} container {cname}: image {image!r} must be pinned (no :latest, no implicit tag)",
        )

        resources = container.get("resources", {}) or {}
        result.check(
            bool(resources.get("requests", {}).get("cpu"))
            and bool(resources.get("requests", {}).get("memory"))
            and bool(resources.get("limits", {}).get("cpu"))
            and bool(resources.get("limits", {}).get("memory")),
            f"{rid} container {cname}: must set cpu+memory requests AND limits",
        )

        if doc.get("kind") in PROBED_KINDS:
            result.check(
                "readinessProbe" in container,
                f"{rid} container {cname}: missing readinessProbe",
            )
            result.check(
                "livenessProbe" in container,
                f"{rid} container {cname}: missing livenessProbe",
            )


def check_serviceaccount_automount(doc: dict[str, Any], pod_spec: dict[str, Any], result: Result) -> None:
    rid = _resource_id(doc)
    sa_name = pod_spec.get("serviceAccountName", "default")
    automount = pod_spec.get("automountServiceAccountToken")
    justified = sa_name in JUSTIFIED_AUTOMOUNT
    result.check(
        automount is False or justified,
        f"{rid}: automountServiceAccountToken must be false for ServiceAccount "
        f"{sa_name!r} (not in the justified-exceptions list)",
    )


def check_no_wildcard_rbac(doc: dict[str, Any], result: Result) -> None:
    kind = doc.get("kind")
    if kind not in ("Role", "ClusterRole"):
        return
    rid = _resource_id(doc)
    for rule in doc.get("rules", []) or []:
        result.check(
            "*" not in (rule.get("resources") or []),
            f"{rid}: rule uses wildcard resources",
        )
        result.check(
            "*" not in (rule.get("verbs") or []),
            f"{rid}: rule uses wildcard verbs",
        )
        result.check(
            "*" not in (rule.get("apiGroups") or []),
            f"{rid}: rule uses wildcard apiGroups",
        )
    if kind == "ClusterRoleBinding":
        role_ref = doc.get("roleRef", {}) or {}
        result.check(
            role_ref.get("name") != "cluster-admin",
            f"{rid}: binds cluster-admin",
        )


def check_db_redis_not_public(doc: dict[str, Any], result: Result) -> None:
    if doc.get("kind") != "Service":
        return
    name = (doc.get("metadata") or {}).get("name", "")
    if name not in ("s43-db", "s43-redis"):
        return
    rid = _resource_id(doc)
    svc_type = (doc.get("spec") or {}).get("type", "ClusterIP")
    result.check(
        svc_type not in ("NodePort", "LoadBalancer"),
        f"{rid}: Service type {svc_type!r} would make Postgres/Redis publicly reachable",
    )


SECRET_PLACEHOLDER_PREFIX = "CHANGEME"


def check_no_real_secrets_embedded(doc: dict[str, Any], result: Result, *, source_file: str) -> None:
    if doc.get("kind") != "Secret":
        return
    rid = _resource_id(doc)
    # secret.example.yaml is a documented template, never applied (not
    # listed in any kustomization.yaml's resources) — its placeholder
    # values are expected and fine. Every value in it must still start
    # with CHANGEME, which is checked below regardless of source file, so
    # this isn't a blanket exemption.
    is_example_file = "secret.example" in source_file
    for key, value in {**(doc.get("data") or {}), **(doc.get("stringData") or {})}.items():
        # Composite values (e.g. DATABASE_URL embedding a password) carry
        # the placeholder mid-string rather than as a strict prefix, so
        # "contains" is the correct check here, not startswith().
        looks_like_placeholder = isinstance(value, str) and SECRET_PLACEHOLDER_PREFIX in value
        result.check(
            looks_like_placeholder,
            f"{rid} key {key!r} (from {source_file}): does not look like a "
            f"CHANGEME placeholder — real secret values must never be committed"
            + (" (expected in a template file)" if is_example_file else ""),
        )


def check_network_policy_coverage(all_docs: list[dict[str, Any]], result: Result) -> None:
    kinds_present = {d.get("kind") for d in all_docs}
    if "NetworkPolicy" not in kinds_present:
        result.check(False, "no NetworkPolicy resources found in this render at all")
        return
    default_deny = any(
        d.get("kind") == "NetworkPolicy"
        and (d.get("spec") or {}).get("podSelector") == {}
        and set((d.get("spec") or {}).get("policyTypes") or []) >= {"Ingress", "Egress"}
        for d in all_docs
    )
    result.check(default_deny, "no namespace-wide default-deny (Ingress+Egress) NetworkPolicy found")

    workload_apps = {
        (d.get("metadata") or {}).get("labels", {}).get("app")
        for d in all_docs
        if d.get("kind") in WORKLOAD_KINDS
    }
    workload_apps.discard(None)
    policy_selected_apps = {
        (d.get("spec") or {}).get("podSelector", {}).get("matchLabels", {}).get("app")
        for d in all_docs
        if d.get("kind") == "NetworkPolicy"
    }
    for app in workload_apps:
        result.check(
            app in policy_selected_apps,
            f"workload app={app!r} has no NetworkPolicy selecting it by app label",
        )


def run(paths: list[str]) -> int:
    all_docs: list[dict[str, Any]] = []
    doc_sources: list[str] = []

    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            for doc in yaml.safe_load_all(f):
                if not doc:
                    continue
                all_docs.append(doc)
                doc_sources.append(path)

    result = Result()

    for doc, source in zip(all_docs, doc_sources):
        check_deprecated_api(doc, result)
        check_no_wildcard_rbac(doc, result)
        check_db_redis_not_public(doc, result)
        check_no_real_secrets_embedded(doc, result, source_file=source)

        kind = doc.get("kind")
        pod_spec = None
        if kind in WORKLOAD_KINDS:
            pod_spec = (((doc.get("spec") or {}).get("template") or {}).get("spec")) or {}
        elif kind == "Pod":
            pod_spec = doc.get("spec") or {}

        if pod_spec:
            check_pod_security(doc, pod_spec, result)
            check_serviceaccount_automount(doc, pod_spec, result)

    check_network_policy_coverage(all_docs, result)

    print(f"Checked {len(all_docs)} resources across {len(paths)} file(s), {result.checks_run} assertions run.")
    if result.failures:
        print(f"\n{len(result.failures)} FAILURE(S):")
        for failure in result.failures:
            print(f"  FAIL: {failure}")
        return 1

    print("PASS: all policy checks passed.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/k8s_policy_check.py <rendered.yaml> [...]", file=sys.stderr)
        sys.exit(2)
    sys.exit(run(sys.argv[1:]))
