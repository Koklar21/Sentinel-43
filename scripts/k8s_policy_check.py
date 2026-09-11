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

# Datastores that must never be exposed outside the cluster network.
DATASTORE_SERVICES = {"s43-db"}

# The API process holds singleton state that cannot be shared between pods:
# the idempotency ledger is an in-process dict, FenrirHunter and the Sparta
# watchdog run per process, and dashboard WebSocket clients are held per
# process. Two replicas means duplicate event processing, duplicate findings
# and a split broadcast fan-out -- and the ReadWriteOnce state PVC could not
# attach to a second pod anyway. See base/s43-api-deployment.yaml.
SINGLETON_WORKLOADS = {"s43-api"}

# Environment variables naming a file the application WRITES. Each must
# resolve inside a mount backed by a PersistentVolumeClaim: the container
# runs with readOnlyRootFilesystem, and an emptyDir would silently discard
# the audit chain / dead-letter records on restart.
PERSISTENT_PATH_VARS = (
    "S43_AUDIT_SQLITE_PATH",
    "S43_DEAD_LETTER_PATH",
    "S43_DB_PATH",
)

# Local/dev environments relax the production startup contract
# (core/api/main.py::_is_local_environment).
LOCAL_ENVIRONMENTS = {"local", "dev", "development", "test", "testing"}

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

    init_names = {
        c.get("name") for c in pod_spec.get("initContainers", []) or []
    }

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

        # Probe checks apply to long-running app containers only.
        # Kubernetes rejects readiness/liveness probes on a plain
        # initContainer, so demanding them here would be unsatisfiable.
        is_init = cname in init_names
        if doc.get("kind") in PROBED_KINDS and not is_init:
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


def check_datastore_not_public(doc: dict[str, Any], result: Result) -> None:
    if doc.get("kind") != "Service":
        return
    name = (doc.get("metadata") or {}).get("name", "")
    if name not in DATASTORE_SERVICES:
        return
    rid = _resource_id(doc)
    svc_type = (doc.get("spec") or {}).get("type", "ClusterIP")
    result.check(
        svc_type not in ("NodePort", "LoadBalancer"),
        f"{rid}: Service type {svc_type!r} would make the datastore publicly reachable",
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


def check_referenced_objects_exist(all_docs: list[dict[str, Any]], result: Result) -> None:
    """Every object a workload names must be present in the same render.

    A workload referencing a ServiceAccount that no kustomization creates is
    not a cosmetic error: the pod is rejected at admission and the workload
    never runs. This repo shipped exactly that (a Redis StatefulSet naming a
    ServiceAccount defined nowhere) undetected, because nothing checked.

    The Secret is the deliberate exception -- it is provisioned out of band
    at deploy time and must never be committed, so its absence from a render
    is correct.
    """
    present: dict[str, set[str]] = {}
    for doc in all_docs:
        present.setdefault(doc.get("kind", ""), set()).add(
            (doc.get("metadata") or {}).get("name", "")
        )

    for doc in all_docs:
        kind = doc.get("kind")
        if kind in WORKLOAD_KINDS:
            pod_spec = (((doc.get("spec") or {}).get("template") or {}).get("spec")) or {}
        elif kind == "Pod":
            pod_spec = doc.get("spec") or {}
        else:
            continue

        rid = _resource_id(doc)
        sa_name = pod_spec.get("serviceAccountName")
        if sa_name:
            result.check(
                sa_name in present.get("ServiceAccount", set()),
                f"{rid}: references ServiceAccount {sa_name!r}, which this "
                f"render does not create -- its pods would be rejected",
            )

        for volume in pod_spec.get("volumes", []) or []:
            claim = (volume.get("persistentVolumeClaim") or {}).get("claimName")
            if claim:
                result.check(
                    claim in present.get("PersistentVolumeClaim", set()),
                    f"{rid}: mounts PersistentVolumeClaim {claim!r}, which "
                    f"this render does not create",
                )

        for container in _iter_containers(pod_spec):
            for source in container.get("envFrom", []) or []:
                ref = (source.get("configMapRef") or {}).get("name")
                if ref:
                    result.check(
                        ref in present.get("ConfigMap", set()),
                        f"{rid} container {container.get('name')!r}: envFrom "
                        f"ConfigMap {ref!r} is not created by this render",
                    )


def _api_config(all_docs: list[dict[str, Any]]) -> dict[str, str]:
    for doc in all_docs:
        if (
            doc.get("kind") == "ConfigMap"
            and (doc.get("metadata") or {}).get("name") == "sentinel43-config"
        ):
            return {k: str(v) for k, v in (doc.get("data") or {}).items()}
    return {}


def check_singleton_workloads(all_docs: list[dict[str, Any]], result: Result) -> None:
    """A workload that is only safe at one replica must be pinned to one.

    Both halves matter. `replicas: 1` alone is not enough: the default
    RollingUpdate strategy runs the new pod alongside the old one, which is
    the doubled-singleton state the replica count exists to prevent.
    """
    for doc in all_docs:
        if doc.get("kind") != "Deployment":
            continue
        name = (doc.get("metadata") or {}).get("name", "")
        if name not in SINGLETON_WORKLOADS:
            continue
        rid = _resource_id(doc)
        spec = doc.get("spec") or {}

        result.check(
            spec.get("replicas") == 1,
            f"{rid}: is a singleton workload but declares "
            f"replicas={spec.get('replicas')!r}; scaling it out requires "
            f"shared idempotency/broadcast state, not a manifest change",
        )
        result.check(
            (spec.get("strategy") or {}).get("type") == "Recreate",
            f"{rid}: singleton workload must use strategy Recreate; "
            f"RollingUpdate overlaps old and new pods during every rollout",
        )

        selector_labels = (spec.get("selector") or {}).get("matchLabels") or {}
        for other in all_docs:
            if other.get("kind") != "PodDisruptionBudget":
                continue
            pdb_labels = ((other.get("spec") or {}).get("selector") or {}).get(
                "matchLabels"
            ) or {}
            if pdb_labels and pdb_labels.items() <= selector_labels.items():
                result.check(
                    False,
                    f"{_resource_id(other)}: PodDisruptionBudget selects the "
                    f"singleton {name!r}; on a 1-replica workload it cannot "
                    f"add availability and blocks voluntary eviction, so node "
                    f"drains hang indefinitely",
                )


def check_written_state_is_persistent(all_docs: list[dict[str, Any]], result: Result) -> None:
    """Databases the app writes must land on a PVC, not an emptyDir."""
    config = _api_config(all_docs)
    configured = {
        var: config[var] for var in PERSISTENT_PATH_VARS if config.get(var)
    }
    if not configured:
        return

    for doc in all_docs:
        if doc.get("kind") != "Deployment":
            continue
        if (doc.get("metadata") or {}).get("name") not in SINGLETON_WORKLOADS:
            continue

        rid = _resource_id(doc)
        pod_spec = (((doc.get("spec") or {}).get("template") or {}).get("spec")) or {}
        persistent_volumes = {
            v.get("name")
            for v in pod_spec.get("volumes", []) or []
            if v.get("persistentVolumeClaim")
        }

        # Long-running app containers only. An initContainer does not own
        # the application's state and legitimately mounts nothing durable.
        for container in pod_spec.get("containers", []) or []:
            durable_mounts = [
                m.get("mountPath", "")
                for m in container.get("volumeMounts", []) or []
                if m.get("name") in persistent_volumes
            ]
            for var, path in configured.items():
                result.check(
                    any(
                        path.startswith(mount.rstrip("/") + "/")
                        for mount in durable_mounts
                        if mount
                    ),
                    f"{rid} container {container.get('name')!r}: {var}="
                    f"{path!r} is not inside a PersistentVolumeClaim mount "
                    f"{sorted(durable_mounts)} -- that state is discarded on "
                    f"every restart",
                )


def check_internal_callers_pass_host_guard(
    all_docs: list[dict[str, Any]], result: Result
) -> None:
    """In-cluster callers must survive the API's own Host allow-list.

    Fenrir reports findings to S43_FENRIR_*_URL, so those requests arrive
    with the Service DNS name in the Host header. TrustedHostGuard matches
    the bare host against S43_TRUSTED_HOSTS and does not exempt the event
    ingress paths, so an omission here means the API answers its own
    detection node with 400 and findings vanish without an obvious symptom.
    """
    from urllib.parse import urlsplit

    config = _api_config(all_docs)
    trusted = {
        h.strip().lower()
        for h in config.get("S43_TRUSTED_HOSTS", "").split(",")
        if h.strip()
    }
    if not trusted:
        return  # emptiness is reported by the public-profile check

    for var in ("S43_FENRIR_WATCHTOWER_URL", "S43_FENRIR_BROADCAST_URL"):
        url = config.get(var)
        if not url:
            continue
        host = (urlsplit(url).hostname or "").lower()
        if not host:
            continue
        result.check(
            host in trusted,
            f"ConfigMap/sentinel43-config: {var} targets Host {host!r}, "
            f"which is not in S43_TRUSTED_HOSTS ({sorted(trusted)}) -- the "
            f"API would reject its own detection node with 400",
        )


def check_proxy_trust_is_parseable(all_docs: list[dict[str, Any]], result: Result) -> None:
    """S43_TRUSTED_PROXIES is CIDRs or empty -- never a CHANGEME string.

    An unparseable value does not degrade to "trust nothing": the parser
    raises, so it surfaces as a broken request path rather than a safe
    default. Empty is the real fail-closed value.
    """
    import ipaddress

    raw = _api_config(all_docs).get("S43_TRUSTED_PROXIES", "").strip()
    for item in (part.strip() for part in raw.split(",")):
        if not item:
            continue
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            result.check(
                False,
                f"ConfigMap/sentinel43-config: S43_TRUSTED_PROXIES entry "
                f"{item!r} is not a CIDR; leave it empty to trust no proxy",
            )


def check_public_profile_startup_contract(
    all_docs: list[dict[str, Any]], result: Result
) -> None:
    """A public-facing profile must satisfy the app's own startup validation.

    Scoped to renders containing an Ingress. The base render has no edge and
    deliberately does not assert TLS termination -- it is a template to build
    overlays on, not a deployable profile, and failing it here would push
    someone to set the assertion untruthfully to make CI pass.
    """
    ingresses = [d for d in all_docs if d.get("kind") == "Ingress"]
    if not ingresses:
        return

    config = _api_config(all_docs)
    if config.get("S43_ENV", "").strip().lower() in LOCAL_ENVIRONMENTS:
        return

    trusted = {
        h.strip().lower()
        for h in config.get("S43_TRUSTED_HOSTS", "").split(",")
        if h.strip()
    }
    result.check(
        bool(trusted),
        "ConfigMap/sentinel43-config: S43_TRUSTED_HOSTS is empty; a "
        "non-local API refuses to start without it",
    )
    result.check(
        config.get("S43_TLS_TERMINATED_AT_TRUSTED_EDGE", "").strip().lower()
        == "true",
        "ConfigMap/sentinel43-config: a profile with an Ingress must assert "
        "S43_TLS_TERMINATED_AT_TRUSTED_EDGE=true; the app cannot verify TLS "
        "termination from inside and refuses to start without the claim",
    )

    for origin in (
        o.strip() for o in config.get("S43_ALLOWED_ORIGINS", "").split(",") if o.strip()
    ):
        result.check(
            origin.startswith("https://"),
            f"ConfigMap/sentinel43-config: browser origin {origin!r} is "
            f"plaintext behind a TLS ingress",
        )

    for ingress in ingresses:
        for rule in (ingress.get("spec") or {}).get("rules", []) or []:
            host = str(rule.get("host", "")).strip().lower()
            if not host:
                continue
            result.check(
                host in trusted,
                f"{_resource_id(ingress)}: routes Host {host!r}, which is "
                f"not in S43_TRUSTED_HOSTS ({sorted(trusted)}) -- the API "
                f"would answer every public request with 400",
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
        check_datastore_not_public(doc, result)
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
    check_referenced_objects_exist(all_docs, result)
    check_singleton_workloads(all_docs, result)
    check_written_state_is_persistent(all_docs, result)
    check_internal_callers_pass_host_guard(all_docs, result)
    check_proxy_trust_is_parseable(all_docs, result)
    check_public_profile_startup_contract(all_docs, result)

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
