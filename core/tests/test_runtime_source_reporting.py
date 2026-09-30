# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Runtime/deployment provenance reporting contract."""

from pathlib import Path

from core.monitoring.event_types import normalize_event


REPO_ROOT = Path(__file__).resolve().parents[2]
OWNER_CORE = REPO_ROOT / "Sentinel-43" / "Sentinel_core.py"
AUTHORITY = REPO_ROOT / "core" / "governance" / "runtime_authority.py"
API_MAIN = REPO_ROOT / "core" / "api" / "main.py"
K8S_API = REPO_ROOT / "deploy" / "kubernetes" / "base" / "s43-api-deployment.yaml"


def test_runtime_event_retains_kubernetes_provenance():
    result = normalize_event(
        {
            "event_id": "runtime-k8s-1",
            "kind": "runtime",
            "source": "kubernetes",
            "source_identity": "s43-api-abc123",
            "platform": "kubernetes",
            "runtime_role": "api",
            "runtime_event": "pod_identity",
            "instance_id": "s43-api-abc123",
            "namespace": "sentinel43",
            "workload": "s43-api",
            "node_name": "worker-a",
            "pod_name": "s43-api-abc123",
            "pod_ip": "10.42.0.12",
            "runtime_metadata": {"service_account": "s43-api"},
        }
    )

    event = result.event
    assert event.kind == "runtime"
    assert event.source == "kubernetes"
    assert event.platform == "kubernetes"
    assert event.runtime_role == "api"
    assert event.runtime_event == "pod_identity"
    assert event.namespace == "sentinel43"
    assert event.workload == "s43-api"
    assert event.node_name == "worker-a"
    assert event.pod_name == "s43-api-abc123"
    assert event.pod_ip == "10.42.0.12"
    assert event.runtime_metadata["service_account"] == "s43-api"


def test_owner_core_supports_api_kubernetes_and_future_runtime_sources():
    source = OWNER_CORE.read_text(encoding="utf-8")

    assert "class RuntimeSource" in source
    assert 'KUBERNETES = "kubernetes"' in source
    assert 'API = "api"' in source
    assert 'DOCKER = "docker"' in source
    assert "class RuntimeObservation" in source
    assert "def build_runtime_observation(" in source
    assert "def report_runtime_observation(" in source
    assert "_report_runtime_observation_from_node" in source


def test_runtime_observations_cross_the_s43_authority_boundary():
    authority = AUTHORITY.read_text(encoding="utf-8")
    api = API_MAIN.read_text(encoding="utf-8")

    assert "def report_runtime_observation(" in authority
    assert "def _report_runtime_observation_from_node(" in authority
    assert "manager.analyze_event(" in authority
    assert "_report_runtime_identity_to_sentinel43" in api
    assert 'source="api"' in api
    assert 'source="kubernetes"' in api
    assert "authority.report_runtime_observation(" in api


def test_kubernetes_downward_api_supplies_runtime_provenance():
    manifest = K8S_API.read_text(encoding="utf-8")

    assert "S43_RUNTIME_PLATFORM" in manifest
    assert 'value: "kubernetes"' in manifest
    assert "S43_RUNTIME_ROLE" in manifest
    assert "S43_K8S_POD_NAME" in manifest
    assert "fieldPath: metadata.name" in manifest
    assert "S43_K8S_NAMESPACE" in manifest
    assert "fieldPath: metadata.namespace" in manifest
    assert "S43_K8S_NODE_NAME" in manifest
    assert "fieldPath: spec.nodeName" in manifest
    assert "S43_K8S_POD_IP" in manifest
    assert "fieldPath: status.podIP" in manifest
    assert "S43_K8S_SERVICE_ACCOUNT" in manifest
    assert "fieldPath: spec.serviceAccountName" in manifest
