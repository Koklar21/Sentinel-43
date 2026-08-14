# =============================================================================
# Sentinel-43 — Kubernetes manifest validation
#
# Renders every overlay (kubectl kustomize), schema-validates the rendered
# output with kubeconform (catches invalid/deprecated APIs), then runs
# scripts/k8s_policy_check.py (the Phase-12-equivalent security checklist —
# no root, readOnlyRootFilesystem, pinned images, resource limits, probes,
# NetworkPolicy coverage, no public db/redis, no wildcard RBAC, no secrets
# embedded in tracked manifests, no hostPath, automountServiceAccountToken
# false). Fails the whole run (nonzero exit) if any overlay fails either
# check — this is what .github/workflows/k8s.yml calls in CI.
#
# Usage: pwsh scripts/k8s-validate.ps1
# =============================================================================

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Kubeconform = Join-Path $RepoRoot ".tools/kubeconform.exe"
$K8sVersion = "1.30.0"

if (-not (Test-Path $Kubeconform)) {
    throw "kubeconform not found at $Kubeconform - see deploy/kubernetes/README.md's tooling setup."
}

$overlays = @(
    (Join-Path $RepoRoot "deploy/kubernetes/base"),
    (Join-Path $RepoRoot "deploy/kubernetes/overlays/dev"),
    (Join-Path $RepoRoot "deploy/kubernetes/overlays/beta")
)

$overallFailed = $false

foreach ($overlay in $overlays) {
    $name = Split-Path -Leaf $overlay
    Write-Host "`n=== $name ===" -ForegroundColor Cyan

    $rendered = Join-Path $env:TEMP "s43-k8s-rendered-$name.yaml"
    kubectl kustomize $overlay | Out-File -FilePath $rendered -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: kubectl kustomize failed for $name" -ForegroundColor Red
        $overallFailed = $true
        continue
    }

    Write-Host "-- kubeconform (schema + deprecated API check) --"
    & $Kubeconform -strict -summary -kubernetes-version $K8sVersion $rendered
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: kubeconform found issues in $name" -ForegroundColor Red
        $overallFailed = $true
    }

    Write-Host "-- policy checklist --"
    python (Join-Path $RepoRoot "scripts/k8s_policy_check.py") $rendered
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: policy checklist found issues in $name" -ForegroundColor Red
        $overallFailed = $true
    }
}

Write-Host ""
if ($overallFailed) {
    Write-Host "One or more overlays failed validation." -ForegroundColor Red
    exit 1
}
Write-Host "All overlays passed validation." -ForegroundColor Green
exit 0
