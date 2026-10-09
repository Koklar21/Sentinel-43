"""Regression guard for the opt-in edge deployment script.

Static contract checks run on every platform without PowerShell or administrator rights.
"""
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "router-monitor.ps1"


def test_default_mode_is_read_only_identify():
    source = SCRIPT.read_text(encoding="utf-8")
    assert '[string]$Mode = "Identify"' in source
    assert '[string]$Mode = "Deploy"' not in source


def test_existing_firewall_rule_is_preserved():
    source = SCRIPT.read_text(encoding="utf-8")
    firewall = source.split("function Set-EdgeFirewall", 1)[1].split("function Save-Configuration", 1)[0]
    assert "if($existing.Count -gt 0){throw" in firewall
    assert "Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction SilentlyContinue|Remove-NetFirewallRule" not in firewall


def test_secret_automation_not_coupled_to_router_script():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "generate_secrets" not in source
    assert "rotate_secrets" not in source
