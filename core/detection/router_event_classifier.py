# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
"""Deterministic classification for authenticated router/syslog observations."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Final


_MAX_MESSAGE: Final[int] = 4096

_SOURCE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\b(?:SRC|SOURCE|SRC_IP|SOURCE_IP)\s*[=:]\s*([^\s,;]+)", re.IGNORECASE),
    re.compile(r"\bsrc\s+([^\s,;]+)", re.IGNORECASE),
)

_PORT_SCAN_RE = re.compile(r"\b(?:port[-_ ]?scan|tcp[-_ ]?scan|udp[-_ ]?scan|nmap)\b", re.IGNORECASE)
_BRUTE_FORCE_RE = re.compile(r"\b(?:brute[-_ ]?force|bruteforce)\b", re.IGNORECASE)
_CREDENTIAL_STUFFING_RE = re.compile(r"\bcredential[-_ ]?stuffing\b", re.IGNORECASE)
_AUTH_FAILURE_RE = re.compile(
    r"\b(?:authentication|auth|login|password)\b.{0,80}\b(?:fail(?:ed|ure)?|invalid|denied)\b",
    re.IGNORECASE,
)
_EXFIL_RE = re.compile(r"\b(?:exfiltration|data exfil|exfil)\b", re.IGNORECASE)
_SPYWARE_RE = re.compile(
    r"(?:\bspyware\b.{0,80}\b(?:detected|blocked|found|alert)\b|"
    r"\b(?:detected|blocked|found|alert)\b.{0,80}\bspyware\b)",
    re.IGNORECASE,
)
_MALWARE_RE = re.compile(
    r"(?:\b(?:malware|virus)\b.{0,80}\b(?:detected|blocked|found|infected|alert)\b|"
    r"\b(?:detected|blocked|found|infected|alert)\b.{0,80}\b(?:malware|virus)\b)",
    re.IGNORECASE,
)
_BLOCK_ACTIONS: Final[frozenset[str]] = frozenset({"deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected"})


@dataclass(frozen=True, slots=True)
class RouterClassification:
    event_type: str
    source_ip: str
    detector_eligible: bool
    success: bool | None
    reason: str


def _normalized_ip(value: str | None) -> str:
    raw = str(value or "").strip().strip("[](),")
    if not raw:
        return ""
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


def _source_ip_from_message(message: str) -> str:
    for pattern in _SOURCE_PATTERNS:
        match = pattern.search(message)
        if match:
            parsed = _normalized_ip(match.group(1))
            if parsed:
                return parsed
    return ""


def classify_router_event(
    *,
    message: str,
    source_ip: str | None = None,
    action: str | None = None,
) -> RouterClassification:
    """Map bounded router facts to S43-owned event semantics.

    The collector reports observations only. Threat vocabulary is chosen here
    inside Sentinel-43 so an external sensor cannot self-declare a severity,
    threat kind, or trusted detector event type.
    """
    text = str(message or "")[:_MAX_MESSAGE]
    subject_ip = _normalized_ip(source_ip) or _source_ip_from_message(text)
    normalized_action = str(action or "").strip().lower()

    event_type = "router_observation"
    detector_eligible = False
    success: bool | None = None
    reason = "informational_router_observation"

    if _PORT_SCAN_RE.search(text):
        event_type = "port_scan"
        detector_eligible = True
        success = False
        reason = "router_reported_port_scan"
    elif _BRUTE_FORCE_RE.search(text):
        event_type = "brute_force"
        detector_eligible = True
        success = False
        reason = "router_reported_brute_force"
    elif _CREDENTIAL_STUFFING_RE.search(text):
        event_type = "credential_stuffing"
        detector_eligible = True
        success = False
        reason = "router_reported_credential_stuffing"
    elif _AUTH_FAILURE_RE.search(text):
        event_type = "auth_failure"
        detector_eligible = True
        success = False
        reason = "router_reported_auth_failure"
    elif _EXFIL_RE.search(text):
        event_type = "exfiltration"
        detector_eligible = True
        success = False
        reason = "router_reported_exfiltration"
    elif _SPYWARE_RE.search(text):
        event_type = "spyware_activity"
        detector_eligible = True
        success = False
        reason = "router_reported_spyware"
    elif _MALWARE_RE.search(text):
        event_type = "malware_activity"
        detector_eligible = True
        success = False
        reason = "router_reported_malware"
    elif normalized_action in _BLOCK_ACTIONS:
        event_type = "router_firewall_block"
        success = False
        reason = "router_reported_firewall_block"

    if detector_eligible and not subject_ip:
        detector_eligible = False
        reason += "_without_subject_ip"

    return RouterClassification(
        event_type=event_type,
        source_ip=subject_ip,
        detector_eligible=detector_eligible,
        success=success,
        reason=reason,
    )


__all__ = ["RouterClassification", "classify_router_event"]
