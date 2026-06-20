# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
#
# Sentinel-43 is distributed under a dual-license model:
#
# 1. GNU Affero General Public License (AGPL v3.0)
#    for open-source use, modification, and distribution.
#
# 2. Commercial License
#    for proprietary, enterprise, government, or other commercial use
#    not permitted under the AGPL v3.0.
#
# Use, modification, redistribution, and commercial use are governed by
# the terms of the applicable license. Any use outside those terms is
# prohibited.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

"""
Sentinel-43 — Shared Threat Types.

Single canonical source for ThreatKind, ThreatSeverity, ThreatSourceKind,
and ThreatAssessment. Every layer that produces or consumes a threat
assessment (the scoring detector, the response/escalation engines) imports
from here instead of defining its own copy.

Why this file exists:

Before this pass, sentinel_threat_detector.py, Shadow_mode.py, and
sentinel_ai_escalation.py each independently defined their own ThreatKind /
ThreatSeverity / ThreatSourceKind / ThreatAssessment -- same names, same
member names, but DIFFERENT underlying types (the detector used str-based
Enum subclasses; the response/escalation engines used plain enum.Enum with
auto() integer values). Wiring the detector's output directly into
Sentinel43ResponseEngine.handle_assessment() would silently break on any
isinstance/identity check, even though .name-based field access happened to
work by coincidence across both.

What changed when consolidating:

  - ThreatKind: the detector's version is a strict superset (adds
    PAYLOAD_ABUSE, RATE_ANOMALY, TIMESTAMP_ABUSE on top of the 6 members
    the response/escalation engines already used). Verified safe: nowhere
    in Shadow_mode.py / sentinel_ai_escalation.py does code exhaustively
    switch over every ThreatKind member -- the only consumer
    (Sentinel43ResponseEngine._build_mid_high) does a narrow `in` check
    against a small explicit set, which is unaffected by additional
    members existing.
  - ThreatSeverity / ThreatSourceKind: member sets were already identical
    across all three files, only the base Enum type differed.
  - ThreatAssessment: field names were already identical. The only
    difference was `indicators`: Optional[object] = None in the response/
    escalation engines vs. Mapping[str, Any] = field(default_factory=dict)
    in the detector. Verified safe: `indicators` is never read anywhere in
    Shadow_mode.py / sentinel_ai_escalation.py (it's constructed without
    ever passing this field, so only the default value mattered, and
    nothing downstream inspects it) -- so switching the default to an
    empty dict has zero behavioral impact there, and is a strictly better
    default for the detector, which does populate it.
  - Base type change to str-Enum is safe for existing consumers: every
    place Shadow_mode.py / sentinel_ai_escalation.py reads one of these
    enums, it uses `.name` (e.g. `severity=d.threat_severity.name` when
    persisting to SQLite), never `.value`, and never relies on numeric
    ordering (plain enum.Enum doesn't support `<`/`>` anyway, so nothing
    could have depended on that). `.name` behaves identically regardless
    of the Enum's base type.

Import path note: this module is written as
sentinel_43_ai/detection/sentinel_threat_types.py, alongside
sentinel_threat_detector.py, based on the existing
`from sentinel_43_ai.detection.sentinel_threat_detector import ...`
import seen elsewhere in this codebase. Adjust the import path in the
files below if your actual package layout differs.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Mapping


# =============================================================================
# Enums
# =============================================================================

class ThreatKind(str, Enum):
    GENERIC_INTRUSION = "GENERIC_INTRUSION"
    CREDENTIAL_ATTACK = "CREDENTIAL_ATTACK"
    MALWARE_DELIVERY = "MALWARE_DELIVERY"
    SPYWARE_ACTIVITY = "SPYWARE_ACTIVITY"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    PAYLOAD_ABUSE = "PAYLOAD_ABUSE"
    RATE_ANOMALY = "RATE_ANOMALY"
    TIMESTAMP_ABUSE = "TIMESTAMP_ABUSE"
    UNKNOWN = "UNKNOWN"


class ThreatSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatSourceKind(str, Enum):
    HUMAN_LIKELY = "HUMAN_LIKELY"
    AI_AUTOMATION_LIKELY = "AI_AUTOMATION_LIKELY"
    MIXED_OR_UNKNOWN = "MIXED_OR_UNKNOWN"


# =============================================================================
# ThreatAssessment
# =============================================================================

@dataclass(frozen=True)
class ThreatAssessment:
    identity: str
    source_ip: str
    threat_kind: ThreatKind
    severity: ThreatSeverity
    source_kind: ThreatSourceKind
    score: float
    indicators: Mapping[str, Any] = field(default_factory=dict)
    supporting_tags: List[str] = field(default_factory=list)
    window_size: int = 0
    generated_at: float = field(default_factory=time.time)


__all__ = [
    "ThreatKind",
    "ThreatSeverity",
    "ThreatSourceKind",
    "ThreatAssessment",
]
