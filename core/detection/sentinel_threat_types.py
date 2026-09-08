# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Canonical threat types shared across Sentinel-43 detection and governance."""

from __future__ import annotations

import math
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


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


@dataclass(frozen=True, slots=True)
class ThreatAssessment:
    identity: str
    source_ip: str
    threat_kind: ThreatKind
    severity: ThreatSeverity
    source_kind: ThreatSourceKind
    score: float
    indicators: Mapping[str, Any] = field(default_factory=dict)
    supporting_tags: list[str] = field(default_factory=list)
    window_size: int = 0
    generated_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.identity.strip():
            raise ValueError("identity must not be empty")

        if not self.source_ip.strip():
            raise ValueError("source_ip must not be empty")

        if not math.isfinite(self.score):
            raise ValueError("score must be finite")

        if not 0.0 <= self.score <= 100.0:
            raise ValueError("score must be between 0 and 100")

        if self.window_size < 0:
            raise ValueError("window_size must be >= 0")

        if not math.isfinite(self.generated_at):
            raise ValueError("generated_at must be finite")


__all__ = [
    "ThreatAssessment",
    "ThreatKind",
    "ThreatSeverity",
    "ThreatSourceKind",
]
