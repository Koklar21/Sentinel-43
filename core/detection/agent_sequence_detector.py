# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
"""Deterministic AI/agent behavioral sequence matching.

This module recognizes bounded ordered activity patterns only. It does not call
models, infer intent, authorize responses, or enforce actions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Iterable


@dataclass(frozen=True, slots=True)
class AgentSequenceMatch:
    sequence_id: str
    level: str
    event_types: tuple[str, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class _SequenceRule:
    sequence_id: str
    level: str
    steps: tuple[frozenset[str], ...]
    reason: str


_RULES: Final[tuple[_SequenceRule, ...]] = (
    _SequenceRule(
        sequence_id="agent_recon_to_secret_access",
        level="high",
        steps=(
            frozenset({"agent_discovery", "agent_enumeration"}),
            frozenset({"agent_secret_access", "agent_credential_access"}),
        ),
        reason="agent discovery was followed by secret or credential access",
    ),
    _SequenceRule(
        sequence_id="agent_secret_to_external_transfer",
        level="critical",
        steps=(
            frozenset({"agent_secret_access", "agent_credential_access"}),
            frozenset({"agent_external_transfer", "agent_data_export"}),
        ),
        reason="agent secret access was followed by external data transfer",
    ),
    _SequenceRule(
        sequence_id="agent_policy_probe_to_privileged_action",
        level="high",
        steps=(
            frozenset({"agent_policy_probe", "agent_permission_probe"}),
            frozenset({"agent_privileged_action", "agent_permission_change"}),
        ),
        reason="agent policy probing was followed by a privileged action",
    ),
)


def match_agent_sequences(event_types: Iterable[str]) -> tuple[AgentSequenceMatch, ...]:
    """Return ordered sequence matches over an already-bounded event window."""
    normalized = tuple(
        str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
        for value in event_types
        if str(value or "").strip()
    )
    matches: list[AgentSequenceMatch] = []

    for rule in _RULES:
        cursor = 0
        matched: list[str] = []
        for event_type in normalized:
            if event_type in rule.steps[cursor]:
                matched.append(event_type)
                cursor += 1
                if cursor == len(rule.steps):
                    matches.append(
                        AgentSequenceMatch(
                            sequence_id=rule.sequence_id,
                            level=rule.level,
                            event_types=tuple(matched),
                            reason=rule.reason,
                        )
                    )
                    break

    return tuple(matches)


__all__ = ["AgentSequenceMatch", "match_agent_sequences"]
