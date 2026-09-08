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

"""Expectation-profile bootstrap for Sentinel-43 guards.

This module only selects and registers expectation definitions.

It does NOT:
    - contact Watchtower
    - read Watchtower configuration
    - mutate process environment
    - create threads
    - perform startup telemetry

Application startup may report the returned bootstrap result afterward.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .expectations import (
    get_basic_expectations,
    get_hardened_expectations,
    get_sentinel43_expectations,
)
from .registry import (
    list_expectations,
    register_expectations,
)


_VALID_BOOTSTRAP_PROFILES: Final[frozenset[str]] = frozenset(
    {
        "basic",
        "hardened",
        "sentinel43",
    }
)


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    profile: str
    loaded_profiles: tuple[str, ...]
    loaded_counts: dict[str, int]
    total_expectations: int


def _normalize_profile(
    profile: str,
) -> str:
    normalized = str(
        profile
        or ""
    ).strip().lower()

    if normalized not in _VALID_BOOTSTRAP_PROFILES:
        raise ValueError(
            f"unknown expectation bootstrap profile {profile!r}; "
            f"expected one of {sorted(_VALID_BOOTSTRAP_PROFILES)}"
        )

    return normalized


def bootstrap_expectations(
    profile: str = "sentinel43",
) -> BootstrapResult:
    """Register expectation definitions for one supported profile."""
    normalized = _normalize_profile(
        profile
    )

    loaded_profiles: list[str] = []
    loaded_counts: dict[str, int] = {
        "basic": 0,
        "hardened": 0,
        "sentinel43": 0,
    }

    basic = list(
        get_basic_expectations()
    )
    register_expectations(
        basic
    )
    loaded_profiles.append(
        "basic"
    )
    loaded_counts[
        "basic"
    ] = len(
        basic
    )

    if normalized in {
        "hardened",
        "sentinel43",
    }:
        hardened = list(
            get_hardened_expectations()
        )
        register_expectations(
            hardened
        )
        loaded_profiles.append(
            "hardened"
        )
        loaded_counts[
            "hardened"
        ] = len(
            hardened
        )

    if normalized == "sentinel43":
        sentinel43 = list(
            get_sentinel43_expectations()
        )
        register_expectations(
            sentinel43
        )
        loaded_profiles.append(
            "sentinel43"
        )
        loaded_counts[
            "sentinel43"
        ] = len(
            sentinel43
        )

    return BootstrapResult(
        profile=normalized,
        loaded_profiles=tuple(
            loaded_profiles
        ),
        loaded_counts=dict(
            loaded_counts
        ),
        total_expectations=len(
            list_expectations()
        ),
    )


__all__ = [
    "BootstrapResult",
    "bootstrap_expectations",
]
