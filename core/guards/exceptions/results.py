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

"""Expectation report DTO for logging and API responses."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .contracts import (
    ExpectationCategory,
    ExpectationSeverity,
)


@dataclass(frozen=True, slots=True)
class ExpectationReport:
    expectation_name: str
    category: ExpectationCategory
    severity: ExpectationSeverity
    passed: bool
    message: str
    metadata: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        name = self.expectation_name.strip()

        if not name:
            raise ValueError(
                "expectation_name must not be empty"
            )

        object.__setattr__(
            self,
            "expectation_name",
            name,
        )

        if self.metadata is not None:
            object.__setattr__(
                self,
                "metadata",
                MappingProxyType(
                    dict(
                        self.metadata
                    )
                ),
            )


__all__ = [
    "ExpectationReport",
]
