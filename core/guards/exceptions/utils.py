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

"""Small helpers for expectation collections."""

from __future__ import annotations

from collections.abc import Iterable

from .contracts import ExpectationContract


def expectation_names(
    expectations: Iterable[ExpectationContract],
) -> tuple[str, ...]:
    return tuple(
        expectation.name
        for expectation in expectations
    )


def expectation_categories(
    expectations: Iterable[ExpectationContract],
) -> tuple[str, ...]:
    return tuple(
        expectation.category.value
        for expectation in expectations
    )


__all__ = [
    "expectation_categories",
    "expectation_names",
]
