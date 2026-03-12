# Sentinel-43
# Copyright (c) 2026 Justin
#
# This file is part of the Sentinel-43 project.
#
# Licensed under one of the following:
#
# 1. GNU Affero General Public License v3.0 (AGPL-3.0)
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, version 3 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#    See the GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program. If not, see https://www.gnu.org/licenses/.
#
# 2. Commercial License
#    This software is also available under a commercial license that permits
#    use, modification, and distribution without the obligations of the AGPL.
#    For commercial licensing terms, contact the project owner.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

from .expectations import (
    get_basic_expectations,
    get_hardened_expectations,
    get_sentinel43_expectations,
)
from .registry import register_expectations


_VALID_BOOTSTRAP_PROFILES = {"basic", "hardened", "sentinel43"}


def bootstrap_expectations(profile: str = "sentinel43") -> None:
    """
    Register expectations for the selected bootstrap profile.

    Supported profiles:
        - basic
        - hardened
        - sentinel43
    """
    normalized = profile.strip().lower()

    if normalized not in _VALID_BOOTSTRAP_PROFILES:
        raise ValueError(
            f"Unknown expectation bootstrap profile: {profile!r}. "
            f"Expected one of: {sorted(_VALID_BOOTSTRAP_PROFILES)}"
        )

    register_expectations(get_basic_expectations())

    if normalized in {"hardened", "sentinel43"}:
        register_expectations(get_hardened_expectations())

    if normalized == "sentinel43":
        register_expectations(get_sentinel43_expectations())