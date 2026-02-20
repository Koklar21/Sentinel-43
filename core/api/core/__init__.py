# =============================================================================
# Sentinel-43 Security Platform
# =============================================================================
#
# Copyright (c) 2026 Justin
# All rights reserved.
#
# Core API module initialization.
#
# This module defines the foundational runtime layer for the Sentinel-43 API,
# including configuration, logging, and system-level initialization.
#
# =============================================================================
# LICENSE (DUAL LICENSE MODEL)
# =============================================================================
#
# OPEN SOURCE LICENSE OPTION (AGPLv3):
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# https://www.gnu.org/licenses/agpl-3.0.html
#
#
# COMMERCIAL LICENSE OPTION:
#
# This file may alternatively be used under the terms of a commercial license
# issued by the copyright holder.
#
# Commercial licenses allow private use, modification, and distribution
# without AGPL copyleft requirements.
#
# =============================================================================

"""
Sentinel-43 API Core Module

This package contains core system components required for API operation,
including configuration management and logging initialization.

Nothing in this module should depend on higher-level API layers such as
routers, schemas, or services. Core must remain dependency-clean.
"""

from __future__ import annotations

__all__ = [
    "config",
    "logging",
]

__version__ = "0.1.0"
__author__ = "Justin"
__platform__ = "Sentinel-43"