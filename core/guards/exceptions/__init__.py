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

from .contracts import (
    ExpectationCategory,
    ExpectationContract,
    ExpectationContext,
    ExpectationResult,
    ExpectationSeverity,
    ExpectationViolation,
)

from .exceptions import (
    SentinelError,
    ExpectationFailed,
    ConfigExpectationFailed,
    AuthExpectationFailed,
    PolicyExpectationFailed,
    DetectionExpectationFailed,
)

from .expectations import (
    BaseExpectation,
    CoreStartupExpectation,
    AuditTraceExpectation,
    ServiceResponseExpectation,
    get_default_expectations,
)

__all__ = [
    # contracts
    "ExpectationCategory",
    "ExpectationContract",
    "ExpectationContext",
    "ExpectationResult",
    "ExpectationSeverity",
    "ExpectationViolation",

    # exceptions
    "SentinelError",
    "ExpectationFailed",
    "ConfigExpectationFailed",
    "AuthExpectationFailed",
    "PolicyExpectationFailed",
    "DetectionExpectationFailed",

    # expectations
    "BaseExpectation",
    "CoreStartupExpectation",
    "AuditTraceExpectation",
    "ServiceResponseExpectation",

    # helpers
    "get_default_expectations",
]