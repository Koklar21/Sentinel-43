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
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
#
# Unauthorized copying, redistribution, relicensing, reverse engineering,
# or commercial exploitation outside the terms of the applicable license
# is strictly prohibited.
#
# By accessing, modifying, distributing, or using this software, you agree
# to comply with the terms of the applicable license.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
#
# Commercial Licensing:
# Contact the copyright holder for commercial licensing terms.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

from __future__ import annotations

from threading import RLock
from typing import List

from .models import KeyUsageRecord


class KeyLedger:
    """
    In-memory key usage ledger.

    Stores key usage records and allows lookup by subject_id or key_id.

    Note:
        This is process-local memory only. Records are lost on restart.
        For production persistence, back this with SQLite/PostgreSQL
        or an append-only audit log.
    """

    def __init__(self) -> None:
        self._records: list[KeyUsageRecord] = []
        self._lock = RLock()

    def record_usage(self, record: KeyUsageRecord) -> None:
        """
        Add a key usage record to the ledger.
        """

        if not isinstance(record, KeyUsageRecord):
            raise TypeError(
                f"record must be KeyUsageRecord, got {type(record).__name__}"
            )

        with self._lock:
            self._records.append(record)

    def get_records_for_subject(self, subject_id: str) -> list[KeyUsageRecord]:
        """
        Return all records for a given subject_id.
        """

        if not subject_id:
            raise ValueError("subject_id must not be empty")

        with self._lock:
            return [
                record
                for record in self._records
                if record.subject_id == subject_id
            ]

    def get_records_for_key(self, key_id: str) -> list[KeyUsageRecord]:
        """
        Return all records for a given key_id.
        """

        if not key_id:
            raise ValueError("key_id must not be empty")

        with self._lock:
            return [
                record
                for record in self._records
                if record.key_id == key_id
            ]

    def list_records(self) -> list[KeyUsageRecord]:
        """
        Return a snapshot of all records.
        """

        with self._lock:
            return list(self._records)

    def count(self) -> int:
        """
        Return total number of stored records.
        """

        with self._lock:
            return len(self._records)

    def clear(self) -> None:
        """
        Clear all records.

        Intended for tests only unless explicitly approved.
        """

        with self._lock:
            self._records.clear()
