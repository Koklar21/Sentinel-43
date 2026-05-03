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
