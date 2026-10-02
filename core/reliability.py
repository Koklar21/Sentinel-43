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

"""Event delivery reliability: idempotency, bounded retry, dead-lettering.

The event path already authenticates, normalizes, analyzes, audits and
distributes. This module makes that path survive the boring realities --
duplicate delivery, a Watchtower that is briefly unreachable, a producer that
retries, a queue that fills up -- without turning reliability machinery into
autonomous enforcement.

What this module is NOT:
    - not a second event bus; it wraps delivery on the canonical path
    - not a background worker; nothing here runs on a timer or a thread
    - not an executor; a retry re-attempts DELIVERY of an assessment, never
      the execution of a remediation
    - not a replay daemon; replay is an explicit, authenticated operator act

Everything is bounded. The idempotency ledger has a hard entry cap and a TTL,
the dead-letter store has a row cap, retries have an attempt cap plus a total
deadline, and every failure is recorded rather than swallowed.

SECRET SAFETY
    Dead-letter rows are built by ``sanitize_for_record``, which keeps an
    explicit allowlist of envelope fields and drops everything else --
    including the payload. Tokens, passwords, keys and authorization headers
    have no path into that sanitized, dashboard-visible projection.

    A SEPARATE, protected column (``replay_payload``, written by
    ``sanitize_replay_payload`` and read only by
    ``DeadLetterStore.get_replay_payload``) retains the minimum body needed
    to faithfully redeliver an event on operator replay. It is never
    returned by ``get()``/``list_records()``/``DeadLetterRecord.to_dict()``,
    never logged, bounded in size, and refused (not truncated) rather than
    persisted if it does not fit -- see the REPLAY FIDELITY note below.

REPLAY FIDELITY
    A replay must never claim success while redelivering a materially
    different event than the one that failed. Two consequences follow:

    - Dead-lettering an event without a persisted, faithful replay body
      records that fact (``replay_payload`` stays NULL), and
      ``EventReliabilityManager.replay()`` refuses to replay such a record
      rather than redeliver a payload-less approximation of it. Legacy rows
      written before this existed are exactly this case.
    - ``ReplayStatus.REPLAY_IN_PROGRESS`` marks a record BEFORE the delivery
      attempt, via ``DeadLetterStore.begin_replay_attempt``'s atomic
      claim, and only ``mark_replay_result`` may move it out of that state.
      If persisting the outcome fails after a delivery attempt was already
      made, the row is deliberately left claimed rather than reverted --
      this module cannot know whether the delivery landed, so it refuses to
      let an uncertain outcome look safely replayable again. This is an
      honest at-least-once boundary, not a distributed transaction.
"""

from __future__ import annotations

import json
import logging
import random
import sqlite3
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Final, Mapping

logger = logging.getLogger("sentinel43.reliability")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# =============================================================================
# Delivery state model
# =============================================================================

class DeliveryState(StrEnum):
    """Lifecycle of one logical event through the delivery path.

    A retryable failure is a different operational fact from a terminal one,
    and neither may ever be reported as DELIVERED.
    """

    RECEIVED = "RECEIVED"
    VALIDATED = "VALIDATED"
    ACCEPTED = "ACCEPTED"
    PROCESSING = "PROCESSING"
    DELIVERED = "DELIVERED"
    DUPLICATE = "DUPLICATE"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    FAILED_TERMINAL = "FAILED_TERMINAL"
    DEAD_LETTERED = "DEAD_LETTERED"


#: States from which no further automatic progress is possible.
TERMINAL_STATES: Final[frozenset[DeliveryState]] = frozenset(
    {
        DeliveryState.DELIVERED,
        DeliveryState.DUPLICATE,
        DeliveryState.FAILED_TERMINAL,
        DeliveryState.DEAD_LETTERED,
    }
)


class Retryability(StrEnum):
    RETRYABLE = "retryable"
    TERMINAL = "terminal"


class FailureStage(StrEnum):
    """Where in the path the event stopped."""

    INGRESS = "ingress"
    VALIDATION = "validation"
    NORMALIZATION = "normalization"
    ANALYSIS = "analysis"
    WATCHTOWER_DELIVERY = "watchtower_delivery"
    DISTRIBUTION = "distribution"
    REPLAY = "replay"


# =============================================================================
# Retryability classification
# =============================================================================

#: Statuses worth another attempt.
_RETRYABLE_STATUS: Final[frozenset[int]] = frozenset(
    {408, 425, 429, 500, 502, 503, 504}
)

#: Authentication and authorization failures are NEVER transient. Retrying
#: them burns budget, can trip lockouts, and cannot succeed -- the credential
#: is wrong, and waiting does not change that.
_NEVER_RETRY_STATUS: Final[frozenset[int]] = frozenset(
    {400, 401, 403, 404, 409, 413, 422}
)

#: Transport-level error codes produced by the canonical Watchtower client.
_RETRYABLE_ERRORS: Final[frozenset[str]] = frozenset(
    {"watchtower_timeout", "watchtower_unreachable"}
)
_TERMINAL_ERRORS: Final[frozenset[str]] = frozenset(
    {
        "watchtower_payload_serialization_error",
        "watchtower_invalid_timeout",
        "watchtower_invalid_max_response_bytes",
        "watchtower_response_too_large",
        "watchtower_malformed_response",
    }
)

_MAX_REASON_CHARS: Final[int] = 512


@dataclass(frozen=True, slots=True)
class DeliveryAttemptResult:
    """Outcome of one delivery attempt, already classified."""

    ok: bool
    retryability: Retryability
    reason: str
    status_code: int | None = None

    @property
    def retryable(self) -> bool:
        return not self.ok and self.retryability is Retryability.RETRYABLE


def classify_delivery_result(result: Any) -> DeliveryAttemptResult:
    """Classify a canonical Watchtower-client result.

    ``watchtower_request`` never raises: it returns ``{"error": ...}`` on
    every failure mode and a parsed body otherwise. Success requires BOTH the
    absence of an ``error`` key and a non-error status code -- a 4xx body
    without an ``error`` key must not be read as delivered.
    """
    if not isinstance(result, Mapping):
        return DeliveryAttemptResult(
            ok=False,
            retryability=Retryability.TERMINAL,
            reason="malformed_delivery_result",
        )

    status = result.get("status_code")
    status_code = status if isinstance(status, int) else None
    error = result.get("error")

    if error is None:
        if status_code is None or 200 <= status_code < 300:
            return DeliveryAttemptResult(
                ok=True,
                retryability=Retryability.TERMINAL,
                reason="delivered",
                status_code=status_code,
            )
        error = "unexpected_status"

    if status_code is not None:
        if status_code in _NEVER_RETRY_STATUS:
            retryability = Retryability.TERMINAL
        elif status_code in _RETRYABLE_STATUS:
            retryability = Retryability.RETRYABLE
        else:
            # Any other 5xx may be transient; any other 4xx is a client-side
            # contract problem that will not fix itself.
            retryability = (
                Retryability.RETRYABLE
                if 500 <= status_code < 600
                else Retryability.TERMINAL
            )
        return DeliveryAttemptResult(
            ok=False,
            retryability=retryability,
            reason=str(error),
            status_code=status_code,
        )

    error_text = str(error)
    if error_text in _RETRYABLE_ERRORS:
        retryability = Retryability.RETRYABLE
    else:
        # Terminal for known-terminal codes, and terminal by DEFAULT for an
        # unrecognised failure shape: guessing that an unknown error is
        # transient is how a retry loop becomes infinite. Dead-letter it so a
        # human sees it instead.
        retryability = Retryability.TERMINAL

    return DeliveryAttemptResult(
        ok=False,
        retryability=retryability,
        reason=error_text,
    )


# =============================================================================
# Retry policy
# =============================================================================

@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Bounded retry with exponential backoff and jitter.

    ``total_deadline_seconds`` caps the whole sequence, so a policy can never
    hold a request longer than the caller budgeted regardless of how the
    per-attempt delays add up.
    """

    max_attempts: int = 3
    base_delay_seconds: float = 0.2
    max_delay_seconds: float = 5.0
    jitter_ratio: float = 0.25
    total_deadline_seconds: float = 10.0

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 10:
            raise ValueError("max_attempts must be between 1 and 10")
        if self.base_delay_seconds <= 0:
            raise ValueError("base_delay_seconds must be > 0")
        if self.max_delay_seconds < self.base_delay_seconds:
            raise ValueError("max_delay_seconds must be >= base_delay_seconds")
        if not 0.0 <= self.jitter_ratio <= 1.0:
            raise ValueError("jitter_ratio must be between 0 and 1")
        if self.total_deadline_seconds <= 0:
            raise ValueError("total_deadline_seconds must be > 0")

    def delay_for(self, attempt: int) -> float:
        """Backoff before ``attempt`` (1-based), capped and jittered.

        Jitter is symmetric so a fleet of producers that failed together does
        not retry in lockstep.
        """
        if attempt < 1:
            raise ValueError("attempt must be >= 1")

        capped = min(
            self.base_delay_seconds * (2 ** (attempt - 1)),
            self.max_delay_seconds,
        )
        if self.jitter_ratio == 0.0:
            return capped

        spread = capped * self.jitter_ratio
        return max(
            0.0,
            min(capped + random.uniform(-spread, spread), self.max_delay_seconds),
        )


# =============================================================================
# Idempotency
# =============================================================================

@dataclass(frozen=True, slots=True)
class IdempotencyDecision:
    first_seen: bool
    event_id: str
    original_state: str = ""
    original_recorded_at: str = ""


#: Ledger states from which a NEW producer request for the same event_id
#: may claim a fresh delivery attempt -- terminal failures only.
#: DELIVERED is excluded: that event was genuinely handled, so a repeat is
#: a real duplicate, not a retry. PROCESSING/RECEIVED are excluded too:
#: another delivery for this exact id is in flight right now, and a second
#: concurrent attempt would race it, not recover from it.
_LEDGER_RETRYABLE_STATES: Final[frozenset[str]] = frozenset(
    {
        DeliveryState.FAILED_TERMINAL.value,
        DeliveryState.FAILED_RETRYABLE.value,
        DeliveryState.DEAD_LETTERED.value,
    }
)


class IdempotencyLedger:
    """Bounded, TTL'd record of recently handled ``event_id`` values.

    Keyed on the canonical event id, never on a payload hash: two genuinely
    distinct events can carry identical payloads (the same rule firing twice
    on the same input is real information), and collapsing those loses
    findings.

    Deliberately in-process and bounded rather than durable. It exists to
    absorb transport retries, which happen within seconds, so an entry cap
    plus a TTL is the right shape. A durable ledger of every event id ever
    seen would be an unbounded liability, and the dead-letter store already
    provides the durable record that matters.
    """

    def __init__(
        self,
        *,
        max_entries: int = 10_000,
        ttl_seconds: float = 900.0,
    ) -> None:
        if not 1 <= max_entries <= 1_000_000:
            raise ValueError("max_entries must be between 1 and 1000000")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")

        self._max_entries = max_entries
        self._ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        # event_id -> (monotonic_seen_at, state, iso_recorded_at)
        self._entries: OrderedDict[str, tuple[float, str, str]] = OrderedDict()

    def _evict_expired_locked(self, now: float) -> None:
        cutoff = now - self._ttl_seconds
        while self._entries:
            _, (seen_at, _, _) = next(iter(self._entries.items()))
            if seen_at >= cutoff:
                break
            self._entries.popitem(last=False)

    def check_and_register(
        self,
        event_id: str,
        *,
        state: DeliveryState = DeliveryState.RECEIVED,
    ) -> IdempotencyDecision:
        """Register ``event_id``; report whether this is its first sighting."""
        key = str(event_id).strip()
        if not key:
            raise ValueError("event_id must not be empty")

        now = time.monotonic()
        with self._lock:
            self._evict_expired_locked(now)

            existing = self._entries.get(key)
            if existing is not None:
                _, prior_state, prior_at = existing
                return IdempotencyDecision(
                    first_seen=False,
                    event_id=key,
                    original_state=prior_state,
                    original_recorded_at=prior_at,
                )

            self._entries[key] = (now, str(state), _utc_now())
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

            return IdempotencyDecision(first_seen=True, event_id=key)

    def update_state(self, event_id: str, state: DeliveryState) -> None:
        key = str(event_id).strip()
        with self._lock:
            existing = self._entries.get(key)
            if existing is None:
                return
            seen_at, _, recorded_at = existing
            self._entries[key] = (seen_at, str(state), recorded_at)

    def claim_retry(self, event_id: str) -> bool:
        """Atomically reclaim a failed entry for one fresh delivery attempt.

        Succeeds only when the CURRENTLY recorded state is a terminal
        failure (``_LEDGER_RETRYABLE_STATES``) -- a single guarded
        check-and-set, not a read then a separate write, so two callers
        racing a retry for the same failed event_id cannot both be told
        they may proceed. The same shape as
        ``DeadLetterStore.begin_replay_attempt`` uses for operator replay,
        applied here to the in-process ledger for an ordinary producer
        retry. On success the entry is immediately marked PROCESSING.
        """
        key = str(event_id).strip()
        with self._lock:
            existing = self._entries.get(key)
            if existing is None:
                return False
            seen_at, state, recorded_at = existing
            if state not in _LEDGER_RETRYABLE_STATES:
                return False
            self._entries[key] = (
                seen_at,
                str(DeliveryState.PROCESSING),
                recorded_at,
            )
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


# =============================================================================
# Dead-letter store
# =============================================================================

#: The ONLY envelope fields copied into a dead-letter row. An allowlist, not
#: a denylist: a field nobody named here cannot reach storage, so a new
#: producer field cannot quietly carry a credential into the database.
_RECORD_FIELDS: Final[tuple[str, ...]] = (
    "event_id",
    "correlation_id",
    "parent_event_id",
    "event_type",
    "kind",
    "schema_version",
    "source",
    "source_identity",
    "created_at",
    "ingested_at",
)


def sanitize_for_record(envelope: Mapping[str, Any]) -> dict[str, Any]:
    """Project an event envelope down to the fields safe to persist.

    Allowlist only. Anything not named in ``_RECORD_FIELDS`` is dropped,
    including the payload, which may carry arbitrary producer data. The
    payload has its own separate, protected persistence path -- see
    ``sanitize_replay_payload``.
    """
    record: dict[str, Any] = {}
    for field_name in _RECORD_FIELDS:
        value = envelope.get(field_name)
        if value is None:
            continue
        record[field_name] = str(value)[:256]
    return record


def sanitize_reason(reason: Any) -> str:
    """Bound and flatten a failure reason for storage.

    Reasons come from upstream error bodies, so they are truncated and
    stripped of newlines to keep them from bloating rows or injecting
    structure into logs.
    """
    text = str(reason or "").replace("\n", " ").replace("\r", " ").strip()
    return text[:_MAX_REASON_CHARS]


#: Bound on the persisted replay body. The dead-letter store already bounds
#: row COUNT (``max_rows``); this bounds the SIZE of any single row, so one
#: large producer payload cannot make the underlying SQLite file grow
#: unpredictably. 64 KiB comfortably holds a Fenrir finding or a Sparta
#: integrity report; anything larger is refused rather than truncated,
#: because a truncated body cannot be faithfully redelivered.
_MAX_REPLAY_PAYLOAD_BYTES: Final[int] = 65536


def sanitize_replay_payload(payload: Any) -> str | None:
    """Bound and serialize the body needed to faithfully replay an event.

    Deliberately NOT the same allowlist as ``sanitize_for_record``: the
    point of this value is to redeliver the ORIGINAL event, so it is not
    projected down to a UI-safe subset. What keeps it safe instead:
      - it is persisted in a column nothing but
        ``DeadLetterStore.get_replay_payload`` ever reads,
      - that accessor is called only from replay internals, never from a
        dashboard/status route,
      - it is never logged,
      - it is bounded in size and refused -- not truncated -- when it does
        not fit, because a truncated replay body is not a faithful one.

    Returns None -- meaning "persist no replay body for this event" -- if
    the payload is missing, is not JSON-serializable, or exceeds the size
    bound. None is what makes ``EventReliabilityManager.replay()`` correctly
    refuse an old or oversized record later instead of fabricating a
    partial redelivery.
    """
    if payload is None:
        return None

    try:
        # No `default=` fallback: coercing an unserializable value to its
        # str() would silently change what gets redelivered, which is
        # exactly the unfaithful replay this module exists to refuse.
        encoded = json.dumps(payload, separators=(",", ":"))
    except (TypeError, ValueError):
        logger.warning(
            "Replay payload is not JSON-serializable; this event will be "
            "recorded as not replayable rather than reconstructed partially."
        )
        return None

    if len(encoded.encode("utf-8")) > _MAX_REPLAY_PAYLOAD_BYTES:
        logger.warning(
            "Replay payload exceeds %d bytes; this event will be recorded "
            "as not replayable rather than truncated.",
            _MAX_REPLAY_PAYLOAD_BYTES,
        )
        return None

    return encoded


class ReplayStatus(StrEnum):
    PENDING = "pending"
    #: Claimed by ``begin_replay_attempt`` before a delivery attempt is
    #: made. Only ``mark_replay_result`` may move a row out of this state.
    #: Seeing it OUTSIDE the brief window of an in-flight attempt means one
    #: of two things happened -- a delivery was attempted and persisting its
    #: result then failed, or the process died between the two -- and in
    #: both cases this module genuinely does not know whether delivery
    #: succeeded. It deliberately does not guess: the record stays here,
    #: ineligible for ordinary replay, until a human reconciles it.
    REPLAY_IN_PROGRESS = "replay_in_progress"
    # Historical name retained for storage/API compatibility. This terminal
    # state means the dead-lettered logical event was successfully redelivered,
    # either by explicit operator replay or by a later ordinary producer retry.
    REPLAYED_OK = "replayed_ok"
    REPLAY_FAILED = "replay_failed"


#: Statuses an ordinary operator replay request may act on.
_REPLAYABLE_STATUSES: Final[frozenset[str]] = frozenset(
    {ReplayStatus.PENDING.value, ReplayStatus.REPLAY_FAILED.value}
)


class ReplayEligibility(StrEnum):
    """Outcome of atomically attempting to claim one replay attempt."""

    CLAIMED = "claimed"
    NOT_FOUND = "not_found"
    ALREADY_REPLAYED = "already_replayed"
    IN_PROGRESS = "in_progress"


@dataclass(frozen=True, slots=True)
class DeadLetterRecord:
    row_id: int
    event_id: str
    correlation_id: str
    parent_event_id: str
    event_type: str
    schema_version: str
    source: str
    source_identity: str
    created_at: str
    ingested_at: str
    failure_stage: str
    failure_classification: str
    failure_reason: str
    attempts: int
    first_failed_at: str
    last_attempt_at: str
    replay_status: str
    replay_attempts: int
    #: Whether a faithful replay body was persisted for this event -- NOT
    #: the payload itself (see ``DeadLetterStore.get_replay_payload``, the
    #: only reader of that protected column). False means an ordinary
    #: replay request will be refused: either this row predates replay-body
    #: persistence, or the payload was refused at record time for being
    #: unserializable or too large (see ``sanitize_replay_payload``).
    replay_available: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "row_id": self.row_id,
            "event_id": self.event_id,
            "correlation_id": self.correlation_id,
            "parent_event_id": self.parent_event_id,
            "event_type": self.event_type,
            "schema_version": self.schema_version,
            "source": self.source,
            "source_identity": self.source_identity,
            "created_at": self.created_at,
            "ingested_at": self.ingested_at,
            "failure_stage": self.failure_stage,
            "failure_classification": self.failure_classification,
            "failure_reason": self.failure_reason,
            "attempts": self.attempts,
            "first_failed_at": self.first_failed_at,
            "last_attempt_at": self.last_attempt_at,
            "replay_status": self.replay_status,
            "replay_attempts": self.replay_attempts,
            "replay_available": self.replay_available,
        }


_SCHEMA: Final[str] = """
CREATE TABLE IF NOT EXISTS dead_letter_events (
    row_id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id               TEXT NOT NULL UNIQUE,
    correlation_id         TEXT NOT NULL DEFAULT '',
    parent_event_id        TEXT NOT NULL DEFAULT '',
    event_type             TEXT NOT NULL DEFAULT '',
    schema_version         TEXT NOT NULL DEFAULT '',
    source                 TEXT NOT NULL DEFAULT '',
    source_identity        TEXT NOT NULL DEFAULT '',
    created_at             TEXT NOT NULL DEFAULT '',
    ingested_at            TEXT NOT NULL DEFAULT '',
    failure_stage          TEXT NOT NULL DEFAULT '',
    failure_classification TEXT NOT NULL DEFAULT '',
    failure_reason         TEXT NOT NULL DEFAULT '',
    attempts               INTEGER NOT NULL DEFAULT 0,
    first_failed_at        TEXT NOT NULL DEFAULT '',
    last_attempt_at        TEXT NOT NULL DEFAULT '',
    replay_status          TEXT NOT NULL DEFAULT 'pending',
    replay_attempts        INTEGER NOT NULL DEFAULT 0,
    replay_payload         TEXT
);
CREATE INDEX IF NOT EXISTS idx_dl_replay_status
    ON dead_letter_events (replay_status);
"""


class DeadLetterStore:
    """Bounded, durable record of events that could not be delivered.

    SQLite, matching the audit store's existing persistence choice, so a
    process interruption does not lose the record of what failed. The
    authoritative audit ledger is append-only and HMAC-chained and is
    therefore the wrong home for a row whose replay status must change; this
    store holds operational state, and the audit ledger remains the security
    record.

    Bounded by ``max_rows``: when full, already-replayed rows are evicted
    first, then the oldest remaining. Every eviction is logged, so dropping a
    failed-event record is observable rather than silent.
    """

    def __init__(
        self,
        *,
        sqlite_path: Path,
        max_rows: int = 10_000,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not 1 <= max_rows <= 1_000_000:
            raise ValueError("max_rows must be between 1 and 1000000")

        self._path = Path(sqlite_path)
        self._max_rows = max_rows
        self._timeout = timeout_seconds
        self._lock = threading.RLock()
        self._initialized = False

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            timeout=self._timeout,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def initialize(self) -> None:
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            connection = self._connect()
            try:
                connection.executescript(_SCHEMA)
                self._migrate_schema(connection)
            finally:
                connection.close()
            self._initialized = True

    def _migrate_schema(self, connection: sqlite3.Connection) -> None:
        """Additive column migration for a store created before replay
        fidelity (parent_event_id, replay_payload) existed.

        ``CREATE TABLE IF NOT EXISTS`` does not add columns to a table that
        already exists, so a dead-letter database from before this change
        would otherwise be missing them, and every row read would fail.
        There is no data to backfill: an old row correctly reports
        ``parent_event_id=''`` and ``replay_available=False`` -- the causal
        link and the replay body were never captured for it, and pretending
        otherwise would be exactly the fabrication this module refuses to
        do (see the REPLAY FIDELITY module note).
        """
        existing = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(dead_letter_events)"
            )
        }
        if "parent_event_id" not in existing:
            connection.execute(
                "ALTER TABLE dead_letter_events "
                "ADD COLUMN parent_event_id TEXT NOT NULL DEFAULT ''"
            )
        if "replay_payload" not in existing:
            connection.execute(
                "ALTER TABLE dead_letter_events ADD COLUMN replay_payload TEXT"
            )

    def _require_ready(self) -> None:
        if not self._initialized:
            raise RuntimeError(
                "DeadLetterStore.initialize() must be called before use"
            )

    def record_failure(
        self,
        *,
        envelope: Mapping[str, Any],
        failure_stage: FailureStage | str,
        classification: Retryability | str,
        reason: Any,
        attempts: int,
    ) -> str:
        """Persist (or update) the dead-letter row for one logical event.

        Keyed on ``event_id`` so a retried-then-failed event updates its own
        row rather than accumulating one row per attempt. ``envelope`` may
        carry a ``"payload"`` field (the original producer body) -- it is
        NOT covered by ``sanitize_for_record``'s allowlist; it goes through
        the separate, protected ``sanitize_replay_payload`` path so a
        faithful replay stays possible without widening the sanitized,
        dashboard-visible projection.
        """
        self._require_ready()

        safe = sanitize_for_record(envelope)
        event_id = safe.get("event_id") or ""
        if not event_id:
            raise ValueError("cannot dead-letter an event with no event_id")

        replay_payload = sanitize_replay_payload(envelope.get("payload"))

        now = _utc_now()
        with self._lock:
            connection = self._connect()
            try:
                connection.execute(
                    """
                    INSERT INTO dead_letter_events (
                        event_id, correlation_id, parent_event_id,
                        event_type, schema_version, source, source_identity,
                        created_at, ingested_at, failure_stage,
                        failure_classification, failure_reason, attempts,
                        first_failed_at, last_attempt_at, replay_status,
                        replay_attempts, replay_payload
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)
                    ON CONFLICT(event_id) DO UPDATE SET
                        failure_stage          = excluded.failure_stage,
                        failure_classification = excluded.failure_classification,
                        failure_reason         = excluded.failure_reason,
                        attempts               = excluded.attempts,
                        last_attempt_at        = excluded.last_attempt_at
                    """,
                    (
                        event_id,
                        safe.get("correlation_id", ""),
                        safe.get("parent_event_id", ""),
                        safe.get("event_type", "") or safe.get("kind", ""),
                        safe.get("schema_version", ""),
                        safe.get("source", ""),
                        safe.get("source_identity", ""),
                        safe.get("created_at", ""),
                        safe.get("ingested_at", ""),
                        str(failure_stage),
                        str(classification),
                        sanitize_reason(reason),
                        int(attempts),
                        now,
                        now,
                        ReplayStatus.PENDING.value,
                        replay_payload,
                    ),
                )
                self._enforce_bound(connection)
            finally:
                connection.close()

        return event_id

    def _enforce_bound(self, connection: sqlite3.Connection) -> None:
        total = connection.execute(
            "SELECT COUNT(*) AS n FROM dead_letter_events"
        ).fetchone()["n"]

        if total <= self._max_rows:
            return

        victims = connection.execute(
            """
            SELECT row_id, event_id FROM dead_letter_events
            ORDER BY (replay_status = ?) DESC, row_id ASC
            LIMIT ?
            """,
            (ReplayStatus.REPLAYED_OK.value, total - self._max_rows),
        ).fetchall()

        for row in victims:
            connection.execute(
                "DELETE FROM dead_letter_events WHERE row_id = ?",
                (row["row_id"],),
            )
            logger.warning(
                "Dead-letter store at capacity (%d); evicted event_id=%s -- "
                "a failed-event record was dropped.",
                self._max_rows,
                row["event_id"],
            )

    def get(self, event_id: str) -> DeadLetterRecord | None:
        self._require_ready()
        with self._lock:
            connection = self._connect()
            try:
                row = connection.execute(
                    "SELECT * FROM dead_letter_events WHERE event_id = ?",
                    (str(event_id),),
                ).fetchone()
            finally:
                connection.close()
        return _row_to_record(row) if row is not None else None

    def list_records(
        self,
        *,
        limit: int = 50,
        replay_status: str | None = None,
    ) -> tuple[DeadLetterRecord, ...]:
        self._require_ready()
        bounded = max(1, min(int(limit), 500))

        with self._lock:
            connection = self._connect()
            try:
                if replay_status:
                    rows = connection.execute(
                        """
                        SELECT * FROM dead_letter_events
                        WHERE replay_status = ?
                        ORDER BY row_id DESC LIMIT ?
                        """,
                        (str(replay_status), bounded),
                    ).fetchall()
                else:
                    rows = connection.execute(
                        "SELECT * FROM dead_letter_events "
                        "ORDER BY row_id DESC LIMIT ?",
                        (bounded,),
                    ).fetchall()
            finally:
                connection.close()

        return tuple(_row_to_record(row) for row in rows)

    def counts(self) -> dict[str, int]:
        self._require_ready()
        with self._lock:
            connection = self._connect()
            try:
                total = connection.execute(
                    "SELECT COUNT(*) AS n FROM dead_letter_events"
                ).fetchone()["n"]
                rows = connection.execute(
                    "SELECT replay_status, COUNT(*) AS n "
                    "FROM dead_letter_events GROUP BY replay_status"
                ).fetchall()
            finally:
                connection.close()

        result = {"total": int(total)}
        for row in rows:
            result[str(row["replay_status"])] = int(row["n"])
        return result

    def begin_replay_attempt(
        self, event_id: str
    ) -> tuple[ReplayEligibility, DeadLetterRecord | None]:
        """Atomically decide whether one replay attempt may proceed.

        This is the ONLY place replay eligibility is decided, and it is a
        single guarded UPDATE, not a read-then-write: two concurrent replay
        requests for the same event_id cannot both be told CLAIMED. The
        winner's row is durably marked ``REPLAY_IN_PROGRESS`` BEFORE the
        caller may attempt external delivery, so a process crash -- or a
        later failure to persist the eventual result -- leaves the row in a
        state that is deliberately NOT eligible for another ordinary replay
        (see ``ReplayStatus.REPLAY_IN_PROGRESS``): it requires human
        reconciliation, not an automatic retry.

        This does not build a distributed transaction or exactly-once
        delivery -- it is what an honest at-least-once boundary looks like
        with a single SQLite writer, which matches this application's
        single-replica-safe deployment model.
        """
        self._require_ready()
        now = _utc_now()

        with self._lock:
            connection = self._connect()
            try:
                cursor = connection.execute(
                    """
                    UPDATE dead_letter_events
                    SET replay_status   = ?,
                        last_attempt_at = ?
                    WHERE event_id = ? AND replay_status IN (?, ?)
                    """,
                    (
                        ReplayStatus.REPLAY_IN_PROGRESS.value,
                        now,
                        str(event_id),
                        ReplayStatus.PENDING.value,
                        ReplayStatus.REPLAY_FAILED.value,
                    ),
                )
                claimed = cursor.rowcount == 1
                row = connection.execute(
                    "SELECT * FROM dead_letter_events WHERE event_id = ?",
                    (str(event_id),),
                ).fetchone()
            finally:
                connection.close()

        if row is None:
            return ReplayEligibility.NOT_FOUND, None

        record = _row_to_record(row)
        if claimed:
            return ReplayEligibility.CLAIMED, record
        if record.replay_status == ReplayStatus.REPLAYED_OK.value:
            return ReplayEligibility.ALREADY_REPLAYED, record
        # Anything else not claimed is REPLAY_IN_PROGRESS -- either a
        # genuinely concurrent attempt or an earlier one whose outcome was
        # never confirmed. Both refuse identically: only a human can tell
        # them apart, and only a human may clear it.
        return ReplayEligibility.IN_PROGRESS, record

    def get_replay_payload(self, event_id: str) -> dict[str, Any] | None:
        """The minimum body needed to faithfully redeliver one dead-lettered
        event. INTERNAL REPLAY USE ONLY.

        Never returned by ``get()``, ``list_records()``, or
        ``DeadLetterRecord.to_dict()`` -- those stay sanitized metadata
        only, so this is the one path that reads the protected
        ``replay_payload`` column, and it exists solely for
        ``EventReliabilityManager.replay()`` to reconstruct what to
        redeliver. Do not call this from any dashboard/status route.

        Returns None if no replay body was persisted: a legacy row from
        before this existed, or one whose payload was refused at record
        time (see ``sanitize_replay_payload``). The caller must treat None
        as "this event cannot be faithfully replayed," never as an empty
        payload.
        """
        self._require_ready()
        with self._lock:
            connection = self._connect()
            try:
                row = connection.execute(
                    "SELECT replay_payload FROM dead_letter_events "
                    "WHERE event_id = ?",
                    (str(event_id),),
                ).fetchone()
            finally:
                connection.close()

        if row is None or row["replay_payload"] is None:
            return None

        try:
            decoded = json.loads(row["replay_payload"])
        except (TypeError, ValueError):
            logger.error(
                "Stored replay payload for event_id=%s is corrupt JSON; "
                "treating as not replayable.",
                event_id,
            )
            return None

        return decoded if isinstance(decoded, dict) else None

    def mark_recovered_delivery(self, event_id: str) -> bool:
        """Make an old dead-letter row ineligible after producer recovery.

        Ordinary producer retries use the normal delivery path rather than
        replay(). If one succeeds, the historical dead-letter record must no
        longer remain operator-replayable. The replay_attempts counter is left
        unchanged because this was not an operator-initiated replay.
        """
        self._require_ready()
        with self._lock:
            connection = self._connect()
            try:
                cursor = connection.execute(
                    """
                    UPDATE dead_letter_events
                    SET replay_status = ?,
                        last_attempt_at = ?
                    WHERE event_id = ?
                      AND replay_status IN (?, ?)
                    """,
                    (
                        ReplayStatus.REPLAYED_OK.value,
                        _utc_now(),
                        str(event_id),
                        ReplayStatus.PENDING.value,
                        ReplayStatus.REPLAY_FAILED.value,
                    ),
                )
                return cursor.rowcount == 1
            finally:
                connection.close()

    def mark_replay_result(
        self,
        event_id: str,
        *,
        succeeded: bool,
        reason: Any = "",
    ) -> DeadLetterRecord | None:
        """Record the outcome of one operator-initiated replay attempt.

        Only applies from ``REPLAY_IN_PROGRESS`` -- the state
        ``begin_replay_attempt`` puts a row into before delivery is
        attempted. If no row matches (already resolved by a concurrent
        writer, or called outside the normal
        begin-attempt/deliver/mark-result flow), this refuses to overwrite
        whatever the row's actual state is rather than silently clobbering
        it, and logs the anomaly -- that should not happen given this
        module's own call pattern.
        """
        self._require_ready()
        status = (
            ReplayStatus.REPLAYED_OK
            if succeeded
            else ReplayStatus.REPLAY_FAILED
        )
        safe_reason = sanitize_reason(reason)

        with self._lock:
            connection = self._connect()
            try:
                cursor = connection.execute(
                    """
                    UPDATE dead_letter_events
                    SET replay_status   = ?,
                        replay_attempts = replay_attempts + 1,
                        last_attempt_at = ?,
                        failure_reason  = CASE WHEN ? = ''
                                               THEN failure_reason ELSE ? END
                    WHERE event_id = ? AND replay_status = ?
                    """,
                    (
                        status.value,
                        _utc_now(),
                        safe_reason,
                        safe_reason,
                        str(event_id),
                        ReplayStatus.REPLAY_IN_PROGRESS.value,
                    ),
                )
                if cursor.rowcount != 1:
                    logger.error(
                        "mark_replay_result for event_id=%s found no row in "
                        "REPLAY_IN_PROGRESS -- refusing to overwrite its "
                        "current state. This should not happen outside "
                        "begin_replay_attempt()->deliver->mark_replay_result.",
                        event_id,
                    )
            finally:
                connection.close()
        return self.get(event_id)


def _row_to_record(row: sqlite3.Row) -> DeadLetterRecord:
    return DeadLetterRecord(
        row_id=int(row["row_id"]),
        event_id=str(row["event_id"]),
        correlation_id=str(row["correlation_id"]),
        parent_event_id=str(row["parent_event_id"]),
        event_type=str(row["event_type"]),
        schema_version=str(row["schema_version"]),
        source=str(row["source"]),
        source_identity=str(row["source_identity"]),
        created_at=str(row["created_at"]),
        ingested_at=str(row["ingested_at"]),
        failure_stage=str(row["failure_stage"]),
        failure_classification=str(row["failure_classification"]),
        failure_reason=str(row["failure_reason"]),
        attempts=int(row["attempts"]),
        first_failed_at=str(row["first_failed_at"]),
        last_attempt_at=str(row["last_attempt_at"]),
        replay_status=str(row["replay_status"]),
        replay_attempts=int(row["replay_attempts"]),
        replay_available=row["replay_payload"] is not None,
    )


# =============================================================================
# Metrics
# =============================================================================

class ReliabilityMetrics:
    """Bounded counters for the delivery path.

    Fixed counter names only -- no event payloads, identifiers, tokens or
    other high-cardinality values are ever used as keys.
    """

    _NAMES: Final[tuple[str, ...]] = (
        "events_received",
        "events_accepted",
        "events_duplicate",
        "events_rejected",
        "events_retried_after_failure",
        "events_delivery_in_progress",
        "delivery_success",
        "delivery_retry",
        "delivery_failed_terminal",
        "delivery_dead_lettered",
        "delivery_reconciliation_required",
        "replay_requested",
        "replay_success",
        "replay_failed",
        "replay_unavailable",
        "replay_conflict",
        "replay_reconciliation_required",
        "queue_overflow",
        "ws_slow_client_disconnect",
        "audit_write_failed",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {name: 0 for name in self._NAMES}

    def increment(self, name: str, amount: int = 1) -> None:
        with self._lock:
            if name not in self._counters:
                # Unknown names are ignored rather than added, so metric
                # cardinality cannot grow from a caller typo.
                return
            self._counters[name] += int(amount)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counters)

    def reset(self) -> None:
        with self._lock:
            for name in self._counters:
                self._counters[name] = 0


# =============================================================================
# Delivery outcome + manager
# =============================================================================

@dataclass(frozen=True, slots=True)
class DeliveryOutcome:
    state: DeliveryState
    event_id: str
    correlation_id: str
    attempts: int
    reason: str = ""
    status_code: int | None = None
    response: Any = None

    @property
    def delivered(self) -> bool:
        return self.state is DeliveryState.DELIVERED

    @property
    def handled(self) -> bool:
        """Delivered, or a duplicate of something already delivered."""
        return self.state in (
            DeliveryState.DELIVERED,
            DeliveryState.DUPLICATE,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "event_id": self.event_id,
            "correlation_id": self.correlation_id,
            "attempts": self.attempts,
            "reason": self.reason,
            "status_code": self.status_code,
        }


class EventReliabilityManager:
    """Policy layer over delivery of one authenticated, normalized event.

    Owns no transport: the caller supplies the delivery callable, so this
    wraps the canonical path rather than becoming a second event system. The
    composition root builds it and injects it.
    """

    def __init__(
        self,
        *,
        dead_letter_store: DeadLetterStore | None = None,
        idempotency: IdempotencyLedger | None = None,
        retry_policy: RetryPolicy | None = None,
        metrics: ReliabilityMetrics | None = None,
        audit_sink: Callable[[dict[str, Any]], Any] | None = None,
        sleep: Callable[[float], Any] | None = None,
    ) -> None:
        self.dead_letter_store = dead_letter_store
        self.idempotency = idempotency or IdempotencyLedger()
        self.retry_policy = retry_policy or RetryPolicy()
        self.metrics = metrics or ReliabilityMetrics()
        self._audit_sink = audit_sink
        self._sleep = sleep or time.sleep

    def _audit(self, **fields: Any) -> None:
        """Best-effort audit of a delivery-state transition.

        Reliability telemetry must never break delivery, so a failure here is
        logged and swallowed. The authoritative security records are written
        on the governance and ingress paths, not from this helper.

        The AUDIT RECORD's own identity is never the caller-supplied
        ``event_id``: the authoritative audit store's ``event_id`` column is
        UNIQUE, and it is the audit ledger's own row identity, auto-assigned
        by ``AuditStore.append`` whenever the caller omits it -- not the
        identity of the logical event a row is ABOUT. Passing the logical
        event_id straight through as ``event_id`` collided with that unique
        constraint on every second audit entry for the same event (a
        replay's PROCESSING row and its outcome row both reusing the
        original delivery's audit id, for instance), and the try/except
        below silently swallowed every one of those failures -- so replay
        activity was vanishing from the authoritative audit history. The
        logical identity is preserved under ``subject_event_id`` instead,
        letting ``append`` assign a fresh, genuinely unique row id each time.
        """
        sink = self._audit_sink
        if sink is None:
            return

        record = dict(fields)
        subject_event_id = record.pop("event_id", None)
        if subject_event_id is not None:
            record["subject_event_id"] = subject_event_id

        try:
            sink({"event_category": "event_delivery", **record})
        except Exception:
            # Best-effort by design (see the docstring), but "swallowed"
            # must not mean "invisible": a uniqueness or storage failure
            # here is a real defect (or a real full/unavailable audit
            # volume), and an operator needs a way to notice it even though
            # it will never break the delivery this audit entry describes.
            self.metrics.increment("audit_write_failed")
            logger.warning(
                "Delivery audit append failed for subject_event_id=%s",
                subject_event_id,
                exc_info=True,
            )

    def deliver(
        self,
        envelope: Mapping[str, Any],
        deliver_fn: Callable[[], Any],
        *,
        stage: FailureStage = FailureStage.WATCHTOWER_DELIVERY,
    ) -> DeliveryOutcome:
        """Deliver one event with idempotency, bounded retry and dead-letter.

        The returned state is the truth about what happened. A caller must
        not report success unless ``delivered`` (or ``handled``) is True --
        converting FAILED into DELIVERED is exactly the failure this layer
        exists to prevent.

        A producer retrying the SAME event_id is classified by what
        actually happened to the prior attempt, not treated as one
        unconditional "duplicate" bucket:
          - DELIVERED: genuinely handled already -- report DUPLICATE, make
            no second delivery attempt. Redelivering it would turn one
            logical finding into two alerts.
          - PROCESSING / RECEIVED: another delivery for this exact id is
            in flight right now -- refuse the concurrent attempt rather
            than racing it, but never call that "handled".
          - FAILED_TERMINAL / FAILED_RETRYABLE / DEAD_LETTERED: nothing
            succeeded yet. This is a new producer request, not an operator
            replay, so it may re-enter the normal bounded delivery path
            below -- a recovered dependency should not require a human to
            notice and replay it by hand. This is still exactly ONE bounded
            attempt sequence per call, on an explicit new request; nothing
            here loops, schedules, or retries on its own.
        """
        event_id = str(envelope.get("event_id") or "").strip()
        correlation_id = str(envelope.get("correlation_id") or "").strip()

        if not event_id:
            self.metrics.increment("events_rejected")
            return DeliveryOutcome(
                state=DeliveryState.FAILED_TERMINAL,
                event_id="",
                correlation_id=correlation_id,
                attempts=0,
                reason="missing_event_id",
            )

        self.metrics.increment("events_received")

        decision = self.idempotency.check_and_register(event_id)
        if not decision.first_seen:
            if decision.original_state == DeliveryState.DELIVERED.value:
                self.metrics.increment("events_duplicate")
                self._audit(
                    event_id=event_id,
                    correlation_id=correlation_id,
                    delivery_state=DeliveryState.DUPLICATE.value,
                    original_state=decision.original_state,
                )
                return DeliveryOutcome(
                    state=DeliveryState.DUPLICATE,
                    event_id=event_id,
                    correlation_id=correlation_id,
                    attempts=0,
                    reason="duplicate_event_id",
                )

            if (
                decision.original_state in _LEDGER_RETRYABLE_STATES
                and self.idempotency.claim_retry(event_id)
            ):
                # Claimed: the prior attempt genuinely failed, so this
                # request may proceed through the ordinary bounded delivery
                # path below exactly as a first-seen event would.
                self.metrics.increment("events_retried_after_failure")
                self._audit(
                    event_id=event_id,
                    correlation_id=correlation_id,
                    delivery_state=DeliveryState.PROCESSING.value,
                    retry_of_failed_event=True,
                    original_state=decision.original_state,
                )
            else:
                # Either genuinely in flight (PROCESSING/RECEIVED), or
                # another caller won the retry claim above at the same
                # moment. Either way: refuse the concurrent duplicate
                # rather than racing it. This is NOT a successfully
                # handled event, so it must never be reported as DUPLICATE.
                self.metrics.increment("events_delivery_in_progress")
                self._audit(
                    event_id=event_id,
                    correlation_id=correlation_id,
                    delivery_state=DeliveryState.PROCESSING.value,
                    reason="delivery_in_progress",
                    original_state=decision.original_state,
                )
                return DeliveryOutcome(
                    state=DeliveryState.PROCESSING,
                    event_id=event_id,
                    correlation_id=correlation_id,
                    attempts=0,
                    reason="delivery_in_progress",
                )
        else:
            self.metrics.increment("events_accepted")
            self.idempotency.update_state(event_id, DeliveryState.PROCESSING)

        deadline = time.monotonic() + self.retry_policy.total_deadline_seconds
        attempts = 0
        last: DeliveryAttemptResult | None = None
        response: Any = None

        while attempts < self.retry_policy.max_attempts:
            attempts += 1
            try:
                response = deliver_fn()
                last = classify_delivery_result(response)
            except Exception as exc:
                # A raising transport is treated as transient, but is still
                # bounded by the same attempt and deadline caps.
                last = DeliveryAttemptResult(
                    ok=False,
                    retryability=Retryability.RETRYABLE,
                    reason=type(exc).__name__,
                )

            if last.ok:
                self.metrics.increment("delivery_success")
                self.idempotency.update_state(
                    event_id, DeliveryState.DELIVERED
                )

                store = self.dead_letter_store
                if store is not None:
                    try:
                        store.mark_recovered_delivery(event_id)
                    except Exception:
                        # The delivery itself succeeded, so never lie and
                        # classify it as failed. The stale durable replay row
                        # is an operational reconciliation problem that must
                        # be visible before an operator considers replay.
                        self.metrics.increment(
                            "delivery_reconciliation_required"
                        )
                        logger.error(
                            "Delivered event_id=%s but failed to retire its "
                            "dead-letter replay eligibility; operator "
                            "reconciliation is required before replay.",
                            event_id,
                            exc_info=True,
                        )
                        self._audit(
                            event_id=event_id,
                            correlation_id=correlation_id,
                            delivery_state=DeliveryState.DELIVERED.value,
                            attempts=attempts,
                            reconciliation_required=True,
                            dead_letter_resolution_failed=True,
                        )

                self._audit(
                    event_id=event_id,
                    correlation_id=correlation_id,
                    delivery_state=DeliveryState.DELIVERED.value,
                    attempts=attempts,
                )
                return DeliveryOutcome(
                    state=DeliveryState.DELIVERED,
                    event_id=event_id,
                    correlation_id=correlation_id,
                    attempts=attempts,
                    reason=last.reason,
                    status_code=last.status_code,
                    response=response,
                )

            if not last.retryable:
                break
            if attempts >= self.retry_policy.max_attempts:
                break

            delay = self.retry_policy.delay_for(attempts)
            if time.monotonic() + delay >= deadline:
                # Respect the caller's total budget rather than overrun it.
                break

            self.metrics.increment("delivery_retry")
            self._sleep(delay)

        reason = last.reason if last is not None else "no_attempt"
        classification = (
            last.retryability if last is not None else Retryability.TERMINAL
        )
        status_code = last.status_code if last is not None else None

        if classification is Retryability.TERMINAL:
            self.metrics.increment("delivery_failed_terminal")
            state = DeliveryState.FAILED_TERMINAL
        else:
            state = DeliveryState.FAILED_RETRYABLE

        if self._dead_letter(
            envelope=envelope,
            stage=stage,
            classification=classification,
            reason=reason,
            attempts=attempts,
        ):
            state = DeliveryState.DEAD_LETTERED

        self.idempotency.update_state(event_id, state)
        self._audit(
            event_id=event_id,
            correlation_id=correlation_id,
            delivery_state=state.value,
            attempts=attempts,
            failure_stage=str(stage),
            failure_classification=str(classification),
            failure_reason=sanitize_reason(reason),
        )

        return DeliveryOutcome(
            state=state,
            event_id=event_id,
            correlation_id=correlation_id,
            attempts=attempts,
            reason=reason,
            status_code=status_code,
            response=response,
        )

    def _dead_letter(
        self,
        *,
        envelope: Mapping[str, Any],
        stage: FailureStage,
        classification: Retryability,
        reason: Any,
        attempts: int,
    ) -> bool:
        store = self.dead_letter_store
        if store is None:
            logger.warning(
                "Event delivery failed with no dead-letter store configured; "
                "event_id=%s stage=%s",
                envelope.get("event_id"),
                stage,
            )
            return False

        try:
            store.record_failure(
                envelope=envelope,
                failure_stage=stage,
                classification=classification,
                reason=reason,
                attempts=attempts,
            )
        except Exception:
            logger.error(
                "Failed to dead-letter an undeliverable event", exc_info=True
            )
            return False

        self.metrics.increment("delivery_dead_lettered")
        return True

    def replay(
        self,
        event_id: str,
        deliver_fn: Callable[[Mapping[str, Any]], Any],
        *,
        operator: str,
    ) -> DeliveryOutcome:
        """Replay one dead-lettered event on explicit operator instruction.

        Never runs on a timer and never loops: one operator request produces
        at most one delivery attempt, and only when every eligibility check
        below passes. The replayed event keeps its original event_id and
        provenance, reconstructed from the protected replay body -- it is
        the same logical event being delivered again, not a new
        origination, and not an approximation of one.

        Eligibility is checked in this order; the first failure wins and no
        delivery attempt is made:
          1. the record must exist                    -> else "unknown_event_id"
          2. a faithful replay body must have been
             persisted for it                          -> else "replay_unavailable"
          3. it must not already be REPLAYED_OK         -> else "already_replayed"
          4. it must not have another attempt
             outstanding or unresolved                  -> else "replay_in_progress"
        Steps 3 and 4 are enforced atomically by
        ``DeadLetterStore.begin_replay_attempt``, not inferred from a
        separate read.

        If persisting the delivery outcome fails AFTER a delivery attempt
        was made, this does not report a clean success or a clean failure
        -- it returns "reconciliation_required" and leaves the record
        claimed (see the REPLAY FIDELITY module note): this module would
        rather require a human to resolve an uncertain outcome than let a
        second automatic attempt risk redelivering an event that may
        already have landed.
        """
        store = self.dead_letter_store
        if store is None:
            raise RuntimeError("no dead-letter store configured")

        operator_id = str(operator or "").strip()
        if not operator_id:
            raise ValueError("replay requires an operator identity")

        record = store.get(event_id)
        if record is None:
            return DeliveryOutcome(
                state=DeliveryState.FAILED_TERMINAL,
                event_id=str(event_id),
                correlation_id="",
                attempts=0,
                reason="unknown_event_id",
            )

        payload = store.get_replay_payload(event_id)
        if payload is None:
            self.metrics.increment("replay_unavailable")
            self._audit(
                event_id=record.event_id,
                correlation_id=record.correlation_id,
                delivery_state=DeliveryState.FAILED_TERMINAL.value,
                replay=True,
                operator=operator_id,
                failure_reason="replay_unavailable",
            )
            return DeliveryOutcome(
                state=DeliveryState.FAILED_TERMINAL,
                event_id=record.event_id,
                correlation_id=record.correlation_id,
                attempts=0,
                reason="replay_unavailable",
            )

        eligibility, claimed_record = store.begin_replay_attempt(event_id)

        if eligibility is ReplayEligibility.NOT_FOUND:
            # Deleted between the two reads above (eviction, concurrent
            # admin action). Same outward reason as never having existed.
            return DeliveryOutcome(
                state=DeliveryState.FAILED_TERMINAL,
                event_id=str(event_id),
                correlation_id="",
                attempts=0,
                reason="unknown_event_id",
            )

        if eligibility in (
            ReplayEligibility.ALREADY_REPLAYED,
            ReplayEligibility.IN_PROGRESS,
        ):
            conflict_reason = (
                "already_replayed"
                if eligibility is ReplayEligibility.ALREADY_REPLAYED
                else "replay_in_progress"
            )
            self.metrics.increment("replay_conflict")
            self._audit(
                event_id=record.event_id,
                correlation_id=record.correlation_id,
                delivery_state=DeliveryState.FAILED_TERMINAL.value,
                replay=True,
                operator=operator_id,
                failure_reason=conflict_reason,
            )
            return DeliveryOutcome(
                state=DeliveryState.FAILED_TERMINAL,
                event_id=record.event_id,
                correlation_id=record.correlation_id,
                attempts=0,
                reason=conflict_reason,
            )

        # eligibility is CLAIMED: exactly one delivery attempt follows, and
        # the row is already durably REPLAY_IN_PROGRESS.
        record = claimed_record or record
        self.metrics.increment("replay_requested")
        self._audit(
            event_id=record.event_id,
            correlation_id=record.correlation_id,
            delivery_state=DeliveryState.PROCESSING.value,
            replay=True,
            operator=operator_id,
        )

        # Original identity, causal linkage, and the protected replay body
        # are what get redelivered -- never audited or logged as a whole.
        envelope = {
            **payload,
            "event_id": record.event_id,
            "correlation_id": record.correlation_id,
            "parent_event_id": record.parent_event_id,
            "event_type": record.event_type,
            "schema_version": record.schema_version,
            "source": record.source,
            "source_identity": record.source_identity,
            "replay_of": record.event_id,
        }

        try:
            result = classify_delivery_result(deliver_fn(envelope))
        except Exception as exc:
            result = DeliveryAttemptResult(
                ok=False,
                retryability=Retryability.RETRYABLE,
                reason=type(exc).__name__,
            )

        try:
            store.mark_replay_result(
                record.event_id,
                succeeded=result.ok,
                reason="" if result.ok else result.reason,
            )
        except Exception:
            # The delivery attempt above may already have reached
            # Watchtower -- this genuinely does not know. The row is left
            # exactly where begin_replay_attempt put it
            # (REPLAY_IN_PROGRESS), which ordinary replay cannot act on.
            # Reported as its own outcome rather than as a clean failure
            # (it might have succeeded) or a clean success (persisting that
            # fact just failed).
            logger.error(
                "Failed to persist a replay result for event_id=%s after a "
                "delivery attempt (delivery reported ok=%s) -- the record "
                "is left REPLAY_IN_PROGRESS and requires manual "
                "reconciliation; it will not be replayed again "
                "automatically.",
                record.event_id,
                result.ok,
                exc_info=True,
            )
            self.metrics.increment("replay_reconciliation_required")
            self._audit(
                event_id=record.event_id,
                correlation_id=record.correlation_id,
                delivery_state="RECONCILIATION_REQUIRED",
                replay=True,
                operator=operator_id,
                attempts=1,
                reconciliation_required=True,
                delivery_may_have_succeeded=result.ok,
            )
            return DeliveryOutcome(
                state=DeliveryState.FAILED_TERMINAL,
                event_id=record.event_id,
                correlation_id=record.correlation_id,
                attempts=1,
                reason="reconciliation_required",
                status_code=result.status_code,
            )

        if result.ok:
            self.metrics.increment("replay_success")
            state = DeliveryState.DELIVERED
        else:
            self.metrics.increment("replay_failed")
            # A failed replay returns to the dead-letter state. It is never
            # recycled automatically.
            state = DeliveryState.DEAD_LETTERED

        self._audit(
            event_id=record.event_id,
            correlation_id=record.correlation_id,
            delivery_state=state.value,
            replay=True,
            operator=operator_id,
            attempts=1,
            failure_reason="" if result.ok else sanitize_reason(result.reason),
        )

        return DeliveryOutcome(
            state=state,
            event_id=record.event_id,
            correlation_id=record.correlation_id,
            attempts=1,
            reason=result.reason,
            status_code=result.status_code,
        )

    def status(self) -> dict[str, Any]:
        counts: dict[str, Any] = {}
        if self.dead_letter_store is not None:
            try:
                counts = self.dead_letter_store.counts()
            except Exception:
                counts = {"error": "unavailable"}

        return {
            "metrics": self.metrics.snapshot(),
            "dead_letter": counts,
            "idempotency_tracked": len(self.idempotency),
            "retry_policy": {
                "max_attempts": self.retry_policy.max_attempts,
                "base_delay_seconds": self.retry_policy.base_delay_seconds,
                "max_delay_seconds": self.retry_policy.max_delay_seconds,
                "total_deadline_seconds": (
                    self.retry_policy.total_deadline_seconds
                ),
            },
            "timestamp": _utc_now(),
        }


__all__ = [
    "TERMINAL_STATES",
    "DeadLetterRecord",
    "DeadLetterStore",
    "DeliveryAttemptResult",
    "DeliveryOutcome",
    "DeliveryState",
    "EventReliabilityManager",
    "FailureStage",
    "IdempotencyDecision",
    "IdempotencyLedger",
    "ReliabilityMetrics",
    "ReplayEligibility",
    "ReplayStatus",
    "RetryPolicy",
    "Retryability",
    "classify_delivery_result",
    "sanitize_for_record",
    "sanitize_reason",
    "sanitize_replay_payload",
]
