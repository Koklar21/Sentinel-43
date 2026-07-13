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
# 1. GNU Affero General Public License (AGPL v3.0)
#    for open-source use, modification, and distribution.
#
# 2. Commercial License
#    for proprietary, enterprise, government, or other commercial use
#    not permitted under the AGPL v3.0.
#
# Use, modification, redistribution, and commercial use are governed by
# the terms of the applicable license. Any use outside those terms is
# prohibited.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

"""
Sentinel-43 AI Threat Detector.

Pure detection/scoring layer.

Responsibilities:
- Normalize event input.
- Maintain sequence windows.
- Score suspicious behavior.
- Return structured threat assessments.

Non-responsibilities:
- No blocking.
- No firewall changes.
- No approvals/vetoes.
- No secret handling.
- No direct enforcement.
"""

from __future__ import annotations

import ipaddress
import math
import time
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional, Tuple

from .sentinel_threat_types import ThreatKind, ThreatSeverity, ThreatSourceKind, ThreatAssessment


# =============================================================================
# Hardening pass — changelog (this pass)
#
# Reviewed by three independent passes (two AI models plus a human-directed
# review) before this recode. Only claims that were verified against the
# actual source are implemented below; claims that didn't hold up are noted
# explicitly so the reasoning isn't lost.
# =============================================================================
#
# VALIDATED AND FIXED:
#
#   1. SequenceWindow.prune() assumed insertion order == timestamp order.
#      add_event() never enforced that, so an out-of-order timestamp landed
#      on the right side of the deque and prune()'s left-only scan would
#      never reach it -- it could sit there indefinitely (bounded only by
#      max_events). add_event() now silently rejects (no-ops, returns False)
#      any event older than the current newest entry for that window,
#      mirroring SentinelWindowStore's reject_out_of_order pattern. This
#      also makes events_in_interval()'s reversed-scan fast path safe to
#      use here too (see fix #7).
#
#   2. self._windows had no key-count cap or eviction policy -- the same
#      unbounded-growth vector already fixed in SentinelWindowStore.
#      self._windows is now an OrderedDict; ingest() moves a touched key to
#      the end, and a brand-new key arriving at max_keys_hint capacity
#      evicts the least-recently-used key instead of growing without bound.
#      assess_all() deliberately does NOT touch LRU order -- see fix #4.
#
#   3. self._last_ts was write-only dead state: set in ingest(), popped in
#      assess_all()'s cleanup, cleared in reset(), never read anywhere.
#      Removed entirely. (One review framed this as a "race condition"
#      between _last_ts and window updates; checked against the actual
#      code, window mutation happens before _last_ts was ever set, so
#      there was no divergence as described -- moot anyway now that the
#      field is gone.)
#
#   4. assess_all() does NOT call move_to_end() on the keys it scans.
#      A periodic full sweep marking every key as most-recently-used would
#      defeat LRU eviction entirely -- every key would look "fresh" right
#      after each sweep. Only ingest() (new data) and events_in_interval()
#      (a targeted, identity-specific query) count as a real touch.
#
#   5. assess_window() did 5-6 separate passes over the window's events
#      (a filtering list comprehension, then _failure_count, then
#      _max_payload_size, then two Counter() constructions). Consolidated
#      into a single pass. _failure_count/_max_payload_size/_payload_len
#      are removed as standalone functions; their logic is inlined.
#
#   6. _failure_count's status-code set (400/401/403/404/409/429) was a
#      hardcoded module-level constant -- now DetectorConfig.
#      failure_status_codes, defaulting to the identical set so behavior
#      is unchanged out of the box, but operators can tune it without a
#      code change. The separate "server_error_cluster" (500-count) signal
#      keeps its existing low weight (+5 vs +10 for the other status
#      signals) with a comment explaining why: 500s often mean the
#      protected service is unhealthy, not that the caller is hostile.
#
#   7. _normalize_ip() silently returned malformed input unchanged (e.g.
#      "999.999.999.999" became a valid tracking key). An attacker
#      spraying malformed IP variants for one identity could fragment
#      their activity across many distinct fake keys, evading per-key
#      thresholds. Now raises ValueError for unparseable input, checked
#      early in ingest() before the lock is acquired, consistent with how
#      the existing future-skew timestamp check already works.
#
#   8. events_in_interval() now uses the same reversed-scan-with-early-
#      break fast path as SentinelWindowStore's version, safe now that
#      fix #1 guarantees monotonic ordering.
#
#   9. Cross-file type duplication FIXED. ThreatKind / ThreatSeverity /
#      ThreatSourceKind / ThreatAssessment previously existed as two
#      independent, incompatible definitions -- this file (str-Enum) and
#      Shadow_mode.py / sentinel_ai_escalation.py (auto()-Enum). All four
#      now live in sentinel_threat_types.py and every consumer (this file,
#      Shadow_mode.py, sentinel_ai_escalation.py) imports the same
#      definitions. See sentinel_threat_types.py's docstring for the full
#      compatibility analysis (member sets, .name-only usage, no ordering
#      dependency) that made this safe to do without changing behavior in
#      the response/escalation engines.
#
# CONSIDERED AND DELIBERATELY NOT IMPLEMENTED:
#
#   - A separate "reject stale events before touching the window" fast
#     path was proposed (twice, independently) as a performance
#     optimization. One version of that proposal synthesized a fresh
#     severity=LOW / score=0.0 / window_size=0 assessment for the
#     rejected event -- which would have been a correctness regression:
#     it discards whatever the identity's *existing* window already
#     showed. E.g. an identity with 80 events already scored HIGH would
#     get reported as LOW/0.0 just because the latest event happened to
#     be stale. Fix #1 (out-of-order rejection in add_event) already
#     handles this correctly and safely -- a stale event is silently not
#     added, and assess_window() naturally reflects the window's real,
#     unchanged state. A separate pre-filter would be redundant and
#     re-introduces the risk above if implemented carelessly, so it was
#     left out.
#
#   - SentinelWindowStore.build_window() calls SequenceWindow() with no
#     args (default max_events=500) instead of passing this file's actual
#     max_events_per_window. FIXED in this same pass -- see
#     sentinel_window_store.py's changelog.
#
# CLAIMS CHECKED AND FOUND NOT TO HOLD UP (not implemented, for the record):
#
#   - "_failure_count double-counts up to 3 per event": based on a
#     transcription of the function that dropped its `continue`
#     statements. The actual code's continue-per-branch means only one
#     of the three conditions can ever increment the counter for a given
#     event. Verified directly against source; no double-counting occurs.
#
#   - "RATE_ANOMALY overrides DATA_EXFILTRATION / MALWARE_DELIVERY in
#     _choose_kind": backwards. It's an early-return chain checked in
#     order credential -> malware -> spyware -> exfiltration -> payload
#     -> rate -> failure-fallback. Every more specific threat type is
#     checked, and would return, before RATE_ANOMALY is ever reached.
#     CREDENTIAL_ATTACK does take priority over PAYLOAD_ABUSE when both
#     signals are present in the same window, which is true, but that's
#     a deliberate single-label priority order (most specific signal
#     wins), not a contradiction -- see the comment on _choose_kind.
# =============================================================================


# =============================================================================
# Models
#
# ThreatKind / ThreatSeverity / ThreatSourceKind / ThreatAssessment now live
# in sentinel_threat_types.py and are imported above. See that module's
# docstring for why -- this used to define its own independent copies that
# were incompatible with the ones used by Sentinel43ResponseEngine.
# =============================================================================

@dataclass(frozen=True)
class EventContext:
    """
    Normalized event input for detector/window-store consumers.

    Keep payload optional. The detector should not need raw payload contents for
    most scoring. Payload length and metadata are safer than payload logging.
    """

    source_identity: str
    source_ip: str
    event_type: str
    timestamp: float = field(default_factory=time.time)
    success: Optional[bool] = None
    status_code: Optional[int] = None
    payload: Optional[bytes] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.source_identity, str) or not self.source_identity.strip():
            raise ValueError("source_identity must be a non-empty string")
        if not isinstance(self.source_ip, str) or not self.source_ip.strip():
            raise ValueError("source_ip must be a non-empty string")
        if not isinstance(self.event_type, str) or not self.event_type.strip():
            raise ValueError("event_type must be a non-empty string")
        if not isinstance(self.timestamp, (int, float)) or not math.isfinite(float(self.timestamp)):
            raise ValueError("timestamp must be a finite number")
        if self.payload is not None and not isinstance(self.payload, (bytes, bytearray)):
            raise ValueError("payload must be bytes, bytearray, or None")


@dataclass(frozen=True)
class DetectorConfig:
    window_seconds: float = 60.0
    max_events_per_window: int = 500

    medium_events_per_window: int = 25
    high_events_per_window: int = 75
    critical_events_per_window: int = 150

    medium_failures: int = 8
    high_failures: int = 20
    critical_failures: int = 50

    identity_spray_threshold: int = 10
    ip_spray_threshold: int = 10

    suspicious_payload_bytes: int = 128 * 1024
    abusive_payload_bytes: int = 512 * 1024

    future_skew_seconds: float = 60.0
    out_of_order_penalty: float = 5.0

    automation_event_rate: int = 60
    automation_failure_rate: int = 15

    # Fix (scrub #6): previously a hardcoded module-level constant inside
    # _failure_count. Same default set, now tunable without a code change.
    failure_status_codes: frozenset = frozenset({400, 401, 403, 404, 409, 429})

    # Fix (scrub #2): 0 = no cap (matches SentinelWindowConfig's
    # max_keys_hint convention). When set, ingest() LRU-evicts the
    # least-recently-used (identity, ip) key to make room for a genuinely
    # new one instead of growing self._windows without bound.
    max_keys_hint: int = 0

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if self.max_events_per_window <= 0:
            raise ValueError("max_events_per_window must be > 0")
        if not (self.medium_events_per_window <= self.high_events_per_window <= self.critical_events_per_window):
            raise ValueError("rate thresholds must be ordered medium <= high <= critical")
        if not (self.medium_failures <= self.high_failures <= self.critical_failures):
            raise ValueError("failure thresholds must be ordered medium <= high <= critical")
        if self.suspicious_payload_bytes <= 0 or self.abusive_payload_bytes <= 0:
            raise ValueError("payload thresholds must be > 0")
        if not self.failure_status_codes:
            raise ValueError("failure_status_codes must not be empty")
        if self.max_keys_hint < 0:
            raise ValueError("max_keys_hint must be >= 0")
        # Sanity ceilings, consistent with SentinelWindowConfig's pattern.
        if self.window_seconds > 86400:
            raise ValueError("window_seconds too large (max 86400)")
        if self.max_events_per_window > 100_000:
            raise ValueError("max_events_per_window too large (max 100000)")


# =============================================================================
# Sequence Window
# =============================================================================

class SequenceWindow:
    """
    Lightweight in-memory ordered event window.

    This class is intentionally simple because other modules import it directly.
    Detection logic belongs in SentinelThreatDetector.
    """

    def __init__(self, max_events: int = 500) -> None:
        if max_events <= 0:
            raise ValueError("max_events must be > 0")
        self.max_events = int(max_events)
        self._events: Deque[EventContext] = deque(maxlen=self.max_events)

    def add_event(self, event: EventContext) -> bool:
        """
        Append an event. Returns True if accepted, False if silently
        rejected.

        Fix (scrub #1): rejects (no-ops) any event older than the current
        newest entry in this window. Previously this always appended
        unconditionally, which let an out-of-order timestamp land on the
        right side of the deque where prune()'s left-only scan could never
        reach it -- it would sit there indefinitely, bounded only by
        max_events. This mirrors SentinelWindowStore's
        reject_out_of_order behavior for consistency between the two
        sibling files.
        """
        if self._events and event.timestamp < self._events[-1].timestamp:
            return False
        self._events.append(event)
        return True

    def extend(self, events: Iterable[EventContext]) -> None:
        # Deliberately calls add_event() per item rather than
        # self._events.extend(events) directly. A bulk deque.extend()
        # would bypass the out-of-order rejection added in add_event(),
        # creating a validation gap between the single-event and bulk-add
        # paths.
        for event in events:
            self.add_event(event)

    def events(self) -> List[EventContext]:
        return list(self._events)

    def __iter__(self):
        return iter(self._events)

    def __len__(self) -> int:
        return len(self._events)

    def prune(self, *, now: Optional[float] = None, window_seconds: float = 60.0) -> None:
        # Safe to assume monotonic order here now that add_event() enforces
        # it (fix #1) -- this early-break left-only scan would otherwise
        # silently fail to remove out-of-order stale entries.
        current = time.time() if now is None else float(now)
        cutoff = current - window_seconds
        while self._events and self._events[0].timestamp < cutoff:
            self._events.popleft()


# =============================================================================
# Detector
# =============================================================================

class SentinelThreatDetector:
    """
    Scores event sequences and returns structured assessments.

    This class does not enforce. It only detects and explains.
    """

    def __init__(self, cfg: Optional[DetectorConfig] = None) -> None:
        self.cfg = cfg or DetectorConfig()
        self._lock = RLock()
        # Fix (scrub #2): OrderedDict so key order tracks least-recently-
        # used -> most-recently-used, enabling LRU eviction at capacity.
        # Only ingest() and events_in_interval() move a key to the end --
        # see the changelog note on why assess_all() deliberately does not.
        self._windows: "OrderedDict[Tuple[str, str], SequenceWindow]" = OrderedDict()
        # Fix (scrub #3): self._last_ts removed entirely (was write-only,
        # never read anywhere in this file).

    def ingest(self, event: EventContext) -> ThreatAssessment:
        """
        Add one event and return an assessment for that event's identity/IP window.
        """
        now = time.time()
        self._validate_event_time(event, now=now)
        # Fix (scrub #7): raises ValueError for unparseable IPs, checked
        # before the lock is acquired (cheap, pure function, no shared
        # state needed) -- consistent with how the future-skew check above
        # already fails fast without touching the lock.
        normalized_ip = _normalize_ip(event.source_ip)
        key = (event.source_identity.strip(), normalized_ip)

        with self._lock:
            is_new_key = key not in self._windows

            if self.cfg.max_keys_hint and is_new_key and len(self._windows) >= self.cfg.max_keys_hint:
                self._windows.popitem(last=False)  # evict LRU

            window = self._windows.get(key)
            if window is None:
                window = SequenceWindow(max_events=self.cfg.max_events_per_window)
                self._windows[key] = window  # new keys land at the end (MRU) already
            else:
                self._windows.move_to_end(key)

            # Fix (scrub #1): silently rejected if out-of-order relative to
            # this window's newest entry. assess_window() below naturally
            # reflects the window's real, unchanged state in that case --
            # see the changelog note on why a separate stale-event
            # pre-filter was deliberately not added.
            window.add_event(event)
            window.prune(now=now, window_seconds=self.cfg.window_seconds)

            return self.assess_window(
                identity=key[0],
                source_ip=key[1],
                window=window,
                now=now,
            )

    def assess_window(
        self,
        *,
        identity: str,
        source_ip: str,
        window: SequenceWindow,
        now: Optional[float] = None,
    ) -> ThreatAssessment:
        """
        Score an existing SequenceWindow.

        Safe to call with windows built by SentinelWindowStore.
        """
        current = time.time() if now is None else float(now)
        cutoff = current - self.cfg.window_seconds

        # Fix (scrub #5): single pass over window.events() instead of
        # building a filtered list and then looping it four more times
        # (failure count, payload max, two Counter constructions). For
        # max_events_per_window events this was 5-6 total traversals per
        # score call; this collapses it to one.
        event_count = 0
        failure_count = 0
        payload_max = 0
        status_counter: Counter = Counter()
        type_counter: Counter = Counter()

        for ev in window.events():
            if ev.timestamp < cutoff:
                continue
            event_count += 1

            if ev.status_code is not None:
                status_counter[ev.status_code] += 1
            norm_type = _event_type_norm(ev.event_type)
            type_counter[norm_type] += 1

            if ev.payload is not None and isinstance(ev.payload, (bytes, bytearray)):
                p_len = len(ev.payload)
                if p_len > payload_max:
                    payload_max = p_len

            if ev.success is False:
                failure_count += 1
            elif ev.status_code in self.cfg.failure_status_codes:
                failure_count += 1
            elif norm_type in {"login_failure", "auth_failure", "failed_login", "waf_block", "blocked"}:
                failure_count += 1

        if event_count == 0:
            return ThreatAssessment(
                identity=identity,
                source_ip=source_ip,
                threat_kind=ThreatKind.UNKNOWN,
                severity=ThreatSeverity.LOW,
                source_kind=ThreatSourceKind.MIXED_OR_UNKNOWN,
                score=0.0,
                indicators={"reason": "empty_window"},
                supporting_tags=["empty_window"],
                window_size=0,
            )

        indicators: Dict[str, Any] = {
            "event_count": event_count,
            "failure_count": failure_count,
            "max_payload_bytes": payload_max,
            "top_event_types": dict(type_counter.most_common(5)),
            "status_codes": dict(status_counter.most_common(8)),
        }
        tags: List[str] = []
        score = 0.0

        if event_count >= self.cfg.critical_events_per_window:
            score += 55
            tags.append("critical_rate")
        elif event_count >= self.cfg.high_events_per_window:
            score += 35
            tags.append("high_rate")
        elif event_count >= self.cfg.medium_events_per_window:
            score += 20
            tags.append("medium_rate")

        if failure_count >= self.cfg.critical_failures:
            score += 45
            tags.append("critical_failure_volume")
        elif failure_count >= self.cfg.high_failures:
            score += 30
            tags.append("high_failure_volume")
        elif failure_count >= self.cfg.medium_failures:
            score += 15
            tags.append("medium_failure_volume")

        suspicious_types = {
            "brute_force",
            "credential_stuffing",
            "login_failure",
            "auth_failure",
            "malware_beacon",
            "exfiltration",
            "port_scan",
            "payload_rejected",
            "waf_block",
        }
        matched_types = sorted(t for t in type_counter if t in suspicious_types)
        if matched_types:
            score += min(25, 5 * len(matched_types))
            tags.extend(f"type:{t}" for t in matched_types)
            indicators["matched_suspicious_types"] = matched_types

        if payload_max >= self.cfg.abusive_payload_bytes:
            score += 25
            tags.append("abusive_payload_size")
        elif payload_max >= self.cfg.suspicious_payload_bytes:
            score += 10
            tags.append("suspicious_payload_size")

        if status_counter.get(401, 0) + status_counter.get(403, 0) >= self.cfg.medium_failures:
            score += 10
            tags.append("auth_status_errors")
        if status_counter.get(429, 0) >= 3:
            score += 10
            tags.append("rate_limited_repeatedly")
        if status_counter.get(500, 0) >= 5:
            # Fix (scrub #6, tuning note): deliberately low weight here
            # (+5, vs +10 for the other status-based signals above). 500s
            # often mean the protected service itself is unhealthy, not
            # that the caller is hostile -- a weak, secondary signal.
            score += 5
            tags.append("server_error_cluster")

        source_kind = self._classify_source(event_count=event_count, failure_count=failure_count)

        if source_kind is ThreatSourceKind.AI_AUTOMATION_LIKELY:
            score += 10
            tags.append("automation_likely")

        score = max(0.0, min(100.0, score))
        kind = self._choose_kind(type_counter=type_counter, tags=tags, failure_count=failure_count, event_count=event_count)
        severity = _severity_from_score(score)

        return ThreatAssessment(
            identity=identity,
            source_ip=source_ip,
            threat_kind=kind,
            severity=severity,
            source_kind=source_kind,
            score=round(score, 2),
            indicators=indicators,
            supporting_tags=sorted(set(tags)),
            window_size=event_count,
        )

    def assess_all(self) -> List[ThreatAssessment]:
        now = time.time()
        with self._lock:
            out: List[ThreatAssessment] = []
            # list() materializes a snapshot before the loop so popping
            # from self._windows during iteration below is safe.
            for (identity, ip), window in list(self._windows.items()):
                window.prune(now=now, window_seconds=self.cfg.window_seconds)
                if len(window) == 0:
                    self._windows.pop((identity, ip), None)
                    continue
                # Fix (scrub #4): deliberately NOT calling move_to_end()
                # here. This is a periodic full sweep, not a signal that
                # any particular key is actively interesting -- marking
                # every scanned key as most-recently-used would defeat LRU
                # eviction entirely, since every key would look "fresh"
                # immediately after each sweep.
                out.append(self.assess_window(identity=identity, source_ip=ip, window=window, now=now))
            return out

    def events_in_interval(self, identity: str, ip: str, interval_seconds: float) -> int:
        """
        Primitive used by higher layers for burst detection.
        """
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")

        key = (identity.strip(), _normalize_ip(ip))
        now = time.time()
        cutoff = now - interval_seconds

        with self._lock:
            window = self._windows.get(key)
            if window is None:
                return 0
            self._windows.move_to_end(key)

            # Fix (scrub #8): reversed-scan-with-early-break, same fast
            # path as SentinelWindowStore.events_in_interval(). Safe now
            # that add_event() guarantees monotonic ordering (fix #1) --
            # previously this had no such guarantee in this file, so a
            # full scan was the only correct option.
            count = 0
            for ev in reversed(window.events()):
                if ev.timestamp < cutoff:
                    break
                count += 1
            return count

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()

    def _validate_event_time(self, event: EventContext, *, now: float) -> None:
        if event.timestamp > now + self.cfg.future_skew_seconds:
            raise ValueError("event timestamp is too far in the future")

    def _classify_source(self, *, event_count: int, failure_count: int) -> ThreatSourceKind:
        """
        Known limitation: this is a simple count-based heuristic. It will
        misclassify slow/low-and-slow automated attacks that stay under
        the event/failure-rate thresholds, and can misclassify a
        legitimately bursty human session as automation-likely. A more
        sophisticated behavioral/statistical classifier is out of scope
        for this pass.
        """
        if event_count >= self.cfg.automation_event_rate or failure_count >= self.cfg.automation_failure_rate:
            return ThreatSourceKind.AI_AUTOMATION_LIKELY
        if event_count <= 5 and failure_count <= 2:
            return ThreatSourceKind.HUMAN_LIKELY
        return ThreatSourceKind.MIXED_OR_UNKNOWN

    def _choose_kind(
        self,
        *,
        type_counter: Counter[str],
        tags: List[str],
        failure_count: int,
        event_count: int,
    ) -> ThreatKind:
        """
        Single-label classification via an intentional priority chain:
        the most specific available signal wins, in this fixed order --
        credential attack, malware, spyware, exfiltration, payload abuse,
        then the broader rate-anomaly/failure-volume fallbacks. When
        multiple signals are present simultaneously (e.g. both a
        credential-attack event type AND an oversized payload), the more
        specific classification is returned and the less specific one is
        not. This is a deliberate design choice, not a bug -- if this
        ever needs to report multiple co-occurring threat kinds instead of
        one, that's a different (multi-label) data model than
        ThreatAssessment.threat_kind currently supports.
        """
        event_types = set(type_counter)

        if {"credential_stuffing", "brute_force", "login_failure", "auth_failure"} & event_types:
            return ThreatKind.CREDENTIAL_ATTACK
        if {"malware_beacon"} & event_types:
            return ThreatKind.MALWARE_DELIVERY
        if {"spyware", "spyware_activity"} & event_types:
            return ThreatKind.SPYWARE_ACTIVITY
        if {"exfiltration", "data_exfiltration"} & event_types:
            return ThreatKind.DATA_EXFILTRATION
        if "abusive_payload_size" in tags or "suspicious_payload_size" in tags:
            return ThreatKind.PAYLOAD_ABUSE
        if event_count >= self.cfg.medium_events_per_window:
            return ThreatKind.RATE_ANOMALY
        if failure_count >= self.cfg.medium_failures:
            return ThreatKind.CREDENTIAL_ATTACK

        return ThreatKind.UNKNOWN


# =============================================================================
# Helpers
# =============================================================================

def _normalize_ip(ip: str) -> str:
    """
    Fix (scrub #7): previously caught ValueError from ipaddress.ip_address()
    and silently returned the raw, unparseable string -- meaning
    "999.999.999.999" became a perfectly valid tracking key. Now raises,
    consistent with how malformed/invalid input is already rejected
    elsewhere in this file (e.g. _validate_event_time's future-skew check).
    """
    value = str(ip or "").strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"source_ip is not a valid IP address: {value!r}") from exc


def _event_type_norm(value: str) -> str:
    # Intentional: "login failure", "login-failure", and "login_failure"
    # all normalize to the same "login_failure" string. This collapses
    # common formatting variants of the same conceptual event type into
    # one canonical form for counting/matching purposes.
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _severity_from_score(score: float) -> ThreatSeverity:
    if score >= 85:
        return ThreatSeverity.CRITICAL
    if score >= 65:
        return ThreatSeverity.HIGH
    if score >= 40:
        return ThreatSeverity.MEDIUM
    return ThreatSeverity.LOW


__all__ = [
    "DetectorConfig",
    "EventContext",
    "SequenceWindow",
    "SentinelThreatDetector",
    "ThreatAssessment",
    "ThreatKind",
    "ThreatSeverity",
    "ThreatSourceKind",
]
