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
# for open-source use, modification, and distribution.
#
# 2. Commercial License
# for proprietary, enterprise, government, or other commercial use
# not permitted under the AGPL v3.0.
#
# Use, modification, redistribution, and commercial use are governed by
# the terms of the applicable license. Any use outside those terms is
# prohibited.
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

import math
import time
from collections import deque, OrderedDict
from dataclasses import dataclass
from threading import RLock
from typing import Deque, Dict, List, Optional, Tuple

# Fix (scrub, public-beta hardening): was an absolute import
# (sentinel_43_ai.detection.sentinel_threat_detector). Because Python
# always runs a package's __init__.py when any submodule is imported, one
# absolute import buried in a submodule becomes a single point of failure
# for the ENTIRE package the moment it's relocated/renamespaced -- e.g.
# nested under a different top-level package. Switched to relative,
# matching sentinel_threat_detector.py's own import style.
from .sentinel_threat_detector import EventContext, SequenceWindow


# =============================================================================
# Hardening pass — changelog (this pass)
# =============================================================================
#   1. Orphaned payloads fixed. Payloads were only pruned by count
#      (max_payloads), never by time, so a payload attached to an early
#      event could sit in memory indefinitely past window_seconds as long
#      as the key stayed "alive" via newer payload-less events. Payloads
#      now carry their own timestamp (Deque[Tuple[float, bytes]] instead
#      of Deque[bytes]) and are pruned by the same cutoff as events,
#      independent of whether the events queue itself is still active.
#   2. Stat increments outside the lock fixed. dict["key"] += 1 is not
#      atomic across threads (LOAD_SUBSCR + BINARY_ADD + STORE_SUBSCR are
#      separate bytecodes), so concurrent callers could lose increments.
#      These counters matter beyond cosmetics — a spike in rejected/
#      dropped events is itself a signal worth alerting on. All stat
#      mutations now happen under self._lock.
#   3. No proactive sweep fixed. Pruning was purely reactive — a key only
#      got pruned when touched again via add_event/build_window/
#      recent_payloads. A flood of distinct keys that then goes quiet sat
#      in memory forever. Added periodic_cleanup() for an external
#      scheduler (thread or asyncio task) to call periodically.
#   4. Key-capacity behavior changed from refuse to LRU-evict. Previously,
#      once max_keys_hint was hit, brand-new (identity, ip) pairs were
#      refused tracking entirely — meaning an attacker who sprayed enough
#      junk keys first could permanently blind detection to every
#      subsequent novel attacker. self._events is now an OrderedDict;
#      every touch (insert, build_window, recent_payloads) moves a key to
#      the end, and hitting capacity now evicts the least-recently-used
#      key instead of refusing the new one. Capacity pressure now falls
#      on stale/idle actors, not on tracking new ones.
#   5. get_stats() no longer does an O(N) sum over every key's deque
#      length while holding the lock. Running totals (_total_events_count,
#      _total_payloads_count) are maintained incrementally at every
#      insert/prune/evict site instead, making get_stats() O(1).
#   6. Added events_in_interval(identity, ip, interval_seconds) as a pure
#      data-query primitive: cost is O(events for that one key within the
#      interval), not O(total events across the whole store). This is
#      deliberately NOT a "detect_bursts()"-style method that scans every
#      tracked key under the lock on every call — that pattern makes the
#      store itself the ingestion bottleneck under load, and also bakes a
#      detection threshold into what should be a pure store. The detector
#      layer (sentinel_threat_detector.py) owns thresholds and scoring;
#      this class owns memory and lookup. Added active_keys() alongside
#      it so a detector loop can enumerate suspects to check, at whatever
#      cadence it chooses, outside this store's lock.
#   7. `if payload:` truthiness fixed to `if payload is not None:`. An
#      empty bytes payload (b"") is falsy in Python, so it was silently
#      never stored at all rather than being explicitly evaluated.
#   8. RLock kept deliberately, not switched to a plain Lock. Re-entrancy
#      is not exercised by any code path today (_prune_locked never
#      re-acquires), so a plain Lock would technically work and shave a
#      negligible amount of overhead. But the downside of switching is a
#      latent deadlock the moment a future change nests a nother locked
#      call without realizing it; that risk isn't worth the saved
#      microseconds here.
#   9. __exit__ documented (not changed): calling `with SentinelWindowStore()
#      as store:` wipes ALL tracked state on block exit via cleanup(), not
#      just resources opened by the context manager. This is a footgun for
#      a long-lived store backing live detection; the docstring now says
#      so explicitly instead of leaving it to be discovered the hard way.
#  10. build_window() constructed SequenceWindow() with no arguments,
#      relying on that class's own unrelated default (max_events=500)
#      instead of this store's actual max_events_per_key. Harmless while
#      the default (200) stayed under 500, but if this store is ever
#      tuned above 500, events it intentionally retained would be
#      silently truncated via SequenceWindow's internal deque(maxlen=...)
#      with zero error or warning. Now passes max_events=self.cfg.
#      max_events_per_key explicitly.
# =============================================================================


@dataclass(frozen=True)
class SentinelWindowConfig:
    window_seconds: float = 60.0
    max_events_per_key: int = 200
    max_payloads: int = 50

    # Hardening knobs
    max_payload_size_bytes: int = 1 * 1024 * 1024  # 1MB
    clock_skew_seconds: float = 60.0              # allow small future skew
    reject_out_of_order: bool = True              # safest + fastest
    max_keys_hint: int = 0                        # 0 = no hard cap (optional)

    def __post_init__(self) -> None:
        if not (self.window_seconds > 0):
            raise ValueError("window_seconds must be > 0")
        if not (self.max_events_per_key > 0):
            raise ValueError("max_events_per_key must be > 0")
        if not (self.max_payloads >= 0):
            raise ValueError("max_payloads must be >= 0")
        if not (self.max_payload_size_bytes > 0):
            raise ValueError("max_payload_size_bytes must be > 0")
        if not (self.clock_skew_seconds >= 0):
            raise ValueError("clock_skew_seconds must be >= 0")
        if not (self.max_keys_hint >= 0):
            raise ValueError("max_keys_hint must be >= 0")

        # sanity ceilings (prevents absurd configs)
        if self.window_seconds > 86400:
            raise ValueError("window_seconds too large (max 86400)")
        if self.max_events_per_key > 100_000:
            raise ValueError("max_events_per_key too large (max 100000)")
        if self.max_payloads > 10_000:
            raise ValueError("max_payloads too large (max 10000)")
        if self.max_payload_size_bytes > 10 * 1024 * 1024:
            raise ValueError("max_payload_size_bytes too large (max 10MB)")


class SentinelWindowStore:
    """
    Thread-safe rolling window store for events per (identity, ip).

    Single responsibility:
    - store recent events + payloads
    - prune by time/count
    - LRU-evict whole keys under capacity pressure
    No scoring, no policy, no decisions — see events_in_interval()'s
    docstring for why that boundary is enforced deliberately.
    """

    def __init__(self, cfg: Optional[SentinelWindowConfig] = None) -> None:
        self.cfg = cfg or SentinelWindowConfig()
        self._lock = RLock()

        # OrderedDict so key order tracks least-recently-used -> most-
        # recently-used. Every touch (insert, build_window,
        # recent_payloads) calls move_to_end(); capacity eviction pops
        # from the front (oldest/least-recently-used). See changelog #4.
        self._events: "OrderedDict[Tuple[str, str], Deque[EventContext]]" = OrderedDict()
        # Payloads now carry their own timestamp so they can be pruned by
        # time independently of the events queue. See changelog #1.
        self._payloads: Dict[Tuple[str, str], Deque[Tuple[float, bytes]]] = {}

        # Running totals maintained incrementally at every add/prune/evict
        # site so get_stats() is O(1) instead of O(N) over every key. See
        # changelog #5.
        self._total_events_count = 0
        self._total_payloads_count = 0

        self._stats = {
            "events_added": 0,
            "events_dropped_expired": 0,
            "events_dropped_out_of_order": 0,
            "events_dropped_overflow": 0,
            "payloads_dropped_overflow": 0,
            "payloads_dropped_expired": 0,
            "keys_removed_empty": 0,
            "keys_evicted_lru": 0,
            "payloads_rejected_too_large": 0,
            "events_rejected_bad_timestamp": 0,
        }

    # ------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------

    def add_event(self, event: EventContext) -> None:
        now = time.time()

        # Validate identity/IP (cheap guardrails)
        identity = getattr(event, "source_identity", None)
        ip = getattr(event, "source_ip", None)
        if not identity or not ip:
            raise ValueError("EventContext requires source_identity and source_ip")

        # Validate timestamp
        ts = getattr(event, "timestamp", None)
        if not isinstance(ts, (int, float)) or not math.isfinite(ts):
            # Fix (scrub #2): stat increment now under the lock.
            with self._lock:
                self._stats["events_rejected_bad_timestamp"] += 1
            raise ValueError("Event timestamp must be a finite number")

        # If it's way in the future, reject (prevents never-prune abuse)
        if ts > now + self.cfg.clock_skew_seconds:
            with self._lock:
                self._stats["events_rejected_bad_timestamp"] += 1
            raise ValueError("Event timestamp is too far in the future")

        # If already expired, drop silently (don't store trash)
        if ts < now - self.cfg.window_seconds:
            with self._lock:
                self._stats["events_dropped_expired"] += 1
            return

        key = (identity, ip)

        with self._lock:
            is_new_key = key not in self._events

            # Fix (scrub #4): evict LRU key at capacity instead of
            # refusing the new one. See changelog #4 for the reasoning.
            if self.cfg.max_keys_hint and is_new_key and len(self._events) >= self.cfg.max_keys_hint:
                evicted_key, evicted_events_q = self._events.popitem(last=False)
                self._total_events_count -= len(evicted_events_q)
                evicted_payloads_q = self._payloads.pop(evicted_key, None)
                if evicted_payloads_q:
                    self._total_payloads_count -= len(evicted_payloads_q)
                self._stats["keys_evicted_lru"] += 1

            events_q = self._events.get(key)
            if events_q is None:
                events_q = deque()
                self._events[key] = events_q  # new keys land at the end (MRU position) already
            else:
                self._events.move_to_end(key)

            # Out-of-order handling
            if self.cfg.reject_out_of_order and events_q and ts < events_q[-1].timestamp:
                self._stats["events_dropped_out_of_order"] += 1
                return

            # Store event
            events_q.append(event)
            self._stats["events_added"] += 1
            self._total_events_count += 1

            # Enforce per-key event bound
            while len(events_q) > self.cfg.max_events_per_key:
                events_q.popleft()
                self._total_events_count -= 1
                self._stats["events_dropped_overflow"] += 1

            # Store payloads (bounded by count + size + time)
            # Fix (scrub #7): explicit `is not None` instead of truthiness,
            # so an empty bytes payload (b"") is evaluated rather than
            # silently skipped.
            payload = getattr(event, "payload", None)
            if payload is not None:
                if not isinstance(payload, (bytes, bytearray)):
                    # If payload isn't bytes, ignore it rather than exploding
                    # (You can be stricter if you prefer)
                    payload = None
                elif len(payload) > self.cfg.max_payload_size_bytes:
                    self._stats["payloads_rejected_too_large"] += 1
                    # Reject storing payload; still keep the event
                    payload = None

                if payload is not None and self.cfg.max_payloads > 0:
                    payload_q = self._payloads.get(key)
                    if payload_q is None:
                        payload_q = deque()
                        self._payloads[key] = payload_q

                    # Fix (scrub #1): store (timestamp, payload) so this
                    # entry can be aged out by time in _prune_locked, not
                    # just by count here.
                    payload_q.append((ts, bytes(payload)))
                    self._total_payloads_count += 1
                    while len(payload_q) > self.cfg.max_payloads:
                        payload_q.popleft()
                        self._total_payloads_count -= 1
                        self._stats["payloads_dropped_overflow"] += 1

            # Prune after insert
            self._prune_locked(key, now=now)

    # ------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------

    def build_window(self, identity: str, ip: str) -> SequenceWindow:
        key = (identity, ip)
        with self._lock:
            self._prune_locked(key, now=time.time())
            q = self._events.get(key)
            if q is not None:
                self._events.move_to_end(key)
            # Fix (scrub, public-beta hardening): previously SequenceWindow()
            # was constructed with no args, relying on ITS OWN unrelated
            # default (max_events=500) rather than this store's actual
            # per-key cap. Harmless while max_events_per_key (200) stayed
            # under 500, but if this store is ever tuned above 500, events
            # this store intentionally retained would be silently
            # truncated via SequenceWindow's internal deque(maxlen=...)
            # the moment more than 500 add_event() calls happened, with no
            # error or warning. Pass the real cap explicitly.
            window = SequenceWindow(max_events=self.cfg.max_events_per_key)
            if q:
                for ev in q:
                    window.add_event(ev)
            return window

    def recent_payloads(self, identity: str, ip: str) -> List[bytes]:
        key = (identity, ip)
        with self._lock:
            self._prune_locked(key, now=time.time())
            if key in self._events:
                self._events.move_to_end(key)
            q = self._payloads.get(key)
            return [payload for _ts, payload in q] if q else []

    def events_in_interval(self, identity: str, ip: str, interval_seconds: float) -> int:
        """
        Count events for (identity, ip) within the last interval_seconds.

        Fix (scrub #6): this is a pure data query — it returns a count,
        not a verdict. No threshold or scoring decision is made here;
        that belongs in the separate detector layer
        (sentinel_threat_detector.py), which can call this once per
        suspect it already cares about. Deliberately NOT a
        "detect_bursts()"-style method that scans every tracked key
        under the lock on every call — that pattern is O(total events
        across the whole store) per call and would make this store the
        ingestion bottleneck under load.

        Cost: O(events for this one key within interval_seconds), not
        O(N) over the whole store. See also active_keys() for how a
        detector loop enumerates which keys to check.
        """
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")

        key = (identity, ip)
        now = time.time()
        cutoff = now - interval_seconds

        with self._lock:
            self._prune_locked(key, now=now)
            q = self._events.get(key)
            if not q:
                return 0
            self._events.move_to_end(key)

            if self.cfg.reject_out_of_order:
                # Queue is guaranteed monotonic (ascending timestamp) in
                # this configuration, so the most recent events are at
                # the right end. Count from the right and stop at the
                # first event older than the interval cutoff.
                count = 0
                for ev in reversed(q):
                    if ev.timestamp < cutoff:
                        break
                    count += 1
                return count

            # reject_out_of_order=False: queue may not be sorted, so a
            # full scan is required for correctness in this configuration.
            return sum(1 for ev in q if ev.timestamp >= cutoff)

    def active_keys(self) -> List[Tuple[str, str]]:
        """
        Return a snapshot list of all currently tracked (identity, ip)
        keys.

        Fix (scrub #6): intended for an external detector loop to
        enumerate suspects and then call events_in_interval()/
        build_window() on whichever ones it cares about, at whatever
        cadence it chooses. This method itself does no scoring or
        filtering — see the module-level changelog on store/detector
        separation.
        """
        with self._lock:
            return list(self._events.keys())

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            # Fix (scrub #5): O(1) running totals instead of summing
            # every key's deque length under the lock on every call.
            return {
                **self._stats,
                "total_keys": len(self._events),
                "total_events": self._total_events_count,
                "total_payload_keys": len(self._payloads),
                "total_payloads": self._total_payloads_count,
            }

    def periodic_cleanup(self) -> None:
        """
        Scan every tracked key and prune expired events/payloads, even
        for keys that have not been touched by add_event/build_window/
        recent_payloads recently.

        Fix (scrub #3): pruning elsewhere in this class is reactive — it
        only runs for a key when that specific key is touched again. A
        burst of activity from many distinct (identity, ip) pairs that
        then goes quiet leaves all of those keys sitting in memory
        indefinitely, well past window_seconds, since nothing ever
        touches them again to trigger a prune.

        Call this periodically from a background thread or scheduled
        task (e.g. every window_seconds / 2) to bound memory from dead
        keys. This is intentionally NOT run automatically inside this
        class — the caller owns concurrency/scheduling primitives,
        consistent with the rest of this store's design.
        """
        now = time.time()
        with self._lock:
            # Materialize keys to a list first since _prune_locked may
            # delete entries from self._events during iteration.
            for key in list(self._events.keys()):
                self._prune_locked(key, now=now)

    def cleanup(self) -> None:
        with self._lock:
            self._events.clear()
            self._payloads.clear()
            self._total_events_count = 0
            self._total_payloads_count = 0

    def __enter__(self) -> "SentinelWindowStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        """
        Fix (scrub #9, documented not changed): this calls cleanup(),
        which discards ALL tracked state, not just resources opened by
        this context manager. Only use `with SentinelWindowStore() as
        store:` for short-lived scopes where wiping all rolling-window
        history on exit is actually what you want (e.g. a self-contained
        test). For a long-lived store backing live threat detection,
        construct it directly and never enter/exit it as a context
        manager — every `with` block will erase detection history on
        exit otherwise.
        """
        self.cleanup()
        return False

    # ------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------

    def _prune_locked(self, key: Tuple[str, str], *, now: float) -> None:
        """
        Time-based pruning for both events and payloads of a single key.

        Must be called with self._lock already held (this method never
        acquires it itself — see changelog #8 on why RLock is kept
        despite that). Updates the running totals
        (_total_events_count, _total_payloads_count) as it removes
        entries so get_stats() can stay O(1).
        """
        cutoff = now - self.cfg.window_seconds

        q = self._events.get(key)
        if q is not None:
            # Fast path: monotonic queue (guaranteed when
            # reject_out_of_order=True).
            while q and q[0].timestamp < cutoff:
                q.popleft()
                self._total_events_count -= 1

            # If we allow out-of-order, we must occasionally clean
            # mid-queue junk. O(n) filter, but only when needed.
            if not self.cfg.reject_out_of_order and q:
                if any(ev.timestamp < cutoff for ev in q):
                    before = len(q)
                    filtered = deque(ev for ev in q if ev.timestamp >= cutoff)
                    self._total_events_count -= (before - len(filtered))
                    self._events[key] = filtered
                    q = filtered

            # Remove empty keys to stop dict growth.
            if not q:
                del self._events[key]
                self._stats["keys_removed_empty"] += 1

        # Fix (scrub #1): payloads are now pruned by time, independent of
        # whether the events queue for this key is still active. A
        # payload's stored timestamp is always the timestamp of the
        # event it was attached to, so it ages out under the identical
        # cutoff used for events above — they can never desync.
        pq = self._payloads.get(key)
        if pq is not None:
            while pq and pq[0][0] < cutoff:
                pq.popleft()
                self._total_payloads_count -= 1
                self._stats["payloads_dropped_expired"] += 1
            if not pq:
                del self._payloads[key]
