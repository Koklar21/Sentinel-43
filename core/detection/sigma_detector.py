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

"""Bounded Sigma-compatible deterministic matching for Sentinel-43.

This module is an evidence detector only. It has no network client, queue,
scheduler, database, governance handle, response primitive, or enforcement
authority.

pySigma owns Sigma YAML parsing and condition parsing. Sentinel-43 deliberately
implements only the event-local subset it can evaluate against its normalized
telemetry. Unsupported Sigma value types/constructs are rejected at load time
instead of being approximated.

Supported condition tree:
    - field-bound scalar string/number/bool/null comparisons
    - Sigma string wildcards and common modifiers that compile into SigmaString
      (contains/startswith/endswith/all/cased)
    - boolean AND / OR / NOT
    - pySigma-resolved selection conditions such as 1 of selection_*

Intentionally unsupported here:
    - correlation/timeframe rules (Phase 3 owns temporal sequence correlation)
    - unbound keyword searches
    - regex/CIDR/field-reference/query/compare/exists/expansion expressions
    - fields Sentinel-43 does not currently project from normalized telemetry
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Mapping

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.exceptions import SigmaRuleLocation
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaNull,
    SigmaNumber,
    SigmaString,
    SpecialChars,
)


SIGMA_DETECTOR_VERSION: Final[str] = "s43-sigma-1"
_MAX_RULE_FILE_BYTES: Final[int] = 1_048_576
_MAX_ISSUES: Final[int] = 1_000

_FIELD_ALIASES: Final[dict[str, str]] = {
    "kind": "kind",
    "category": "category",
    "product": "product",
    "service": "service",
    "eventtype": "event_type",
    "source": "source",
    "sourceidentity": "source_identity",
    "identitytype": "source_identity",
    "sourceip": "source_ip",
    "srcip": "source_ip",
    "ipaddress": "source_ip",
    "principalid": "principal_id",
    "user": "principal_id",
    "username": "principal_id",
    "targetusername": "principal_id",
    "status": "status",
    "statuscode": "status_code",
    "success": "success",
    "severity": "severity",
    "threatkind": "threat_kind",
    "confidence": "confidence",
    "action": "action",
    "integritystatus": "integrity_status",
    "runtimeevent": "runtime_event",
    "platform": "platform",
    "runtimerole": "runtime_role",
    "instanceid": "instance_id",
    "namespace": "namespace",
    "workload": "workload",
    "nodename": "node_name",
    "podname": "pod_name",
    "dependencystatus": "dependency_status",
    "driftdetected": "drift_detected",
    "unsafeconfig": "unsafe_config",
    "privilegeescalation": "privilege_escalation",
    "secretsexposed": "secrets_exposed",
    "crashloop": "crash_loop",
    "latencyms": "latency_ms",
    "failedchecks": "failed_checks",
    "errorratepercent": "error_rate_percent",
    "cpupercent": "cpu_percent",
    "memorypercent": "memory_percent",
    "diskpercent": "disk_percent",
    "unsignedartifact": "unsigned_artifact",
    "debugmodeenabled": "debug_mode_enabled",
    "configageseconds": "config_age_seconds",
    "versionmismatch": "version_mismatch",
}

_LEVELS: Final[frozenset[str]] = frozenset(
    {"informational", "low", "medium", "high", "critical"}
)

_MISSING = object()


class SigmaRuleLoadError(RuntimeError):
    """The configured Sigma rule source cannot be loaded safely."""


class SigmaUnsupportedRuleError(ValueError):
    """A syntactically valid Sigma rule is outside S43's bounded subset."""


@dataclass(frozen=True, slots=True)
class SigmaRuleIssue:
    source: str
    kind: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "source": self.source,
            "kind": self.kind,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class SigmaMatch:
    rule_id: str
    title: str
    level: str
    tags: tuple[str, ...]
    source: str
    source_sha256: str

    def to_evidence(self, *, event_id: str = "") -> dict[str, Any]:
        payload: dict[str, Any] = {
            "detector": "sigma",
            "detector_version": SIGMA_DETECTOR_VERSION,
            "rule_id": self.rule_id,
            "title": self.title,
            "level": self.level,
            "tags": list(self.tags),
            "rule_source": self.source,
            "rule_source_sha256": self.source_sha256,
        }
        if event_id:
            payload["event_id"] = event_id
        return payload


@dataclass(frozen=True, slots=True)
class _FieldPredicate:
    field: str
    value_kind: str
    expected: Any

    def evaluate(self, event: Mapping[str, Any]) -> bool:
        actual = event.get(self.field, _MISSING)

        if self.value_kind == "null":
            return actual is _MISSING or actual is None

        if actual is _MISSING:
            return False

        if self.value_kind == "string":
            return bool(self.expected.fullmatch(str(actual)))

        if self.value_kind == "number":
            if isinstance(actual, bool):
                return False
            try:
                return float(actual) == float(self.expected)
            except (TypeError, ValueError):
                return False

        if self.value_kind == "bool":
            return isinstance(actual, bool) and actual is self.expected

        return False


@dataclass(frozen=True, slots=True)
class _All:
    args: tuple["_Expression", ...]

    def evaluate(self, event: Mapping[str, Any]) -> bool:
        return all(arg.evaluate(event) for arg in self.args)


@dataclass(frozen=True, slots=True)
class _Any:
    args: tuple["_Expression", ...]

    def evaluate(self, event: Mapping[str, Any]) -> bool:
        return any(arg.evaluate(event) for arg in self.args)


@dataclass(frozen=True, slots=True)
class _Not:
    arg: "_Expression"

    def evaluate(self, event: Mapping[str, Any]) -> bool:
        return not self.arg.evaluate(event)


_Expression = _FieldPredicate | _All | _Any | _Not


@dataclass(frozen=True, slots=True)
class _CompiledRule:
    rule_id: str
    title: str
    level: str
    tags: tuple[str, ...]
    source: str
    source_sha256: str
    logsource_product: str
    logsource_category: str
    logsource_service: str
    conditions: tuple[_Expression, ...]

    def applies_to(self, event: Mapping[str, Any]) -> bool:
        if self.logsource_product:
            if _lower(event.get("product")) != self.logsource_product:
                return False

        if self.logsource_category:
            if _lower(event.get("category")) != self.logsource_category:
                return False

        if self.logsource_service:
            if _lower(event.get("service")) != self.logsource_service:
                return False

        return True

    def matches(self, event: Mapping[str, Any]) -> bool:
        return self.applies_to(event) and any(
            condition.evaluate(event) for condition in self.conditions
        )

    def public_match(self) -> SigmaMatch:
        return SigmaMatch(
            rule_id=self.rule_id,
            title=self.title,
            level=self.level,
            tags=self.tags,
            source=self.source,
            source_sha256=self.source_sha256,
        )


class SigmaDetector:
    """Immutable loaded rule set with bounded per-event evaluation."""

    def __init__(
        self,
        rules: tuple[_CompiledRule, ...],
        *,
        issues: tuple[SigmaRuleIssue, ...] = (),
        max_matches_per_event: int = 8,
    ) -> None:
        if not 1 <= max_matches_per_event <= 128:
            raise ValueError("max_matches_per_event must be between 1 and 128")

        self._rules = tuple(rules)
        self._issues = tuple(issues[:_MAX_ISSUES])
        self.max_matches_per_event = int(max_matches_per_event)
        self._lock = threading.Lock()
        self._stats = {
            "events_evaluated": 0,
            "matches": 0,
            "match_truncations": 0,
            "rule_failures": 0,
        }

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        max_rules: int = 256,
        max_matches_per_event: int = 8,
    ) -> "SigmaDetector":
        if not 1 <= max_rules <= 10_000:
            raise ValueError("max_rules must be between 1 and 10000")

        root = Path(path)
        if not root.exists():
            raise SigmaRuleLoadError(
                f"Sigma rule path does not exist: {root}"
            )

        if root.is_file():
            files = [root]
            source_root = root.parent
        elif root.is_dir():
            files = sorted(
                {
                    *root.rglob("*.yml"),
                    *root.rglob("*.yaml"),
                }
            )
            source_root = root
        else:
            raise SigmaRuleLoadError(
                f"Sigma rule path is neither a file nor directory: {root}"
            )

        rules: list[_CompiledRule] = []
        issues: list[SigmaRuleIssue] = []
        seen_ids: set[str] = set()

        for rule_file in files:
            display_source = _display_source(rule_file, source_root)

            try:
                raw = rule_file.read_bytes()
            except OSError as exc:
                _append_issue(
                    issues,
                    SigmaRuleIssue(
                        display_source,
                        "invalid",
                        f"unable to read rule file: {type(exc).__name__}",
                    ),
                )
                continue

            if len(raw) > _MAX_RULE_FILE_BYTES:
                _append_issue(
                    issues,
                    SigmaRuleIssue(
                        display_source,
                        "unsupported",
                        f"rule file exceeds {_MAX_RULE_FILE_BYTES} bytes",
                    ),
                )
                continue

            source_sha256 = hashlib.sha256(raw).hexdigest()

            try:
                collection = SigmaCollection.from_yaml(
                    raw.decode("utf-8"),
                    collect_errors=True,
                    source=SigmaRuleLocation(rule_file),
                )
            except Exception as exc:
                _append_issue(
                    issues,
                    SigmaRuleIssue(
                        display_source,
                        "invalid",
                        f"pySigma parse failed: {type(exc).__name__}: {exc}",
                    ),
                )
                continue

            for error in collection.errors:
                _append_issue(
                    issues,
                    SigmaRuleIssue(
                        display_source,
                        "invalid",
                        f"pySigma validation failed: {error}",
                    ),
                )

            for index, rule in enumerate(collection.rules, start=1):
                if len(rules) >= max_rules:
                    _append_issue(
                        issues,
                        SigmaRuleIssue(
                            display_source,
                            "capacity",
                            f"rule rejected: max_rules={max_rules} reached",
                        ),
                    )
                    continue

                if not isinstance(rule, SigmaRule):
                    _append_issue(
                        issues,
                        SigmaRuleIssue(
                            display_source,
                            "unsupported",
                            "Sigma correlation/filter rules are not supported in Phase 1",
                        ),
                    )
                    continue

                try:
                    compiled = _compile_rule(
                        rule,
                        display_source=display_source,
                        source_sha256=source_sha256,
                        fallback_index=index,
                    )
                except SigmaUnsupportedRuleError as exc:
                    _append_issue(
                        issues,
                        SigmaRuleIssue(
                            display_source,
                            "unsupported",
                            str(exc),
                        ),
                    )
                    continue
                except Exception as exc:
                    _append_issue(
                        issues,
                        SigmaRuleIssue(
                            display_source,
                            "invalid",
                            f"rule compilation failed: {type(exc).__name__}: {exc}",
                        ),
                    )
                    continue

                if compiled.rule_id in seen_ids:
                    _append_issue(
                        issues,
                        SigmaRuleIssue(
                            display_source,
                            "invalid",
                            f"duplicate Sigma rule id {compiled.rule_id!r}",
                        ),
                    )
                    continue

                seen_ids.add(compiled.rule_id)
                rules.append(compiled)

        return cls(
            tuple(rules),
            issues=tuple(issues),
            max_matches_per_event=max_matches_per_event,
        )

    @property
    def issues(self) -> tuple[SigmaRuleIssue, ...]:
        return self._issues

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def match(self, event: Mapping[str, Any]) -> tuple[SigmaMatch, ...]:
        if not isinstance(event, Mapping):
            raise TypeError("Sigma event must be a mapping")

        matches: list[SigmaMatch] = []
        rule_failures = 0
        truncated = False

        for rule in self._rules:
            try:
                matched = rule.matches(event)
            except Exception:
                rule_failures += 1
                continue

            if not matched:
                continue

            matches.append(rule.public_match())
            if len(matches) >= self.max_matches_per_event:
                truncated = True
                break

        with self._lock:
            self._stats["events_evaluated"] += 1
            self._stats["matches"] += len(matches)
            self._stats["rule_failures"] += rule_failures
            if truncated:
                self._stats["match_truncations"] += 1

        return tuple(matches)

    def status(self) -> dict[str, Any]:
        with self._lock:
            stats = dict(self._stats)

        return {
            "detector": "sigma",
            "version": SIGMA_DETECTOR_VERSION,
            "active": bool(self._rules),
            "rules_loaded": len(self._rules),
            "rules_rejected": len(self._issues),
            "max_matches_per_event": self.max_matches_per_event,
            "stats": stats,
            "issues": [
                issue.to_dict()
                for issue in self._issues[:20]
            ],
        }


def _compile_rule(
    rule: SigmaRule,
    *,
    display_source: str,
    source_sha256: str,
    fallback_index: int,
) -> _CompiledRule:
    data = rule.to_dict()

    title = str(data.get("title") or "").strip()
    if not title:
        raise SigmaUnsupportedRuleError("rule title is required")

    raw_id = str(data.get("id") or "").strip()
    rule_id = raw_id or (
        f"sha256:{source_sha256[:24]}:{fallback_index}"
    )

    level = str(data.get("level") or "low").strip().lower()
    if level not in _LEVELS:
        level = "low"

    raw_tags = data.get("tags") or []
    if isinstance(raw_tags, str):
        raw_tags = [raw_tags]
    tags = tuple(
        str(tag).strip()[:128]
        for tag in list(raw_tags)[:32]
        if str(tag).strip()
    )

    logsource = data.get("logsource") or {}
    if not isinstance(logsource, Mapping):
        raise SigmaUnsupportedRuleError("logsource must be a mapping")

    product = _lower(logsource.get("product"))
    category = _lower(logsource.get("category"))
    service = _lower(logsource.get("service"))

    conditions: list[_Expression] = []
    parsed_conditions = getattr(rule.detection, "parsed_condition", ())
    for condition in parsed_conditions:
        parsed = getattr(condition, "parsed", None)
        if parsed is None:
            raise SigmaUnsupportedRuleError(
                "Sigma condition could not be resolved by pySigma"
            )
        conditions.append(_compile_expression(parsed))

    if not conditions:
        raise SigmaUnsupportedRuleError(
            "rule has no supported condition"
        )

    return _CompiledRule(
        rule_id=rule_id[:256],
        title=title[:256],
        level=level,
        tags=tags,
        source=display_source[:512],
        source_sha256=source_sha256,
        logsource_product=product,
        logsource_category=category,
        logsource_service=service,
        conditions=tuple(conditions),
    )


def _compile_expression(node: Any) -> _Expression:
    if isinstance(node, ConditionAND):
        if not node.args:
            raise SigmaUnsupportedRuleError("empty AND condition is unsupported")
        return _All(tuple(_compile_expression(arg) for arg in node.args))

    if isinstance(node, ConditionOR):
        if not node.args:
            raise SigmaUnsupportedRuleError("empty OR condition is unsupported")
        return _Any(tuple(_compile_expression(arg) for arg in node.args))

    if isinstance(node, ConditionNOT):
        if len(node.args) != 1 or node.args[0] is None:
            raise SigmaUnsupportedRuleError("malformed NOT condition")
        return _Not(_compile_expression(node.args[0]))

    if isinstance(node, ConditionValueExpression):
        raise SigmaUnsupportedRuleError(
            "unbound keyword/value Sigma searches are not supported"
        )

    if isinstance(node, ConditionFieldEqualsValueExpression):
        field = _resolve_field(node.field)
        value = node.value

        if isinstance(value, SigmaCasedString):
            return _FieldPredicate(
                field,
                "string",
                _compile_sigma_string(value, case_sensitive=True),
            )

        if isinstance(value, SigmaString):
            if value.contains_placeholder():
                raise SigmaUnsupportedRuleError(
                    f"field {node.field!r} uses an expansion placeholder"
                )
            return _FieldPredicate(
                field,
                "string",
                _compile_sigma_string(value, case_sensitive=False),
            )

        if isinstance(value, SigmaNumber):
            return _FieldPredicate(field, "number", value.to_plain())

        if isinstance(value, SigmaBool):
            return _FieldPredicate(field, "bool", bool(value.to_plain()))

        if isinstance(value, SigmaNull):
            return _FieldPredicate(field, "null", None)

        raise SigmaUnsupportedRuleError(
            f"field {node.field!r} uses unsupported Sigma value type "
            f"{type(value).__name__}"
        )

    raise SigmaUnsupportedRuleError(
        f"unsupported Sigma condition node {type(node).__name__}"
    )


def _compile_sigma_string(
    value: SigmaString,
    *,
    case_sensitive: bool,
) -> re.Pattern[str]:
    pieces: list[str] = []

    for part in value.iter_parts():
        if isinstance(part, str):
            pieces.append(re.escape(part))
        elif part is SpecialChars.WILDCARD_MULTI:
            pieces.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            pieces.append(".")
        else:
            raise SigmaUnsupportedRuleError(
                f"unsupported Sigma string component {type(part).__name__}"
            )

    flags = 0 if case_sensitive else re.IGNORECASE
    return re.compile("".join(pieces), flags)


def _resolve_field(field: Any) -> str:
    raw = str(field or "").strip()
    key = re.sub(r"[^a-z0-9]", "", raw.casefold())
    resolved = _FIELD_ALIASES.get(key)
    if resolved is None:
        raise SigmaUnsupportedRuleError(
            f"Sigma field {raw!r} is not available in S43 Phase 1 telemetry"
        )
    return resolved


def _lower(value: Any) -> str:
    return str(value or "").strip().casefold()


def _display_source(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return path.name


def _append_issue(
    issues: list[SigmaRuleIssue],
    issue: SigmaRuleIssue,
) -> None:
    if len(issues) < _MAX_ISSUES:
        issues.append(issue)


__all__ = [
    "SIGMA_DETECTOR_VERSION",
    "SigmaDetector",
    "SigmaMatch",
    "SigmaRuleIssue",
    "SigmaRuleLoadError",
    "SigmaUnsupportedRuleError",
]
