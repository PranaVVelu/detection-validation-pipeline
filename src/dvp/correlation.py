"""Evaluate Sigma correlation rules: patterns across many events over time.

Supported: ``event_count`` and ``value_count`` with ``gte``. Anything else raises
``RuleError``.

Spec: https://sigmahq.io/docs/meta/correlations.html
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Tuple

from dvp.errors import PipelineError, RuleError

SUPPORTED_TYPES = {"event_count", "value_count"}
_SECONDS_PER_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_TIMESPAN = re.compile(r"^(\d+)([smhd])$")
_TIME_FIELDS = ("timestamp", "UtcTime")


@dataclass(frozen=True)
class Correlation:
    type: str
    base_rule: str
    group_by: Tuple[str, ...]
    timespan_seconds: int
    threshold: int
    field: Optional[str]


def parse_correlation(block: Any) -> Correlation:
    """Validate a ``correlation`` block, refusing anything that can't be evaluated."""
    if not isinstance(block, Mapping):
        raise RuleError("correlation must be a mapping")
    kind = block.get("type")
    if kind not in SUPPORTED_TYPES:
        raise RuleError(f"unsupported correlation type {kind!r}")

    rules, group_by = block.get("rules"), block.get("group-by")
    if not isinstance(rules, list) or len(rules) != 1:
        raise RuleError("correlation must reference exactly one rule")
    if not isinstance(group_by, list) or not group_by:
        raise RuleError("correlation needs a group-by list")

    timespan = _TIMESPAN.match(str(block.get("timespan")))
    if not timespan:
        raise RuleError(f"unsupported correlation timespan {block.get('timespan')!r}")

    condition = block.get("condition")
    if not isinstance(condition, Mapping) or not set(condition) <= {"gte", "field"} \
            or not isinstance(condition.get("gte"), int):
        raise RuleError(f"correlation condition must use gte: {condition!r}")
    if (kind == "value_count") != ("field" in condition):
        raise RuleError("a condition field is required for value_count, and only for value_count")

    return Correlation(
        type=kind,
        base_rule=str(rules[0]),
        group_by=tuple(str(field) for field in group_by),
        timespan_seconds=int(timespan.group(1)) * _SECONDS_PER_UNIT[timespan.group(2)],
        threshold=condition["gte"],
        field=condition.get("field"),
    )


def _event_time(event: Mapping[str, Any]) -> float:
    raw = next((event[name] for name in _TIME_FIELDS if event.get(name)), None)
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError as exc:
        raise PipelineError(f"event has no usable timestamp: {raw!r}") from exc
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp()


def _required(event: Mapping[str, Any], field: str) -> Any:
    """A matching event that can't be counted would silently hide an attack."""
    value = event.get(field)
    if value in (None, ""):
        raise PipelineError(f"correlation needs field {field!r}, which is missing from a matching event")
    return value


class CorrelationWindow:
    """Tracks one rule's sliding time windows, with one window per group."""

    def __init__(self, correlation: Correlation) -> None:
        self.correlation = correlation
        self._groups: Dict[Tuple[Any, ...], List[Tuple[float, Any]]] = {}

    def observe(self, event: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Count an event that matched the base rule, returning details if it crosses the threshold."""
        rule = self.correlation
        key = tuple(_required(event, field) for field in rule.group_by)
        now = _event_time(event)
        value = _required(event, rule.field) if rule.field else None

        window = [entry for entry in self._groups.get(key, []) if now - entry[0] <= rule.timespan_seconds]
        window.append((now, value))
        self._groups[key] = window

        count = len({entry[1] for entry in window}) if rule.field else len(window)
        if count < rule.threshold:
            return None
        # Start over, so a long attack alerts periodically instead of on every event.
        del self._groups[key]
        return {"group": dict(zip(rule.group_by, key)), "count": count, "events": len(window)}
