"""Load Sigma and KQL rule files into a single ``Rule`` representation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

import yaml

from dvp.correlation import Correlation, parse_correlation
from dvp.errors import RuleError
from dvp.kql_engine import compile_kql
from dvp.sigma_engine import compile_sigma

SIGMA_SUFFIXES = {".yml", ".yaml"}
KQL_SUFFIXES = {".kql"}
RULE_SUFFIXES = SIGMA_SUFFIXES | KQL_SUFFIXES

_SIGMA_TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_KQL_METADATA = re.compile(r"^//\s*@(\w+)\s*:\s*(.+?)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class Rule:
    """A detection rule, reduced to what the pipeline needs to validate it."""

    id: str
    title: str
    kind: str
    techniques: List[str]
    test_id: str
    category: str
    matcher: Callable[[Mapping[str, Any]], bool]
    correlation: Optional[Correlation] = None

    def matches(self, event: Mapping[str, Any]) -> bool:
        return event.get("_meta", {}).get("category") == self.category and self.matcher(event)


def _require(metadata: Mapping[str, Any], key: str, source: str) -> str:
    value = metadata.get(key)
    if not value:
        raise RuleError(f"{source}: missing required field {key!r}")
    return str(value)


def _sigma_test_id(doc: Mapping[str, Any], source: str) -> str:
    """A rule proves itself with an Atomic test or one of this project's game tests."""
    return str(doc.get("x_game_test") or _require(doc, "x_atomic_test", source))


def _sigma_documents(text: str, source: str) -> Tuple[Mapping[str, Any], Optional[Correlation]]:
    """Split a rule file into the document describing the rule, and any correlation.

    A correlation rule is two YAML documents: a base rule that selects events, then
    the correlation that counts them. The correlation carries the rule's identity,
    so the logsource and detection are merged in from the base rule.
    """
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise RuleError(f"{source}: invalid YAML: {exc}") from exc
    if not docs or len(docs) > 2 or not all(isinstance(doc, Mapping) for doc in docs):
        raise RuleError(f"{source}: expected one YAML mapping, or a base rule and a correlation")
    if len(docs) == 1:
        return docs[0], None

    base, outer = docs
    correlation = parse_correlation(outer.get("correlation"))
    if correlation.base_rule != base.get("name"):
        raise RuleError(f"{source}: correlation references unknown rule {correlation.base_rule!r}")
    return {**outer, "logsource": base.get("logsource"), "detection": base.get("detection")}, correlation


def _parse_sigma(text: str, source: str) -> Rule:
    doc, correlation = _sigma_documents(text, source)
    tags = [_SIGMA_TECHNIQUE_TAG.match(str(tag)) for tag in doc.get("tags") or []]
    logsource = doc.get("logsource") or {}
    return Rule(
        id=_require(doc, "id", source),
        title=_require(doc, "title", source),
        kind="sigma",
        techniques=[match.group(1).upper() for match in tags if match],
        test_id=_sigma_test_id(doc, source),
        category=_require(logsource, "category", f"{source} logsource"),
        matcher=compile_sigma(doc.get("detection")),
        correlation=correlation,
    )


def _parse_kql(text: str, source: str) -> Rule:
    metadata: Dict[str, str] = {key: value for key, value in _KQL_METADATA.findall(text)}
    category, matcher = compile_kql(text)
    return Rule(
        id=_require(metadata, "id", source),
        title=_require(metadata, "title", source),
        kind="kql",
        techniques=[item.strip().upper() for item in metadata.get("techniques", "").split(",") if item.strip()],
        test_id=_require(metadata, "atomic_test", source),
        category=category,
        matcher=matcher,
    )


def parse_rule(filename: str, text: str) -> Rule:
    """Parse rule text, choosing the language from the file extension."""
    suffix = Path(filename).suffix.lower()
    try:
        if suffix in SIGMA_SUFFIXES:
            return _parse_sigma(text, filename)
        if suffix in KQL_SUFFIXES:
            return _parse_kql(text, filename)
    except RuleError as exc:
        raise RuleError(f"{filename}: {exc}") from exc
    raise RuleError(f"{filename}: unsupported rule type {suffix!r}")


def load_rule(path: Path) -> Rule:
    """Read and parse a rule file."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleError(f"cannot read rule {path}: {exc}") from exc
    return parse_rule(str(path), text)
