"""Evaluate a filter-only subset of KQL against normalized events.

A KQL rule here is ``Table | where ... | where ... | project ...``. That covers
single-event detections, the shape this pipeline validates. Joins, summarize,
let, extend and similar raise ``RuleError`` instead of being skipped, and so do
unknown columns, which a real cluster would also reject.

For full-fidelity KQL, see "Kustainer" in docs/IMPLEMENTATION_GUIDE.md.
"""

from __future__ import annotations

import ntpath
import re
from typing import Any, Callable, Dict, List, Mapping, Tuple

from dvp.errors import RuleError

Event = Mapping[str, Any]
Predicate = Callable[[Event], bool]

IGNORED_OPERATORS = {"project", "project-away", "project-keep", "project-reorder"}
_TOKEN = re.compile(
    r"""
    (?P<space>\s+|//[^\n]*)
  | (?P<verbatim>@"(?:[^"]|"")*"|@'(?:[^']|'')*')
  | (?P<string>"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')
  | (?P<symbol>==|!=|=~|!~|[|(),])
  | (?P<word>!?[A-Za-z_][\w-]*~?)
    """,
    re.VERBOSE,
)


def _basename(path: Any) -> str:
    return ntpath.basename(str(path)) if path else ""


# Maps Sysmon-style telemetry onto the Microsoft Defender XDR table schema, so a
# single simulated event can exercise both Sigma and KQL rules.
_TABLES: Dict[str, Tuple[str, Dict[str, Callable[[Event], Any]]]] = {
    "DeviceProcessEvents": (
        "process_creation",
        {
            "DeviceName": lambda e: e.get("Computer"),
            "AccountName": lambda e: e.get("User"),
            "FileName": lambda e: _basename(e.get("Image")),
            "FolderPath": lambda e: e.get("Image"),
            "ProcessCommandLine": lambda e: e.get("CommandLine"),
            "InitiatingProcessFileName": lambda e: _basename(e.get("ParentImage")),
            "InitiatingProcessFolderPath": lambda e: e.get("ParentImage"),
            "InitiatingProcessCommandLine": lambda e: e.get("ParentCommandLine"),
        },
    ),
}


def _has_term(haystack: str, term: str) -> bool:
    """Approximate Kusto's ``has``: match on whole alphanumeric terms."""
    return re.search(rf"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])", haystack, re.I) is not None


def _regex_operator(pattern: str) -> Callable[[str, str], bool]:
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise RuleError(f"invalid regex {pattern!r}: {exc}") from exc
    return lambda actual, _expected: compiled.search(actual) is not None


_SCALAR_OPERATORS: Dict[str, Callable[[str, str], bool]] = {
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "=~": lambda a, b: a.lower() == b.lower(),
    "!~": lambda a, b: a.lower() != b.lower(),
    "has": _has_term,
    "!has": lambda a, b: not _has_term(a, b),
    "contains": lambda a, b: b.lower() in a.lower(),
    "!contains": lambda a, b: b.lower() not in a.lower(),
    "contains_cs": lambda a, b: b in a,
    "startswith": lambda a, b: a.lower().startswith(b.lower()),
    "!startswith": lambda a, b: not a.lower().startswith(b.lower()),
    "endswith": lambda a, b: a.lower().endswith(b.lower()),
    "!endswith": lambda a, b: not a.lower().endswith(b.lower()),
}

_LIST_OPERATORS: Dict[str, Callable[[str, List[str]], bool]] = {
    "in": lambda a, b: a in b,
    "!in": lambda a, b: a not in b,
    "in~": lambda a, b: a.lower() in [v.lower() for v in b],
    "!in~": lambda a, b: a.lower() not in [v.lower() for v in b],
    "has_any": lambda a, b: any(_has_term(a, v) for v in b),
    "has_all": lambda a, b: all(_has_term(a, v) for v in b),
}


def _tokenize(query: str) -> List[Tuple[str, str]]:
    tokens, position = [], 0
    while position < len(query):
        match = _TOKEN.match(query, position)
        if not match:
            raise RuleError(f"unsupported KQL syntax near {query[position:position + 30]!r}")
        position = match.end()
        if match.lastgroup != "space":
            tokens.append((match.lastgroup, match.group()))
    return tokens


def _decode_string(kind: str, literal: str) -> str:
    if kind == "verbatim":
        quote = literal[1]
        return literal[2:-1].replace(quote * 2, quote)
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t"}.get(m.group(1), m.group(1)), literal[1:-1])


class _WhereParser:
    """Recursive descent parser for a ``where`` predicate."""

    def __init__(self, tokens: List[Tuple[str, str]], columns: Dict[str, Callable[[Event], Any]]) -> None:
        self.tokens = tokens
        self.columns = columns
        self.position = 0

    def _peek(self) -> str:
        return self.tokens[self.position][1] if self.position < len(self.tokens) else ""

    def _next(self) -> Tuple[str, str]:
        if self.position >= len(self.tokens):
            raise RuleError("unexpected end of KQL where clause")
        token = self.tokens[self.position]
        self.position += 1
        return token

    def _expect(self, symbol: str) -> None:
        _, text = self._next()
        if text != symbol:
            raise RuleError(f"expected {symbol!r} in KQL, found {text!r}")

    def parse(self) -> Predicate:
        predicate = self._parse_or()
        if self.position != len(self.tokens):
            raise RuleError(f"unexpected {self._peek()!r} in KQL where clause")
        return predicate

    def _parse_or(self) -> Predicate:
        left = self._parse_and()
        while self._peek() == "or":
            self._next()
            first, second = left, self._parse_and()
            left = lambda event, a=first, b=second: a(event) or b(event)
        return left

    def _parse_and(self) -> Predicate:
        left = self._parse_unary()
        while self._peek() == "and":
            self._next()
            first, second = left, self._parse_unary()
            left = lambda event, a=first, b=second: a(event) and b(event)
        return left

    def _parse_unary(self) -> Predicate:
        if self._peek() == "not":
            self._next()
            self._expect("(")
            inner = self._parse_or()
            self._expect(")")
            return lambda event: not inner(event)
        if self._peek() == "(":
            self._next()
            inner = self._parse_or()
            self._expect(")")
            return inner
        return self._parse_comparison()

    def _parse_string(self) -> str:
        kind, text = self._next()
        if kind not in ("string", "verbatim"):
            raise RuleError(f"expected a string literal in KQL, found {text!r}")
        return _decode_string(kind, text)

    def _parse_comparison(self) -> Predicate:
        _, column = self._next()
        if column not in self.columns:
            raise RuleError(f"unknown column {column!r}; known: {sorted(self.columns)}")
        resolve = self.columns[column]
        _, operator = self._next()

        if operator == "matches":
            _, keyword = self._next()
            if keyword != "regex":
                raise RuleError(f"expected 'matches regex', found 'matches {keyword}'")
            scalar, expected = _regex_operator(self._parse_string()), ""
        elif operator in _SCALAR_OPERATORS:
            scalar, expected = _SCALAR_OPERATORS[operator], self._parse_string()
        elif operator in _LIST_OPERATORS:
            return self._parse_list_comparison(resolve, _LIST_OPERATORS[operator])
        else:
            raise RuleError(f"unsupported KQL operator {operator!r}")

        return lambda event: scalar(str(resolve(event) or ""), expected)

    def _parse_list_comparison(self, resolve, operator) -> Predicate:
        self._expect("(")
        values = [self._parse_string()]
        while self._peek() == ",":
            self._next()
            values.append(self._parse_string())
        self._expect(")")
        return lambda event: operator(str(resolve(event) or ""), values)


def _split_pipeline(tokens: List[Tuple[str, str]]) -> List[List[Tuple[str, str]]]:
    stages: List[List[Tuple[str, str]]] = [[]]
    for token in tokens:
        if token == ("symbol", "|"):
            stages.append([])
        else:
            stages[-1].append(token)
    return stages


def compile_kql(query: str) -> Tuple[str, Predicate]:
    """Compile a query, returning its event category and an event predicate."""
    stages = _split_pipeline(_tokenize(query))
    if len(stages[0]) != 1 or stages[0][0][1] not in _TABLES:
        source = " ".join(text for _, text in stages[0])
        raise RuleError(f"query must start with a known table ({sorted(_TABLES)}), found {source!r}")
    category, columns = _TABLES[stages[0][0][1]]

    filters: List[Predicate] = []
    for stage in stages[1:]:
        if not stage:
            raise RuleError("empty stage in KQL pipeline")
        operator = stage[0][1]
        if operator == "where":
            filters.append(_WhereParser(stage[1:], columns).parse())
        elif operator not in IGNORED_OPERATORS:
            raise RuleError(f"unsupported KQL operator {operator!r}")
    if not filters:
        raise RuleError("KQL rule has no where clause, so it would match every event")
    return category, lambda event: all(check(event) for check in filters)
