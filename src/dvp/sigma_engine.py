"""Evaluate the commonly used subset of the Sigma detection language.

Supported: search identifiers (maps and lists of maps), wildcards, the modifiers
in ``SUPPORTED_MODIFIERS``, and conditions built from and/or/not, parentheses,
``1 of`` and ``all of``. Anything else raises ``RuleError``.

Spec: https://sigmahq.io/docs/basics/rules.html
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any, Callable, Dict, List, Mapping

from dvp.errors import RuleError

Event = Mapping[str, Any]
Predicate = Callable[[Event], bool]

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "cased", "windash"}
_WINDASH_ALTERNATIVES = ("-", "/", "–", "—", "―")
_CONDITION_TOKEN = re.compile(r"\s*(\(|\)|(?:1|all)\s+of\s+[\w*]+|[\w*]+)")


def _wildcard_to_regex(value: str) -> str:
    """Translate a Sigma value to regex: ``*`` and ``?`` are wildcards unless escaped."""
    out, i = [], 0
    while i < len(value):
        char = value[i]
        following = value[i + 1] if i + 1 < len(value) else ""
        if char == "\\" and following in ("*", "?", "\\"):
            out.append(re.escape(following))
            i += 2
            continue
        out.append({"*": ".*", "?": "."}.get(char, re.escape(char)))
        i += 1
    return "".join(out)


def _windash_variants(value: str) -> List[str]:
    """Expand a leading dash to the alternatives Windows tools also accept."""
    return [
        re.sub(r"(^|(?<=\s))-", lambda m: m.group(1) + dash, value)
        for dash in _WINDASH_ALTERNATIVES
    ]


def _compile_value(value: Any, modifiers: set) -> Callable[[str], bool]:
    text = str(value)
    if "re" in modifiers:
        try:
            pattern = re.compile(text)
        except re.error as exc:
            raise RuleError(f"invalid regex {text!r}: {exc}") from exc
        return lambda candidate: pattern.search(candidate) is not None

    body = _wildcard_to_regex(text)
    prefix = ".*" if modifiers & {"contains", "endswith"} else ""
    suffix = ".*" if modifiers & {"contains", "startswith"} else ""
    flags = re.DOTALL | (0 if "cased" in modifiers else re.IGNORECASE)
    pattern = re.compile(f"{prefix}{body}{suffix}", flags)
    return lambda candidate: pattern.fullmatch(candidate) is not None


def _compile_field(spec: str, expected: Any) -> Predicate:
    field, *raw_modifiers = spec.split("|")
    modifiers = set(raw_modifiers)
    unsupported = modifiers - SUPPORTED_MODIFIERS
    if unsupported:
        raise RuleError(f"unsupported Sigma modifier(s) on {field!r}: {sorted(unsupported)}")

    values = expected if isinstance(expected, list) else [expected]
    if any(value is None for value in values):
        if len(values) > 1:
            raise RuleError(f"mixing null with other values on {field!r} is not supported")
        return lambda event: event.get(field) in (None, "")

    if "windash" in modifiers:
        groups = [[_compile_value(v, modifiers) for v in _windash_variants(str(value))]
                  for value in values]
    else:
        groups = [[_compile_value(value, modifiers)] for value in values]

    combine = all if "all" in modifiers else any

    def predicate(event: Event) -> bool:
        actual = event.get(field)
        if actual is None:
            return False
        candidate = str(actual)
        return combine(any(match(candidate) for match in group) for group in groups)

    return predicate


def _compile_search(name: str, search: Any) -> Predicate:
    if isinstance(search, Mapping):
        fields = [_compile_field(spec, expected) for spec, expected in search.items()]
        return lambda event: all(field(event) for field in fields)
    if isinstance(search, list) and search and all(isinstance(i, Mapping) for i in search):
        options = [_compile_search(name, item) for item in search]
        return lambda event: any(option(event) for option in options)
    raise RuleError(f"search identifier {name!r} is not supported (keyword searches need a raw log)")


class _ConditionParser:
    """Recursive descent parser: ``or`` < ``and`` < ``not`` < atoms."""

    def __init__(self, condition: str, searches: Dict[str, Predicate]) -> None:
        self.condition = condition
        self.searches = searches
        self.tokens = self._tokenize(condition)
        self.position = 0

    @staticmethod
    def _tokenize(condition: str) -> List[str]:
        tokens, position = [], 0
        stripped = condition.rstrip()
        while position < len(stripped):
            match = _CONDITION_TOKEN.match(stripped, position)
            if not match:
                raise RuleError(f"unsupported Sigma condition syntax: {condition!r}")
            tokens.append(match.group(1))
            position = match.end()
        return tokens

    def _peek(self) -> str:
        return self.tokens[self.position] if self.position < len(self.tokens) else ""

    def _next(self) -> str:
        token = self._peek()
        self.position += 1
        return token

    def parse(self) -> Predicate:
        predicate = self._parse_or()
        if self._peek():
            raise RuleError(f"unexpected {self._peek()!r} in condition {self.condition!r}")
        return predicate

    def _parse_or(self) -> Predicate:
        left = self._parse_and()
        while self._peek() == "or":
            self._next()
            first, second = left, self._parse_and()
            left = lambda event, a=first, b=second: a(event) or b(event)
        return left

    def _parse_and(self) -> Predicate:
        left = self._parse_not()
        while self._peek() == "and":
            self._next()
            first, second = left, self._parse_not()
            left = lambda event, a=first, b=second: a(event) and b(event)
        return left

    def _parse_not(self) -> Predicate:
        if self._peek() == "not":
            self._next()
            inner = self._parse_not()
            return lambda event: not inner(event)
        return self._parse_atom()

    def _parse_atom(self) -> Predicate:
        token = self._next()
        if token == "(":
            inner = self._parse_or()
            if self._next() != ")":
                raise RuleError(f"unbalanced parentheses in condition {self.condition!r}")
            return inner
        quantifier = re.fullmatch(r"(1|all)\s+of\s+([\w*]+)", token)
        if quantifier:
            return self._parse_quantifier(quantifier.group(1), quantifier.group(2))
        if token in self.searches:
            return self.searches[token]
        raise RuleError(f"condition references unknown search identifier {token!r}")

    def _parse_quantifier(self, count: str, target: str) -> Predicate:
        if target == "them":
            names = [name for name in self.searches if not name.startswith("_")]
        else:
            names = [name for name in self.searches if fnmatch.fnmatchcase(name, target)]
        if not names:
            raise RuleError(f"{count} of {target!r} matches no search identifier")
        members = [self.searches[name] for name in names]
        combine = all if count == "all" else any
        return lambda event: combine(member(event) for member in members)


def compile_sigma(detection: Mapping[str, Any]) -> Predicate:
    """Compile a Sigma ``detection`` block into a predicate over a single event."""
    if not isinstance(detection, Mapping) or "condition" not in detection:
        raise RuleError("Sigma rule needs a detection block with a condition")
    searches = {name: _compile_search(name, body)
                for name, body in detection.items() if name != "condition"}
    condition = detection["condition"]
    conditions = condition if isinstance(condition, list) else [condition]
    compiled = [_ConditionParser(str(item), searches).parse() for item in conditions]
    return lambda event: any(predicate(event) for predicate in compiled)
