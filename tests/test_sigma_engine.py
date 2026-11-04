import pytest

from dvp.errors import RuleError
from dvp.sigma_engine import compile_sigma

EVENT = {"Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd.exe /c whoami /all", "User": "bob"}


def matches(detection, event=EVENT):
    return compile_sigma(detection)(event)


@pytest.mark.parametrize("field, value, expected", [
    ("Image|endswith", r"\cmd.exe", True),
    ("Image|endswith", r"\CMD.EXE", True),  # Case-insensitive by default.
    ("Image|endswith", r"\cmd.ex", False),
    ("Image|startswith", "C:\\Windows", True),
    ("CommandLine|contains", "WHOAMI", True),
    ("CommandLine|contains|cased", "WHOAMI", False),
    ("CommandLine", "cmd.exe", False),  # A plain value must match the whole field.
    ("CommandLine", "cmd.exe*", True),
    ("CommandLine", "cmd.exe /c whoam? /all", True),
    ("CommandLine|re", r"whoami\s+/all$", True),
    ("CommandLine|re", r"WHOAMI", False),  # Regex is case-sensitive by default.
    ("Missing", None, True),
    ("User", None, False),
    ("Missing|contains", "x", False),
])
def test_field_matching(field, value, expected):
    assert matches({"sel": {field: value}, "condition": "sel"}) is expected


def test_list_is_or_and_all_modifier_is_and():
    assert matches({"sel": {"CommandLine|contains": ["nope", "whoami"]}, "condition": "sel"})
    assert not matches({"sel": {"CommandLine|contains|all": ["nope", "whoami"]}, "condition": "sel"})
    assert matches({"sel": {"CommandLine|contains|all": ["cmd", "whoami"]}, "condition": "sel"})


def test_escaped_wildcard_is_literal():
    assert compile_sigma({"s": {"F": r"a\*b"}, "condition": "s"})({"F": "a*b"})
    assert not compile_sigma({"s": {"F": r"a\*b"}, "condition": "s"})({"F": "axxb"})


def test_windash_accepts_slash_form():
    detection = {"s": {"C|windash|contains": " -f "}, "condition": "s"}
    assert compile_sigma(detection)({"C": "tool -f x"})
    assert compile_sigma(detection)({"C": "tool /f x"})


@pytest.mark.parametrize("condition, expected", [
    ("yes", True),
    ("no", False),
    ("not no", True),
    ("yes and no", False),
    ("yes or no", True),
    ("no or yes and not no", True),  # "and" binds tighter than "or".
    ("(no or yes) and no", False),
    ("1 of s*", True),
    ("all of s*", False),
    ("1 of them", True),
    ("all of them", False),
])
def test_conditions(condition, expected):
    detection = {
        "yes": {"User": "bob"}, "no": {"User": "eve"},
        "s1": {"User": "bob"}, "s2": {"User": "eve"},
        "condition": condition,
    }
    assert matches(detection) is expected


@pytest.mark.parametrize("detection", [
    {"s": {"F|base64offset": "x"}, "condition": "s"},
    {"s": ["keyword"], "condition": "s"},
    {"s": {"F": "x"}, "condition": "s | count() > 5"},
    {"s": {"F": "x"}, "condition": "missing"},
    {"s": {"F": "x"}, "condition": "1 of nothing*"},
    {"s": {"F": "x"}, "condition": "(s"},
    {"s": {"F|re": "("}, "condition": "s"},
    {"s": {"F": "x"}},
])
def test_unsupported_or_invalid_rules_fail_closed(detection):
    with pytest.raises(RuleError):
        compile_sigma(detection)
