import pytest

from dvp.errors import RuleError
from dvp.kql_engine import compile_kql

EVENT = {
    "Image": r"C:\Windows\System32\cmd.exe",
    "CommandLine": "cmd.exe /c whoami /all",
    "ParentImage": r"C:\Windows\explorer.exe",
}


def matches(where):
    _, predicate = compile_kql(f"DeviceProcessEvents | where {where}")
    return predicate(EVENT)


@pytest.mark.parametrize("where, expected", [
    ('FileName == "cmd.exe"', True),
    ('FileName == "CMD.EXE"', False),
    ('FileName =~ "CMD.EXE"', True),
    ('FileName != "cmd.exe"', False),
    ('FileName !~ "CMD.EXE"', False),
    ('ProcessCommandLine has "whoami"', True),
    ('ProcessCommandLine has "whoam"', False),  # "has" matches whole terms.
    ('ProcessCommandLine !has "whoam"', True),
    ('ProcessCommandLine contains "WHOAM"', True),
    ('ProcessCommandLine contains_cs "WHOAM"', False),
    ('ProcessCommandLine startswith "cmd"', True),
    ('ProcessCommandLine endswith "/ALL"', True),
    ('FileName in ("cmd.exe", "a.exe")', True),
    ('FileName in ("CMD.EXE")', False),
    ('FileName in~ ("CMD.EXE")', True),
    ('FileName !in~ ("CMD.EXE")', False),
    ('ProcessCommandLine has_any ("nope", "whoami")', True),
    ('ProcessCommandLine has_all ("nope", "whoami")', False),
    ('ProcessCommandLine matches regex @"who\\w+\\s"', True),
    ('InitiatingProcessFileName =~ "explorer.exe"', True),
    ('FileName =~ "x" or FileName =~ "cmd.exe"', True),
    ('FileName =~ "cmd.exe" and FileName =~ "x"', False),
    ('not(FileName =~ "x")', True),
    ('(FileName =~ "x" or FileName =~ "cmd.exe") and ProcessCommandLine has "all"', True),
])
def test_where_clauses(where, expected):
    assert matches(where) is expected


def test_comments_and_string_contents_are_not_confused():
    query = """
    // A leading comment | where FileName == "nope"
    DeviceProcessEvents
    | where ProcessCommandLine !contains "//not-a-comment"  // Trailing comment
    | project FileName
    """
    category, predicate = compile_kql(query)
    assert category == "process_creation"
    assert predicate(EVENT)


@pytest.mark.parametrize("query", [
    "UnknownTable | where FileName == 'x'",
    "DeviceProcessEvents",
    "DeviceProcessEvents | project FileName",
    "DeviceProcessEvents | where Nope == 'x'",
    "DeviceProcessEvents | where FileName == 'x' | summarize count()",
    "DeviceProcessEvents | where FileName == 'x' | join (Foo) on Bar",
    "DeviceProcessEvents | where FileName matches regex '('",
    "DeviceProcessEvents | where FileName == ",
    "DeviceProcessEvents | where FileName == 'x' extra",
    "DeviceProcessEvents | where Timestamp > ago(1h)",
    "let x = 1; DeviceProcessEvents | where FileName == 'x'",
])
def test_unsupported_or_invalid_queries_fail_closed(query):
    with pytest.raises(RuleError):
        compile_kql(query)
