"""Real collection only runs on Windows, so its logic is tested on recorded-format XML."""

import pytest
import yaml

from collect_real_telemetry import label_events, verify_upstream
from conftest import FIXTURES, REPO_ROOT
from dvp.catalog import load_atomic_test
from dvp.errors import PipelineError
from dvp.rules import load_rule
from dvp.sysmon import parse_event_xml, parse_export, select_process_tree, select_test_execution

RAW = (FIXTURES.parent / "sysmon_events.xml").read_text(encoding="utf-8").splitlines()
RULE = REPO_ROOT / "detections/sigma/proc_creation_win_powershell_encoded_command.yml"
TEST = load_atomic_test("a538de64-1c74-46ed-aa60-b995ed302598")


def command_lines(events):
    return [event["CommandLine"] for event in events]


def test_parse_flattens_system_and_event_data():
    event = parse_export(RAW)[0]
    assert event["EventID"] == 1
    assert event["Computer"] == "runner"
    assert event["Image"].endswith("svchost.exe")


def test_export_keeps_only_process_creation():
    assert all(event["EventID"] == 1 for event in parse_export(RAW))
    assert "{terminated}" not in [event["ProcessGuid"] for event in parse_export(RAW)]


def test_invalid_xml_is_a_pipeline_error():
    with pytest.raises(PipelineError):
        parse_event_xml("<Event>")


def test_process_tree_follows_guids_and_excludes_wrapper():
    selected = select_process_tree(parse_export(RAW), 100, include_root=False)
    assert command_lines(selected) == [
        '"C:\\Windows\\system32\\whoami.exe"', "cmd.exe /c powershell.exe -e  AAAA", "powershell.exe -e  AAAA",
    ]


def test_test_execution_excludes_invoke_atomic_helpers():
    selected = select_test_execution(parse_export(RAW), 100, TEST.command_marker)
    assert command_lines(selected) == ["cmd.exe /c powershell.exe -e  AAAA", "powershell.exe -e  AAAA"]


def test_helpers_alone_do_not_count_as_the_test_running():
    """Regression: helpers log first, which ended collection before the test's events arrived."""
    without_test = [event for event in parse_export(RAW) if "-e  AAAA" not in event["CommandLine"]]
    assert select_test_execution(without_test, 100, TEST.command_marker) == []


def test_marker_stops_before_input_arguments():
    assert TEST.command_marker == "powershell.exe -e"
    other = load_atomic_test("d0eb3597-a1b3-4d65-b33b-2cda8d397f20")
    assert other.command_marker == "%LOCALAPPDATA:~-3,1%md /c echo"


def test_reused_pid_does_not_pull_in_the_earlier_process():
    selected = select_process_tree(parse_export(RAW), 100, include_root=True)
    assert "cmd.exe /c from reused pid" not in command_lines(selected)
    assert "svchost.exe -k old" not in command_lines(selected)


def test_unknown_pid_selects_nothing():
    assert select_process_tree(parse_export(RAW), 999, include_root=True) == []


def test_ambient_noise_stays_out_of_the_verdict():
    labeled = label_events(parse_export(RAW), TEST, "run", 100, [500])
    assert "powershell.exe -e  RUNNERNOISE" not in command_lines(labeled)
    assert [e["_meta"]["scenario"] for e in labeled] == ["attack", "attack", "benign"]


def test_real_events_satisfy_the_rule_engine():
    labeled = label_events(parse_export(RAW), TEST, "run", 100, [500])
    rule = load_rule(RULE)
    fired = [event["CommandLine"] for event in labeled if rule.matches(event)]
    assert fired == ["powershell.exe -e  AAAA"]


def _definition(command):
    return yaml.safe_dump({"atomic_tests": [
        {"auto_generated_guid": TEST.guid, "executor": {"command": command}},
    ]})


def test_matching_upstream_definition_is_accepted():
    verify_upstream(_definition(TEST.upstream_command + "\n"), TEST)


def test_changed_upstream_command_is_refused():
    with pytest.raises(PipelineError, match="changed upstream"):
        verify_upstream(_definition("something else entirely"), TEST)


def test_missing_upstream_test_is_refused():
    with pytest.raises(PipelineError, match="is not in"):
        verify_upstream(yaml.safe_dump({"atomic_tests": []}), TEST)
