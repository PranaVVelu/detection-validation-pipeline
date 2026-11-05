"""Real collection only runs on Windows, so its logic is tested on recorded-format XML."""

import pytest
import yaml

from collect_real_telemetry import describe_processes, has_both_scenarios, label_events, label_game_events, verify_upstream
from conftest import FIXTURES, REPO_ROOT
from dvp.catalog import load_test
from dvp.errors import PipelineError
from dvp.rules import load_rule
from dvp.sysmon import (
    parse_event_xml,
    parse_export,
    select_process_tree,
    select_scenario_events,
    select_test_execution,
)

RAW = (FIXTURES.parent / "sysmon_events.xml").read_text(encoding="utf-8").splitlines()
RULE = REPO_ROOT / "detections/sigma/proc_creation_win_powershell_encoded_command.yml"
TEST = load_test("a538de64-1c74-46ed-aa60-b995ed302598")


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
    other = load_test("d0eb3597-a1b3-4d65-b33b-2cda8d397f20")
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


def test_process_listing_shows_commands_for_diagnosis():
    listing = describe_processes(parse_export(RAW))
    assert "powershell.exe -e  RUNNERNOISE" in listing
    assert listing.startswith(f"Sysmon recorded {len(parse_export(RAW))} process(es) and 0 other event(s):")


OBSERVED_CMD_EVENTS = [
    {"ProcessId": "5200", "ProcessGuid": "{wrapper}", "ParentProcessGuid": "{python}",
     "CommandLine": "powershell.exe -File run_atomic.ps1"},
    {"ProcessId": "2892", "ProcessGuid": "{cmd}", "ParentProcessGuid": "{wrapper}",
     "Image": "C:\\Windows\\System32\\cmd.exe",
     "CommandLine": '"cmd.exe" /c %%LOCALAPPDATA:~-3,1%%md /c echo Hello, from CMD! > hello.txt & type hello.txt'},
]


def test_doubled_percent_signs_from_real_logs_still_locate_the_test():
    """Regression: copied from real Sysmon output, where % was recorded as %%."""
    test = load_test("d0eb3597-a1b3-4d65-b33b-2cda8d397f20")
    selected = select_test_execution(OBSERVED_CMD_EVENTS, 5200, test.command_marker)
    assert [event["ProcessId"] for event in selected] == ["2892"]


def test_rule_fires_on_the_event_exactly_as_logged():
    """Rules must match the raw log, because production logs aren't normalized."""
    rule = load_rule(REPO_ROOT / "detections/sigma/proc_creation_win_cmd_env_var_substring_obfuscation.yml")
    event = {**OBSERVED_CMD_EVENTS[1], "_meta": {"category": "process_creation"}}
    assert rule.matches(event)


GAME_RULES = REPO_ROOT / "detections/sigma/game"
GAME_EVENTS = [
    {"EventID": 1, "ProcessId": "10", "ProcessGuid": "{attack-script}", "ParentProcessGuid": "{python}",
     "Image": "powershell.exe", "CommandLine": "powershell.exe -File scenario.ps1"},
    {"EventID": 1, "ProcessId": "11", "ProcessGuid": "{game}", "ParentProcessGuid": "{attack-script}",
     "Image": "C:\\g\\FakeQuest.exe", "CommandLine": "FakeQuest.exe"},
    {"EventID": 1, "ProcessId": "12", "ProcessGuid": "{peek}", "ParentProcessGuid": "{attack-script}",
     "Image": "C:\\g\\MemoryPeek.exe", "CommandLine": "MemoryPeek.exe"},
    {"EventID": 7, "ProcessId": "11", "ProcessGuid": "{game}", "Image": "C:\\g\\FakeQuest.exe",
     "ImageLoaded": "C:\\g\\version.dll"},
    {"EventID": 10, "SourceProcessGUID": "{peek}", "SourceImage": "C:\\g\\MemoryPeek.exe",
     "TargetImage": "C:\\g\\FakeQuest.exe", "GrantedAccess": "0x1438"},
    # The script launching the game gets a full-access handle, which isn't the attack.
    {"EventID": 10, "SourceProcessGUID": "{attack-script}", "SourceImage": "powershell.exe",
     "TargetImage": "C:\\g\\FakeQuest.exe", "GrantedAccess": "0x1FFFFF"},
    # Another process on the machine, such as an antivirus scanner.
    {"EventID": 10, "SourceProcessGUID": "{scanner}", "SourceImage": "C:\\av\\MsMpEng.exe",
     "TargetImage": "C:\\g\\FakeQuest.exe", "GrantedAccess": "0x1438"},
    {"EventID": 1, "ProcessId": "20", "ProcessGuid": "{benign-script}", "ParentProcessGuid": "{python}",
     "Image": "powershell.exe", "CommandLine": "powershell.exe -File scenario.ps1"},
    {"EventID": 1, "ProcessId": "21", "ProcessGuid": "{benign-game}", "ParentProcessGuid": "{benign-script}",
     "Image": "C:\\g\\FakeQuest.exe", "CommandLine": "FakeQuest.exe"},
    {"EventID": 7, "ProcessId": "21", "ProcessGuid": "{benign-game}", "Image": "C:\\g\\FakeQuest.exe",
     "ImageLoaded": "C:\\Windows\\System32\\version.dll"},
]


def test_scenario_events_link_actions_to_the_process_tree():
    selected = select_scenario_events(GAME_EVENTS, 10)
    guids = [event.get("ProcessGuid") or event.get("SourceProcessGUID") for event in selected]
    assert guids == ["{game}", "{peek}", "{game}", "{peek}"]


def test_game_labels_categorize_each_event_type():
    labeled = label_game_events(GAME_EVENTS, TEST, "run", 10, 20)
    pairs = {(event["_meta"]["scenario"], event["_meta"]["category"]) for event in labeled}
    assert pairs == {("attack", "process_creation"), ("attack", "image_load"), ("attack", "process_access"),
                     ("benign", "process_creation"), ("benign", "image_load")}


def test_verdict_needs_the_rules_event_type_in_both_scenarios():
    labeled = label_game_events(GAME_EVENTS, TEST, "run", 10, 20)
    assert has_both_scenarios(labeled, "image_load")
    assert not has_both_scenarios(labeled, "process_access")


@pytest.mark.parametrize("name, event, expected", [
    ("image_load_win_game_system_dll_outside_system_folder.yml", {"Image": "C:\\g\\FakeQuest.exe", "ImageLoaded": "C:\\g\\version.dll"}, True),
    ("image_load_win_game_system_dll_outside_system_folder.yml", {"Image": "C:\\g\\FakeQuest.exe", "ImageLoaded": "C:\\Windows\\System32\\version.dll"}, False),
    ("image_load_win_game_system_dll_outside_system_folder.yml", {"Image": "C:\\g\\Other.exe", "ImageLoaded": "C:\\g\\version.dll"}, False),
    ("proc_access_win_game_memory_write_access.yml", {"SourceImage": "C:\\g\\MemoryPeek.exe", "TargetImage": "C:\\g\\FakeQuest.exe", "GrantedAccess": "0x1438"}, True),
    ("proc_access_win_game_memory_write_access.yml", {"SourceImage": "C:\\g\\MemoryPeek.exe", "TargetImage": "C:\\g\\FakeQuest.exe", "GrantedAccess": "0x1000"}, False),
    ("proc_access_win_game_memory_write_access.yml", {"SourceImage": "C:\\Program Files\\Windows Defender\\MsMpEng.exe", "TargetImage": "C:\\g\\FakeQuest.exe", "GrantedAccess": "0x1438"}, False),
])
def test_game_rule_logic(name, event, expected):
    rule = load_rule(GAME_RULES / name)
    assert rule.matches({**event, "_meta": {"category": rule.category}}) is expected


def test_rule_ignores_events_from_other_categories():
    rule = load_rule(GAME_RULES / "image_load_win_game_system_dll_outside_system_folder.yml")
    event = {"Image": "C:\\g\\FakeQuest.exe", "ImageLoaded": "C:\\g\\version.dll"}
    assert not rule.matches({**event, "_meta": {"category": "process_creation"}})
