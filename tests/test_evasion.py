"""The scorecard must notice when a result changes, and must not confuse "didn't run" with "missed"."""

import json
import sys

import pytest
import yaml

from collect_real_telemetry import label_game_events
from conftest import REPO_ROOT, run_script
from dvp.catalog import load_test
from run_evasion import NO_PROCESS

PASS, FAIL, ERROR = 0, 1, 2
VARIANTS = REPO_ROOT / "simulation/variants.yml"
LICENSE_LOCAL = ["guessing-many-machine-ids", "sharing-same-machine-id"]


def edited_variants(tmp_path, change):
    document = yaml.safe_load(VARIANTS.read_text(encoding="utf-8"))
    change(document["variants"])
    path = tmp_path / "variants.yml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def flip_first(variants):
    variants[0]["expected"] = "caught" if variants[0]["expected"] == "missed" else "missed"


def test_modeled_results_match_the_record(tmp_path):
    report = tmp_path / "scorecard.json"
    result = run_script("run_evasion.py", "--mode", "simulated", "--run-id", "t", "--report", report)
    assert result.returncode == PASS, result.stdout + result.stderr
    results = json.loads(report.read_text(encoding="utf-8"))["results"]
    assert {entry["actual"] for entry in results} == {"caught", "missed"}


def test_every_variant_has_a_script_and_a_reason():
    for variant in yaml.safe_load(VARIANTS.read_text(encoding="utf-8"))["variants"]:
        scripts = list((REPO_ROOT / "game/variants").glob(f"{variant['id']}.*"))
        assert len(scripts) == 1, variant["id"]
        assert variant["why"], variant["id"]


def test_a_changed_result_fails_the_run(tmp_path):
    path = edited_variants(tmp_path, flip_first)
    result = run_script("run_evasion.py", "--mode", "simulated", "--run-id", "t", "--variants", path)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "differ from" in result.stdout


def test_a_variant_with_no_events_is_an_error_not_a_miss(tmp_path):
    path = edited_variants(tmp_path, lambda variants: variants[0].update(events=[]))
    result = run_script("run_evasion.py", "--mode", "simulated", "--run-id", "t", "--variants", path)
    assert result.returncode == ERROR, result.stdout + result.stderr


def test_a_variant_without_an_expected_result_is_an_error(tmp_path):
    path = edited_variants(tmp_path, lambda variants: variants[0].pop("expected"))
    result = run_script("run_evasion.py", "--mode", "simulated", "--run-id", "t", "--variants", path)
    assert result.returncode == ERROR, result.stdout + result.stderr


def test_game_variant_labels_keep_only_what_the_script_started():
    events = [
        {"EventID": 1, "ProcessId": "10", "ProcessGuid": "{script}", "ParentProcessGuid": "{python}", "Image": "powershell.exe"},
        {"EventID": 1, "ProcessId": "11", "ProcessGuid": "{game}", "ParentProcessGuid": "{script}", "Image": "Quest.exe"},
        {"EventID": 1, "ProcessId": "99", "ProcessGuid": "{other}", "ParentProcessGuid": "{system}", "Image": "svchost.exe"},
    ]
    labeled = label_game_events(events, load_test("game-bootleg-build"), "run", 10, NO_PROCESS)
    assert [event["Image"] for event in labeled] == ["Quest.exe"]
    assert labeled[0]["_meta"]["scenario"] == "attack"


@pytest.mark.parametrize("variant", LICENSE_LOCAL)
def test_license_variants_match_the_record_on_the_real_server(variant, tmp_path):
    result = run_script("run_evasion.py", "--mode", "real", "--run-id", "t", "--only", variant, "--raw-out", tmp_path / "raw.jsonl")
    assert result.returncode == PASS, result.stdout + result.stderr


@pytest.mark.skipif(sys.platform == "darwin", reason="macOS only assigns 127.0.0.1 to the loopback interface")
def test_guessing_from_many_addresses_really_uses_many_addresses(tmp_path):
    raw = tmp_path / "raw.jsonl"
    result = run_script("run_evasion.py", "--mode", "real", "--run-id", "t", "--only", "guessing-many-addresses", "--raw-out", raw)
    assert result.returncode == PASS, result.stdout + result.stderr
    addresses = {json.loads(line)["client_ip"] for line in raw.read_text(encoding="utf-8").splitlines()}
    assert len(addresses) == 25
