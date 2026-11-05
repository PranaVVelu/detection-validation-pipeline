"""The noise score must notice when a result changes, and must score every rule on every scenario."""

import json

import pytest
import yaml

from conftest import REPO_ROOT, run_script

PASS, FAIL, ERROR = 0, 1, 2
SCENARIOS = REPO_ROOT / "simulation/noise.yml"
LICENSE_SCENARIOS = ["launch-day", "lan-event-small", "lan-event-large", "family-shared-pc", "new-pc-same-hour"]


def edited_scenarios(tmp_path, change):
    document = yaml.safe_load(SCENARIOS.read_text(encoding="utf-8"))
    change(document["scenarios"])
    path = tmp_path / "noise.yml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def test_modeled_results_match_the_record(tmp_path):
    report = tmp_path / "noise.json"
    result = run_script("run_noise.py", "--mode", "simulated", "--run-id", "t", "--report", report)
    assert result.returncode == PASS, result.stdout + result.stderr
    document = json.loads(report.read_text(encoding="utf-8"))
    published = [p for p in (REPO_ROOT / "detections").rglob("*") if p.suffix in {".yml", ".kql"}]
    assert len(document["rules"]) == len(published)
    assert any(score["noisy_scenarios"] for score in document["rules"])


def test_every_scenario_has_a_script_and_a_reason():
    for scenario in yaml.safe_load(SCENARIOS.read_text(encoding="utf-8"))["scenarios"]:
        assert len(list((REPO_ROOT / "game/noise").glob(f"{scenario['id']}.*"))) == 1, scenario["id"]
        assert scenario["why"], scenario["id"]


@pytest.mark.parametrize("change", [
    lambda scenarios: scenarios[0].update(fires=[scenarios[3]["fires"][0]]),
    lambda scenarios: scenarios[3].update(fires=[]),
], ids=["recorded rule stays quiet", "unrecorded rule fires"])
def test_a_changed_result_fails_the_run(tmp_path, change):
    path = edited_scenarios(tmp_path, change)
    result = run_script("run_noise.py", "--mode", "simulated", "--run-id", "t", "--scenarios", path)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "differ from" in result.stdout


def test_a_scenario_with_no_events_is_an_error_not_quiet(tmp_path):
    path = edited_scenarios(tmp_path, lambda scenarios: scenarios[0].update(events=[]))
    result = run_script("run_noise.py", "--mode", "simulated", "--run-id", "t", "--scenarios", path)
    assert result.returncode == ERROR, result.stdout + result.stderr


def test_a_scenario_without_a_record_is_an_error(tmp_path):
    path = edited_scenarios(tmp_path, lambda scenarios: scenarios[0].pop("fires"))
    result = run_script("run_noise.py", "--mode", "simulated", "--run-id", "t", "--scenarios", path)
    assert result.returncode == ERROR, result.stdout + result.stderr


@pytest.mark.parametrize("scenario", LICENSE_SCENARIOS)
def test_license_scenarios_match_the_record_on_the_real_server(scenario):
    result = run_script("run_noise.py", "--mode", "real", "--run-id", "t", "--only", scenario)
    assert result.returncode == PASS, result.stdout + result.stderr
