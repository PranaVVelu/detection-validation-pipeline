"""Run the real scripts, and assert on the exit codes CI depends on.

The negative controls are the point: a validator that can only ever say PASS is
worthless, so these prove it fails when it should.
"""

import json
from pathlib import Path

import pytest
import yaml

from conftest import FIXTURES, REPO_ROOT, run_script
from dvp.sysmon import normalize_percent_signs

PASS, FAIL, ERROR = 0, 1, 2
REPO_RULES = sorted((REPO_ROOT / "detections").rglob("*.*"))
FAILING_CONTROLS = ["fail_too_narrow.yml", "fail_too_broad.yml", "fail_wrong_technique.yml", "fail_too_broad.kql",
                    "fail_game_dll_any_path.yml", "fail_license_counts_retries.yml", "fail_license_counts_reinstalls.yml"]
ERROR_CONTROLS = ["error_unsupported_modifier.yml", "error_unknown_atomic.yml",
                  "error_summarize.kql", "error_unknown_column.kql", "error_unsupported_correlation.yml"]


def run_offline(rule: Path, tmp_path: Path, run_id: str = "test-run"):
    """Run simulate, ship and validate. Returns the first failing step or the validator."""
    events, alerts = tmp_path / "events.jsonl", tmp_path / "alerts.json"
    step = run_script("simulate_atomic.py", "--rule", rule, "--run-id", run_id, "--out", events)
    if step.returncode:
        return step
    step = run_script("ship_events.py", "--rule", rule, "--events", events, "--run-id", run_id, "--alerts-out", alerts)
    if step.returncode:
        return step
    return run_script("validate_alert.py", "--rule", rule, "--run-id", run_id, "--alerts-file", alerts,
                      "--report", tmp_path / "report.json", "--summary", tmp_path / "summary.md")


def test_repository_has_rules():
    assert len(REPO_RULES) >= 3


@pytest.mark.parametrize("rule", REPO_RULES, ids=lambda path: path.name)
def test_published_rules_pass(rule, tmp_path):
    result = run_offline(rule, tmp_path)
    assert result.returncode == PASS, result.stdout + result.stderr
    assert json.loads((tmp_path / "report.json").read_text())["verdict"] == "PASS"
    assert "PASS" in (tmp_path / "summary.md").read_text()


@pytest.mark.parametrize("name", FAILING_CONTROLS)
def test_bad_rules_fail(name, tmp_path):
    result = run_offline(FIXTURES / name, tmp_path)
    assert result.returncode == FAIL, result.stdout + result.stderr
    assert "RESULT: FAIL" in result.stdout


def test_each_control_fails_for_the_expected_reason(tmp_path):
    expected = {
        "fail_too_narrow.yml": "True positive",
        "fail_too_broad.yml": "No false positive",
        "fail_wrong_technique.yml": "Technique mapping",
        "fail_too_broad.kql": "No false positive",
        "fail_game_dll_any_path.yml": "No false positive",
        "fail_license_counts_retries.yml": "No false positive",
        "fail_license_counts_reinstalls.yml": "No false positive",
    }
    for name, failing_check in expected.items():
        run_offline(FIXTURES / name, tmp_path)
        checks = json.loads((tmp_path / "report.json").read_text())["checks"]
        assert [c["name"] for c in checks if not c["passed"]] == [failing_check], name


@pytest.mark.parametrize("name", ERROR_CONTROLS)
def test_unevaluable_rules_error_instead_of_getting_a_verdict(name, tmp_path):
    result = run_offline(FIXTURES / name, tmp_path)
    assert result.returncode == ERROR, result.stdout + result.stderr


def test_alerts_from_another_run_do_not_count(tmp_path):
    rule = REPO_ROOT / "detections/sigma/proc_creation_win_powershell_encoded_command.yml"
    assert run_offline(rule, tmp_path, run_id="old-run").returncode == PASS
    result = run_script("validate_alert.py", "--rule", rule, "--run-id", "new-run",
                        "--alerts-file", tmp_path / "alerts.json")
    assert result.returncode == ERROR


def test_missing_benign_telemetry_is_an_error_not_a_pass(tmp_path):
    rule = REPO_ROOT / "detections/sigma/proc_creation_win_powershell_encoded_command.yml"
    run_offline(rule, tmp_path)
    alerts_path = tmp_path / "alerts.json"
    document = json.loads(alerts_path.read_text())
    del document["stats"]["events"]["benign"]
    alerts_path.write_text(json.dumps(document))
    result = run_script("validate_alert.py", "--rule", rule, "--run-id", "test-run", "--alerts-file", alerts_path)
    assert result.returncode == ERROR
    assert "incomplete telemetry" in result.stderr


def test_api_flow_polls_through_ingestion_lag(siem_url, tmp_path):
    rule = REPO_ROOT / "detections/kql/powershell_encoded_command.kql"
    events = tmp_path / "events.jsonl"
    assert run_script("simulate_atomic.py", "--rule", rule, "--run-id", "api", "--out", events).returncode == 0
    assert run_script("ship_events.py", "--rule", rule, "--events", events, "--run-id", "api",
                      "--siem-url", siem_url).returncode == 0
    result = run_script("validate_alert.py", "--rule", rule, "--run-id", "api", "--siem-url", siem_url,
                        "--timeout", "10", "--poll-interval", "0.2", "--settle", "0.2")
    assert result.returncode == PASS, result.stdout + result.stderr


def test_api_flow_reports_a_rule_that_never_fires(siem_url, tmp_path):
    rule = FIXTURES / "fail_too_narrow.yml"
    events = tmp_path / "events.jsonl"
    run_script("simulate_atomic.py", "--rule", rule, "--run-id", "api", "--out", events)
    run_script("ship_events.py", "--rule", rule, "--events", events, "--run-id", "api", "--siem-url", siem_url)
    result = run_script("validate_alert.py", "--rule", rule, "--run-id", "api", "--siem-url", siem_url,
                        "--timeout", "2", "--poll-interval", "0.2")
    assert result.returncode == FAIL, result.stdout + result.stderr


def test_siem_rejects_an_unsupported_rule_at_load_time(siem_url, tmp_path):
    rule = FIXTURES / "error_summarize.kql"
    events = tmp_path / "events.jsonl"
    events.write_text("{}\n")
    result = run_script("ship_events.py", "--rule", rule, "--events", events, "--run-id", "api", "--siem-url", siem_url)
    assert result.returncode == ERROR
    assert "422" in result.stderr


def test_unreachable_siem_is_an_error_not_a_failed_rule():
    rule = REPO_ROOT / "detections/sigma/proc_creation_win_powershell_encoded_command.yml"
    result = run_script("validate_alert.py", "--rule", rule, "--run-id", "x", "--siem-url", "http://127.0.0.1:9",
                        "--timeout", "1", "--poll-interval", "0.2")
    assert result.returncode == ERROR


def test_catalog_events_contain_the_upstream_atomic_command():
    """Keeps the simulation anchored to the real test, not to what a rule expects."""
    catalog = yaml.safe_load((REPO_ROOT / "simulation/catalog.yml").read_text(encoding="utf-8"))
    for guid, test in catalog["tests"].items():
        if test.get("kind", "atomic") != "atomic":
            continue
        fixed_prefix = test["upstream_command"].split("#{")[0].strip()
        assert any(fixed_prefix in normalize_percent_signs(event["CommandLine"])
                   for event in test["attack_events"]), guid
