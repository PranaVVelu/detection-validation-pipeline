"""Unit tests for counting events over time, plus the license server's real logs."""

import json
import subprocess
import sys

import pytest

from conftest import REPO_ROOT, run_script
from dvp.correlation import Correlation, CorrelationWindow, parse_correlation
from dvp.errors import PipelineError, RuleError
from dvp.rules import load_rule, parse_rule

LICENSE_RULES = sorted((REPO_ROOT / "detections/sigma/license").glob("*.yml"))
BLOCK = {"type": "value_count", "rules": ["base"], "group-by": ["ip"], "timespan": "5m",
         "condition": {"gte": 3, "field": "key"}}


def window(kind="value_count", threshold=3, field="key", seconds=300):
    return CorrelationWindow(Correlation(kind, "base", ("ip",), seconds, threshold, field))


def event(second=0, ip="1.1.1.1", key="a"):
    return {"timestamp": f"2026-11-05T00:{second // 60:02d}:{second % 60:02d}Z", "ip": ip, "key": key}


def test_value_count_ignores_repeats_of_the_same_value():
    counter = window()
    assert not any(counter.observe(event(second, key="same")) for second in range(10))


def test_value_count_fires_when_enough_different_values_appear():
    counter = window()
    assert counter.observe(event(1, key="a")) is None
    assert counter.observe(event(2, key="b")) is None
    assert counter.observe(event(3, key="c")) == {"group": {"ip": "1.1.1.1"}, "count": 3, "events": 3}


def test_event_count_counts_every_event():
    counter = window("event_count", field=None)
    results = [counter.observe(event(second, key="same")) for second in range(3)]
    assert results[:2] == [None, None] and results[2]["count"] == 3


def test_activity_spread_out_past_the_window_does_not_fire():
    counter = window(seconds=60)
    assert not any(counter.observe(event(second, key=str(second))) for second in (0, 61, 122, 183, 244))


def test_each_group_counts_separately():
    counter = window()
    assert not any(counter.observe(event(second, ip=f"1.1.1.{second}", key=str(second))) for second in range(6))


def test_a_long_attack_starts_counting_again_after_alerting():
    counter = window()
    results = [counter.observe(event(second, key=str(second))) for second in range(6)]
    assert [bool(result) for result in results] == [False, False, True, False, False, True]


@pytest.mark.parametrize("broken", [
    {"timestamp": "2026-11-05T00:00:00Z", "key": "a"},
    {"timestamp": "2026-11-05T00:00:00Z", "ip": "1.1.1.1"},
    {"timestamp": "yesterday", "ip": "1.1.1.1", "key": "a"},
    {"ip": "1.1.1.1", "key": "a"},
])
def test_events_that_cannot_be_counted_are_errors_not_misses(broken):
    with pytest.raises(PipelineError):
        window().observe(broken)


@pytest.mark.parametrize("change", [
    {"type": "temporal"},
    {"rules": ["a", "b"]},
    {"group-by": []},
    {"timespan": "soon"},
    {"condition": {"lt": 3, "field": "key"}},
    {"condition": {"gte": 3}},
    {"type": "event_count"},
])
def test_unsupported_correlations_are_refused(change):
    with pytest.raises(RuleError):
        parse_correlation({**BLOCK, **change})


def test_correlation_must_reference_its_base_rule():
    text = (REPO_ROOT / "tests/fixtures/rules/fail_license_counts_retries.yml").read_text(encoding="utf-8")
    with pytest.raises(RuleError, match="unknown rule"):
        parse_rule("rule.yml", text.replace("rules: [control_unknown_key]", "rules: [something_else]"))


def test_rule_takes_its_identity_from_the_correlation():
    rule = load_rule(REPO_ROOT / "detections/sigma/license/license_activation_key_sharing.yml")
    assert rule.id == "e5c28b70-3d1f-4a96-8c47-1f9e0b6d2a83"
    assert rule.techniques == ["T1078"]
    assert rule.category == "license_activation"
    assert rule.correlation.threshold == 3


@pytest.mark.parametrize("rule", LICENSE_RULES, ids=lambda path: path.name)
def test_rules_pass_on_logs_from_the_real_license_server(rule, tmp_path):
    events, alerts, raw = tmp_path / "events.jsonl", tmp_path / "alerts.json", tmp_path / "raw.txt"
    step = run_script("collect_real_telemetry.py", "--rule", rule, "--run-id", "real", "--out", events, "--raw-out", raw)
    assert step.returncode == 0, step.stdout + step.stderr
    step = run_script("ship_events.py", "--rule", rule, "--events", events, "--run-id", "real", "--alerts-out", alerts)
    assert step.returncode == 0, step.stdout + step.stderr
    step = run_script("validate_alert.py", "--rule", rule, "--run-id", "real", "--alerts-file", alerts)
    assert step.returncode == 0, step.stdout + step.stderr


def test_license_log_never_contains_a_key(tmp_path):
    rule = REPO_ROOT / "detections/sigma/license/license_activation_key_sharing.yml"
    raw = tmp_path / "raw.txt"
    step = run_script("collect_real_telemetry.py", "--rule", rule, "--run-id", "real",
                      "--out", tmp_path / "events.jsonl", "--raw-out", raw)
    assert step.returncode == 0, step.stdout + step.stderr
    assert "FQ-DEMO" not in raw.read_text(encoding="utf-8")
    assert all(json.loads(line)["license_key_hash"] for line in raw.read_text(encoding="utf-8").splitlines())


def test_license_scenarios_refuse_any_other_host():
    script = REPO_ROOT / "game/scenarios/license-key-guessing.py"
    result = subprocess.run([sys.executable, str(script), "--scenario", "attack", "--url", "http://example.com"],
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode != 0
    assert "must point at 127.0.0.1" in result.stderr
