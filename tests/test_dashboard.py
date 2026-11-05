"""The public page must tell the truth about a run, including when something failed or is missing."""

import json

import pytest

from conftest import run_script

RULE_ID = "9a4d2f68-1e7b-4c30-a8d5-6f0b3c7e2914"
RULE_FILE = "detections/sigma/game/proc_creation_win_game_unofficial_build.yml"


def write(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")


def variation(**changes):
    return {"id": "v", "name": "A variation", "rule": "A rule", "rule_file": RULE_FILE, "expected": "caught",
            "actual": "caught", "as_recorded": True, "why": "A reason", "events": 1, "events_rule_reads": 1, "alerts": 1, **changes}


def scenario(**changes):
    return {"id": "s", "name": "A scenario", "events": 1, "fires": [], "recorded": [], "as_recorded": True,
            "alerts": {}, "why": "A reason", **changes}


@pytest.fixture
def artifacts(tmp_path):
    folder = tmp_path / "artifacts"
    write(folder / "real-telemetry-bootleg/report.json", {"rule_id": RULE_ID, "verdict": "PASS",
                                                          "checks": [{"name": "True positive", "passed": True}]})
    write(folder / "evasion-scorecard/scorecard.json", {"mode": "real", "results": [variation()]})
    write(folder / "evasion-scorecard/noise.json", {"mode": "real", "results": [scenario()], "rules": [
        {"rule": "A rule", "rule_file": RULE_FILE, "noisy_scenarios": 0, "alerts": 0, "scenarios": 1}]})
    write(folder / "elastic-comparison/elastic.json", {"results": [
        {"dataset": "test/x", "rule": "A rule", "rule_file": RULE_FILE, "scenario": "attack",
         "engine_fires": True, "elastic_fires": True, "agree": True}]})
    return folder


def build(artifacts, tmp_path):
    out = tmp_path / "site"
    result = run_script("build_dashboard.py", "--artifacts", artifacts, "--out", out, "--commit", "abc1234def",
                        "--run-url", "https://example.test/run", "--finished", "today")
    return result, out


def test_page_shows_the_run_it_came_from(artifacts, tmp_path):
    result, out = build(artifacts, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    page = (out / "index.html").read_text(encoding="utf-8")
    assert "abc1234" in page and "https://example.test/run" in page and "today" in page
    assert "Results match the record" not in page  # Only one of the ten rules has a result here.
    assert "Preview." not in page


def test_page_runs_no_scripts_and_loads_nothing_from_other_sites(artifacts, tmp_path):
    _, out = build(artifacts, tmp_path)
    page = (out / "index.html").read_text(encoding="utf-8")
    assert "<script" not in page
    assert 'src="' not in page and "@import" not in page and "url(" not in page


def test_a_failed_rule_shows_as_failed(artifacts, tmp_path):
    write(artifacts / "real-telemetry-bootleg/report.json", {"rule_id": RULE_ID, "verdict": "FAIL",
                                                             "checks": [{"name": "True positive", "passed": False}]})
    _, out = build(artifacts, tmp_path)
    page = (out / "index.html").read_text(encoding="utf-8")
    assert "Fails on real logs" in page
    assert "Results need attention" in page
    assert 'class="t fail"' in page


def test_a_changed_result_shows_as_changed(artifacts, tmp_path):
    write(artifacts / "evasion-scorecard/scorecard.json",
          {"mode": "real", "results": [variation(actual="missed", as_recorded=False)]})
    _, out = build(artifacts, tmp_path)
    assert "Changed: missed" in (out / "index.html").read_text(encoding="utf-8")


def test_a_missing_result_says_so_instead_of_showing_zero(artifacts, tmp_path):
    (artifacts / "elastic-comparison/elastic.json").unlink()
    _, out = build(artifacts, tmp_path)
    page = (out / "index.html").read_text(encoding="utf-8")
    assert "No result" in page
    assert "This run saved no result for this." in page
    assert "Results need attention" in page
    assert json.loads((out / "results.json").read_text(encoding="utf-8"))["summary"]["elastic_agree"] is None


def test_values_are_escaped(artifacts, tmp_path):
    write(artifacts / "evasion-scorecard/scorecard.json",
          {"mode": "real", "results": [variation(name="<img src=x onerror=alert(1)>", why='"><b>')]})
    _, out = build(artifacts, tmp_path)
    page = (out / "index.html").read_text(encoding="utf-8")
    assert "<img" not in page and '"><b>' not in page
    assert "&lt;img" in page


def test_simulated_results_are_labeled_as_a_preview(artifacts, tmp_path):
    write(artifacts / "evasion-scorecard/scorecard.json", {"mode": "simulated", "results": [variation()]})
    _, out = build(artifacts, tmp_path)
    assert "Preview." in (out / "index.html").read_text(encoding="utf-8")


def test_published_data_matches_the_page(artifacts, tmp_path):
    _, out = build(artifacts, tmp_path)
    summary = json.loads((out / "results.json").read_text(encoding="utf-8"))["summary"]
    assert summary["evasion_caught"] == 1 and summary["evasion_total"] == 1
    assert summary["rules_passed"] == 1 and summary["rules_total"] >= 10


def test_no_results_publishes_nothing(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    result, out = build(empty, tmp_path)
    assert result.returncode == 2
    assert not out.exists()
