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


def build(artifacts, tmp_path, *extra):
    out = tmp_path / "site"
    result = run_script("build_dashboard.py", "--artifacts", artifacts, "--out", out, "--commit", "abc1234def",
                        "--run-url", "https://example.test/run", "--finished", "today", *extra)
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


def test_coverage_counts_only_rules_that_pass_on_real_logs(artifacts, tmp_path):
    _, out = build(artifacts, tmp_path)
    coverage = {entry["technique"]: entry for entry in json.loads((out / "results.json").read_text(encoding="utf-8"))["coverage"]}
    assert coverage["T1554"]["passing"] == 1 and coverage["T1554"]["tactics"] == ["persistence"]
    assert coverage["T1059.001"]["passing"] == 0  # These rules have no result in this run.


def test_attack_layer_marks_untested_techniques(artifacts, tmp_path):
    _, out = build(artifacts, tmp_path)
    layer = json.loads((out / "attack-layer.json").read_text(encoding="utf-8"))
    colors = {item["techniqueID"]: item["color"] for item in layer["techniques"]}
    assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"] == "4.5"
    assert colors["T1554"] == "#0ca30c"
    assert colors["T1059.001"] == "#fab219"


def test_page_links_the_layer_to_attack_navigator(artifacts, tmp_path):
    _, out = build(artifacts, tmp_path)
    page = (out / "index.html").read_text(encoding="utf-8")
    assert "attack-navigator/#layerURL=https%3A%2F%2Fpranavvelu.github.io%2Fdetection-validation-pipeline%2Fattack-layer.json" in page
    assert 'href="https://attack.mitre.org/techniques/T1574/001/"' in page


def history(out):
    return json.loads((out / "history.json").read_text(encoding="utf-8"))["runs"]


def test_history_starts_from_the_seed_and_adds_this_run(artifacts, tmp_path):
    _, out = build(artifacts, tmp_path)
    runs = history(out)
    assert runs[0]["summary"]["evasion_caught"] == 2  # The first real evasion run, before any fixes.
    assert runs[-1]["url"] == "https://example.test/run" and runs[-1]["summary"]["evasion_caught"] == 1
    assert "healthy" not in runs[-1]["summary"]


def test_history_continues_the_published_one_without_duplicates(artifacts, tmp_path):
    previous = tmp_path / "previous.json"
    write(previous, {"runs": [{"label": "Old", "url": "https://example.test/old", "finished": "then", "summary": {"rules_passed": 9, "rules_total": 10}},
                              {"label": "Same", "url": "https://example.test/run", "finished": "today", "summary": {}}]})
    _, out = build(artifacts, tmp_path, "--previous-history", previous)
    assert [item["url"] for item in history(out)] == ["https://example.test/old", "https://example.test/run"]


def test_a_missing_published_history_falls_back_to_the_seed(artifacts, tmp_path):
    result, out = build(artifacts, tmp_path, "--previous-history", tmp_path / "missing.json")
    assert result.returncode == 0, result.stderr
    assert len(history(out)) > 1


def test_previews_never_enter_the_history(artifacts, tmp_path):
    write(artifacts / "evasion-scorecard/scorecard.json", {"mode": "simulated", "results": [variation()]})
    _, out = build(artifacts, tmp_path)
    assert all(item["url"] != "https://example.test/run" for item in history(out))


def test_history_chart_names_each_point_and_skips_unmeasured_runs(artifacts, tmp_path):
    _, out = build(artifacts, tmp_path)
    page = (out / "index.html").read_text(encoding="utf-8")
    assert "<title>Evasion scorecard added, 5 Nov 2026: 2 of 10</title>" in page
    assert page.count('class="spark"') == 4
