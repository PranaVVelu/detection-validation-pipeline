"""The comparison must catch new disagreements, and must not hide them behind its workarounds.

These need no Elasticsearch or pySigma. The real comparison runs in the real-telemetry workflow.
"""

import pytest

from compare_elastic import (
    Dataset,
    check_against_record,
    compare_dataset,
    fix_like_backslashes,
    fix_rlike_patterns,
    index_mappings,
    result_key,
    sigma_rule_files,
    to_document,
)

RULE = "detections/sigma/game/proc_creation_win_game_unofficial_build.yml"


def event(scenario="attack", **fields):
    return {"timestamp": "2026-11-05T00:00:00Z", **fields, "_meta": {"scenario": scenario, "category": "process_creation"}}


def result(agree, dataset="noise/x"):
    return {"dataset": dataset, "rule_file": "rule.yml", "scenario": "benign", "agree": agree}


class FakeElastic:
    def __init__(self, fires):
        self.fires_result = fires
        self.loaded = None

    def load(self, events):
        self.loaded = events

    def fires(self, query, category, scenario):
        return self.fires_result


def test_like_patterns_get_the_extra_escaping():
    query = r'where CommandLine like "*\\etc\\hosts*" and ends_with(Image, "\\cmd.exe")'
    assert fix_like_backslashes(query) == r'where CommandLine like "*\\\\etc\\\\hosts*" and ends_with(Image, "\\cmd.exe")'


def test_rlike_is_not_treated_as_like():
    assert fix_like_backslashes(r'where a rlike "x\\\\d"') == r'where a rlike "x\\\\d"'


def test_rlike_patterns_match_anywhere_and_keep_their_classes():
    assert fix_rlike_patterns(r'where a rlike "%x:~\\\\d+%"') == r'where a rlike ".*%x:~\\d+.*"'.replace("+.*", "+%.*")


def test_labels_stay_out_of_the_fields_a_rule_can_read():
    document = to_document({**event(Image="a.exe"), "variant": "v"})
    assert document["Image"] == "a.exe"
    assert document["dvp_scenario"] == "attack"
    assert document["dvp_category"] == "process_creation"
    assert "_meta" not in document and "variant" not in document


def test_sysmon_timestamps_are_read_as_utc():
    document = to_document({"UtcTime": "2026-11-05 07:13:00.123", "_meta": {"scenario": "attack", "category": "x"}})
    assert document["@timestamp"].startswith("2026-11-05T07:13:00.123")
    assert document["@timestamp"].endswith("+00:00")


def test_every_field_a_rule_reads_is_defined_up_front():
    properties = index_mappings()["properties"]
    for field in ("OriginalFileName", "GrantedAccess", "license_key_hash", "client_ip", "machine_id", "@timestamp"):
        assert field in properties


def test_new_disagreement_is_a_problem():
    assert check_against_record([result(False)], {}) == ["new disagreement: noise/x|rule.yml|benign"]


def test_recorded_disagreement_is_fine():
    assert check_against_record([result(False)], {result_key(result(False)): "known"}) == []


def test_recorded_disagreement_that_went_away_is_a_problem():
    problems = check_against_record([result(True)], {result_key(result(True)): "known"})
    assert problems == ["recorded disagreement has gone away: noise/x|rule.yml|benign"]


def test_a_record_for_logs_that_did_not_run_says_nothing():
    assert check_against_record([result(True, "noise/other")], {"noise/x|rule.yml|benign": "known"}) == []


@pytest.mark.parametrize("elastic_fires, agree", [(True, True), (False, False)])
def test_engine_and_elasticsearch_are_compared_per_side(elastic_fires, agree):
    bad_build = event("attack", Image="C:\\g\\FakeQuest.exe", Hashes="SHA256=NOT-LISTED")
    dataset = Dataset("test/x", [bad_build], [RULE], None)
    results = compare_dataset(dataset, FakeElastic(elastic_fires), lambda rule, placeholders: "query")
    assert [(r["scenario"], r["engine_fires"], r["agree"]) for r in results] == [("attack", True, agree)]


def test_a_dataset_with_no_logs_is_an_error():
    from dvp.errors import PipelineError
    with pytest.raises(PipelineError):
        compare_dataset(Dataset("test/x", [], sigma_rule_files(), None), FakeElastic(False), lambda r, p: "q")
