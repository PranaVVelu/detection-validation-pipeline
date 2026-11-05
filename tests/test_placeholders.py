"""Unit tests for the expand modifier, and the bootleg rule that depends on it."""

import pytest
import yaml

from conftest import REPO_ROOT
from dvp.errors import RuleError
from dvp.rules import load_rule
from dvp.sigma_engine import compile_sigma

BOOTLEG_RULE = REPO_ROOT / "detections/sigma/game/proc_creation_win_game_unofficial_build.yml"
DETECTION = {"selection": {"Hashes|expand": "%hashes%"}, "condition": "selection"}


@pytest.fixture
def placeholders(tmp_path, monkeypatch):
    path = tmp_path / "placeholders.yml"
    monkeypatch.setenv("DVP_PLACEHOLDERS", str(path))
    return path


def test_expand_matches_any_listed_value(placeholders):
    placeholders.write_text("hashes: [SHA256=AAA, SHA256=BBB]\n")
    matcher = compile_sigma(DETECTION)
    assert matcher({"Hashes": "SHA256=AAA"})
    assert matcher({"Hashes": "SHA256=bbb"})
    assert not matcher({"Hashes": "SHA256=CCC"})


@pytest.mark.parametrize("content", ["other: [SHA256=AAA]\n", "hashes: []\n", "hashes: SHA256=AAA\n", "", "- not a map\n"])
def test_unusable_placeholder_lists_are_refused(placeholders, content):
    placeholders.write_text(content)
    with pytest.raises(RuleError):
        compile_sigma(DETECTION)


def test_missing_placeholder_file_is_refused(placeholders):
    with pytest.raises(RuleError, match="cannot read"):
        compile_sigma(DETECTION)


def test_expand_needs_a_placeholder_value():
    with pytest.raises(RuleError, match="needs a value"):
        compile_sigma({"selection": {"Hashes|expand": "SHA256=AAA"}, "condition": "selection"})


def test_rule_uses_the_hashes_from_the_environment(placeholders):
    placeholders.write_text("official_fakequest_hashes: [SHA256=RELEASED]\n")
    rule = load_rule(BOOTLEG_RULE)
    meta = {"_meta": {"category": rule.category}}
    game = {"Image": "C:\\g\\FakeQuest.exe", **meta}
    assert not rule.matches({**game, "Hashes": "SHA256=RELEASED"})
    assert rule.matches({**game, "Hashes": "SHA256=MODIFIED"})
    assert not rule.matches({"Image": "C:\\g\\Other.exe", "Hashes": "SHA256=MODIFIED", **meta})


def test_simulated_benign_build_is_on_the_simulated_official_list():
    catalog = yaml.safe_load((REPO_ROOT / "simulation/catalog.yml").read_text(encoding="utf-8"))
    placeholders = yaml.safe_load((REPO_ROOT / "simulation/placeholders.yml").read_text(encoding="utf-8"))
    test = catalog["tests"]["game-bootleg-build"]
    assert test["benign_events"][0]["Hashes"] in placeholders["official_fakequest_hashes"]
    assert test["attack_events"][0]["Hashes"] not in placeholders["official_fakequest_hashes"]
