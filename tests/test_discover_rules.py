import json
import subprocess
from pathlib import Path

import pytest

from conftest import run_script
from discover_rules import is_rule_path


def git(repo: Path, *args: str) -> str:
    identity = ["-c", "user.name=test", "-c", "user.email=test@example.com"]
    return subprocess.run(["git", *identity, *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def commit(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "--allow-empty", "-m", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / "detections/sigma").mkdir(parents=True)
    (tmp_path / "detections/kql").mkdir(parents=True)
    (tmp_path / "scripts").mkdir()
    (tmp_path / "detections/sigma/existing.yml").write_text("a")
    (tmp_path / "detections/kql/existing.kql").write_text("a")
    return tmp_path


@pytest.fixture
def discover(tmp_path_factory, monkeypatch):
    def run(repo: Path, *args: str):
        output = tmp_path_factory.mktemp("out") / "github_output"
        monkeypatch.setenv("GITHUB_OUTPUT", str(output))
        result = run_script("discover_rules.py", "--root", repo, *args)
        assert result.returncode == 0, result.stderr
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        return [item["rule"] for item in json.loads(values["matrix"])["include"]], int(values["count"])
    return run


@pytest.mark.parametrize("path, expected", [
    ("detections/sigma/a.yml", True),
    ("detections/sigma/nested/a.yaml", True),
    ("detections/kql/a.kql", True),
    ("detections/kql/a.yml", False),
    ("detections/sigma/README.md", False),
    ("tests/fixtures/rules/a.yml", False),
])
def test_is_rule_path(path, expected):
    assert is_rule_path(path) is expected


def test_only_new_rules_are_selected(repo, discover):
    base = commit(repo, "base")
    (repo / "detections/sigma/new.yml").write_text("b")
    (repo / "detections/kql/nested").mkdir()
    (repo / "detections/kql/nested/new.kql").write_text("b")
    (repo / "README.md").write_text("docs")
    head = commit(repo, "add rules")
    rules, count = discover(repo, "--base", base, "--head", head)
    assert rules == ["detections/kql/nested/new.kql", "detections/sigma/new.yml"]
    assert count == 2


def test_deleted_rule_is_not_selected(repo, discover):
    base = commit(repo, "base")
    (repo / "detections/sigma/existing.yml").unlink()
    head = commit(repo, "remove")
    assert discover(repo, "--base", base, "--head", head) == ([], 0)


def test_docs_change_selects_nothing(repo, discover):
    base = commit(repo, "base")
    (repo / "README.md").write_text("docs")
    head = commit(repo, "docs")
    assert discover(repo, "--base", base, "--head", head) == ([], 0)


def test_pipeline_change_selects_everything(repo, discover):
    base = commit(repo, "base")
    (repo / "scripts/validate_alert.py").write_text("changed")
    head = commit(repo, "pipeline")
    _, count = discover(repo, "--base", base, "--head", head)
    assert count == 2


@pytest.mark.parametrize("base", ["0" * 40, "1234567890" * 4])
def test_unusable_base_falls_back_to_everything(repo, discover, base):
    head = commit(repo, "base")
    _, count = discover(repo, "--base", base, "--head", head)
    assert count == 2


def test_unsafe_filename_is_rejected(repo):
    (repo / "detections/sigma/$(curl evil).yml").write_text("x")
    result = run_script("discover_rules.py", "--root", repo, "--all")
    assert result.returncode == 2
