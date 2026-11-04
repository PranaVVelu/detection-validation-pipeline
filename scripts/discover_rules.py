#!/usr/bin/env python3
"""Work out which rules a change touched, and emit a GitHub Actions job matrix.

Exit codes: 0 = success (possibly zero rules), 2 = pipeline error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

RULE_DIRECTORIES = {"detections/sigma": {".yml", ".yaml"}, "detections/kql": {".kql"}}
# A change to any of these can alter verdicts, so every rule gets re-validated.
PIPELINE_PREFIXES = ("src/", "scripts/", "simulation/", "Dockerfile", "docker-compose.yml",
                     "requirements", ".github/workflows/detect-test.yml")
# Filenames come from the PR author. Restricting them here is defense in depth
# on top of the workflow passing them through environment variables.
SAFE_PATH = re.compile(r"^[A-Za-z0-9_./-]+$")
NULL_SHA = "0" * 40


def is_rule_path(path: str) -> bool:
    candidate = Path(path)
    # Any depth counts: a rule in a subfolder must not silently skip validation.
    return any(
        candidate.suffix.lower() in suffixes and Path(directory) in candidate.parents
        for directory, suffixes in RULE_DIRECTORIES.items()
    )


def all_rules(root: Path) -> List[str]:
    return sorted(
        path.relative_to(root).as_posix()
        for directory in RULE_DIRECTORIES
        for path in (root / directory).rglob("*")
        if path.is_file() and is_rule_path(path.relative_to(root).as_posix())
    )


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)


def changed_paths(root: Path, base: str, head: str, filter_spec: str) -> List[str]:
    result = _git(root, "diff", "--name-only", "-z", f"--diff-filter={filter_spec}", f"{base}...{head}")
    if result.returncode != 0:
        raise RuntimeError(f"git diff failed: {result.stderr.strip()}")
    return [path for path in result.stdout.split("\0") if path]


def select_rules(root: Path, base: Optional[str], head: str, validate_all: bool) -> List[str]:
    # A null or unknown base means a new branch or a force-push; there is nothing
    # reliable to diff against, so validate everything.
    if validate_all or not base or base == NULL_SHA or _git(root, "cat-file", "-e", f"{base}^{{commit}}").returncode:
        return all_rules(root)
    # Deletions count as pipeline changes, but deleted rules must not be validated.
    if any(path.startswith(PIPELINE_PREFIXES) for path in changed_paths(root, base, head, "ACMRD")):
        return all_rules(root)
    return sorted(path for path in changed_paths(root, base, head, "ACMR") if is_rule_path(path))


def build_matrix(rules: List[str]) -> Dict[str, List[Dict[str, str]]]:
    return {"include": [{"rule": rule, "name": re.sub(r"[^A-Za-z0-9_-]+", "-", rule)} for rule in rules]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", help="base commit SHA of the change")
    parser.add_argument("--head", default="HEAD", help="head commit SHA of the change")
    parser.add_argument("--all", action="store_true", help="select every rule")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()

    try:
        rules = select_rules(args.root, args.base, args.head, args.all)
    except (RuntimeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    unsafe = [rule for rule in rules if not SAFE_PATH.match(rule)]
    if unsafe:
        print(f"ERROR: rule paths contain unsupported characters: {unsafe}", file=sys.stderr)
        return 2

    matrix = json.dumps(build_matrix(rules), separators=(",", ":"))
    print(f"Selected {len(rules)} rule(s):")
    for rule in rules:
        print(f"  - {rule}")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write(f"matrix={matrix}\ncount={len(rules)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
