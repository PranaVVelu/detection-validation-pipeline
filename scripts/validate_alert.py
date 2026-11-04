#!/usr/bin/env python3
"""Decide whether a detection rule fired correctly for its Atomic Red Team test.

A rule passes only if all of these hold for this run:

  1. Technique mapping  The rule is tagged with the technique its test exercises.
  2. True positive      It alerted on an event produced by the mapped test.
  3. No false positive  It stayed quiet on the benign baseline events.

Before judging the rule, the script confirms that telemetry for both scenarios
reached the SIEM. Without that check, a broken log pipeline would look like a
rule that missed, and an empty benign set would make check 3 meaningless.

Alerts come from the mock SIEM API (--siem-url) or a JSON file (--alerts-file).

Exit codes:
  0  PASS   the rule behaved as expected
  1  FAIL   the rule is wrong: the author needs to fix it
  2  ERROR  no trustworthy verdict: the pipeline or the rule file needs attention
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dvp.catalog import DEFAULT_CATALOG, AtomicTest, load_atomic_test  # noqa: E402
from dvp.errors import PipelineError  # noqa: E402
from dvp.rules import Rule, load_rule  # noqa: E402


class ExitCode(IntEnum):
    PASS = 0
    FAIL = 1
    ERROR = 2


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


@dataclass
class Report:
    rule_id: str
    rule_title: str
    run_id: str
    atomic_test: str
    technique: str
    verdict: str
    checks: List[Check] = field(default_factory=list)
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# --------------------------------------------------------------------------- #
# Alert sources
# --------------------------------------------------------------------------- #

class ApiSource:
    """Reads from the mock SIEM. Swap this class to target a real SIEM's API."""

    polls = True

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def _get(self, path: str) -> Dict[str, Any]:
        try:
            with urllib.request.urlopen(f"{self.base_url}{path}", timeout=10) as response:
                return json.load(response)
        except (OSError, json.JSONDecodeError) as exc:
            raise PipelineError(f"SIEM request {path} failed: {exc}") from exc

    def stats(self, run_id: str) -> Dict[str, Any]:
        return self._get(f"/api/v1/runs/{urllib.parse.quote(run_id)}/stats")

    def alerts(self, run_id: str, rule_id: str) -> List[Dict[str, Any]]:
        query = urllib.parse.urlencode({"rule_id": rule_id})
        return self._get(f"/api/v1/runs/{urllib.parse.quote(run_id)}/alerts?{query}")["alerts"]


class FileSource:
    """Reads the JSON document written by ship_events.py --alerts-out."""

    polls = False

    def __init__(self, path: Path) -> None:
        try:
            self.document = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PipelineError(f"cannot read alerts file {path}: {exc}") from exc

    def stats(self, run_id: str) -> Dict[str, Any]:
        stats = self.document.get("stats", {})
        return stats if stats.get("run_id") == run_id else {}

    def alerts(self, run_id: str, rule_id: str) -> List[Dict[str, Any]]:
        return [alert for alert in self.document.get("alerts", [])
                if alert.get("run_id") == run_id and alert.get("rule_id") == rule_id]


# --------------------------------------------------------------------------- #
# Collection
# --------------------------------------------------------------------------- #

def wait_for_telemetry(source: Any, run_id: str, rule_id: str, timeout: float, poll: float) -> None:
    """Confirm the rule and both scenarios' events reached the SIEM, or raise."""
    deadline = time.monotonic() + timeout
    last_problem = "no response"
    while True:
        try:
            stats = source.stats(run_id)
            events = stats.get("events", {})
            if rule_id not in stats.get("rules", []):
                last_problem = f"rule {rule_id} not loaded for run {run_id}"
            elif not events.get("attack") or not events.get("benign"):
                last_problem = f"incomplete telemetry for run {run_id}: {events}"
            else:
                return
        except PipelineError as exc:
            last_problem = str(exc)
        if not source.polls or time.monotonic() >= deadline:
            raise PipelineError(f"telemetry check failed: {last_problem}")
        time.sleep(poll)


def collect_alerts(source: Any, run_id: str, rule_id: str, timeout: float,
                   poll: float, settle: float) -> List[Dict[str, Any]]:
    """Poll until an attack alert appears, then wait so late benign alerts are seen too."""
    deadline = time.monotonic() + timeout
    while True:
        alerts = source.alerts(run_id, rule_id)
        if not source.polls:
            return alerts
        if any(alert.get("scenario") == "attack" for alert in alerts):
            time.sleep(settle)
            return source.alerts(run_id, rule_id)
        if time.monotonic() >= deadline:
            return alerts
        time.sleep(poll)


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #

def evaluate(rule: Rule, test: AtomicTest, alerts: List[Dict[str, Any]]) -> List[Check]:
    """Apply the pass criteria. This is pure logic, which keeps it easy to unit test."""
    true_positives = [a for a in alerts if a.get("scenario") == "attack" and a.get("atomic_test") == test.guid]
    false_positives = [a for a in alerts if a.get("scenario") == "benign"]

    return [
        Check(
            "Technique mapping",
            test.technique in rule.techniques,
            f"test exercises {test.technique}; rule declares {rule.techniques or 'no techniques'}",
        ),
        Check(
            "True positive",
            bool(true_positives),
            f"{len(true_positives)} alert(s) on {len(test.attack_events)} attack event(s) from '{test.name}'",
        ),
        Check(
            "No false positive",
            not false_positives,
            f"{len(false_positives)} alert(s) on {len(test.benign_events)} benign event(s)"
            + "".join(f"\n      matched: {a.get('matched_event', {}).get('CommandLine')}" for a in false_positives),
        ),
    ]


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def _table_cell(text: Any) -> str:
    """Rule titles are author-controlled, so keep them from breaking the table."""
    return str(text).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;")


def render_markdown(report: Report) -> str:
    icon = {"PASS": "✅", "FAIL": "❌"}.get(report.verdict, "⚠️")
    lines = [
        f"### {icon} {report.verdict}: {_table_cell(report.rule_title)}",
        "",
        f"Rule `{report.rule_id}` against Atomic test `{report.atomic_test}` ({report.technique}), "
        f"run `{report.run_id}`",
        "",
        "| Check | Result | Detail |",
        "| --- | --- | --- |",
    ]
    lines += [f"| {c.name} | {'pass' if c.passed else '**FAIL**'} | {_table_cell(c.detail)} |" for c in report.checks]
    return "\n".join(lines) + "\n"


def write_outputs(report: Report, report_path: Optional[Path], summary_path: Optional[Path]) -> None:
    if report_path:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")
    if summary_path:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(render_markdown(report), encoding="utf-8")


def write_error_summary(summary_path: Optional[Path], rule_path: Path, message: str) -> None:
    print(f"RESULT: ERROR - {message}", file=sys.stderr)
    if summary_path:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(
            f"### ⚠️ ERROR: `{rule_path}`\n\nNo verdict was reached: {_table_cell(message)}\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rule", type=Path, required=True, help="path to the Sigma or KQL rule")
    parser.add_argument("--run-id", required=True, help="the run ID used when generating telemetry")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--siem-url", help="base URL of the mock SIEM API")
    source.add_argument("--alerts-file", type=Path, help="JSON file from ship_events.py --alerts-out")
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--timeout", type=float, default=30.0, help="seconds to wait for telemetry and alerts")
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--settle", type=float, default=2.0,
                        help="seconds to keep waiting for late alerts after the first attack alert")
    parser.add_argument("--report", type=Path, help="write a JSON report here")
    parser.add_argument("--summary", type=Path, help="write a Markdown summary here")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        rule = load_rule(args.rule)
        test = load_atomic_test(rule.atomic_test, args.catalog)
        source = ApiSource(args.siem_url) if args.siem_url else FileSource(args.alerts_file)
        wait_for_telemetry(source, args.run_id, rule.id, args.timeout, args.poll_interval)
        alerts = collect_alerts(source, args.run_id, rule.id, args.timeout, args.poll_interval, args.settle)
    except PipelineError as exc:
        write_error_summary(args.summary, args.rule, str(exc))
        return ExitCode.ERROR

    checks = evaluate(rule, test, alerts)
    passed = all(check.passed for check in checks)
    report = Report(rule.id, rule.title, args.run_id, test.guid, test.technique,
                    "PASS" if passed else "FAIL", checks, alerts)
    write_outputs(report, args.report, args.summary)

    print(f"Rule: {rule.title} ({rule.id})")
    print(f"Test: {test.technique} {test.name} ({test.guid})")
    for check in checks:
        print(f"  [{'PASS' if check.passed else 'FAIL'}] {check.name}: {check.detail}")
    print(f"RESULT: {report.verdict}")
    return ExitCode.PASS if passed else ExitCode.FAIL


if __name__ == "__main__":
    sys.exit(main())
