#!/usr/bin/env python3
"""Score how noisy each rule is on normal activity.

Every scenario is scored against every rule, because noise can come from a rule
nobody was thinking about. A noisy rule isn't a failure here. The run fails when the
rules that fire differ from the record in simulation/noise.yml, in either direction.

--mode simulated evaluates the modeled events. --mode real EXECUTES the scripts, so it
belongs only on a disposable Windows machine with Sysmon installed.

Exit codes: 0 = every result as recorded, 1 = a result changed, 2 = pipeline error.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(ROOT / "src"))

from collect_real_telemetry import GAME_DIR, label_game_events, label_license_events, run_license_script  # noqa: E402
from dvp.catalog import ValidationTest, expand_events  # noqa: E402
from dvp.errors import PipelineError  # noqa: E402
from dvp.rules import RULE_SUFFIXES, Rule, load_rule  # noqa: E402
from dvp.siem import SiemStore  # noqa: E402
from run_evasion import NO_PROCESS, print_evidence, run_game_script  # noqa: E402

DEFAULT_SCENARIOS = ROOT / "simulation" / "noise.yml"
NOISE_DIR = GAME_DIR / "noise"
LICENSE_CATEGORY = "license_activation"
SCENARIO_LABEL = "benign"


def load_scenarios(path: Path) -> List[Dict[str, Any]]:
    try:
        scenarios = yaml.safe_load(path.read_text(encoding="utf-8"))["scenarios"]
    except (OSError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise PipelineError(f"cannot load scenarios from {path}: {exc}") from exc
    for scenario in scenarios:
        if not isinstance(scenario.get("fires"), list):
            raise PipelineError(f"scenario {scenario.get('id')!r} needs a fires list")
    return scenarios


def load_rules() -> Dict[str, Rule]:
    """Load every published rule, keyed by its path in the repository."""
    paths = [path for path in sorted((ROOT / "detections").rglob("*")) if path.suffix.lower() in RULE_SUFFIXES]
    return {path.relative_to(ROOT).as_posix(): load_rule(path) for path in paths}


def as_test(scenario: Dict[str, Any]) -> ValidationTest:
    """The labeling code expects a test, and a noise scenario is one with only a benign side."""
    return ValidationTest(guid=scenario["id"], kind=scenario["kind"], technique="", name=scenario["name"],
                          category=LICENSE_CATEGORY, upstream_command="", attack_events=[], benign_events=[],
                          upstream_commit="")


def modeled_events(scenario: Dict[str, Any], run_id: str) -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc).isoformat()
    events = []
    for event in expand_events(scenario["events"]):
        fields = {key: value for key, value in event.items() if key != "category"}
        events.append({"timestamp": now, **fields, "_meta": {
            "event_id": str(uuid.uuid4()), "run_id": run_id, "scenario": SCENARIO_LABEL,
            "category": event["category"], "test_id": scenario["id"], "technique": "",
        }})
    return events


def real_events(scenario: Dict[str, Any], run_id: str, workdir: Path) -> List[Dict[str, Any]]:
    test = as_test(scenario)
    if scenario["kind"] == "license":
        log_path = workdir / f"{scenario['id']}.jsonl"
        run_license_script(NOISE_DIR / f"{scenario['id']}.py", "benign", log_path)
        return label_license_events(log_path.read_text(encoding="utf-8").splitlines(), test, run_id, SCENARIO_LABEL)
    raw_events, pid = run_game_script(NOISE_DIR / f"{scenario['id']}.ps1", workdir / "raw.xml", workdir)
    return label_game_events(raw_events, test, run_id, NO_PROCESS, pid)


def alerts_by_rule(rules: Dict[str, Rule], run_id: str, events: List[Dict[str, Any]]) -> Dict[str, int]:
    """Each scenario gets a fresh SIEM, so one scenario can't complete another's count."""
    store = SiemStore()
    for rule in rules.values():
        store.load_rule(run_id, rule)
    store.ingest(run_id, events)
    counts = {path: len(store.alerts(run_id, rule.id)) for path, rule in rules.items()}
    return {path: count for path, count in counts.items() if count}


def score_scenario(scenario: Dict[str, Any], rules: Dict[str, Rule], mode: str, run_id: str,
                   raw_out: Optional[Path], workdir: Path) -> Dict[str, Any]:
    scenario_run = f"{run_id}-{scenario['id']}"
    events = modeled_events(scenario, scenario_run) if mode == "simulated" else real_events(scenario, scenario_run, workdir)
    if not events:
        raise PipelineError(f"Scenario {scenario['id']} produced no events")
    if raw_out:
        with raw_out.open("a", encoding="utf-8") as handle:
            handle.writelines(json.dumps({"scenario": scenario["id"], **event}) + "\n" for event in events)

    alerts = alerts_by_rule(rules, scenario_run, events)
    print_evidence(scenario["id"], events)
    return {
        "id": scenario["id"],
        "name": scenario["name"],
        "events": len(events),
        "fires": sorted(alerts),
        "recorded": sorted(scenario["fires"]),
        "as_recorded": sorted(alerts) == sorted(scenario["fires"]),
        "alerts": alerts,
        "why": scenario.get("why", ""),
    }


def rule_scores(results: List[Dict[str, Any]], rules: Dict[str, Rule]) -> List[Dict[str, Any]]:
    scores = [{
        "rule": rule.title,
        "rule_file": path,
        "noisy_scenarios": sum(path in result["alerts"] for result in results),
        "alerts": sum(result["alerts"].get(path, 0) for result in results),
        "scenarios": len(results),
    } for path, rule in rules.items()]
    return sorted(scores, key=lambda score: (-score["noisy_scenarios"], -score["alerts"], score["rule"]))


def render_markdown(results: List[Dict[str, Any]], scores: List[Dict[str, Any]], rules: Dict[str, Rule], mode: str) -> str:
    quiet = sum(not result["fires"] for result in results)
    lines = [
        f"### Noise score: {quiet} of {len(results)} normal scenarios set off no rules ({mode} telemetry)",
        "",
        "| Normal activity | Rules set off | Why |",
        "| --- | --- | --- |",
    ]
    for result in results:
        fired = ", ".join(f"{rules[path].title} ({result['alerts'][path]})" for path in result["fires"]) or "None"
        if not result["as_recorded"]:
            fired = f"**{fired} (recorded: {', '.join(result['recorded']) or 'none'})**"
        lines.append(f"| {result['name']} | {fired} | {result['why']} |")
    lines += ["", "| Rule | Noisy scenarios | Alerts |", "| --- | --- | --- |"]
    lines += [f"| {score['rule']} | {score['noisy_scenarios']} of {score['scenarios']} | {score['alerts']} |" for score in scores]
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", choices=["simulated", "real"], required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--scenarios", type=Path, default=DEFAULT_SCENARIOS)
    parser.add_argument("--only", action="append", help="score only this scenario ID (repeatable)")
    parser.add_argument("--report", type=Path, help="write the JSON score here")
    parser.add_argument("--summary", type=Path, help="write the Markdown score here")
    parser.add_argument("--raw-out", type=Path, help="keep every labeled event here")
    args = parser.parse_args(argv)

    for path in (args.report, args.summary, args.raw_out):
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
    try:
        rules = load_rules()
        scenarios = [s for s in load_scenarios(args.scenarios) if not args.only or s["id"] in args.only]
        with tempfile.TemporaryDirectory() as temp:
            results = [score_scenario(scenario, rules, args.mode, args.run_id, args.raw_out, Path(temp))
                       for scenario in scenarios]
    except (PipelineError, OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    scores = rule_scores(results, rules)
    summary = render_markdown(results, scores, rules, args.mode)
    print(summary)
    if args.report:
        args.report.write_text(json.dumps({"mode": args.mode, "run_id": args.run_id, "results": results, "rules": scores},
                                          indent=2), encoding="utf-8")
    if args.summary:
        args.summary.write_text(summary, encoding="utf-8")
    changed = [result["id"] for result in results if not result["as_recorded"]]
    if changed:
        print(f"RESULT: FAIL - these differ from simulation/noise.yml: {changed}")
        return 1
    print("RESULT: PASS - every result matches simulation/noise.yml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
