#!/usr/bin/env python3
"""Score the rules against harmless variations of each attack.

A rule missing a known blind spot isn't a failure here. The run fails when a result
differs from the one recorded in simulation/variants.yml, in either direction, so a
rule that stops catching something can't go unnoticed.

--mode simulated evaluates the modeled events. --mode real EXECUTES the variation
scripts, so it belongs only on a disposable Windows machine with Sysmon installed.

Exit codes: 0 = every result as recorded, 1 = a result changed, 2 = pipeline error.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(ROOT / "src"))

from collect_real_telemetry import (  # noqa: E402
    GAME_DIR,
    POWERSHELL,
    SYSMON_SETTLE_SECONDS,
    SYSMON_WAIT_SECONDS,
    describe_processes,
    export_sysmon,
    label_game_events,
    label_license_events,
    run_license_script,
)
from dvp.catalog import DEFAULT_CATALOG, ValidationTest, expand_events, load_test  # noqa: E402
from dvp.errors import PipelineError  # noqa: E402
from dvp.rules import Rule, load_rule  # noqa: E402
from dvp.siem import SiemStore  # noqa: E402
from dvp.sysmon import select_scenario_events  # noqa: E402

DEFAULT_VARIANTS = ROOT / "simulation" / "variants.yml"
VARIANTS_DIR = GAME_DIR / "variants"
OUTCOMES = {"caught", "missed"}
EVIDENCE_FIELDS = ("Image", "CommandLine", "OriginalFileName", "SourceImage", "GrantedAccess")
NO_PROCESS = -1  # A variation only has an attack side.


def load_variants(path: Path) -> List[Dict[str, Any]]:
    try:
        variants = yaml.safe_load(path.read_text(encoding="utf-8"))["variants"]
    except (OSError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise PipelineError(f"cannot load variants from {path}: {exc}") from exc
    for variant in variants:
        if variant.get("expected") not in OUTCOMES:
            raise PipelineError(f"variant {variant.get('id')!r} needs expected: caught or missed")
    return variants


def modeled_events(variant: Dict[str, Any], rule: Rule, test: ValidationTest, run_id: str) -> List[Dict[str, Any]]:
    """Give each modeled event the envelope that a logged event would have."""
    now = datetime.now(timezone.utc).isoformat()
    meta = {"run_id": run_id, "scenario": "attack", "category": rule.category,
            "test_id": test.guid, "technique": test.technique}
    return [{"timestamp": now, **event, "_meta": {**meta, "event_id": str(uuid.uuid4())}}
            for event in expand_events(variant["events"])]


def run_game_variant(variant: Dict[str, Any], test: ValidationTest, run_id: str,
                     raw_path: Path, workdir: Path) -> List[Dict[str, Any]]:
    since = datetime.now(timezone.utc) - timedelta(seconds=2)
    command = [*POWERSHELL, str(VARIANTS_DIR / f"{variant['id']}.ps1"), "-GameDir", str(GAME_DIR / "bin")]
    process = subprocess.Popen(command, cwd=workdir, stdin=subprocess.DEVNULL)
    if process.wait(timeout=180) != 0:
        raise PipelineError(f"Variant {variant['id']} failed with exit code {process.returncode}")

    # A variation that logged nothing proves nothing, so it mustn't read as "missed".
    deadline = time.monotonic() + SYSMON_WAIT_SECONDS
    while True:
        raw_events = export_sysmon(since, raw_path)
        if select_scenario_events(raw_events, process.pid):
            time.sleep(SYSMON_SETTLE_SECONDS)
            return label_game_events(export_sysmon(since, raw_path), test, run_id, process.pid, NO_PROCESS)
        if time.monotonic() >= deadline:
            print(describe_processes(raw_events), file=sys.stderr)
            raise PipelineError(f"Sysmon logged nothing for variant {variant['id']}")
        time.sleep(3)


def run_license_variant(variant: Dict[str, Any], test: ValidationTest, run_id: str, workdir: Path) -> List[Dict[str, Any]]:
    log_path = workdir / f"{variant['id']}.jsonl"
    run_license_script(VARIANTS_DIR / f"{variant['id']}.py", "attack", log_path)
    return label_license_events(log_path.read_text(encoding="utf-8").splitlines(), test, run_id, "attack")


def score(rule: Rule, run_id: str, events: List[Dict[str, Any]]) -> int:
    """Each variant gets a fresh SIEM, so one variation can't complete another's count."""
    store = SiemStore()
    store.load_rule(run_id, rule)
    store.ingest(run_id, events)
    return len(store.alerts(run_id, rule.id))


def print_evidence(variant_id: str, events: List[Dict[str, Any]]) -> None:
    """Show the logged values that decide a result, so a miss can be understood from the job log."""
    for event in events:
        fields = {name: event[name] for name in EVIDENCE_FIELDS if event.get(name)}
        if fields and event["_meta"]["category"] != "image_load":
            print(f"  [{variant_id}] {event['_meta']['category']} {fields}")


def score_variant(variant: Dict[str, Any], mode: str, run_id: str, catalog: Path,
                  raw_out: Optional[Path], workdir: Path) -> Dict[str, Any]:
    rule = load_rule(ROOT / variant["rule"])
    test = load_test(rule.test_id, catalog)
    if mode == "simulated":
        events = modeled_events(variant, rule, test, run_id)
    elif test.kind == "license":
        events = run_license_variant(variant, test, run_id, workdir)
    else:
        events = run_game_variant(variant, test, run_id, workdir / "raw.xml", workdir)
    if not events:
        raise PipelineError(f"Variant {variant['id']} produced no events")
    if raw_out:
        with raw_out.open("a", encoding="utf-8") as handle:
            handle.writelines(json.dumps({"variant": variant["id"], **event}) + "\n" for event in events)

    alerts = score(rule, run_id, events)
    actual = "caught" if alerts else "missed"
    print_evidence(variant["id"], events)
    return {
        "id": variant["id"],
        "name": variant["name"],
        "rule": rule.title,
        "rule_file": variant["rule"],
        "expected": variant["expected"],
        "actual": actual,
        "as_recorded": actual == variant["expected"],
        "why": variant.get("why", ""),
        "events": len(events),
        "events_rule_reads": sum(event["_meta"]["category"] == rule.category for event in events),
        "alerts": alerts,
    }


def render_markdown(results: List[Dict[str, Any]], mode: str) -> str:
    caught = sum(result["actual"] == "caught" for result in results)
    lines = [
        f"### Evasion scorecard: {caught} of {len(results)} variations caught ({mode} telemetry)",
        "",
        "| Variation | Rule | Result | Alerts | Why |",
        "| --- | --- | --- | --- | --- |",
    ]
    for result in results:
        outcome = result["actual"] if result["as_recorded"] else f"**{result['actual']} (recorded: {result['expected']})**"
        lines.append(f"| {result['name']} | {result['rule']} | {outcome} | {result['alerts']} | {result['why']} |")
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", choices=["simulated", "real"], required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--variants", type=Path, default=DEFAULT_VARIANTS)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--only", action="append", help="score only this variant ID (repeatable)")
    parser.add_argument("--report", type=Path, help="write the JSON scorecard here")
    parser.add_argument("--summary", type=Path, help="write the Markdown scorecard here")
    parser.add_argument("--raw-out", type=Path, help="keep every labeled event here")
    args = parser.parse_args(argv)

    for path in (args.report, args.summary, args.raw_out):
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
    try:
        variants = [v for v in load_variants(args.variants) if not args.only or v["id"] in args.only]
        with tempfile.TemporaryDirectory() as temp:
            results = [score_variant(variant, args.mode, args.run_id, args.catalog, args.raw_out, Path(temp))
                       for variant in variants]
    except (PipelineError, OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    summary = render_markdown(results, args.mode)
    print(summary)
    if args.report:
        args.report.write_text(json.dumps({"mode": args.mode, "run_id": args.run_id, "results": results}, indent=2), encoding="utf-8")
    if args.summary:
        args.summary.write_text(summary, encoding="utf-8")
    changed = [result["id"] for result in results if not result["as_recorded"]]
    if changed:
        print(f"RESULT: FAIL - these differ from simulation/variants.yml: {changed}")
        return 1
    print("RESULT: PASS - every result matches simulation/variants.yml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
