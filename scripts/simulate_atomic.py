#!/usr/bin/env python3
"""Emit the telemetry an Atomic Red Team test would produce, without running it.

Nothing is executed: this writes synthetic Sysmon-style process creation events
to a JSONL file, along with benign baseline events that the rule must not match.
It therefore needs no network access and runs in a container with none.

Exit codes: 0 = success, 2 = pipeline error.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dvp.catalog import DEFAULT_CATALOG, AtomicTest, load_atomic_test  # noqa: E402
from dvp.errors import PipelineError  # noqa: E402
from dvp.rules import load_rule  # noqa: E402


def _render(template: Dict[str, Any], test: AtomicTest, run_id: str, scenario: str) -> Dict[str, Any]:
    """Combine a catalog event with the envelope fields a real sensor would add."""
    return {
        "EventID": 1,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "WIN-SIMULATED-01",
        "User": "SIMLAB\\atomic",
        "UtcTime": datetime.now(timezone.utc).isoformat(),
        "ProcessGuid": f"{{{uuid.uuid4()}}}",
        **template,
        # Pipeline bookkeeping lives under _meta, where rule logic can't match it.
        "_meta": {
            "event_id": str(uuid.uuid4()),
            "run_id": run_id,
            "scenario": scenario,
            "category": "process_creation",
            "atomic_test": test.guid,
            "technique": test.technique,
        },
    }


def build_events(test: AtomicTest, run_id: str) -> List[Dict[str, Any]]:
    attack = [_render(event, test, run_id, "attack") for event in test.attack_events]
    benign = [_render(event, test, run_id, "benign") for event in test.benign_events]
    return attack + benign


def write_jsonl(events: Iterable[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rule", type=Path, required=True, help="rule whose mapped test to simulate")
    parser.add_argument("--run-id", required=True, help="unique ID for this validation run")
    parser.add_argument("--out", type=Path, required=True, help="output JSONL path")
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    args = parser.parse_args()

    try:
        rule = load_rule(args.rule)
        test = load_atomic_test(rule.atomic_test, args.catalog)
    except PipelineError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    events = build_events(test, args.run_id)
    write_jsonl(events, args.out)
    print(f"Simulated {test.technique} '{test.name}' ({test.guid}): "
          f"{len(test.attack_events)} attack + {len(test.benign_events)} benign events -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
