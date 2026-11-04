#!/usr/bin/env python3
"""Play the log forwarder: load a rule and deliver a run's events to the SIEM.

With --siem-url the events go to the mock SIEM API. With --alerts-out they are
evaluated in-process and the results written to a JSON file, so the pipeline can
also run with no server at all.

Exit codes: 0 = success, 2 = pipeline error (including a rule the SIEM rejects).
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dvp.errors import PipelineError  # noqa: E402
from dvp.rules import parse_rule  # noqa: E402
from dvp.siem import SiemStore  # noqa: E402


def read_events(path: Path) -> List[Dict[str, Any]]:
    try:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, json.JSONDecodeError) as exc:
        raise PipelineError(f"cannot read events {path}: {exc}") from exc


def _post(url: str, payload: Dict[str, Any]) -> None:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30):
            pass
    except urllib.error.HTTPError as exc:
        raise PipelineError(f"SIEM rejected {url}: HTTP {exc.code} {exc.read().decode('utf-8', 'replace')}") from exc
    except OSError as exc:
        raise PipelineError(f"cannot reach SIEM at {url}: {exc}") from exc


def ship_to_api(base_url: str, run_id: str, filename: str, text: str, events: List[Dict[str, Any]]) -> None:
    run_url = f"{base_url.rstrip('/')}/api/v1/runs/{run_id}"
    # The rule must load first: the SIEM only evaluates events on arrival.
    _post(f"{run_url}/rules", {"filename": filename, "content": text})
    _post(f"{run_url}/events", {"events": events})


def ship_offline(out: Path, run_id: str, filename: str, text: str, events: List[Dict[str, Any]]) -> None:
    store = SiemStore()
    store.load_rule(run_id, parse_rule(filename, text))
    store.ingest(run_id, events)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(store.export(run_id), indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rule", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--siem-url", help="base URL of the mock SIEM API")
    target.add_argument("--alerts-out", type=Path, help="write results here, with no server")
    args = parser.parse_args()

    try:
        text = args.rule.read_text(encoding="utf-8")
        events = read_events(args.events)
        if args.siem_url:
            ship_to_api(args.siem_url, args.run_id, args.rule.name, text, events)
        else:
            ship_offline(args.alerts_out, args.run_id, args.rule.name, text, events)
    except (PipelineError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(f"Shipped {len(events)} event(s) for run {args.run_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
