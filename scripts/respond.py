#!/usr/bin/env python3
"""Turn alerts into draft incidents, and carry out a suggested action once a person approves it.

    respond.py draft    --rule R --alerts-file A --run-id ID --out reports/incidents.json
    respond.py approve  --incidents reports/incidents.json --id INCIDENT --approver NAME --license-url URL

A draft gathers context, the playbook's checklist, and a suggested action. Nothing
runs at that point: every action waits for a person. Approving runs the action, which
is only possible for actions this project can automate, and records who approved it.
The admin token for the license server comes from LICENSE_ADMIN_TOKEN, never the command line.

Exit codes: 0 = done, 1 = the action failed or can't be automated, 2 = pipeline error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dvp.errors import PipelineError  # noqa: E402
from dvp.rules import load_rule  # noqa: E402

PLAYBOOKS = ROOT / "response" / "playbooks.yml"
VARIANTS = ROOT / "simulation" / "variants.yml"
NOISE = ROOT / "simulation" / "noise.yml"
CONTEXT_FIELDS = ("Image", "CommandLine", "ParentImage", "ImageLoaded", "SourceImage", "TargetImage", "GrantedAccess",
                  "OriginalFileName", "Hashes", "license_key_hash", "machine_id", "client_ip", "reason", "timestamp", "UtcTime")
MAX_INCIDENTS = 3
AUTOMATED = {"disable_license_key"}


def load_yaml(path: Path) -> Dict[str, Any]:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise PipelineError(f"cannot read {path}: {exc}") from exc


def known_limits(rule_file: str) -> Dict[str, List[str]]:
    """What the scorecards record about this rule, so a responder knows where it's weak."""
    misses = [f"{item['name']}: {item['why']}" for item in load_yaml(VARIANTS).get("variants", [])
              if item["rule"] == rule_file and item["expected"] == "missed"]
    noise = [f"{item['name']}: {item['why']}" for item in load_yaml(NOISE).get("scenarios", [])
             if rule_file in item["fires"]]
    return {"known_misses": misses, "known_noise": noise}


def draft_incident(alert: Dict[str, Any], rule_file: str, playbook: Dict[str, Any], number: int) -> Dict[str, Any]:
    event = alert.get("matched_event", {})
    context = {field: event[field] for field in CONTEXT_FIELDS if event.get(field)}
    correlation = alert.get("correlation")
    action = dict(playbook["action"])
    if action.get("target"):
        target = (correlation or {}).get("group", {}).get(action["target"]) or event.get(action["target"])
        if not target:
            raise PipelineError(f"alert has no {action['target']!r} for the suggested action")
        action["target_value"] = target
    action["status"] = "awaiting approval" if action["type"] in AUTOMATED else "manual step for a person"
    summary = f"{alert['rule_title']} fired"
    if correlation:
        summary += f": a count of {correlation['count']} for {', '.join(f'{k} {v}' for k, v in correlation['group'].items())}"
    return {
        "id": f"{alert.get('run_id', 'run')}-{number}",
        "created": datetime.now(timezone.utc).isoformat(),
        "rule": alert["rule_title"],
        "rule_file": rule_file,
        "severity": playbook["severity"],
        "techniques": alert.get("techniques", []),
        "summary": summary,
        "context": context,
        **known_limits(rule_file),
        "checklist": playbook["checklist"],
        "action": action,
        "approval": None,
    }


def draft(args: argparse.Namespace) -> int:
    rule_file = args.rule.resolve().relative_to(ROOT).as_posix()
    playbook = load_yaml(PLAYBOOKS).get("playbooks", {}).get(rule_file)
    if not playbook:
        raise PipelineError(f"{rule_file} has no playbook in {PLAYBOOKS.relative_to(ROOT)}")
    rule = load_rule(args.rule)
    try:
        alerts = json.loads(args.alerts_file.read_text(encoding="utf-8"))["alerts"]
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        raise PipelineError(f"cannot read alerts from {args.alerts_file}: {exc}") from exc
    attack = [alert for alert in alerts if alert.get("run_id") == args.run_id and alert.get("rule_id") == rule.id
              and alert.get("scenario") == "attack"]
    incidents = [draft_incident(alert, rule_file, playbook, number) for number, alert in enumerate(attack[:MAX_INCIDENTS], 1)]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"incidents": incidents}, indent=2), encoding="utf-8")
    print(f"Drafted {len(incidents)} incident(s) from {len(attack)} attack alert(s) for {rule.title}")
    for incident in incidents:
        print(f"  {incident['id']} [{incident['severity']}] {incident['summary']} -> {incident['action']['summary']} "
              f"({incident['action']['status']})")
    return 0


def disable_license_key(url: str, license_key_hash: str) -> None:
    token = os.environ.get("LICENSE_ADMIN_TOKEN", "")
    if not token:
        raise PipelineError("LICENSE_ADMIN_TOKEN isn't set, so the license server can't be told to disable the key")
    if urllib.parse.urlparse(url).hostname != "127.0.0.1":
        raise PipelineError("the license server URL must point at 127.0.0.1")
    request = urllib.request.Request(
        f"{url.rstrip('/')}/admin/disable", data=json.dumps({"license_key_hash": license_key_hash}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10):
            pass
    except urllib.error.HTTPError as exc:
        raise PipelineError(f"the license server refused: HTTP {exc.code}") from exc
    except OSError as exc:
        raise PipelineError(f"cannot reach the license server: {exc}") from exc


def approve(args: argparse.Namespace) -> int:
    try:
        document = json.loads(args.incidents.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PipelineError(f"cannot read incidents from {args.incidents}: {exc}") from exc
    incident = next((item for item in document["incidents"] if item["id"] == args.id), None)
    if incident is None:
        raise PipelineError(f"no incident {args.id!r} in {args.incidents}")
    action = incident["action"]
    if action["type"] not in AUTOMATED:
        print(f"Not automated: {action['summary']} This is a step for a person to take.", file=sys.stderr)
        return 1
    if incident["approval"]:
        print(f"Already approved by {incident['approval']['approver']}.", file=sys.stderr)
        return 1
    if not args.license_url:
        raise PipelineError("--license-url is required for this action")
    disable_license_key(args.license_url, action["target_value"])
    action["status"] = "done"
    incident["approval"] = {"approver": args.approver, "approved": datetime.now(timezone.utc).isoformat()}
    args.incidents.write_text(json.dumps(document, indent=2), encoding="utf-8")
    print(f"{args.approver} approved {incident['id']}: {action['summary']} ({action['target_value']})")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    drafting = commands.add_parser("draft", help="turn alerts into draft incidents")
    drafting.add_argument("--rule", type=Path, required=True)
    drafting.add_argument("--alerts-file", type=Path, required=True)
    drafting.add_argument("--run-id", required=True)
    drafting.add_argument("--out", type=Path, required=True)
    approving = commands.add_parser("approve", help="carry out an incident's suggested action")
    approving.add_argument("--incidents", type=Path, required=True)
    approving.add_argument("--id", required=True)
    approving.add_argument("--approver", required=True, help="the person approving the action")
    approving.add_argument("--license-url", help="the local license server, for license actions")
    args = parser.parse_args(argv)
    try:
        return draft(args) if args.command == "draft" else approve(args)
    except PipelineError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
