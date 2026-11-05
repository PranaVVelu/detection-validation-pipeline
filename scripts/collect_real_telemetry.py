#!/usr/bin/env python3
"""Run a rule's Atomic test on this machine and collect the real Sysmon logs.

This EXECUTES the test, so it belongs only on a disposable Windows machine with
Sysmon installed. It writes the same JSONL format as simulate_atomic.py, so the
later pipeline stages don't change.

Exit codes: 0 = success, 2 = pipeline error (no trustworthy telemetry).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import yaml

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS.parent / "src"))

from dvp.catalog import DEFAULT_CATALOG, AtomicTest, load_atomic_test  # noqa: E402
from dvp.errors import PipelineError  # noqa: E402
from dvp.rules import load_rule  # noqa: E402
from dvp.sysmon import parse_export, select_process_tree, select_test_execution, to_pipeline_event  # noqa: E402

ATOMIC_URL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/{commit}/atomics/{technique}/{technique}.yaml"
BENIGN_TIMEOUT_SECONDS = 15
SYSMON_WAIT_SECONDS = 45
SYSMON_SETTLE_SECONDS = 5
POWERSHELL = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]


def verify_upstream(definition: str, test: AtomicTest) -> None:
    """Refuse to run if the pinned Atomic definition differs from the catalog."""
    for atomic in yaml.safe_load(definition).get("atomic_tests", []):
        if atomic.get("auto_generated_guid") == test.guid:
            command = atomic["executor"]["command"].strip()
            if command != test.upstream_command.strip():
                raise PipelineError(f"Atomic test {test.guid} has changed upstream: {command!r}")
            return
    raise PipelineError(f"Atomic test {test.guid} is not in the {test.technique} definition")


def fetch_atomic(test: AtomicTest, atomics_dir: Path) -> None:
    """Download only the definition this test needs, at the commit the catalog pins."""
    url = ATOMIC_URL.format(commit=test.upstream_commit, technique=test.technique)
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            definition = response.read().decode("utf-8")
    except OSError as exc:
        raise PipelineError(f"cannot download {url}: {exc}") from exc
    verify_upstream(definition, test)

    target = atomics_dir / test.technique / f"{test.technique}.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(definition, encoding="utf-8")


def run_benign_commands(test: AtomicTest, workdir: Path) -> List[int]:
    """Run the catalog's baseline for real, returning each root process ID."""
    pids = []
    for template in test.benign_events:
        process = subprocess.Popen(template["CommandLine"], cwd=workdir, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pids.append(process.pid)
        try:
            # A nonzero exit is fine: the telemetry is the process starting. GUI
            # programs such as notepad never exit on their own, so they get killed.
            process.wait(timeout=BENIGN_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    return pids


def run_atomic(test: AtomicTest, atomics_dir: Path, workdir: Path) -> int:
    """Run the test through Invoke-AtomicTest, returning the root process ID."""
    command = [*POWERSHELL, str(SCRIPTS / "run_atomic.ps1"), "-Technique", test.technique,
               "-TestGuid", test.guid, "-AtomicsPath", str(atomics_dir)]
    result = subprocess.Popen(command, cwd=workdir, stdin=subprocess.DEVNULL)
    if result.wait(timeout=180) != 0:
        raise PipelineError(f"Invoke-AtomicTest failed for {test.guid} with exit code {result.returncode}")
    return result.pid


def export_sysmon(since: datetime, raw_path: Path) -> List[Dict[str, Any]]:
    command = [*POWERSHELL, str(SCRIPTS / "export_sysmon.ps1"), "-Since", since.isoformat(), "-OutFile", str(raw_path)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode != 0:
        raise PipelineError(f"Sysmon export failed: {result.stderr.strip()}")
    return parse_export(raw_path.read_text(encoding="utf-8").splitlines())


def label_events(raw_events: List[Dict[str, Any]], test: AtomicTest, run_id: str,
                 atomic_pid: int, benign_pids: List[int]) -> List[Dict[str, Any]]:
    """Label the test's own processes as attack, and each baseline process tree as benign."""
    labeled = [to_pipeline_event(event, test, run_id, "attack")
               for event in select_test_execution(raw_events, atomic_pid, test.command_marker)]
    for pid in benign_pids:
        labeled += [to_pipeline_event(event, test, run_id, "benign")
                    for event in select_process_tree(raw_events, pid, include_root=True)]
    return labeled


def describe_processes(raw_events: List[Dict[str, Any]]) -> str:
    """List everything Sysmon recorded, so a missing command can be diagnosed from the job log."""
    lines = [f"Sysmon recorded {len(raw_events)} process(es):"]
    lines += [f"  pid={event.get('ProcessId')} parent={event.get('ParentProcessId')} "
              f"{event.get('Image')}: {event.get('CommandLine')}" for event in raw_events]
    return "\n".join(lines)


def wait_for_events(since: datetime, raw_path: Path, test: AtomicTest, run_id: str,
                    atomic_pid: int, benign_pids: List[int]) -> List[Dict[str, Any]]:
    """Poll until every tree has logged, because Sysmon writes asynchronously."""
    deadline = time.monotonic() + SYSMON_WAIT_SECONDS
    while True:
        raw_events = export_sysmon(since, raw_path)
        seen = {str(event.get("ProcessId")) for event in raw_events}
        labeled = label_events(raw_events, test, run_id, atomic_pid, benign_pids)
        attack = [event for event in labeled if event["_meta"]["scenario"] == "attack"]
        if attack and all(str(pid) in seen for pid in benign_pids):
            # The test's process has logged, so give its children time to log too.
            time.sleep(SYSMON_SETTLE_SECONDS)
            return label_events(export_sysmon(since, raw_path), test, run_id, atomic_pid, benign_pids)
        if time.monotonic() >= deadline:
            print(describe_processes(raw_events), file=sys.stderr)
            raise PipelineError(
                f"Sysmon logged {len(attack)} event(s) for command {test.command_marker!r}, "
                f"and these benign processes are missing: "
                f"{[pid for pid in benign_pids if str(pid) not in seen]}"
            )
        time.sleep(3)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rule", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out", type=Path, required=True, help="output JSONL path")
    parser.add_argument("--raw-out", type=Path, required=True, help="where to keep the raw Sysmon XML")
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    args = parser.parse_args()

    try:
        test = load_atomic_test(load_rule(args.rule).atomic_test, args.catalog)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.raw_out.parent.mkdir(parents=True, exist_ok=True)
        since = datetime.now(timezone.utc) - timedelta(seconds=2)

        with tempfile.TemporaryDirectory() as temp:
            workdir = Path(temp)
            fetch_atomic(test, workdir / "atomics")
            benign_pids = run_benign_commands(test, workdir)
            atomic_pid = run_atomic(test, workdir / "atomics", workdir)
            events = wait_for_events(since, args.raw_out.resolve(), test, args.run_id, atomic_pid, benign_pids)
    except (PipelineError, OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    with args.out.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")

    print(f"Collected {len(events)} real event(s) for {test.technique} '{test.name}':")
    for event in events:
        print(f"  [{event['_meta']['scenario']}] {event.get('Image')}: {event.get('CommandLine')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
