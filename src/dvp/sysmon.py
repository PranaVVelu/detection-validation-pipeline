"""Turn raw Sysmon event XML into labeled pipeline events.

Real machines are noisy, so a time window alone can't say which events came from
a test. Labeling follows the process tree instead: an event only counts if it
descends from a process the pipeline started itself. Everything else is ambient
and is left out of the verdict.
"""

from __future__ import annotations

import uuid
import xml.etree.ElementTree as ElementTree
from typing import Any, Dict, Iterable, List, Set

from dvp.catalog import AtomicTest
from dvp.errors import PipelineError

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
PROCESS_CREATE_EVENT_ID = 1


def parse_event_xml(xml_text: str) -> Dict[str, Any]:
    """Flatten one exported event into its System and EventData fields."""
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise PipelineError(f"invalid Sysmon XML: {exc}") from exc

    event_id = root.findtext("e:System/e:EventID", namespaces=_NS)
    if event_id is None:
        raise PipelineError("Sysmon event has no EventID")
    event: Dict[str, Any] = {
        "EventID": int(event_id),
        "Channel": root.findtext("e:System/e:Channel", namespaces=_NS),
        "Computer": root.findtext("e:System/e:Computer", namespaces=_NS),
    }
    for data in root.findall("e:EventData/e:Data", namespaces=_NS):
        event[data.get("Name", "")] = data.text or ""
    return event


def parse_export(lines: Iterable[str]) -> List[Dict[str, Any]]:
    """Parse export_sysmon.ps1 output, keeping only process creation events."""
    events = [parse_event_xml(line) for line in lines if line.strip()]
    return [event for event in events if event["EventID"] == PROCESS_CREATE_EVENT_ID]


def _walk_tree(events: List[Dict[str, Any]], root: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return an event and its descendants, linked by ProcessGuid.

    Windows reuses process IDs, but each process has a unique ProcessGuid.
    """
    tree: Set[str] = {root["ProcessGuid"]}
    selected = [root]
    for event in events:
        if event.get("ParentProcessGuid") in tree and event.get("ProcessGuid") not in tree:
            tree.add(event["ProcessGuid"])
            selected.append(event)
    return selected


def select_process_tree(events: List[Dict[str, Any]], root_pid: int, include_root: bool) -> List[Dict[str, Any]]:
    """Return the events for a process and its descendants, using the latest process with that ID."""
    roots = [event for event in events if str(event.get("ProcessId")) == str(root_pid)]
    if not roots:
        return []
    selected = _walk_tree(events, roots[-1])
    return selected if include_root else selected[1:]


def select_test_execution(events: List[Dict[str, Any]], root_pid: int, marker: str) -> List[Dict[str, Any]]:
    """Return only the process running the test's command, and its descendants.

    Invoke-AtomicTest also starts helpers such as whoami.exe for its own logging.
    Those aren't attack behavior, and they log first, so seeing them doesn't mean
    the test's own events have been written yet.
    """
    wrapper_tree = select_process_tree(events, root_pid, include_root=False)
    for event in wrapper_tree:
        if marker in event.get("CommandLine", ""):
            return _walk_tree(events, event)
    return []


def to_pipeline_event(raw: Dict[str, Any], test: AtomicTest, run_id: str, scenario: str) -> Dict[str, Any]:
    """Add the same _meta envelope that simulate_atomic.py uses."""
    return {
        **raw,
        "_meta": {
            "event_id": str(uuid.uuid4()),
            "run_id": run_id,
            "scenario": scenario,
            "category": "process_creation",
            "atomic_test": test.guid,
            "technique": test.technique,
            "source": "sysmon",
        },
    }
