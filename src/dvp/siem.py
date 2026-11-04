"""In-memory detection engine behind the mock SIEM.

Kept free of HTTP so the same logic serves the API server and offline runs.
Rules and events are scoped by ``run_id``, so one run can never be satisfied by
alerts left over from another.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional

from dvp.rules import Rule


class SiemStore:
    def __init__(self, alert_delay_seconds: float = 0.0) -> None:
        # The delay models ingestion lag, which forces the validator to poll.
        self._alert_delay = alert_delay_seconds
        self._lock = threading.Lock()
        self._rules: Dict[str, Dict[str, Rule]] = defaultdict(dict)
        self._event_counts: Dict[str, Counter] = defaultdict(Counter)
        self._alerts: List[Dict[str, Any]] = []

    def load_rule(self, run_id: str, rule: Rule) -> None:
        with self._lock:
            self._rules[run_id][rule.id] = rule

    def ingest(self, run_id: str, events: Iterable[Mapping[str, Any]]) -> int:
        """Evaluate each event against the run's rules, returning how many were ingested."""
        ingested = 0
        with self._lock:
            rules = list(self._rules[run_id].values())
            for event in events:
                meta = event.get("_meta", {})
                self._event_counts[run_id][meta.get("scenario", "unknown")] += 1
                ingested += 1
                for rule in rules:
                    if rule.matches(event):
                        self._alerts.append(self._build_alert(run_id, rule, event))
        return ingested

    def _build_alert(self, run_id: str, rule: Rule, event: Mapping[str, Any]) -> Dict[str, Any]:
        meta = event["_meta"]
        return {
            "alert_id": str(uuid.uuid4()),
            "rule_id": rule.id,
            "rule_title": rule.title,
            "techniques": rule.techniques,
            "run_id": run_id,
            "scenario": meta.get("scenario"),
            "atomic_test": meta.get("atomic_test"),
            "event_id": meta.get("event_id"),
            "fired_at": datetime.now(timezone.utc).isoformat(),
            "matched_event": dict(event),
            "_visible_at": time.monotonic() + self._alert_delay,
        }

    def alerts(self, run_id: str, rule_id: Optional[str] = None) -> List[Dict[str, Any]]:
        now = time.monotonic()
        with self._lock:
            return [
                {key: value for key, value in alert.items() if key != "_visible_at"}
                for alert in self._alerts
                if alert["run_id"] == run_id
                and (rule_id is None or alert["rule_id"] == rule_id)
                and alert["_visible_at"] <= now
            ]

    def stats(self, run_id: str) -> Dict[str, Any]:
        with self._lock:
            return {
                "run_id": run_id,
                "events": dict(self._event_counts.get(run_id, {})),
                "rules": sorted(self._rules.get(run_id, {})),
            }

    def export(self, run_id: str) -> Dict[str, Any]:
        """Snapshot a run as the JSON document that validate_alert.py reads offline."""
        return {"stats": self.stats(run_id), "alerts": self.alerts(run_id)}
