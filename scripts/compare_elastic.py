#!/usr/bin/env python3
"""Check this project's rule engine against a real Elasticsearch.

Rules pass or fail on an engine this project wrote, so a pass could mean the engine
and the rule share a misunderstanding. This loads the logs saved by the real runs into
Elasticsearch, converts each Sigma rule with the standard pySigma tools, and compares
whether each rule fires on each set of logs.

KQL rules aren't compared, because Elasticsearch can't run KQL as written here.

Exit codes: 0 = results match the record, 1 = a result changed, 2 = pipeline error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dvp.errors import PipelineError  # noqa: E402
from dvp.rules import Rule, load_rule  # noqa: E402
from dvp.siem import SiemStore  # noqa: E402

DEFAULT_DIFFERENCES = ROOT / "simulation" / "siem-differences.yml"
DEFAULT_VARIANTS = ROOT / "simulation" / "variants.yml"
INDEX = "dvp-logs"
SCENARIOS = ("attack", "benign")
FROM_CLAUSE = "from * metadata _id, _index, _version"
_LIKE_PATTERN = re.compile(r'\blike "((?:[^"\\]|\\.)*)"')
_RLIKE_PATTERN = re.compile(r'\brlike "((?:[^"\\]|\\.)*)"')


@dataclass(frozen=True)
class Dataset:
    """A set of real logs, the rules to compare on it, and the official hash list of its build."""

    name: str
    events: List[Dict[str, Any]]
    rule_files: List[str]
    placeholders: Optional[Path]


def sigma_rule_files() -> List[str]:
    return [path.relative_to(ROOT).as_posix() for path in sorted((ROOT / "detections" / "sigma").rglob("*.yml"))]


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    try:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, json.JSONDecodeError) as exc:
        raise PipelineError(f"cannot read logs from {path}: {exc}") from exc


def rule_fields() -> Set[str]:
    """Every field a rule reads, from the selections and any correlation."""
    fields: Set[str] = set()
    for path in sigma_rule_files():
        for doc in yaml.safe_load_all((ROOT / path).read_text(encoding="utf-8")):
            for name, search in (doc.get("detection") or {}).items():
                if name != "condition":
                    for item in search if isinstance(search, list) else [search]:
                        fields |= {spec.split("|")[0] for spec in item}
            correlation = doc.get("correlation") or {}
            fields |= set(correlation.get("group-by") or [])
            fields |= {correlation["condition"]["field"]} if "field" in (correlation.get("condition") or {}) else set()
    return fields


def index_mappings() -> Dict[str, Any]:
    """Define every field up front, because a query fails if it names one the logs don't have."""
    properties: Dict[str, Any] = {field: {"type": "keyword"} for field in rule_fields()}
    properties["@timestamp"] = {"type": "date"}
    return {
        "dynamic_templates": [{"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}}],
        "properties": properties,
    }


def group_by(events: Iterable[Dict[str, Any]], key: str) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for event in events:
        groups.setdefault(event[key], []).append(event)
    return groups


def rule_file_by_id() -> Dict[str, str]:
    return {load_rule(ROOT / path).id: path for path in sigma_rule_files()}


def rule_test_datasets(artifacts: Path) -> List[Dataset]:
    """One dataset per rule job: the logs from that rule's own attack and benign sides."""
    files = rule_file_by_id()
    datasets = []
    for report_path in sorted(artifacts.glob("real-telemetry-*/report.json")):
        rule_id = json.loads(report_path.read_text(encoding="utf-8"))["rule_id"]
        if rule_id in files:  # Anything else is a KQL rule.
            job = report_path.parent
            datasets.append(Dataset(f"test/{job.name}", read_jsonl(job / "events.jsonl"), [files[rule_id]],
                                    job / "placeholders.yml"))
    return datasets


def scorecard_datasets(artifacts: Path, variants_path: Path) -> List[Dataset]:
    """The evasion variations against their own rule, and normal activity against every rule."""
    folder = artifacts / "evasion-scorecard"
    placeholders = folder / "placeholders.yml"
    rules = {variant["id"]: variant["rule"]
             for variant in yaml.safe_load(variants_path.read_text(encoding="utf-8"))["variants"]}
    datasets = [Dataset(f"evasion/{variant}", events, [rules[variant]], placeholders)
                for variant, events in group_by(read_jsonl(folder / "raw-logs.txt"), "variant").items()]
    datasets += [Dataset(f"noise/{scenario}", events, sigma_rule_files(), placeholders)
                 for scenario, events in group_by(read_jsonl(folder / "noise-raw-logs.txt"), "scenario").items()]
    return datasets


def to_document(event: Dict[str, Any]) -> Dict[str, Any]:
    """Keep the fields as logged, and put the pipeline's labels where a rule can't match them."""
    meta = event["_meta"]
    logged = str(event.get("timestamp") or event.get("UtcTime") or datetime.now(timezone.utc).isoformat())
    parsed = datetime.fromisoformat(logged.replace("Z", "+00:00").replace(" ", "T"))
    moment = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    # The scorecards label each line with its own "variant" or "scenario" key.
    fields = {key: value for key, value in event.items() if key not in ("_meta", "variant", "scenario")}
    return {**fields, "@timestamp": moment.isoformat(), "dvp_scenario": meta["scenario"], "dvp_category": meta["category"]}


class Elastic:
    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")

    def _request(self, method: str, path: str, body: Optional[bytes] = None, content_type: str = "application/json") -> Dict[str, Any]:
        request = urllib.request.Request(f"{self.url}{path}", data=body, method=method,
                                         headers={"Content-Type": content_type})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)

    def load(self, events: List[Dict[str, Any]]) -> None:
        """Start from an empty index, so one dataset can't affect another's results."""
        try:
            self._request("DELETE", f"/{INDEX}?ignore_unavailable=true")
            self._request("PUT", f"/{INDEX}", json.dumps({"mappings": index_mappings()}).encode("utf-8"))
            lines = []
            for event in events:
                lines += ['{"index":{}}', json.dumps(to_document(event))]
            result = self._request("POST", f"/{INDEX}/_bulk?refresh=true", ("\n".join(lines) + "\n").encode("utf-8"),
                                   "application/x-ndjson")
        except (OSError, ValueError) as exc:
            raise PipelineError(f"cannot load logs into Elasticsearch: {exc}") from exc
        if result.get("errors"):
            raise PipelineError(f"Elasticsearch rejected some logs: {json.dumps(result)[:500]}")

    def fires(self, query: str, category: str, scenario: str) -> bool:
        if FROM_CLAUSE not in query:
            raise PipelineError(f"unexpected query shape: {query}")
        scoped = query.replace(FROM_CLAUSE, f'{FROM_CLAUSE.replace("*", INDEX)} '
                                            f'| where dvp_category == "{category}" and dvp_scenario == "{scenario}"')
        try:
            return bool(self._request("POST", "/_query", json.dumps({"query": scoped}).encode("utf-8"))["values"])
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            raise PipelineError(f"Elasticsearch rejected a query ({exc.code}): {detail[:500]}\n{scoped}") from exc
        except OSError as exc:
            raise PipelineError(f"cannot reach Elasticsearch: {exc}") from exc


def convert(rule_file: str, placeholders: Optional[Path]) -> str:
    """Use the standard tools, so nothing from this project's engine reaches the query."""
    from sigma.backends.elasticsearch import ESQLBackend
    from sigma.collection import SigmaCollection
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import ValueListPlaceholderTransformation

    values = yaml.safe_load(placeholders.read_text(encoding="utf-8")) if placeholders else {}
    pipeline = ProcessingPipeline(items=[ProcessingItem(transformation=ValueListPlaceholderTransformation())], vars=values)
    queries = ESQLBackend(processing_pipeline=pipeline).convert(
        SigmaCollection.from_yaml((ROOT / rule_file).read_text(encoding="utf-8")))
    # A correlation rule converts to the one query that counts its base rule's events.
    return fix_rlike_patterns(fix_like_backslashes(queries[-1]))


def fix_like_backslashes(query: str) -> str:
    """Work around pySigma-backend-elasticsearch 1.1.6, whose LIKE patterns Elasticsearch rejects.

    A LIKE pattern has its own escaping on top of the string literal's, so one literal
    backslash has to be written as four. The backend writes two.
    """
    return _LIKE_PATTERN.sub(lambda match: f'like "{match.group(1).replace(chr(92) * 2, chr(92) * 4)}"', query)


def fix_rlike_patterns(query: str) -> str:
    """Work around pySigma-backend-elasticsearch 1.1.6, whose RLIKE patterns can't match as the rule means.

    A Sigma regex matches anywhere in the value, but RLIKE has to match all of it. The
    backend also escapes the backslash in a class like \\\\d, which turns it into a literal.
    """
    def repair(match: "re.Match[str]") -> str:
        return f'rlike ".*{match.group(1).replace(chr(92) * 4, chr(92) * 2)}.*"'
    return _RLIKE_PATTERN.sub(repair, query)


def engine_fires(rule: Rule, events: List[Dict[str, Any]], scenario: str) -> bool:
    store = SiemStore()
    store.load_rule("compare", rule)
    store.ingest("compare", [event for event in events if event["_meta"]["scenario"] == scenario])
    return bool(store.alerts("compare", rule.id))


def compare_dataset(dataset: Dataset, elastic: Any, convert_rule: Any = convert) -> List[Dict[str, Any]]:
    if dataset.placeholders:
        os.environ["DVP_PLACEHOLDERS"] = str(dataset.placeholders)
    if not dataset.events:
        raise PipelineError(f"Dataset {dataset.name} has no logs")
    elastic.load(dataset.events)
    results = []
    for rule_file in dataset.rule_files:
        rule = load_rule(ROOT / rule_file)
        query = convert_rule(rule_file, dataset.placeholders)
        for scenario in {event["_meta"]["scenario"] for event in dataset.events} & set(SCENARIOS):
            engine, siem = engine_fires(rule, dataset.events, scenario), elastic.fires(query, rule.category, scenario)
            results.append({"dataset": dataset.name, "rule": rule.title, "rule_file": rule_file, "scenario": scenario,
                            "engine_fires": engine, "elastic_fires": siem, "agree": engine == siem})
    return results


def result_key(result: Dict[str, Any]) -> str:
    return f"{result['dataset']}|{result['rule_file']}|{result['scenario']}"


def load_recorded(path: Path) -> Dict[str, str]:
    try:
        differences = yaml.safe_load(path.read_text(encoding="utf-8"))["differences"] or []
        return {f"{item['dataset']}|{item['rule_file']}|{item['scenario']}": item["why"] for item in differences}
    except (OSError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise PipelineError(f"cannot load recorded differences from {path}: {exc}") from exc


def check_against_record(results: List[Dict[str, Any]], recorded: Dict[str, str]) -> List[str]:
    """Return what differs from the record. Datasets that didn't run say nothing about their entries."""
    found: Set[str] = {result_key(result) for result in results if not result["agree"]}
    compared = {result_key(result) for result in results}
    problems = [f"new disagreement: {key}" for key in sorted(found - set(recorded))]
    problems += [f"recorded disagreement has gone away: {key}" for key in sorted((set(recorded) - found) & compared)]
    return problems


def render_markdown(results: List[Dict[str, Any]], recorded: Dict[str, str]) -> str:
    agree = sum(result["agree"] for result in results)
    lines = [f"### Elasticsearch comparison: {agree} of {len(results)} results agree with the project's engine", ""]
    disagreements = [result for result in results if not result["agree"]]
    if disagreements:
        lines += ["| Logs | Rule | Side | Engine | Elasticsearch | Why |", "| --- | --- | --- | --- | --- | --- |"]
        for result in disagreements:
            why = recorded.get(result_key(result), "**Not recorded**")
            lines.append(f"| {result['dataset']} | {result['rule']} | {result['scenario']} | "
                         f"{'fires' if result['engine_fires'] else 'quiet'} | "
                         f"{'fires' if result['elastic_fires'] else 'quiet'} | {why} |")
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--artifacts", type=Path, required=True, help="folder holding the real runs' artifacts")
    parser.add_argument("--elastic-url", default="http://127.0.0.1:9200")
    parser.add_argument("--differences", type=Path, default=DEFAULT_DIFFERENCES)
    parser.add_argument("--variants", type=Path, default=DEFAULT_VARIANTS)
    parser.add_argument("--report", type=Path, help="write the JSON comparison here")
    parser.add_argument("--summary", type=Path, help="write the Markdown comparison here")
    args = parser.parse_args(argv)

    try:
        recorded = load_recorded(args.differences)
        datasets = rule_test_datasets(args.artifacts) + scorecard_datasets(args.artifacts, args.variants)
        if not datasets:
            raise PipelineError(f"no logs found in {args.artifacts}")
        elastic = Elastic(args.elastic_url)
        results = [result for dataset in datasets for result in compare_dataset(dataset, elastic)]
    except (PipelineError, OSError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    summary = render_markdown(results, recorded)
    print(summary)
    for path, content in ((args.report, json.dumps({"results": results}, indent=2)), (args.summary, summary)):
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
    problems = check_against_record(results, recorded)
    if problems:
        print("RESULT: FAIL\n  " + "\n  ".join(problems))
        return 1
    print("RESULT: PASS - every result matches simulation/siem-differences.yml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
