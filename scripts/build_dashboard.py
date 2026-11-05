#!/usr/bin/env python3
"""Build the public dashboard from the results of one real run.

Every score on the page comes from that run's saved results, so the numbers can't
drift from what happened. A missing result shows as missing and a failed check shows
as failed. The page has no scripts and loads nothing from other sites.

Exit codes: 0 = page written, 2 = no usable results, so nothing is published.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dvp.errors import PipelineError  # noqa: E402
from dvp.rules import RULE_SUFFIXES, load_rule  # noqa: E402

REPO_URL = "https://github.com/PranaVVelu/detection-validation-pipeline"
DASHBOARD_DIR = ROOT / "dashboard"
SOURCE_LABELS = {
    "process_creation": "Sysmon process creation",
    "image_load": "Sysmon DLL load",
    "process_access": "Sysmon process access",
    "license_activation": "License server log",
}


@dataclass(frozen=True)
class RunInfo:
    url: str
    commit: str
    finished: str


def read_json(path: Path) -> Optional[Dict[str, Any]]:
    """A missing or unreadable file means no result, and the page says so."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def rule_catalog() -> List[Dict[str, Any]]:
    rules = []
    for path in sorted((ROOT / "detections").rglob("*")):
        if path.suffix.lower() in RULE_SUFFIXES:
            rule = load_rule(path)
            threat = ""
            if rule.kind == "sigma":
                threat = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))[-1].get("x_game_threat", "")
            rules.append({"id": rule.id, "title": rule.title, "file": path.relative_to(ROOT).as_posix(), "kind": rule.kind,
                          "techniques": rule.techniques, "category": rule.category, "threat": threat})
    return rules


def collect(artifacts: Path) -> Dict[str, Any]:
    """Reduce the run's artifacts to the facts the page shows, which are also published as results.json."""
    reports = {}
    for path in sorted(artifacts.glob("real-telemetry-*/report.json")):
        report = read_json(path)
        if report:
            reports[report["rule_id"]] = report
    evasion = read_json(artifacts / "evasion-scorecard" / "scorecard.json")
    noise = read_json(artifacts / "evasion-scorecard" / "noise.json")
    elastic = read_json(artifacts / "elastic-comparison" / "elastic.json")
    if not reports and not evasion and not noise and not elastic:
        raise PipelineError(f"no results found in {artifacts}")

    rules = []
    for rule in rule_catalog():
        report = reports.get(rule["id"])
        variations = [item for item in (evasion or {}).get("results", []) if item["rule_file"] == rule["file"]]
        noise_score = next((item for item in (noise or {}).get("rules", []) if item["rule_file"] == rule["file"]), None)
        compared = [item for item in (elastic or {}).get("results", []) if item["rule_file"] == rule["file"]]
        rules.append({
            **rule,
            "verdict": report["verdict"] if report else None,
            "checks": [{"name": check["name"], "passed": check["passed"]} for check in report["checks"]] if report else [],
            "evasion_caught": sum(item["actual"] == "caught" for item in variations),
            "evasion_total": len(variations),
            "noisy_scenarios": noise_score["noisy_scenarios"] if noise_score else None,
            "scenarios": noise_score["scenarios"] if noise_score else None,
            "elastic_agree": sum(item["agree"] for item in compared),
            "elastic_total": len(compared),
        })
    return {
        "mode": (evasion or noise or {}).get("mode", "real"),
        "rules": rules,
        "evasion": (evasion or {}).get("results"),
        "noise": (noise or {}).get("results"),
        "elastic": (elastic or {}).get("results"),
    }


def summarize(data: Dict[str, Any]) -> Dict[str, Any]:
    rules, evasion, noise, elastic = data["rules"], data["evasion"], data["noise"], data["elastic"]
    return {
        "rules_passed": sum(rule["verdict"] == "PASS" for rule in rules),
        "rules_total": len(rules),
        "evasion_caught": sum(item["actual"] == "caught" for item in evasion) if evasion is not None else None,
        "evasion_total": len(evasion) if evasion is not None else None,
        "noise_quiet": sum(not item["fires"] for item in noise) if noise is not None else None,
        "noise_total": len(noise) if noise is not None else None,
        "elastic_agree": sum(item["agree"] for item in elastic) if elastic is not None else None,
        "elastic_total": len(elastic) if elastic is not None else None,
        "healthy": (
            all(rule["verdict"] == "PASS" for rule in rules)
            and evasion is not None and all(item["as_recorded"] for item in evasion)
            and noise is not None and all(item["as_recorded"] for item in noise)
            and elastic is not None
        ),
    }


def status(kind: str, label: str) -> str:
    """Color never carries meaning alone, so the label is always written out."""
    return f'<span class="status {kind}"><i aria-hidden="true"></i>{escape(label)}</span>'


def tile(label: str, value: Optional[int], total: Optional[int], note: str) -> str:
    if value is None or not total:
        return (f'<div class="tile"><p class="label">{escape(label)}</p><p class="value">No result</p>'
                f'<p class="note">This run saved no result for this.</p></div>')
    percent = round(100 * value / total)
    return (f'<div class="tile"><p class="label">{escape(label)}</p>'
            f'<p class="value">{value} <small>of {total}</small></p>'
            f'<div class="meter" role="img" aria-label="{value} of {total}"><i style="width:{percent}%"></i></div>'
            f'<p class="note">{escape(note)}</p></div>')


def ruler(data: Dict[str, Any]) -> str:
    """One tick per real check. Known gaps stand taller, and failures taller again."""
    def group(ticks: List[str]) -> str:
        return f'<span class="ruler-group" style="--ticks:{len(ticks)}">{"".join(ticks)}</span>' if ticks else ""

    def tick(kind: str, label: str) -> str:
        return f'<span class="t {kind}" title="{escape(label, quote=True)}"></span>'

    rule_ticks = [tick("" if check["passed"] else "fail", f"{rule['title']}: {check['name']}")
                  for rule in data["rules"] for check in rule["checks"]]
    evasion_ticks = [tick("fail" if not item["as_recorded"] else "" if item["actual"] == "caught" else "gap", item["name"])
                     for item in data["evasion"] or []]
    noise_ticks = [tick("fail" if not item["as_recorded"] else "gap" if item["fires"] else "", item["name"])
                   for item in data["noise"] or []]
    elastic_ticks = [tick("" if item["agree"] else "gap", f"{item['dataset']}: {item['rule']}") for item in data["elastic"] or []]
    return "".join(group(ticks) for ticks in (rule_ticks, evasion_ticks, noise_ticks, elastic_ticks))


def rule_card(rule: Dict[str, Any]) -> str:
    verdict = {"PASS": status("good", "Passes on real logs"), "FAIL": status("bad", "Fails on real logs")}.get(
        rule["verdict"], status("warn", "No result"))
    meta = " · ".join(filter(None, [", ".join(rule["techniques"]), rule["threat"].replace("-", " "), rule["kind"].upper()]))
    rows = [("Reads", SOURCE_LABELS.get(rule["category"], rule["category"].replace("_", " ")))]
    if rule["evasion_total"]:
        rows.append(("Variations caught", f"{rule['evasion_caught']} of {rule['evasion_total']}"))
    if rule["scenarios"] is not None:
        rows.append(("Noisy scenarios", f"{rule['noisy_scenarios']} of {rule['scenarios']}"))
    rows.append(("Elasticsearch agrees", f"{rule['elastic_agree']} of {rule['elastic_total']}" if rule["elastic_total"] else "Not compared"))
    details = "".join(f"<dt>{escape(name)}</dt><dd>{escape(value)}</dd>" for name, value in rows)
    return (f'<article class="card">{verdict}<div><h3>{escape(rule["title"])}</h3>'
            f'<div class="mono">{escape(meta)}</div></div><dl>{details}</dl></article>')


def evasion_rows(results: List[Dict[str, Any]]) -> str:
    rows = []
    for item in results:
        state = status("good", "Caught") if item["actual"] == "caught" else status("warn", "Missed")
        if not item["as_recorded"]:
            state = status("bad", f"Changed: {item['actual']}")
        rows.append(f'<li><div><strong>{escape(item["name"])}</strong><span class="sub">{escape(item["rule"])}</span></div>'
                    f'<div>{state}</div><div class="why">{escape(item["why"])}</div></li>')
    return f'<ul class="rows">{"".join(rows)}</ul>'


def noise_rows(results: List[Dict[str, Any]], titles: Dict[str, str]) -> str:
    rows = []
    for item in sorted(results, key=lambda entry: bool(entry["fires"])):
        state = status("warn", "Sets off rules") if item["fires"] else status("good", "Quiet")
        if not item["as_recorded"]:
            state = status("bad", "Changed")
        fired = ", ".join(titles.get(path, path) for path in item["fires"]) or "No rules"
        rows.append(f'<li><div><strong>{escape(item["name"])}</strong><span class="sub">{escape(fired)}</span></div>'
                    f'<div>{state}</div><div class="why">{escape(item["why"])}</div></li>')
    return f'<ul class="rows">{"".join(rows)}</ul>'


def elastic_rows(results: List[Dict[str, Any]], recorded: Dict[str, str]) -> str:
    differences = [item for item in results if not item["agree"]]
    if not differences:
        return '<p class="intro">Every result agrees in this run.</p>'
    rows = []
    for item in differences:
        key = f"{item['dataset']}|{item['rule_file']}|{item['scenario']}"
        engine, siem = ("fires" if item["engine_fires"] else "quiet"), ("fires" if item["elastic_fires"] else "quiet")
        rows.append(f'<li><div><strong>{escape(item["rule"])}</strong><span class="sub">{escape(item["dataset"])}</span></div>'
                    f'<div>{status("warn", "Differs")}</div>'
                    f'<div class="why">Project engine {engine}, Elasticsearch {siem}. {escape(recorded.get(key, "Not on record."))}</div></li>')
    return f'<ul class="rows">{"".join(rows)}</ul>'


def section(number: int, total: int, anchor: str, title: str, intro: str, body: str) -> str:
    return (f'<section id="{anchor}"><div class="head"><h2>{escape(title)}</h2>'
            f'<span class="mono">{number:02d} / {total:02d}</span></div>'
            f'<p class="intro">{intro}</p>{body}</section>')


def render(data: Dict[str, Any], summary: Dict[str, Any], content: Dict[str, Any], recorded: Dict[str, str],
           run: RunInfo, css: str) -> str:
    titles = {rule["file"]: rule["title"] for rule in data["rules"]}
    sigma_count = sum(rule["kind"] == "sigma" for rule in data["rules"])
    run_link = f'<a href="{escape(run.url, quote=True)}">{escape(run.commit[:7] or "Latest run")}</a>' if run.url else escape(run.commit[:7])
    health = (status("good", "Results match the record") if summary["healthy"]
              else status("bad", "Results need attention"))
    preview = "" if data["mode"] == "real" else (
        '<p class="banner"><strong>Preview.</strong> These numbers come from simulated logs, not a real run.</p>')

    findings = "".join(
        f'<li><span class="mono">{escape(item["when"])}</span><div><h3><a href="{escape(item["link"], quote=True)}">{escape(item["title"])}</a></h3>'
        f'<p>{escape(item["detail"])}</p></div></li>' for item in content["findings"])
    limits = "".join(f'<div class="limit"><h3>{escape(item["title"])}</h3><p>{escape(item["detail"])}</p></div>'
                     for item in content["limits"])
    missing = '<p class="intro">This run saved no result for this.</p>'

    sections = [
        section(1, 6, "rules", "The rules",
                "Each rule runs on its own disposable Windows machine against a real test. To pass, it has to alert on the attack and stay quiet on normal activity.",
                f'<div class="cards">{"".join(rule_card(rule) for rule in data["rules"])}</div>'),
        section(2, 6, "evasion", "What gets past them",
                "Harmless variations of each game and license attack. Misses are recorded rather than hidden, and any change from the record fails the run.",
                evasion_rows(data["evasion"]) if data["evasion"] is not None else missing),
        section(3, 6, "noise", "What sets them off by mistake",
                "Normal activity, scored against every rule. A rule that fires on normal behavior buries analysts in bad alerts.",
                noise_rows(data["noise"], titles) if data["noise"] is not None else missing),
        section(4, 6, "elastic", "A second opinion",
                f"Rules pass or fail on engines this project wrote, so the real logs also go into a real Elasticsearch, which runs the {sigma_count} Sigma rules after standard conversion. These are the results where the two disagree.",
                elastic_rows(data["elastic"], recorded) if data["elastic"] is not None else missing),
        section(5, 6, "findings", "What real logs changed",
                "Mistakes and surprises that only showed up on real logs and real tools. Each one links to its run.",
                f'<ol class="timeline">{findings}</ol>'),
        section(6, 6, "limits", "What this doesn't prove", escape(content["ground_rules"]), f'<div class="split">{limits}</div>'),
    ]
    nav = "".join(f'<a href="#{anchor}">{label}</a>' for anchor, label in (
        ("rules", "Rules"), ("evasion", "Evasion"), ("noise", "Noise"), ("elastic", "Elasticsearch"), ("findings", "Findings"), ("limits", "Limits")))

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Detection Validation Pipeline</title>
<meta name="description" content="Live results from a detection engineering pipeline that tests rules on real Windows logs, then records what they miss and what sets them off by mistake.">
<style>{css}</style>
</head>
<body>
<header class="bar"><div class="wrap">
<a class="brand" href="#top">Detection Validation Pipeline</a>
<nav class="nav" aria-label="Sections">{nav}</nav>
<a class="pill" href="{REPO_URL}">GitHub ↗</a>
</div></header>
<main class="wrap" id="top">
<div class="hero">
<div class="ruler" role="img" aria-label="One tick for each check in the latest run">{ruler(data)}</div>
<p class="mono ruler-note">One tick per check in the latest run. Taller ticks are known gaps, and red ticks failed.</p>
<h1>Detection rules, tested on real logs.<span>Then on what they miss.</span></h1>
<p class="lede">A detection-as-code pipeline with a video game security focus. Every rule has to catch a real test on a disposable Windows machine, and this page rebuilds itself from the results of the latest run.</p>
{preview}
<dl class="facts">
<div><dt>Status</dt><dd>{health}</dd></div>
<div><dt>Latest run</dt><dd>{run_link}</dd></div>
<div><dt>Finished</dt><dd>{escape(run.finished)}</dd></div>
<div><dt>Tested against</dt><dd>A fake game and scripted traffic</dd></div>
</dl>
<div class="tiles">
{tile("Rules passing on real logs", summary["rules_passed"], summary["rules_total"], "Catch the attack and ignore normal activity.")}
{tile("Evasion variations caught", summary["evasion_caught"], summary["evasion_total"], "The misses are listed below, with reasons.")}
{tile("Normal scenarios that stay quiet", summary["noise_quiet"], summary["noise_total"], "The rest set off at least one rule.")}
{tile("Results Elasticsearch agrees with", summary["elastic_agree"], summary["elastic_total"], "An independent engine, on the same logs.")}
</div>
</div>
{"".join(sections)}
</main>
<footer><div class="wrap mono">
<span>Built by <a href="https://github.com/PranaVVelu">PranaVVelu</a> with Claude Code</span>
<span>Plain data for agents at <a href="results.json">results.json</a></span>
</div></footer>
</body>
</html>
"""


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--artifacts", type=Path, required=True, help="folder holding the real run's artifacts")
    parser.add_argument("--out", type=Path, required=True, help="folder to write the site to")
    parser.add_argument("--run-url", default="")
    parser.add_argument("--commit", default="")
    parser.add_argument("--finished", required=True, help="when the run finished, as readable text")
    args = parser.parse_args(argv)

    try:
        data = collect(args.artifacts)
        summary = summarize(data)
        content = yaml.safe_load((DASHBOARD_DIR / "content.yml").read_text(encoding="utf-8"))
        differences = yaml.safe_load((ROOT / "simulation" / "siem-differences.yml").read_text(encoding="utf-8"))["differences"] or []
        recorded = {f"{item['dataset']}|{item['rule_file']}|{item['scenario']}": item["why"] for item in differences}
        css = (DASHBOARD_DIR / "style.css").read_text(encoding="utf-8")
    except (PipelineError, OSError, yaml.YAMLError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    run = RunInfo(args.run_url, args.commit, args.finished)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "index.html").write_text(render(data, summary, content, recorded, run, css), encoding="utf-8")
    (args.out / "results.json").write_text(json.dumps(
        {"run": {"url": run.url, "commit": run.commit, "finished": run.finished}, "summary": summary, **data}, indent=2), encoding="utf-8")
    print(f"Wrote {args.out / 'index.html'}: {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
