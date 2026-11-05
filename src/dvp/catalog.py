"""Access the catalog of validation tests: Atomic Red Team tests and game tests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import yaml

from dvp.errors import PipelineError

DEFAULT_CATALOG = Path(__file__).resolve().parents[2] / "simulation" / "catalog.yml"


@dataclass(frozen=True)
class ValidationTest:
    guid: str
    kind: str
    technique: str
    name: str
    category: str
    upstream_command: str
    attack_events: List[Dict[str, Any]]
    benign_events: List[Dict[str, Any]]
    upstream_commit: str

    @property
    def command_marker(self) -> str:
        """The fixed start of the upstream command, before any input arguments."""
        return self.upstream_command.split("#{")[0].strip()


def _expand(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Expand ``repeat: N`` into N events, replacing ``{n}`` in their text fields."""
    expanded: List[Dict[str, Any]] = []
    for template in events:
        fields = {key: value for key, value in template.items() if key != "repeat"}
        for n in range(1, template.get("repeat", 1) + 1):
            expanded.append({key: value.replace("{n}", str(n)) if isinstance(value, str) else value
                             for key, value in fields.items()})
    return expanded


def load_test(guid: str, catalog_path: Path = DEFAULT_CATALOG) -> ValidationTest:
    """Return one catalog entry, keyed by Atomic's stable GUID or a game test's name."""
    try:
        catalog = yaml.safe_load(Path(catalog_path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PipelineError(f"cannot load catalog {catalog_path}: {exc}") from exc

    entry = catalog.get("tests", {}).get(guid)
    if entry is None:
        raise PipelineError(f"Test {guid!r} is not in {catalog_path}; add it to the catalog")
    return ValidationTest(
        guid=guid,
        kind=entry.get("kind", "atomic"),
        technique=entry["technique"],
        name=entry["name"],
        category=entry["category"],
        upstream_command=entry.get("upstream_command", ""),
        attack_events=_expand(entry["attack_events"]),
        benign_events=_expand(entry.get("benign_events") or catalog["benign_baseline"][entry["category"]]),
        upstream_commit=catalog["upstream"]["commit"],
    )
