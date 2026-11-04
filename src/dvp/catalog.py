"""Access the catalog of simulated Atomic Red Team tests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import yaml

from dvp.errors import PipelineError

DEFAULT_CATALOG = Path(__file__).resolve().parents[2] / "simulation" / "catalog.yml"


@dataclass(frozen=True)
class AtomicTest:
    guid: str
    technique: str
    name: str
    upstream_command: str
    attack_events: List[Dict[str, Any]]
    benign_events: List[Dict[str, Any]]


def load_atomic_test(guid: str, catalog_path: Path = DEFAULT_CATALOG) -> AtomicTest:
    """Return one catalog entry, keyed by Atomic's stable GUID (test numbers shift)."""
    try:
        catalog = yaml.safe_load(Path(catalog_path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PipelineError(f"cannot load catalog {catalog_path}: {exc}") from exc

    entry = catalog.get("tests", {}).get(guid)
    if entry is None:
        raise PipelineError(f"Atomic test {guid!r} is not in {catalog_path}; add it to the catalog")
    return AtomicTest(
        guid=guid,
        technique=entry["technique"],
        name=entry["name"],
        upstream_command=entry["upstream_command"],
        attack_events=entry["attack_events"],
        benign_events=catalog["benign_baseline"][entry["category"]],
    )
