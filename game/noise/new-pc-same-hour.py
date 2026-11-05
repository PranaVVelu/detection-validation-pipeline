#!/usr/bin/env python3
"""A player sets up a new PC, using their key on a third machine within the hour."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios"))

from license_client import activate, parse_args  # noqa: E402

args = parse_args()
for machine in ("machine-desktop", "machine-laptop", "machine-new-desktop"):
    activate(args.url, "FQ-PLAYER-0001", machine)
