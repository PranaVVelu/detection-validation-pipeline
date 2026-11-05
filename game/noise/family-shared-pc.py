#!/usr/bin/env python3
"""A family sharing one PC, with a different key for each person."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios"))

from license_client import activate, parse_args  # noqa: E402

args = parse_args()
for player in range(1, 4):
    activate(args.url, f"FQ-PLAYER-{player:04d}", "machine-family")
