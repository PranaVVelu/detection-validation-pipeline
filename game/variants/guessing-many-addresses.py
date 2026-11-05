#!/usr/bin/env python3
"""Guess keys from a different local address each time, like spreading out across machines."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios"))

from license_client import activate, parse_args  # noqa: E402

args = parse_args()
for attempt in range(25):
    activate(args.url, f"NOT-A-KEY-{attempt:04d}", "machine-attacker", source_ip=f"127.0.0.{attempt + 2}")
