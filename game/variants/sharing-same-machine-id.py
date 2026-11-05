#!/usr/bin/env python3
"""Share a key among many users who all report the same machine ID."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios"))

from license_client import activate, parse_args  # noqa: E402

args = parse_args()
for _ in range(8):
    activate(args.url, "FQ-DEMO-0002", "machine-cloned")
