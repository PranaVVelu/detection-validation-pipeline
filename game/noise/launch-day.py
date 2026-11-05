#!/usr/bin/env python3
"""Launch day: many players each activate their own key."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios"))

from license_client import activate, parse_args  # noqa: E402

args = parse_args()
for player in range(1, 61):
    activate(args.url, f"FQ-PLAYER-{player:04d}", f"machine-{player}")
