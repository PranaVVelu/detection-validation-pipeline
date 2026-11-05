#!/usr/bin/env python3
"""Activate one demo key on many machines, or be a player who reinstalls on their two PCs."""

from license_client import activate, parse_args

args = parse_args()
if args.scenario == "attack":
    for machine in range(8):
        activate(args.url, "FQ-DEMO-0002", f"machine-shared-{machine}")
else:
    for machine in ("machine-desktop", "machine-laptop") * 4:
        activate(args.url, "FQ-DEMO-0001", machine)
