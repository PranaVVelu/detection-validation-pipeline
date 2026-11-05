#!/usr/bin/env python3
"""Try made-up license keys against FakeQuest's local server, or be a player who mistypes one."""

from license_client import activate, parse_args

args = parse_args()
if args.scenario == "attack":
    for attempt in range(25):
        activate(args.url, f"NOT-A-KEY-{attempt:04d}", "machine-attacker")
else:
    # A few typos, then the same wrong key over and over, then the right one.
    for typo in ("FQ-DEMO-00O1", "FQ-DEMO-001", "FQ-DEMO-0011"):
        activate(args.url, typo, "machine-player")
    for _ in range(15):
        activate(args.url, "FQ-DEMO-0011", "machine-player")
    activate(args.url, "FQ-DEMO-0001", "machine-player")
