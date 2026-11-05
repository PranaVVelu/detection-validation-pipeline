"""The client side of the license tests, shared by their scenario scripts."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=["attack", "benign"], required=True)
    parser.add_argument("--url", required=True, help="the local license server")
    args = parser.parse_args()
    # These scripts only ever talk to the project's own server on this machine.
    if urllib.parse.urlparse(args.url).hostname != "127.0.0.1":
        parser.error("--url must point at 127.0.0.1")
    return args


def activate(url: str, key: str, machine_id: str) -> None:
    """Make one activation attempt. A refusal is an expected result, and gets logged by the server."""
    request = urllib.request.Request(
        f"{url}/activate", data=json.dumps({"key": key, "machine_id": machine_id}).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10):
            pass
    except urllib.error.HTTPError as exc:
        if exc.code != 403:
            raise
