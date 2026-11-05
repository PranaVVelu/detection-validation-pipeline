"""The client side of the license tests, shared by their scenario scripts."""

from __future__ import annotations

import argparse
import http.client
import json
import urllib.parse


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=["attack", "benign"], required=True)
    parser.add_argument("--url", required=True, help="the local license server")
    args = parser.parse_args()
    # These scripts only ever talk to the project's own server on this machine.
    if urllib.parse.urlparse(args.url).hostname != "127.0.0.1":
        parser.error("--url must point at 127.0.0.1")
    return args


def activate(url: str, key: str, machine_id: str, source_ip: str = "") -> None:
    """Make one activation attempt. A refusal is an expected result, and gets logged by the server."""
    parsed = urllib.parse.urlparse(url)
    source = (source_ip, 0) if source_ip else None
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10, source_address=source)
    try:
        connection.request("POST", "/activate", json.dumps({"key": key, "machine_id": machine_id}),
                           {"Content-Type": "application/json"})
        status = connection.getresponse().status
    finally:
        connection.close()
    if status not in (200, 403):
        raise RuntimeError(f"unexpected response from the license server: {status}")
