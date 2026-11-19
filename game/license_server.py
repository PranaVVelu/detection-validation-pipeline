#!/usr/bin/env python3
"""A small license server for FakeQuest, so license abuse rules have real logs to read.

It only listens on this machine, and its keys unlock nothing. Each activation
attempt is written to the log as one JSON line. Keys are logged as hashes, because
a log that holds working license keys would be worth stealing.

    POST /activate        {"key": str, "machine_id": str}
    POST /admin/disable   {"license_key_hash": str}, with "Authorization: Bearer <admin token>"

The admin endpoint only exists when the server is started with an admin token. It's
how an approved response action disables a shared key.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Set, TextIO

VALID_KEYS = {"FQ-DEMO-0001", "FQ-DEMO-0002"} | {f"FQ-PLAYER-{n:04d}" for n in range(1, 101)}
SEATS_PER_KEY = 2
MAX_BODY_BYTES = 4096


def key_hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class LicenseServer:
    def __init__(self, log: TextIO) -> None:
        self._log = log
        self._lock = threading.Lock()
        self._seats: Dict[str, Set[str]] = {key: set() for key in VALID_KEYS}
        self._disabled: Set[str] = set()

    def activate(self, key: str, machine_id: str, client_ip: str) -> Optional[str]:
        """Record an attempt, returning why it was refused, or None if it succeeded."""
        with self._lock:
            reason = self._refusal(key, machine_id)
            if reason is None:
                self._seats[key].add(machine_id)
            self._log.write(json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "activation",
                "result": "failure" if reason else "success",
                "reason": reason or "none",
                "license_key_hash": key_hash(key),
                "machine_id": machine_id,
                "client_ip": client_ip,
            }) + "\n")
            self._log.flush()
        return reason

    def disable(self, license_key_hash: str) -> bool:
        """Disable the key with this hash, returning whether one matched. Keys are only known here by hash."""
        with self._lock:
            matches = {key for key in self._seats if key_hash(key) == license_key_hash}
            self._disabled |= matches
            self._log.write(json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "admin_disable",
                "result": "success" if matches else "failure",
                "license_key_hash": license_key_hash,
            }) + "\n")
            self._log.flush()
        return bool(matches)

    def _refusal(self, key: str, machine_id: str) -> Optional[str]:
        seats = self._seats.get(key)
        if seats is None:
            return "unknown_key"
        if key in self._disabled:
            return "disabled"
        if machine_id not in seats and len(seats) >= SEATS_PER_KEY:
            return "seat_limit"
        return None


def build_server(license_server: LicenseServer, admin_token: str = "") -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def _respond(self, status: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY_BYTES:
                raise ValueError("request body too large")
            return json.loads(self.rfile.read(length))

        def do_POST(self) -> None:  # noqa: N802 (http.server naming)
            if self.path == "/admin/disable" and admin_token:
                self._disable()
                return
            if self.path != "/activate":
                self._respond(404, {"error": "not found"})
                return
            try:
                body = self._read_json()
                key, machine_id = str(body["key"]), str(body["machine_id"])
            except (KeyError, TypeError, ValueError) as exc:
                self._respond(400, {"error": f"bad request: {exc}"})
                return
            reason = license_server.activate(key, machine_id, self.client_address[0])
            self._respond(403 if reason else 200, {"activated": not reason, "reason": reason})

        def _disable(self) -> None:
            supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
            if not hmac.compare_digest(supplied.encode("utf-8"), admin_token.encode("utf-8")):
                self._respond(401, {"error": "admin token required"})
                return
            try:
                license_key_hash = str(self._read_json()["license_key_hash"])
            except (KeyError, TypeError, ValueError) as exc:
                self._respond(400, {"error": f"bad request: {exc}"})
                return
            matched = license_server.disable(license_key_hash)
            self._respond(200 if matched else 404, {"disabled": matched})

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass  # The activation log is the record that matters.

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--log", type=Path, required=True, help="where to write the activation log")
    args = parser.parse_args()

    with args.log.open("a", encoding="utf-8") as log:
        server = build_server(LicenseServer(log), os.environ.get("LICENSE_ADMIN_TOKEN", ""))
        print(f"http://127.0.0.1:{server.server_address[1]}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
