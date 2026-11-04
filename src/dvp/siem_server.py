"""Mock SIEM REST API, using only the standard library.

    GET  /healthz
    POST /api/v1/runs/{run_id}/rules    {"filename": str, "content": str}
    POST /api/v1/runs/{run_id}/events   {"events": [ ... ]}
    GET  /api/v1/runs/{run_id}/stats
    GET  /api/v1/runs/{run_id}/alerts?rule_id=...

Run with: python -m dvp.siem_server --host 127.0.0.1 --port 8080
"""

from __future__ import annotations

import argparse
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs, urlparse

from dvp.errors import RuleError
from dvp.rules import parse_rule
from dvp.siem import SiemStore

MAX_BODY_BYTES = 5 * 1024 * 1024
_RUN_ROUTE = re.compile(r"^/api/v1/runs/(?P<run_id>[\w.-]+)/(?P<resource>rules|events|stats|alerts)$")


def build_server(host: str, port: int, store: SiemStore) -> ThreadingHTTPServer:
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
            return json.loads(self.rfile.read(length) or b"{}")

        def _route(self) -> Tuple[str, str]:
            match = _RUN_ROUTE.match(urlparse(self.path).path)
            return (match.group("run_id"), match.group("resource")) if match else ("", "")

        def do_GET(self) -> None:  # noqa: N802 (http.server naming)
            parsed = urlparse(self.path)
            if parsed.path == "/healthz":
                self._respond(200, {"status": "ok"})
                return
            run_id, resource = self._route()
            if resource == "stats":
                self._respond(200, store.stats(run_id))
            elif resource == "alerts":
                rule_id = parse_qs(parsed.query).get("rule_id", [None])[0]
                self._respond(200, {"alerts": store.alerts(run_id, rule_id)})
            else:
                self._respond(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802 (http.server naming)
            run_id, resource = self._route()
            try:
                body = self._read_json()
                if resource == "rules":
                    rule = parse_rule(body["filename"], body["content"])
                    store.load_rule(run_id, rule)
                    self._respond(201, {"rule_id": rule.id})
                elif resource == "events":
                    self._respond(202, {"ingested": store.ingest(run_id, body["events"])})
                else:
                    self._respond(404, {"error": "not found"})
            except RuleError as exc:
                self._respond(422, {"error": str(exc)})
            except (KeyError, TypeError, ValueError) as exc:
                self._respond(400, {"error": f"bad request: {exc}"})

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            print(f"[siem] {self.address_string()} {format % args}", flush=True)

    return ThreadingHTTPServer((host, port), Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--alert-delay", type=float,
                        default=float(os.environ.get("SIEM_ALERT_DELAY_SECONDS", "0")),
                        help="seconds before an alert becomes visible, to model ingestion lag")
    args = parser.parse_args()

    server = build_server(args.host, args.port, SiemStore(args.alert_delay))
    print(f"[siem] listening on {args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
