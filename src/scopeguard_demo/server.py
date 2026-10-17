"""A deliberately small, loopback-only API fixture for ScopeGuard."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

HOST = "127.0.0.1"
PORT = 8000

# Public, synthetic credentials for this local demo only.
TOKENS = {
    "demo-user-a": "user-a",
    "demo-user-b": "user-b",
}

RECORDS = {
    "record-a": {"id": "record-a", "owner": "user-a", "value": "Synthetic record A"},
    "record-b": {"id": "record-b", "owner": "user-b", "value": "Synthetic record B"},
}


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "ScopeGuardDemo/0.1"

    def _send_json(self, status: int, payload: dict[str, str]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _identity(self) -> str | None:
        scheme, _, token = self.headers.get("Authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            return None
        return TOKENS.get(token)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API name
        path = urlsplit(self.path).path

        if path == "/health":
            self._send_json(200, {"status": "ok", "fixture": "synthetic"})
            return

        identity = self._identity()
        if identity is None:
            self._send_json(401, {"error": "unauthorized"})
            return

        parts = path.strip("/").split("/")
        if len(parts) == 2 and parts[0] == "records":
            self._get_owned_record(identity, parts[1])
            return

        if len(parts) == 3 and parts[:2] == ["vulnerable", "records"]:
            self._get_vulnerable_record(parts[2])
            return

        self._send_json(404, {"error": "not_found"})

    def _get_owned_record(self, identity: str, record_id: str) -> None:
        record = RECORDS.get(record_id)
        # Conceal whether another user's record exists.
        if record is None or record["owner"] != identity:
            self._send_json(404, {"error": "not_found"})
            return
        self._send_json(200, record)

    def _get_vulnerable_record(self, record_id: str) -> None:
        # Intentionally broken: authentication is checked, but ownership is not.
        record = RECORDS.get(record_id)
        if record is None:
            self._send_json(404, {"error": "not_found"})
            return
        self._send_json(200, record)

    def log_message(self, format: str, *args: object) -> None:
        # Keep logs concise and avoid dumping headers or response data.
        super().log_message(format, *args)


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), DemoHandler)
    print(f"ScopeGuard demo API listening on http://{HOST}:{PORT}")
    print("Synthetic tokens only. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping ScopeGuard demo API.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
