from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Callable


def create_health_server(
    host: str, port: int, checks: Callable[[], dict]
) -> tuple[ThreadingHTTPServer, Thread]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path not in ("/healthz", "/readyz"):
                self.send_response(404)
                self.end_headers()
                return
            body = checks()
            ok = bool(body.get("ok", False))
            payload = json.dumps(body).encode("utf-8")
            self.send_response(200 if ok else 503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer((host, port), Handler)
    thread = Thread(target=server.serve_forever, name="health-http", daemon=True)
    thread.start()
    return server, thread
