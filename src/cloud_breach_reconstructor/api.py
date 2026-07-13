from __future__ import annotations

import json
import os
import socket
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any

from .engine import reconstruct
from .errors import EvidenceError
from .io import decode_json, load_records

MAX_BODY_BYTES = 5_000_000
REQUEST_TIMEOUT_SECONDS = 10


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "cloud-breach-reconstructor"

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def _headers(self, status: int, content_type: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "img-src 'self'; object-src 'none'; frame-ancestors 'none'",
        )
        self.end_headers()

    def _bytes(self, status: int, body: bytes, content_type: str) -> None:
        self._headers(status, content_type, len(body))
        self.wfile.write(body)

    def _json(self, status: int, value: Any) -> None:
        body = (
            json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
        ).encode()
        self._bytes(status, body, "application/json; charset=utf-8")

    def _error(self, status: int, code: str, message: str) -> None:
        self._json(status, {"error": {"code": code, "message": message}})

    def _asset(self, name: str, content_type: str) -> None:
        asset = resources.files("cloud_breach_reconstructor").joinpath("web").joinpath(name)
        self._bytes(HTTPStatus.OK, asset.read_bytes(), content_type)

    def do_GET(self) -> None:
        path = self.path.split("?", maxsplit=1)[0]
        if path in {"/", "/index.html"}:
            self._asset("index.html", "text/html; charset=utf-8")
            return
        if path == "/app.js":
            self._asset("app.js", "text/javascript; charset=utf-8")
            return
        if path == "/styles.css":
            self._asset("styles.css", "text/css; charset=utf-8")
            return
        if path == "/api/v1/health":
            self._json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "engine": "deterministic-v1",
                    "llm_used_for_causality": False,
                    "schema_version": "1.1",
                },
            )
            return
        if path == "/api/v1/demo":
            try:
                configured = os.environ.get("CLOUD_BREACH_DEMO")
                if configured:
                    records = load_records(Path(configured))
                else:
                    asset = (
                        resources.files("cloud_breach_reconstructor")
                        .joinpath("data")
                        .joinpath("lab-events.jsonl")
                    )
                    with resources.as_file(asset) as demo:
                        records = load_records(demo)
                self._json(HTTPStatus.OK, reconstruct(records).to_dict())
            except (EvidenceError, OSError, UnicodeError) as error:
                self._error(HTTPStatus.NOT_FOUND, "demo_unavailable", str(error))
            return
        self._error(HTTPStatus.NOT_FOUND, "not_found", "route does not exist")

    def do_POST(self) -> None:
        path = self.path.split("?", maxsplit=1)[0]
        if path != "/api/v1/reconstruct":
            self._error(HTTPStatus.NOT_FOUND, "not_found", "route does not exist")
            return
        media_type = self.headers.get("Content-Type", "").split(";", maxsplit=1)[0].strip()
        if media_type != "application/json":
            self._error(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "media_type", "application/json required"
            )
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body_size", "invalid request size")
            return
        try:
            value = decode_json(self.rfile.read(length).decode("utf-8"))
            if not isinstance(value, dict) or set(value) != {"events"}:
                raise EvidenceError("body must contain exactly one events array")
            events = value["events"]
            if not isinstance(events, list) or not all(isinstance(item, dict) for item in events):
                raise EvidenceError("events must be an array of objects")
            if len(events) > 2_000:
                raise EvidenceError("API request exceeds 2000 events")
            self._json(HTTPStatus.OK, reconstruct(events).to_dict())
        except (UnicodeDecodeError, EvidenceError) as error:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_evidence", str(error))
        except TimeoutError:
            self._error(HTTPStatus.REQUEST_TIMEOUT, "request_timeout", "request body timed out")


class ApiServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def get_request(self) -> tuple[socket.socket, Any]:
        request, address = super().get_request()
        request.settimeout(REQUEST_TIMEOUT_SECONDS)
        return request, address


def create_server(host: str, port: int) -> ApiServer:
    return ApiServer((host, port), ApiHandler)


def serve(host: str, port: int) -> None:
    server = create_server(host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
