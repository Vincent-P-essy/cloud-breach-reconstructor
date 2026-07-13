from __future__ import annotations

import http.client
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cloud_breach_reconstructor.api import create_server
from cloud_breach_reconstructor.cli import main
from cloud_breach_reconstructor.errors import EvidenceError, InputLimitError
from cloud_breach_reconstructor.io import decode_json, load_records, load_truth

from .helpers import ROOT, canonical, lab_records


class IoApiCliTests(unittest.TestCase):
    def test_json_and_jsonl_loaders(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            json_path = root / "events.json"
            json_path.write_text(
                json.dumps({"events": [canonical("a", "2026-07-12T10:00:00Z")]}), encoding="utf-8"
            )
            jsonl_path = root / "events.jsonl"
            jsonl_path.write_text(
                json.dumps(canonical("b", "2026-07-12T10:00:00Z")) + "\n\n", encoding="utf-8"
            )
            self.assertEqual("a", load_records(json_path)[0]["event_id"])
            self.assertEqual("b", load_records(jsonl_path)[0]["event_id"])
            self.assertEqual("a", load_truth(json_path)["events"][0]["event_id"])

    def test_loader_rejects_missing_wrong_shapes_and_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(EvidenceError):
                load_records(root / "missing.json")
            for name, text in (
                ("scalar.json", "1"),
                ("object.json", '{"x":1}'),
                ("array.json", "[1]"),
                ("lines.jsonl", "[]\n"),
            ):
                path = root / name
                path.write_text(text, encoding="utf-8")
                with self.subTest(name=name), self.assertRaises(EvidenceError):
                    load_records(path)
            with self.assertRaises(EvidenceError):
                decode_json('{"a":1,"a":2}')
            with self.assertRaises(EvidenceError):
                decode_json("{")
            with self.assertRaises(EvidenceError):
                load_truth(root / "missing-truth.json")

    def test_json_numbers_and_depth_fail_closed(self) -> None:
        for text in ("NaN", "Infinity", "-Infinity", "1e400"):
            with self.subTest(text=text), self.assertRaises(EvidenceError):
                decode_json(text)
        with self.assertRaises(EvidenceError):
            decode_json("[" * 65 + "0" + "]" * 65)

    def test_loader_file_and_line_limits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            huge = root / "huge.json"
            huge.write_bytes(b" " * 50_000_001)
            with self.assertRaises(InputLimitError):
                load_records(huge)
            line = root / "line.jsonl"
            line.write_text('{"x":"' + ("a" * 1_000_001) + '"}\n', encoding="utf-8")
            with self.assertRaises(InputLimitError):
                load_records(line)

    def _server(self):
        server = create_server("127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        content_type: str = "application/json",
    ):
        server, thread = self._server()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            headers = {"Content-Type": content_type} if body is not None else {}
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read()
            headers_result = dict(response.getheaders())
            connection.close()
            return response.status, headers_result, payload
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_health_dashboard_assets_and_security_headers(self) -> None:
        for path in ("/", "/app.js", "/styles.css", "/api/v1/health"):
            with self.subTest(path=path):
                status, headers, payload = self._request("GET", path)
                self.assertEqual(200, status)
                self.assertTrue(payload)
                self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        value = json.loads(self._request("GET", "/api/v1/health")[2])
        self.assertFalse(value["llm_used_for_causality"])
        self.assertEqual("1.1", value["schema_version"])
        self.assertNotIn("Python", self._request("GET", "/api/v1/health")[1]["Server"])

    def test_demo_and_not_found(self) -> None:
        previous = os.environ.get("CLOUD_BREACH_DEMO")
        os.environ["CLOUD_BREACH_DEMO"] = str(ROOT / "datasets/lab/events.jsonl")
        try:
            status, _, payload = self._request("GET", "/api/v1/demo")
            self.assertEqual(200, status)
            self.assertEqual(21, len(json.loads(payload)["events"]))
        finally:
            if previous is None:
                os.environ.pop("CLOUD_BREACH_DEMO", None)
            else:
                os.environ["CLOUD_BREACH_DEMO"] = previous
        self.assertEqual(404, self._request("GET", "/missing")[0])
        self.assertEqual(404, self._request("POST", "/missing", b"{}")[0])

    def test_packaged_demo_is_independent_of_working_directory(self) -> None:
        previous_demo = os.environ.pop("CLOUD_BREACH_DEMO", None)
        previous_directory = Path.cwd()
        try:
            with tempfile.TemporaryDirectory() as directory:
                os.chdir(directory)
                status, _, payload = self._request("GET", "/api/v1/demo")
            self.assertEqual(200, status)
            self.assertEqual(21, len(json.loads(payload)["events"]))
        finally:
            os.chdir(previous_directory)
            if previous_demo is not None:
                os.environ["CLOUD_BREACH_DEMO"] = previous_demo

    def test_demo_unavailable(self) -> None:
        previous = os.environ.get("CLOUD_BREACH_DEMO")
        os.environ["CLOUD_BREACH_DEMO"] = "/definitely/missing/evidence.jsonl"
        try:
            self.assertEqual(404, self._request("GET", "/api/v1/demo")[0])
        finally:
            if previous is None:
                os.environ.pop("CLOUD_BREACH_DEMO", None)
            else:
                os.environ["CLOUD_BREACH_DEMO"] = previous

    def test_reconstruct_endpoint_and_rejections(self) -> None:
        body = json.dumps({"events": lab_records()[:2]}).encode()
        status, _, payload = self._request("POST", "/api/v1/reconstruct", body)
        self.assertEqual(200, status)
        self.assertEqual(2, len(json.loads(payload)["events"]))
        bad_requests = [
            (b'{"events":[],"events":[]}', "application/json"),
            (b'{"events":[],"extra":1}', "application/json"),
            (b'{"events":1}', "application/json"),
            (b"{", "application/json"),
            (b"{}", "text/plain"),
        ]
        expected = [400, 400, 400, 400, 415]
        for (candidate, media), wanted in zip(bad_requests, expected, strict=True):
            with self.subTest(candidate=candidate):
                self.assertEqual(
                    wanted, self._request("POST", "/api/v1/reconstruct", candidate, media)[0]
                )

    def test_reconstruct_endpoint_rejects_non_finite_deep_and_unknown_schema(self) -> None:
        unknown_schema = canonical("a", "2026-07-12T10:00:00Z")
        unknown_schema["schema_version"] = "999"
        unknown_outcome = canonical("b", "2026-07-12T10:00:00Z")
        unknown_outcome["outcome"] = "made-up"
        bodies = [
            b'{"events":[{"score":NaN}]}',
            ("[" * 70 + "0" + "]" * 70).encode(),
            json.dumps({"events": [unknown_schema]}).encode(),
            json.dumps({"events": [unknown_outcome]}).encode(),
        ]
        for body in bodies:
            with self.subTest(body=body[:80]):
                status, _, payload = self._request("POST", "/api/v1/reconstruct", body)
                self.assertEqual(400, status)
                self.assertEqual("invalid_evidence", json.loads(payload)["error"]["code"])

    def test_cli_validate_analyze_benchmark_and_error(self) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            commands = [
                ["validate", "datasets/lab/events.jsonl"],
                ["analyze", "datasets/lab/events.jsonl", "--output", str(output)],
                [
                    "benchmark",
                    "datasets/lab/events.jsonl",
                    "--truth",
                    "datasets/lab/ground-truth.json",
                    "--iterations",
                    "2",
                    "--fail-under",
                    "1.0",
                ],
            ]
            for command in commands:
                result = subprocess.run(
                    [sys.executable, "-m", "cloud_breach_reconstructor", *command],
                    cwd=ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertTrue(result.stdout)
            self.assertTrue((output / "reconstruction.json").is_file())
            failure = subprocess.run(
                [sys.executable, "-m", "cloud_breach_reconstructor", "validate", "missing.json"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(2, failure.returncode)
            self.assertIn("EvidenceError", failure.stderr)

    def test_cli_threshold_failure(self) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        truth = {
            "schema_version": "1.1",
            "causal_edges": [
                {
                    "source": "missing",
                    "target": "also-missing",
                    "kind": "explicit-parent",
                }
            ],
            "findings": [],
            "attack_event_ids": [],
            "techniques": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "truth.json"
            path.write_text(json.dumps(truth), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "cloud_breach_reconstructor",
                    "benchmark",
                    "datasets/lab/events.jsonl",
                    "--truth",
                    str(path),
                    "--iterations",
                    "1",
                    "--fail-under",
                    "1.0",
                ],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(3, result.returncode)

    def test_cli_main_direct_paths(self) -> None:
        evidence = ROOT / "datasets/lab/events.jsonl"
        truth = ROOT / "datasets/lab/ground-truth.json"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "bundle"
            summary_output = root / "summary-bundle"
            benchmark_output = root / "benchmark.json"
            empty_truth = root / "empty-truth.json"
            empty_truth.write_text(
                json.dumps(
                    {
                        "schema_version": "1.1",
                        "causal_edges": [],
                        "findings": [],
                        "attack_event_ids": [],
                        "techniques": [],
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(0, main(["validate", str(evidence)]))
                self.assertEqual(
                    0,
                    main(
                        [
                            "analyze",
                            str(evidence),
                            "--output",
                            str(output),
                            "--stdout",
                        ]
                    ),
                )
                self.assertEqual(
                    0,
                    main(["analyze", str(evidence), "--output", str(summary_output)]),
                )
                self.assertEqual(
                    0,
                    main(
                        [
                            "benchmark",
                            str(evidence),
                            "--truth",
                            str(truth),
                            "--iterations",
                            "1",
                            "--output",
                            str(benchmark_output),
                            "--fail-under",
                            "1.0",
                        ]
                    ),
                )
                self.assertEqual(2, main(["validate", str(root / "missing.json")]))
                self.assertEqual(
                    3,
                    main(
                        [
                            "benchmark",
                            str(evidence),
                            "--truth",
                            str(empty_truth),
                            "--iterations",
                            "1",
                            "--fail-under",
                            "1.0",
                        ]
                    ),
                )
                with patch("cloud_breach_reconstructor.cli.serve") as mocked_serve:
                    self.assertEqual(0, main(["serve", "--host", "127.0.0.1", "--port", "0"]))
                    mocked_serve.assert_called_once_with("127.0.0.1", 0)
            self.assertTrue(output.is_dir())
            self.assertTrue(summary_output.is_dir())
            self.assertTrue(benchmark_output.is_file())
            self.assertIn('"valid": true', stdout.getvalue())
            self.assertIn("EvidenceError", stderr.getvalue())
