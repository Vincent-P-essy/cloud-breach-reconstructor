from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cloud_breach_reconstructor.benchmark import _percentile, benchmark
from cloud_breach_reconstructor.engine import reconstruct
from cloud_breach_reconstructor.reporting import (
    executive_markdown,
    graph_dot,
    technical_markdown,
    write_bundle,
)

from .helpers import lab_records, lab_truth


class ReportingBenchmarkTests(unittest.TestCase):
    def test_benchmark_matches_ground_truth_and_is_deterministic(self) -> None:
        result = benchmark(lab_records(), lab_truth(), iterations=5)
        self.assertTrue(result["deterministic"])
        self.assertEqual(1.0, result["metrics"]["causal_edge_precision"])
        self.assertEqual(1.0, result["metrics"]["causal_edge_recall"])
        self.assertEqual(0.0, result["metrics"]["false_link_rate"])

    def test_benchmark_invalid_iteration_count(self) -> None:
        for value in (0, 1001):
            with self.subTest(value=value), self.assertRaises(ValueError):
                benchmark([], {}, iterations=value)

    def test_empty_truth_metrics_are_defined(self) -> None:
        result = benchmark([], {}, iterations=1)
        self.assertEqual(1.0, result["metrics"]["causal_edge_precision"])
        self.assertEqual(1.0, result["metrics"]["technique_recall"])

    def test_percentile(self) -> None:
        self.assertEqual(0.0, _percentile([], 0.95))
        self.assertEqual(3, _percentile([1, 2, 3], 0.95))

    def test_markdown_exposes_evidence_and_limit(self) -> None:
        report = reconstruct(lab_records())
        executive = executive_markdown(report)
        technical = technical_markdown(report)
        self.assertIn("analytical hypothesis", executive)
        self.assertIn("No language model", executive)
        self.assertIn("Typed causal links", technical)
        self.assertIn("credential-lineage", technical)

    def test_empty_report_markdown(self) -> None:
        report = reconstruct([])
        self.assertIn("0.0/100", executive_markdown(report))
        self.assertIn("No deterministic containment", executive_markdown(report))

    def test_graph_has_every_edge_and_escapes_quotes(self) -> None:
        report = reconstruct(lab_records())
        dot = graph_dot(report)
        self.assertEqual(len(report.edges), dot.count(" -> "))
        self.assertTrue(dot.endswith("}\n"))

    def test_bundle_manifest_binds_all_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            manifest = write_bundle(reconstruct(lab_records()), output)
            self.assertEqual(5, len(manifest))
            for name, expected in manifest.items():
                self.assertEqual(expected, hashlib.sha256((output / name).read_bytes()).hexdigest())
            committed = json.loads((output / "manifest.sha256.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest, committed)
            self.assertEqual(
                22, len((output / "timeline.csv").read_text(encoding="utf-8").splitlines())
            )
