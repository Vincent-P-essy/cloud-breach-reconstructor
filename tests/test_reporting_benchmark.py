from __future__ import annotations

import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cloud_breach_reconstructor.benchmark import QUALITY_METRICS, _percentile, benchmark
from cloud_breach_reconstructor.engine import reconstruct
from cloud_breach_reconstructor.errors import EvidenceError
from cloud_breach_reconstructor.reporting import (
    executive_markdown,
    graph_dot,
    technical_markdown,
    write_bundle,
)

from .helpers import canonical, lab_records, lab_truth


def empty_truth():
    return {
        "schema_version": "1.1",
        "causal_edges": [],
        "findings": [],
        "attack_event_ids": [],
        "techniques": [],
    }


class ReportingBenchmarkTests(unittest.TestCase):
    def test_benchmark_matches_ground_truth_and_is_deterministic(self) -> None:
        result = benchmark(lab_records(), lab_truth(), iterations=5)
        self.assertTrue(result["deterministic"])
        self.assertEqual(1.0, result["metrics"]["causal_edge_precision"])
        self.assertEqual(1.0, result["metrics"]["causal_edge_recall"])
        self.assertEqual(0.0, result["metrics"]["false_link_rate"])
        self.assertTrue(all(result["metrics"][name] == 1.0 for name in QUALITY_METRICS))
        self.assertTrue(all(not values for values in result["false_positives"].values()))

    def test_benchmark_invalid_iteration_count(self) -> None:
        for value in (0, 1001):
            with self.subTest(value=value), self.assertRaises(ValueError):
                benchmark([], {}, iterations=value)

    def test_empty_truth_metrics_are_defined(self) -> None:
        result = benchmark([], empty_truth(), iterations=1)
        self.assertEqual(1.0, result["metrics"]["causal_edge_precision"])
        self.assertEqual(1.0, result["metrics"]["technique_recall"])

    def test_false_findings_events_and_techniques_are_penalized(self) -> None:
        record = canonical(
            "false-positive",
            "2026-07-12T10:00:00Z",
            action="secretsmanager:GetSecretValue",
        )
        result = benchmark([record], empty_truth(), iterations=1)
        self.assertEqual(0.0, result["metrics"]["finding_precision"])
        self.assertEqual(0.0, result["metrics"]["attack_event_precision"])
        self.assertEqual(0.0, result["metrics"]["technique_precision"])
        self.assertEqual(1, result["error_counts"]["finding"]["false_positives"])

    def test_edge_kind_is_part_of_ground_truth(self) -> None:
        records = [
            canonical("a", "2026-07-12T10:00:00Z", session_id="same"),
            canonical("b", "2026-07-12T10:01:00Z", session_id="same"),
        ]
        truth = empty_truth()
        truth["causal_edges"] = [{"source": "a", "target": "b", "kind": "explicit-parent"}]
        result = benchmark(records, truth, iterations=1)
        self.assertEqual(0.0, result["metrics"]["causal_edge_precision"])
        self.assertEqual(0.0, result["metrics"]["causal_edge_recall"])
        self.assertEqual(1, result["error_counts"]["causal_edge"]["false_positives"])
        self.assertEqual(1, result["error_counts"]["causal_edge"]["false_negatives"])

    def test_ground_truth_schema_fails_closed(self) -> None:
        for truth in ({}, {**empty_truth(), "schema_version": "999"}):
            with self.subTest(truth=truth), self.assertRaises(EvidenceError):
                benchmark([], truth, iterations=1)

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

        injected = 'x"; evil [label="INJECTED"]; "tail'
        hostile = graph_dot(reconstruct([canonical(injected, "2026-07-12T10:00:00Z")]))
        self.assertNotIn('"x"; evil', hostile)
        self.assertIn('\\"; evil', hostile)

    def test_markdown_and_csv_neutralize_active_content(self) -> None:
        report = reconstruct(
            [
                canonical(
                    "=cmd|' /C calc'!A0",
                    "2026-07-12T10:00:00Z",
                    actor="|<img src=x onerror=alert(1)>",
                    action="@SUM(1+1)",
                )
            ]
        )
        markdown = technical_markdown(report)
        self.assertIn("&#124;&lt;img", markdown)
        self.assertNotIn("<img", markdown)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            write_bundle(report, output)
            with (output / "timeline.csv").open(encoding="utf-8", newline="") as stream:
                rows = list(csv.reader(stream))
            self.assertTrue(rows[1][0].startswith("'="))
            self.assertTrue(rows[1][4].startswith("'@"))

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
