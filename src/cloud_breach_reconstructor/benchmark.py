from __future__ import annotations

import hashlib
import json
import math
import statistics
import time
from collections.abc import Mapping, Sequence
from typing import Any

from .engine import reconstruct
from .errors import EvidenceError

BENCHMARK_SCHEMA_VERSION = "1.1"
GROUND_TRUTH_SCHEMA_VERSION = "1.1"
QUALITY_METRICS = (
    "causal_edge_precision",
    "causal_edge_recall",
    "finding_precision",
    "finding_recall",
    "attack_event_precision",
    "attack_event_recall",
    "technique_precision",
    "technique_recall",
)

EdgeSignature = tuple[str, str, str]
FindingSignature = tuple[str, tuple[str, ...]]


def _functional_dict(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result.pop("generated_at", None)
    return result


def _digest(value: dict[str, Any]) -> str:
    canonical = json.dumps(
        _functional_dict(value),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    rank = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[rank]


def _strings(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise EvidenceError(f"ground truth {field} must be an array of non-empty strings")
    if len(value) != len(set(value)):
        raise EvidenceError(f"ground truth {field} contains duplicates")
    return tuple(value)


def _ground_truth(
    truth: Mapping[str, Any],
) -> tuple[set[EdgeSignature], set[FindingSignature], set[str], set[str]]:
    if truth.get("schema_version") != GROUND_TRUTH_SCHEMA_VERSION:
        raise EvidenceError(
            f"unsupported ground truth schema_version; expected {GROUND_TRUTH_SCHEMA_VERSION!r}"
        )
    required = {"causal_edges", "findings", "attack_event_ids", "techniques"}
    missing = required - truth.keys()
    if missing:
        raise EvidenceError(f"ground truth missing fields: {', '.join(sorted(missing))}")

    edge_values = truth["causal_edges"]
    if not isinstance(edge_values, list):
        raise EvidenceError("ground truth causal_edges must be an array")
    edges: set[EdgeSignature] = set()
    for index, item in enumerate(edge_values):
        if not isinstance(item, Mapping):
            raise EvidenceError(f"ground truth causal_edges[{index}] must be an object")
        signature = tuple(item.get(key) for key in ("source", "target", "kind"))
        if not all(isinstance(value, str) and value for value in signature):
            raise EvidenceError(
                f"ground truth causal_edges[{index}] requires source, target, and kind"
            )
        typed_signature = (str(signature[0]), str(signature[1]), str(signature[2]))
        if typed_signature in edges:
            raise EvidenceError(f"ground truth contains duplicate edge {typed_signature!r}")
        edges.add(typed_signature)

    finding_values = truth["findings"]
    if not isinstance(finding_values, list):
        raise EvidenceError("ground truth findings must be an array")
    findings: set[FindingSignature] = set()
    for index, item in enumerate(finding_values):
        if (
            not isinstance(item, Mapping)
            or not isinstance(item.get("title"), str)
            or not item["title"]
        ):
            raise EvidenceError(f"ground truth findings[{index}] requires a title")
        event_ids = _strings(item.get("event_ids"), f"findings[{index}].event_ids")
        if not event_ids:
            raise EvidenceError(f"ground truth findings[{index}].event_ids cannot be empty")
        signature = (str(item["title"]), event_ids)
        if signature in findings:
            raise EvidenceError(f"ground truth contains duplicate finding {signature!r}")
        findings.add(signature)

    attack_events = set(_strings(truth["attack_event_ids"], "attack_event_ids"))
    techniques = set(_strings(truth["techniques"], "techniques"))
    return edges, findings, attack_events, techniques


def _classification(expected: set[Any], actual: set[Any]) -> dict[str, Any]:
    true_positives = expected & actual
    false_positives = actual - expected
    false_negatives = expected - actual
    precision = len(true_positives) / len(actual) if actual else float(not expected)
    recall = len(true_positives) / len(expected) if expected else 1.0
    false_positive_rate = len(false_positives) / len(actual) if actual else 0.0
    return {
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "false_positive_rate": round(false_positive_rate, 6),
        "true_positive_count": len(true_positives),
        "false_positive_count": len(false_positives),
        "false_negative_count": len(false_negatives),
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


def _edge_dict(item: EdgeSignature) -> dict[str, str]:
    return {"source": item[0], "target": item[1], "kind": item[2]}


def _finding_dict(item: FindingSignature) -> dict[str, Any]:
    return {"title": item[0], "event_ids": list(item[1])}


def benchmark(
    records: Sequence[Mapping[str, Any]], truth: Mapping[str, Any], iterations: int = 50
) -> dict[str, Any]:
    if iterations < 1 or iterations > 1_000:
        raise ValueError("iterations must be between 1 and 1000")
    expected_edges, expected_findings, expected_events, expected_techniques = _ground_truth(truth)
    latencies: list[float] = []
    digests: set[str] = set()
    last: dict[str, Any] | None = None
    for _ in range(iterations):
        started = time.perf_counter_ns()
        last = reconstruct(records).to_dict()
        latencies.append((time.perf_counter_ns() - started) / 1_000_000)
        digests.add(_digest(last))
    if last is None:
        raise AssertionError("benchmark produced no reconstruction")

    actual_edges = {
        (str(item["source"]), str(item["target"]), str(item["kind"])) for item in last["edges"]
    }
    actual_findings = {
        (str(item["title"]), tuple(str(value) for value in item["event_ids"]))
        for item in last["findings"]
    }
    actual_events = set(last["attack_mapping"])
    actual_techniques = {item for values in last["attack_mapping"].values() for item in values}
    comparisons = {
        "causal_edge": _classification(expected_edges, actual_edges),
        "finding": _classification(expected_findings, actual_findings),
        "attack_event": _classification(expected_events, actual_events),
        "technique": _classification(expected_techniques, actual_techniques),
    }
    metrics: dict[str, float] = {}
    for name, comparison in comparisons.items():
        metrics[f"{name}_precision"] = comparison["precision"]
        metrics[f"{name}_recall"] = comparison["recall"]
        metrics[f"{name}_false_positive_rate"] = comparison["false_positive_rate"]
    metrics["false_link_rate"] = metrics["causal_edge_false_positive_rate"]

    false_positives = {
        "causal_edges": [
            _edge_dict(item) for item in sorted(comparisons["causal_edge"]["false_positives"])
        ],
        "findings": [
            _finding_dict(item) for item in sorted(comparisons["finding"]["false_positives"])
        ],
        "attack_event_ids": sorted(comparisons["attack_event"]["false_positives"]),
        "techniques": sorted(comparisons["technique"]["false_positives"]),
    }
    false_negatives = {
        "causal_edges": [
            _edge_dict(item) for item in sorted(comparisons["causal_edge"]["false_negatives"])
        ],
        "findings": [
            _finding_dict(item) for item in sorted(comparisons["finding"]["false_negatives"])
        ],
        "attack_event_ids": sorted(comparisons["attack_event"]["false_negatives"]),
        "techniques": sorted(comparisons["technique"]["false_negatives"]),
    }
    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "ground_truth_schema_version": GROUND_TRUTH_SCHEMA_VERSION,
        "iterations": iterations,
        "deterministic": len(digests) == 1,
        "functional_sha256": next(iter(digests)) if len(digests) == 1 else "",
        "metrics": metrics,
        "error_counts": {
            name: {
                "true_positives": comparison["true_positive_count"],
                "false_positives": comparison["false_positive_count"],
                "false_negatives": comparison["false_negative_count"],
            }
            for name, comparison in comparisons.items()
        },
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "counts": {
            "actual_edges": len(actual_edges),
            "expected_edges": len(expected_edges),
            "actual_findings": len(actual_findings),
            "expected_findings": len(expected_findings),
            "actual_attack_events": len(actual_events),
            "expected_attack_events": len(expected_events),
            "actual_techniques": len(actual_techniques),
            "expected_techniques": len(expected_techniques),
            "events": len(last["events"]),
            "incidents": len(last["incidents"]),
        },
        "latency_ms": {
            "min": round(min(latencies), 4),
            "median": round(statistics.median(latencies), 4),
            "p95": round(_percentile(latencies, 0.95), 4),
            "max": round(max(latencies), 4),
        },
        "latency_is_environment_dependent": True,
    }
