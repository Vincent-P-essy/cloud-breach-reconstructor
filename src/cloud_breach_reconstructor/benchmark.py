from __future__ import annotations

import hashlib
import json
import math
import statistics
import time
from collections.abc import Mapping, Sequence
from typing import Any

from .engine import reconstruct


def _functional_dict(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result.pop("generated_at", None)
    return result


def _digest(value: dict[str, Any]) -> str:
    canonical = json.dumps(_functional_dict(value), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    rank = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[rank]


def benchmark(
    records: Sequence[Mapping[str, Any]], truth: Mapping[str, Any], iterations: int = 50
) -> dict[str, Any]:
    if iterations < 1 or iterations > 1_000:
        raise ValueError("iterations must be between 1 and 1000")
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
    expected_edges = {
        (str(item["source"]), str(item["target"]))
        for item in truth.get("causal_edges", [])
        if isinstance(item, dict) and "source" in item and "target" in item
    }
    actual_edges = {(str(item["source"]), str(item["target"])) for item in last["edges"]}
    true_positive_edges = expected_edges & actual_edges
    precision = (
        len(true_positive_edges) / len(actual_edges) if actual_edges else float(not expected_edges)
    )
    recall = len(true_positive_edges) / len(expected_edges) if expected_edges else 1.0
    expected_events = {str(item) for item in truth.get("attack_event_ids", [])}
    mapped_events = set(last["attack_mapping"])
    event_recall = (
        len(expected_events & mapped_events) / len(expected_events) if expected_events else 1.0
    )
    expected_techniques = {str(item) for item in truth.get("techniques", [])}
    actual_techniques = {item for values in last["attack_mapping"].values() for item in values}
    technique_recall = (
        len(expected_techniques & actual_techniques) / len(expected_techniques)
        if expected_techniques
        else 1.0
    )
    return {
        "schema_version": "1.0",
        "iterations": iterations,
        "deterministic": len(digests) == 1,
        "functional_sha256": next(iter(digests)) if len(digests) == 1 else "",
        "metrics": {
            "causal_edge_precision": round(precision, 6),
            "causal_edge_recall": round(recall, 6),
            "false_link_rate": round(1.0 - precision, 6),
            "attack_event_recall": round(event_recall, 6),
            "technique_recall": round(technique_recall, 6),
        },
        "counts": {
            "actual_edges": len(actual_edges),
            "expected_edges": len(expected_edges),
            "events": len(last["events"]),
            "findings": len(last["findings"]),
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
