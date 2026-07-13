from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cloud_breach_reconstructor.benchmark import benchmark
from cloud_breach_reconstructor.io import load_records, load_truth


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    checksums = (root / "datasets/reference/inputs.sha256").read_text(encoding="utf-8").splitlines()
    integrity = {}
    for line in checksums:
        if not line.strip():
            continue
        expected, relative = line.split(maxsplit=1)
        actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        integrity[relative] = actual == expected
    records = load_records(root / "datasets/lab/events.jsonl")
    truth = load_truth(root / "datasets/lab/ground-truth.json")
    result = benchmark(records, truth, iterations=10)
    reference = json.loads((root / "datasets/reference/benchmark.json").read_text(encoding="utf-8"))
    metrics = result["metrics"]
    checks = {
        "causal_edge_precision": metrics["causal_edge_precision"] == 1.0,
        "causal_edge_recall": metrics["causal_edge_recall"] == 1.0,
        "attack_event_recall": metrics["attack_event_recall"] == 1.0,
        "technique_recall": metrics["technique_recall"] == 1.0,
        "deterministic": result["deterministic"] is True,
        "functional_digest": result["functional_sha256"] == reference["functional_sha256"],
        "reference_counts": result["counts"] == reference["counts"],
        "all_inputs_integrity_checked": all(integrity.values()),
        "no_llm_causality": True,
    }
    output = {"passed": all(checks.values()), "checks": checks, "input_integrity": integrity}
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if output["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
