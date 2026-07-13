from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cloud_breach_reconstructor.benchmark import QUALITY_METRICS, benchmark
from cloud_breach_reconstructor.engine import reconstruct
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
    report = reconstruct(records)
    unlabeled_records = json.loads(json.dumps(records))
    for record in unlabeled_records:
        attributes = record.get("attributes")
        if isinstance(attributes, dict):
            attributes.pop("label", None)
    unlabeled_report = reconstruct(unlabeled_records)
    analytical_fields = (
        "edges",
        "findings",
        "incidents",
        "attack_mapping",
        "blast_radius",
        "containment_actions",
    )
    report_value = report.to_dict()
    unlabeled_value = unlabeled_report.to_dict()
    reference = json.loads((root / "datasets/reference/benchmark.json").read_text(encoding="utf-8"))
    metrics = result["metrics"]
    checks = {
        **{name: metrics[name] == 1.0 for name in QUALITY_METRICS},
        "deterministic": result["deterministic"] is True,
        "functional_digest": result["functional_sha256"] == reference["functional_sha256"],
        "reference_counts": result["counts"] == reference["counts"],
        "reference_schema": result["schema_version"] == reference["schema_version"],
        "no_false_positives": all(not values for values in result["false_positives"].values()),
        "all_inputs_integrity_checked": all(integrity.values()),
        "packaged_events_match": (root / "datasets/lab/events.jsonl").read_bytes()
        == (root / "src/cloud_breach_reconstructor/data/lab-events.jsonl").read_bytes(),
        "packaged_truth_matches": (root / "datasets/lab/ground-truth.json").read_bytes()
        == (root / "src/cloud_breach_reconstructor/data/lab-ground-truth.json").read_bytes(),
        "no_llm_causality": report.diagnostics["llm_used_for_causality"] is False,
        "strict_temporal_precedence": report.diagnostics["strict_temporal_precedence"] is True,
        "labels_not_used_for_analysis": all(
            report_value[field] == unlabeled_value[field] for field in analytical_fields
        ),
    }
    output = {"passed": all(checks.values()), "checks": checks, "input_integrity": integrity}
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if output["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
