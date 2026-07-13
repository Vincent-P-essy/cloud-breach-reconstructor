from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .api import serve
from .benchmark import benchmark
from .engine import reconstruct
from .errors import EvidenceError
from .io import load_records, load_truth
from .reporting import write_bundle


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud-breach", description="Evidence-first cloud incident reconstruction"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="reconstruct an evidence file")
    analyze.add_argument("evidence", type=Path)
    analyze.add_argument("--output", type=Path, default=Path("reports/latest"))
    analyze.add_argument("--stdout", action="store_true")

    validate = commands.add_parser("validate", help="validate and summarize evidence")
    validate.add_argument("evidence", type=Path)

    measure = commands.add_parser("benchmark", help="compare against labeled ground truth")
    measure.add_argument("evidence", type=Path)
    measure.add_argument("--truth", type=Path, required=True)
    measure.add_argument("--iterations", type=int, default=50)
    measure.add_argument("--output", type=Path)
    measure.add_argument("--fail-under", type=float, default=0.0)

    server = commands.add_parser("serve", help="serve local API and dashboard")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8080)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "serve":
            serve(arguments.host, arguments.port)
            return 0
        records = load_records(arguments.evidence)
        if arguments.command == "analyze":
            report = reconstruct(records)
            manifest = write_bundle(report, arguments.output)
            value = (
                report.to_dict()
                if arguments.stdout
                else {
                    "events": len(report.events),
                    "edges": len(report.edges),
                    "findings": len(report.findings),
                    "incidents": len(report.incidents),
                    "output": str(arguments.output),
                    "artifacts": manifest,
                }
            )
            print(json.dumps(value, indent=2, sort_keys=True))
            return 0
        if arguments.command == "validate":
            report = reconstruct(records)
            print(
                json.dumps(
                    {
                        "valid": True,
                        "events": len(report.events),
                        "edges": len(report.edges),
                        "input_sha256": report.input_sha256,
                        "strict_temporal_precedence": True,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        truth = load_truth(arguments.truth)
        result = benchmark(records, truth, arguments.iterations)
        text = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if arguments.output:
            arguments.output.parent.mkdir(parents=True, exist_ok=True)
            arguments.output.write_text(text, encoding="utf-8")
        print(text, end="")
        minimum = min(
            result["metrics"]["causal_edge_precision"],
            result["metrics"]["causal_edge_recall"],
            result["metrics"]["attack_event_recall"],
            result["metrics"]["technique_recall"],
        )
        return 0 if result["deterministic"] and minimum >= arguments.fail_under else 3
    except (EvidenceError, OSError, ValueError) as error:
        print(json.dumps({"error": type(error).__name__, "message": str(error)}), file=sys.stderr)
        return 2
