from __future__ import annotations

import csv
import hashlib
import html
import json
from pathlib import Path
from typing import Any

from .attack import title_for
from .models import Reconstruction


def _json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"


def _markdown_text(value: Any) -> str:
    text = html.escape(str(value), quote=False)
    return text.replace("|", "&#124;").replace("\r", " ").replace("\n", "<br>")


def _dot_quote(value: Any) -> str:
    escaped: list[str] = []
    for character in str(value):
        if character == "\\":
            escaped.append("\\\\")
        elif character == '"':
            escaped.append('\\"')
        elif character == "\n":
            escaped.append("\\n")
        elif character == "\r":
            escaped.append("\\r")
        elif character == "\t":
            escaped.append("\\t")
        elif ord(character) < 32 or ord(character) == 127:
            escaped.append(f"\\u{ord(character):04x}")
        else:
            escaped.append(character)
    return f'"{"".join(escaped)}"'


def _csv_cell(value: Any) -> str:
    text = str(value)
    candidate = text.lstrip()
    if text.startswith(("=", "+", "-", "@", "\t", "\r", "\n")) or candidate.startswith(
        ("=", "+", "-", "@")
    ):
        return f"'{text}"
    return text


def executive_markdown(report: Reconstruction) -> str:
    highest = max((incident.risk_score for incident in report.incidents), default=0.0)
    techniques = sorted({item for values in report.attack_mapping.values() for item in values})
    lines = [
        "# Cloud incident executive report",
        "",
        f"- Evidence events: **{len(report.events)}**",
        f"- Causal links: **{len(report.edges)}**",
        f"- Reconstructed incidents: **{len(report.incidents)}**",
        f"- Highest incident risk: **{highest:.1f}/100**",
        f"- Providers in blast radius: **{', '.join(report.blast_radius['providers']) or 'none'}**",
        "",
        "## Business interpretation",
        "",
        "The engine linked only evidence satisfying bounded, typed correlation rules. "
        "A link is an analytical hypothesis with an exposed confidence score, not proof of intent.",
        "",
        "## ATT&CK coverage",
        "",
    ]
    lines.extend(f"- `{item}` — {title_for(item)}" for item in techniques)
    lines.extend(["", "## Recommended containment", ""])
    if report.containment_actions:
        lines.extend(
            f"- **{action['priority']}** — {_markdown_text(action['action'])} "
            f"({_markdown_text(action['scope'])})"
            for action in report.containment_actions
        )
    else:
        lines.append("- No deterministic containment action was triggered.")
    lines.extend(
        [
            "",
            "## Important limitation",
            "",
            "No language model determined causality. Missing logs, clock drift, shared "
            "identities, and "
            "provider-specific semantics can still hide or misattribute activity.",
            "",
        ]
    )
    return "\n".join(lines)


def technical_markdown(report: Reconstruction) -> str:
    lines = [
        "# Cloud incident technical report",
        "",
        f"Input SHA-256: `{report.input_sha256}`",
        "",
        "## Timeline",
        "",
        "| UTC | Provider | Actor | Action | Resource | ATT&CK |",
        "|---|---|---|---|---|---|",
    ]
    for event in report.events:
        techniques = ", ".join(report.attack_mapping.get(event.event_id, ()))
        lines.append(
            f"| {event.to_dict()['timestamp']} | {_markdown_text(event.provider)} | "
            f"{_markdown_text(event.actor)} | {_markdown_text(event.action)} | "
            f"{_markdown_text(event.resource)} | {_markdown_text(techniques)} |"
        )
    lines.extend(["", "## Typed causal links", ""])
    for edge in report.edges:
        maximum = (
            f"{edge.max_time_delta_ms} ms" if edge.max_time_delta_ms is not None else "unbounded"
        )
        lines.append(
            f"- {_markdown_text(edge.source)} → {_markdown_text(edge.target)}: "
            f"**{_markdown_text(edge.kind)}**, confidence {edge.confidence:.2f}; "
            f"delta {edge.time_delta_ms} ms, maximum {maximum}; "
            f"{_markdown_text('; '.join(edge.evidence))}"
        )
    lines.extend(["", "## Findings", ""])
    for finding in report.findings:
        lines.append(
            f"- **{finding.severity.upper()}** {_markdown_text(finding.title)}: "
            f"{_markdown_text(finding.rationale)} "
            f"(confidence {finding.confidence:.2f})"
        )
    lines.extend(["", "## Blast radius", ""])
    for kind, values in report.blast_radius.items():
        lines.append(f"- {_markdown_text(kind)}: {_markdown_text(', '.join(values) or 'none')}")
    lines.append("")
    return "\n".join(lines)


def graph_dot(report: Reconstruction) -> str:
    lines = ["digraph incident {", "  rankdir=LR;", '  graph [bgcolor="transparent"];']
    mapped = set(report.attack_mapping)
    for event in report.events:
        color = "#ef4444" if event.event_id in mapped else "#64748b"
        label = f"{event.event_id}\n{event.provider}\n{event.action}"
        lines.append(
            f"  {_dot_quote(event.event_id)} "
            f"[label={_dot_quote(label)}, color={_dot_quote(color)}];"
        )
    for edge in report.edges:
        lines.append(
            f"  {_dot_quote(edge.source)} -> {_dot_quote(edge.target)} "
            f"[label={_dot_quote(f'{edge.kind} {edge.confidence:.2f}')}];"
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def write_bundle(report: Reconstruction, output: Path) -> dict[str, str]:
    output.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "reconstruction.json": _json(report.to_dict()),
        "executive-report.md": executive_markdown(report),
        "technical-report.md": technical_markdown(report),
        "causal-graph.dot": graph_dot(report),
    }
    for name, value in artifacts.items():
        (output / name).write_text(value, encoding="utf-8")
    timeline_path = output / "timeline.csv"
    with timeline_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "event_id",
                "timestamp",
                "provider",
                "actor",
                "action",
                "resource",
                "outcome",
                "techniques",
            ]
        )
        for event in report.events:
            writer.writerow(
                [
                    _csv_cell(event.event_id),
                    _csv_cell(event.to_dict()["timestamp"]),
                    _csv_cell(event.provider),
                    _csv_cell(event.actor),
                    _csv_cell(event.action),
                    _csv_cell(event.resource),
                    _csv_cell(event.outcome),
                    _csv_cell(";".join(report.attack_mapping.get(event.event_id, ()))),
                ]
            )
    names = sorted((*artifacts, "timeline.csv"))
    manifest = {name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in names}
    (output / "manifest.sha256.json").write_text(_json(manifest), encoding="utf-8")
    return manifest
