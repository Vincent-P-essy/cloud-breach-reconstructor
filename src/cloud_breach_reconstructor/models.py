from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .errors import EvidenceError


def parse_timestamp(value: str) -> datetime:
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = f"{candidate[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as error:
        raise EvidenceError(f"invalid ISO-8601 timestamp: {value!r}") from error
    if parsed.tzinfo is None:
        raise EvidenceError("timestamps must contain an explicit UTC offset")
    return parsed.astimezone(timezone.utc)


def timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class CanonicalEvent:
    event_id: str
    timestamp: datetime
    provider: str
    source_type: str
    actor: str
    action: str
    resource: str
    outcome: str
    session_id: str = ""
    request_id: str = ""
    source_ip: str = ""
    credential_id: str = ""
    parent_event_id: str = ""
    account_id: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)
    raw_sha256: str = ""

    def __post_init__(self) -> None:
        required = {
            "event_id": self.event_id,
            "provider": self.provider,
            "source_type": self.source_type,
            "actor": self.actor,
            "action": self.action,
        }
        missing = [name for name, value in required.items() if not value.strip()]
        if missing:
            raise EvidenceError(f"missing canonical fields: {', '.join(sorted(missing))}")
        if self.outcome not in {"success", "failure", "unknown"}:
            raise EvidenceError(f"unsupported outcome: {self.outcome!r}")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["timestamp"] = timestamp_text(self.timestamp)
        return value


@dataclass(frozen=True, slots=True)
class CausalEdge:
    source: str
    target: str
    kind: str
    confidence: float
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "confidence": round(self.confidence, 4),
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    event_ids: tuple[str, ...]
    rationale: str
    confidence: float
    mitre_techniques: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["event_ids"] = list(self.event_ids)
        value["mitre_techniques"] = list(self.mitre_techniques)
        return value


@dataclass(frozen=True, slots=True)
class Incident:
    incident_id: str
    event_ids: tuple[str, ...]
    root_event_ids: tuple[str, ...]
    start: datetime
    end: datetime
    confidence: float
    risk_score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "event_ids": list(self.event_ids),
            "root_event_ids": list(self.root_event_ids),
            "start": timestamp_text(self.start),
            "end": timestamp_text(self.end),
            "confidence": round(self.confidence, 4),
            "risk_score": round(self.risk_score, 2),
        }


@dataclass(frozen=True, slots=True)
class Reconstruction:
    schema_version: str
    generated_at: str
    input_sha256: str
    events: tuple[CanonicalEvent, ...]
    edges: tuple[CausalEdge, ...]
    findings: tuple[Finding, ...]
    incidents: tuple[Incident, ...]
    attack_mapping: dict[str, tuple[str, ...]]
    blast_radius: dict[str, tuple[str, ...]]
    containment_actions: tuple[dict[str, str], ...]
    diagnostics: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "input_sha256": self.input_sha256,
            "events": [event.to_dict() for event in self.events],
            "edges": [edge.to_dict() for edge in self.edges],
            "findings": [finding.to_dict() for finding in self.findings],
            "incidents": [incident.to_dict() for incident in self.incidents],
            "attack_mapping": {key: list(value) for key, value in self.attack_mapping.items()},
            "blast_radius": {key: list(value) for key, value in self.blast_radius.items()},
            "containment_actions": [dict(item) for item in self.containment_actions],
            "diagnostics": self.diagnostics,
        }
