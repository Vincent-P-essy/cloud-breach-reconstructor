from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from .attack import ATTACK_KNOWLEDGE_DATE, techniques_for
from .causal import assert_dag, infer_edges
from .errors import EvidenceError, InputLimitError
from .models import CanonicalEvent, CausalEdge, Finding, Incident, Reconstruction, timestamp_text
from .normalize import normalize_record

MAX_EVENTS = 50_000
RECONSTRUCTION_SCHEMA_VERSION = "1.1"


def _input_digest(records: list[Mapping[str, Any]]) -> str:
    canonical = json.dumps(
        records,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def normalize_records(records: Iterable[Mapping[str, Any]]) -> tuple[CanonicalEvent, ...]:
    materialized = list(records)
    if len(materialized) > MAX_EVENTS:
        raise InputLimitError(f"input exceeds {MAX_EVENTS} events")
    events: dict[str, CanonicalEvent] = {}
    for record in materialized:
        event = normalize_record(record)
        existing = events.get(event.event_id)
        if (
            existing is not None
            and existing.canonical_record_sha256 != event.canonical_record_sha256
        ):
            raise EvidenceError(f"conflicting evidence for event_id {event.event_id!r}")
        events[event.event_id] = event
    return tuple(sorted(events.values(), key=lambda item: (item.timestamp, item.event_id)))


def _finding_key(prefix: str, event_ids: tuple[str, ...]) -> str:
    digest = hashlib.sha256("\x00".join(event_ids).encode()).hexdigest()[:12]
    return f"{prefix}-{digest}"


def _findings(events: tuple[CanonicalEvent, ...]) -> tuple[Finding, ...]:
    results: list[Finding] = []
    actor_geo: dict[str, str] = {}
    actor_ips: dict[str, set[str]] = defaultdict(set)
    for event in events:
        if event.outcome != "success":
            continue
        geo_value = event.attributes.get("geo")
        geo = geo_value if isinstance(geo_value, str) else ""
        prior_geo = actor_geo.get(event.actor)
        known_ips = actor_ips[event.actor]
        normalized_action = event.action.casefold().replace(" ", "")
        is_authentication = any(
            term in normalized_action for term in ("consolelogin", "signin", "login")
        )
        if (
            is_authentication
            and prior_geo
            and geo
            and geo != prior_geo
            and event.source_ip not in known_ips
        ):
            event_ids = (event.event_id,)
            results.append(
                Finding(
                    _finding_key("new-location", event_ids),
                    "Authentication from a new location",
                    "high",
                    event_ids,
                    f"actor moved from {prior_geo} to {geo} and used an unseen source address",
                    0.9,
                    ("T1078",),
                )
            )
        if geo:
            actor_geo[event.actor] = geo
        if event.source_ip:
            known_ips.add(event.source_ip)

        action = normalized_action
        event_ids = (event.event_id,)
        if "createaccesskey" in action or "credentials/write" in action:
            results.append(
                Finding(
                    _finding_key("credential", event_ids),
                    "New persistent cloud credential",
                    "critical",
                    event_ids,
                    "a principal created an additional credential",
                    0.98,
                    ("T1098.001",),
                )
            )
        if "getsecret" in action or "secrets/read" in action or "get:secrets" in action:
            results.append(
                Finding(
                    _finding_key("secret", event_ids),
                    "Secret material accessed",
                    "high",
                    event_ids,
                    "a secrets service returned or exposed secret material",
                    0.96,
                    ("T1555.006",),
                )
            )
        if event.attributes.get("privileged") is True:
            finding_techniques: tuple[str, ...] = ("T1610",)
            if "T1611" in techniques_for(event):
                finding_techniques = ("T1610", "T1611")
            results.append(
                Finding(
                    _finding_key("privileged", event_ids),
                    "Privileged Kubernetes workload created",
                    "critical",
                    event_ids,
                    "audit annotations identify a privileged workload request",
                    0.99,
                    finding_techniques,
                )
            )
        if "network:egress" in action or "flow:egress" in action:
            destination = event.attributes.get("destination")
            allowlisted = event.attributes.get("destination_allowlisted") is True
            if destination and not allowlisted and event.attributes.get("exfiltration") is True:
                finding_techniques = ("T1041",) if "T1041" in techniques_for(event) else ()
                results.append(
                    Finding(
                        _finding_key("egress", event_ids),
                        "Egress to a non-allowlisted destination",
                        "critical",
                        event_ids,
                        f"flow telemetry records outbound transfer to {destination}",
                        0.94,
                        finding_techniques,
                    )
                )
    return tuple(sorted(results, key=lambda item: (item.event_ids, item.finding_id)))


def _components(
    events: tuple[CanonicalEvent, ...],
    edges: tuple[CausalEdge, ...],
    findings: tuple[Finding, ...],
) -> tuple[Incident, ...]:
    suspicious = {event_id for finding in findings for event_id in finding.event_ids}
    neighbors: dict[str, set[str]] = defaultdict(set)
    incoming: dict[str, int] = defaultdict(int)
    for edge in edges:
        neighbors[edge.source].add(edge.target)
        neighbors[edge.target].add(edge.source)
        incoming[edge.target] += 1
    by_id = {event.event_id: event for event in events}
    finding_by_event: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        for event_id in finding.event_ids:
            finding_by_event[event_id].append(finding)
    remaining = set(suspicious)
    incidents: list[Incident] = []
    while remaining:
        root = min(remaining, key=lambda node: (by_id[node].timestamp, node))
        queue: deque[str] = deque([root])
        component: set[str] = set()
        while queue:
            node = queue.popleft()
            if node in component:
                continue
            component.add(node)
            queue.extend(sorted(neighbors[node] - component))
        remaining -= component & suspicious
        ordered_ids = tuple(sorted(component, key=lambda node: (by_id[node].timestamp, node)))
        severity_points = {"low": 8, "medium": 18, "high": 30, "critical": 42}
        points = sum(
            severity_points.get(finding.severity, 0)
            for event_id in component
            for finding in finding_by_event[event_id]
        )
        component_edges = [
            edge for edge in edges if edge.source in component and edge.target in component
        ]
        component_findings = [
            finding for event_id in component for finding in finding_by_event[event_id]
        ]
        confidence_values = [edge.confidence for edge in component_edges]
        confidence_values.extend(finding.confidence for finding in component_findings)
        confidence = sum(confidence_values) / len(confidence_values)
        digest = hashlib.sha256("\x00".join(ordered_ids).encode()).hexdigest()[:12]
        incidents.append(
            Incident(
                incident_id=f"incident-{digest}",
                event_ids=ordered_ids,
                root_event_ids=tuple(node for node in ordered_ids if incoming[node] == 0),
                start=by_id[ordered_ids[0]].timestamp,
                end=by_id[ordered_ids[-1]].timestamp,
                confidence=confidence,
                risk_score=min(100.0, points + min(20, len(component_edges) * 2)),
            )
        )
    return tuple(sorted(incidents, key=lambda item: (item.start, item.incident_id)))


def _containment(
    findings: tuple[Finding, ...], events: tuple[CanonicalEvent, ...]
) -> tuple[dict[str, str], ...]:
    by_id = {event.event_id: event for event in events}
    actions: dict[tuple[str, str], dict[str, str]] = {}

    def add(kind: str, scope: str, action: dict[str, str]) -> None:
        actions.setdefault((kind, scope), action)

    ordered_findings = sorted(
        findings,
        key=lambda finding: (
            by_id[finding.event_ids[0]].timestamp,
            finding.event_ids[0],
            finding.finding_id,
        ),
    )
    for finding in ordered_findings:
        event = by_id[finding.event_ids[0]]
        if "T1098.001" in finding.mitre_techniques:
            issued = event.attributes.get("issued_credential")
            scope = issued if isinstance(issued, str) and issued else event.actor
            add(
                "revoke-credential",
                scope,
                {
                    "priority": "P0",
                    "action": (
                        "Disable the newly created credential and invalidate derived sessions"
                    ),
                    "scope": scope,
                    "evidence_event": event.event_id,
                },
            )
        if "T1555.006" in finding.mitre_techniques:
            scope = event.resource or event.actor
            add(
                "rotate-secret",
                scope,
                {
                    "priority": "P0",
                    "action": "Rotate accessed secrets after confirming dependent service owners",
                    "scope": scope,
                    "evidence_event": event.event_id,
                },
            )
        if finding.title == "Privileged Kubernetes workload created":
            scope = event.resource or event.actor
            add(
                "isolate-workload",
                scope,
                {
                    "priority": "P0",
                    "action": "Isolate and preserve the privileged workload before node triage",
                    "scope": scope,
                    "evidence_event": event.event_id,
                },
            )
        if finding.title == "Egress to a non-allowlisted destination":
            scope = str(event.attributes.get("destination", event.resource))
            add(
                "block-egress",
                scope,
                {
                    "priority": "P1",
                    "action": "Block the evidenced destination and retain flow telemetry",
                    "scope": scope,
                    "evidence_event": event.event_id,
                },
            )
    return tuple(
        sorted(
            actions.values(),
            key=lambda item: (item["priority"], item["action"], item["scope"]),
        )
    )


def reconstruct(records: Iterable[Mapping[str, Any]]) -> Reconstruction:
    materialized = list(records)
    events = normalize_records(materialized)
    edges = infer_edges(events)
    assert_dag(events, edges)
    findings = _findings(events)
    mappings = {event.event_id: techniques_for(event) for event in events if techniques_for(event)}
    incidents = _components(events, edges, findings)
    incident_event_ids = {event_id for incident in incidents for event_id in incident.event_ids}
    incident_context = [event for event in events if event.event_id in incident_event_ids]
    blast_radius = {
        "accounts": tuple(
            sorted({event.account_id for event in incident_context if event.account_id})
        ),
        "actors": tuple(sorted({event.actor for event in incident_context})),
        "credentials": tuple(
            sorted({event.credential_id for event in incident_context if event.credential_id})
        ),
        "resources": tuple(
            sorted({event.resource for event in incident_context if event.resource})
        ),
        "providers": tuple(sorted({event.provider for event in incident_context})),
    }
    return Reconstruction(
        schema_version=RECONSTRUCTION_SCHEMA_VERSION,
        generated_at=timestamp_text(datetime.now(timezone.utc)),
        input_sha256=_input_digest(materialized),
        events=events,
        edges=edges,
        findings=findings,
        incidents=incidents,
        attack_mapping=mappings,
        blast_radius=blast_radius,
        containment_actions=_containment(findings, events),
        diagnostics={
            "attack_knowledge_date": ATTACK_KNOWLEDGE_DATE,
            "causality_engine": "deterministic-v1",
            "deduplicated_event_count": len(events),
            "input_record_count": len(materialized),
            "strict_temporal_precedence": True,
            "llm_used_for_causality": False,
        },
    )
