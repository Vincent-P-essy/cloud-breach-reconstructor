from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from .models import CanonicalEvent, CausalEdge

SESSION_WINDOW = timedelta(minutes=20)
REQUEST_WINDOW = timedelta(minutes=10)
RESOURCE_WINDOW = timedelta(minutes=30)


@dataclass(frozen=True, slots=True)
class Candidate:
    source: CanonicalEvent
    target: CanonicalEvent
    kind: str
    confidence: float
    evidence: tuple[str, ...]

    def edge(self) -> CausalEdge:
        return CausalEdge(
            source=self.source.event_id,
            target=self.target.event_id,
            kind=self.kind,
            confidence=self.confidence,
            evidence=self.evidence,
        )


def _before(left: CanonicalEvent, right: CanonicalEvent) -> bool:
    return (left.timestamp, left.event_id) < (right.timestamp, right.event_id)


def _within(left: CanonicalEvent, right: CanonicalEvent, window: timedelta) -> bool:
    return _before(left, right) and right.timestamp - left.timestamp <= window


def _nearest_predecessors(
    events: tuple[CanonicalEvent, ...],
    key: str,
    getter: object,
) -> dict[str, CanonicalEvent]:
    del events, key, getter
    return {}


def infer_edges(events: tuple[CanonicalEvent, ...]) -> tuple[CausalEdge, ...]:
    """Infer a conservative temporal DAG from explicit, credential, and scoped correlations."""
    ordered = tuple(sorted(events, key=lambda event: (event.timestamp, event.event_id)))
    by_id = {event.event_id: event for event in ordered}
    issued_credentials: dict[str, CanonicalEvent] = {}
    issued_identities: dict[str, CanonicalEvent] = {}
    last_session: dict[tuple[str, str, str], CanonicalEvent] = {}
    last_request: dict[tuple[str, str], CanonicalEvent] = {}
    last_mutation: dict[tuple[str, str, str], CanonicalEvent] = {}
    selected: dict[tuple[str, str], Candidate] = {}

    def select(candidate: Candidate) -> None:
        if not _before(candidate.source, candidate.target):
            return
        key = (candidate.source.event_id, candidate.target.event_id)
        existing = selected.get(key)
        if existing is None or candidate.confidence > existing.confidence:
            selected[key] = candidate

    for event in ordered:
        if event.parent_event_id:
            parent = by_id.get(event.parent_event_id)
            if parent is not None:
                select(
                    Candidate(
                        parent,
                        event,
                        "explicit-parent",
                        1.0,
                        (f"parent_event_id={event.parent_event_id}", "strict timestamp precedence"),
                    )
                )

        if event.credential_id:
            issuer = issued_credentials.pop(event.credential_id, None)
            if issuer is not None:
                select(
                    Candidate(
                        issuer,
                        event,
                        "credential-lineage",
                        0.98,
                        (
                            f"issued_credential={event.credential_id}",
                            "credential observed in target",
                        ),
                    )
                )

        issuer = issued_identities.pop(event.actor, None)
        if issuer is not None:
            select(
                Candidate(
                    issuer,
                    event,
                    "workload-identity-lineage",
                    0.97,
                    (f"issued_identity={event.actor}", "identity observed as target actor"),
                )
            )

        if event.request_id:
            request_key = (event.provider, event.request_id)
            predecessor = last_request.get(request_key)
            if predecessor is not None and _within(predecessor, event, REQUEST_WINDOW):
                select(
                    Candidate(
                        predecessor,
                        event,
                        "request-correlation",
                        0.95,
                        (f"request_id={event.request_id}", f"provider={event.provider}"),
                    )
                )
            last_request[request_key] = event

        if event.session_id:
            session_key = (event.provider, event.account_id, event.session_id)
            predecessor = last_session.get(session_key)
            if predecessor is not None and _within(predecessor, event, SESSION_WINDOW):
                select(
                    Candidate(
                        predecessor,
                        event,
                        "session-sequence",
                        0.86,
                        (
                            f"session_id={event.session_id}",
                            f"account_id={event.account_id or '<unknown>'}",
                            "nearest prior event in bounded window",
                        ),
                    )
                )
            last_session[session_key] = event

        if event.resource:
            resource_key = (event.provider, event.account_id, event.resource)
            predecessor = last_mutation.get(resource_key)
            if predecessor is not None and _within(predecessor, event, RESOURCE_WINDOW):
                select(
                    Candidate(
                        predecessor,
                        event,
                        "resource-lineage",
                        0.88,
                        (f"resource={event.resource}", "prior mutation followed by resource use"),
                    )
                )
            action = event.action.casefold()
            if any(term in action for term in ("create", "update", "write", "put", "deploy")):
                last_mutation[resource_key] = event

        issued_credential = event.attributes.get("issued_credential")
        if isinstance(issued_credential, str) and issued_credential:
            issued_credentials[issued_credential] = event
        issued_identity = event.attributes.get("issued_identity")
        if isinstance(issued_identity, str) and issued_identity:
            issued_identities[issued_identity] = event

    edges = [candidate.edge() for candidate in selected.values()]
    return tuple(sorted(edges, key=lambda edge: (edge.target, edge.source, edge.kind)))


def assert_dag(events: tuple[CanonicalEvent, ...], edges: tuple[CausalEdge, ...]) -> None:
    timestamps = {event.event_id: event.timestamp for event in events}
    graph: dict[str, list[str]] = defaultdict(list)
    indegree: dict[str, int] = {event.event_id: 0 for event in events}
    for edge in edges:
        if edge.source not in timestamps or edge.target not in timestamps:
            raise AssertionError("edge references an unknown event")
        if timestamps[edge.source] > timestamps[edge.target]:
            raise AssertionError("causal edge violates timestamp precedence")
        graph[edge.source].append(edge.target)
        indegree[edge.target] += 1
    queue = sorted(node for node, degree in indegree.items() if degree == 0)
    visited = 0
    while queue:
        node = queue.pop(0)
        visited += 1
        for child in graph[node]:
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)
                queue.sort()
    if visited != len(indegree):
        raise AssertionError("causal graph contains a cycle")
