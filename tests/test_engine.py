from __future__ import annotations

import unittest

from cloud_breach_reconstructor.attack import techniques_for, title_for
from cloud_breach_reconstructor.causal import assert_dag
from cloud_breach_reconstructor.engine import normalize_records, reconstruct
from cloud_breach_reconstructor.errors import EvidenceError, InputLimitError
from cloud_breach_reconstructor.models import CausalEdge

from .helpers import canonical, lab_records


class EngineTests(unittest.TestCase):
    def test_reference_reconstruction_counts_and_dag(self) -> None:
        report = reconstruct(lab_records())
        self.assertEqual(
            (21, 16, 10, 2),
            (len(report.events), len(report.edges), len(report.findings), len(report.incidents)),
        )
        assert_dag(report.events, report.edges)

    def test_reference_has_expected_typed_edges(self) -> None:
        edges = {(edge.source, edge.target): edge for edge in reconstruct(lab_records()).edges}
        self.assertEqual("credential-lineage", edges[("e03", "e04")].kind)
        self.assertEqual("explicit-parent", edges[("e08", "k01")].kind)
        self.assertEqual("resource-lineage", edges[("k01", "k03")].kind)
        self.assertEqual("workload-identity-lineage", edges[("az03", "az04")].kind)

    def test_session_is_bounded_and_scoped_by_provider_account(self) -> None:
        records = [
            canonical("a", "2026-07-12T10:00:00Z", session_id="same"),
            canonical("b", "2026-07-12T10:01:00Z", provider="azure", session_id="same"),
            canonical("c", "2026-07-12T10:02:00Z", account_id="2", session_id="same"),
            canonical("d", "2026-07-12T11:00:00Z", session_id="same"),
        ]
        self.assertEqual((), reconstruct(records).edges)

    def test_request_correlation_uses_nearest_predecessor(self) -> None:
        records = [
            canonical("a", "2026-07-12T10:00:00Z", request_id="r"),
            canonical("b", "2026-07-12T10:01:00Z", request_id="r"),
            canonical("c", "2026-07-12T10:02:00Z", request_id="r"),
        ]
        edges = reconstruct(records).edges
        self.assertEqual({("a", "b"), ("b", "c")}, {(edge.source, edge.target) for edge in edges})
        self.assertTrue(all(edge.kind == "request-correlation" for edge in edges))

    def test_credential_lineage_connects_only_first_use(self) -> None:
        records = [
            canonical("a", "2026-07-12T10:00:00Z", attributes={"issued_credential": "new"}),
            canonical("b", "2026-07-12T10:01:00Z", credential_id="new"),
            canonical("c", "2026-07-12T10:02:00Z", credential_id="new"),
        ]
        self.assertEqual(
            {("a", "b")}, {(edge.source, edge.target) for edge in reconstruct(records).edges}
        )

    def test_workload_identity_connects_only_first_use(self) -> None:
        records = [
            canonical("a", "2026-07-12T10:00:00Z", attributes={"issued_identity": "workload"}),
            canonical("b", "2026-07-12T10:01:00Z", actor="workload"),
            canonical("c", "2026-07-12T10:02:00Z", actor="workload"),
        ]
        self.assertEqual(
            {("a", "b")}, {(edge.source, edge.target) for edge in reconstruct(records).edges}
        )

    def test_unknown_explicit_parent_is_not_invented(self) -> None:
        report = reconstruct([canonical("a", "2026-07-12T10:00:00Z", parent_event_id="missing")])
        self.assertEqual((), report.edges)

    def test_same_pair_retains_strongest_rule(self) -> None:
        records = [
            canonical("a", "2026-07-12T10:00:00Z", session_id="s"),
            canonical("b", "2026-07-12T10:01:00Z", session_id="s", parent_event_id="a"),
        ]
        edge = reconstruct(records).edges[0]
        self.assertEqual("explicit-parent", edge.kind)
        self.assertEqual(1.0, edge.confidence)

    def test_deduplication_and_conflicting_duplicate_detection(self) -> None:
        record = canonical("a", "2026-07-12T10:00:00Z")
        self.assertEqual(1, len(normalize_records([record, dict(record)])))
        changed = dict(record)
        changed["action"] = "different"
        with self.assertRaises(EvidenceError):
            normalize_records([record, changed])

    def test_input_event_limit(self) -> None:
        class TooMany:
            def __iter__(self):
                for _ in range(50_001):
                    yield {}

        with self.assertRaises(InputLimitError):
            normalize_records(TooMany())

    def test_assert_dag_rejects_unknown_reverse_and_cycle(self) -> None:
        events = normalize_records(
            [
                canonical("a", "2026-07-12T10:00:00Z"),
                canonical("b", "2026-07-12T10:01:00Z"),
            ]
        )
        with self.assertRaises(AssertionError):
            assert_dag(events, (CausalEdge("missing", "b", "x", 1, ()),))
        with self.assertRaises(AssertionError):
            assert_dag(events, (CausalEdge("b", "a", "x", 1, ()),))
        with self.assertRaises(AssertionError):
            assert_dag(events, (CausalEdge("a", "b", "x", 1, ()), CausalEdge("b", "a", "x", 1, ())))

    def test_findings_include_location_secret_privileged_and_egress(self) -> None:
        titles = {finding.title for finding in reconstruct(lab_records()).findings}
        self.assertIn("Authentication from a new location", titles)
        self.assertIn("Secret material accessed", titles)
        self.assertIn("Privileged Kubernetes workload created", titles)
        self.assertIn("Egress to a non-allowlisted destination", titles)

    def test_allowlisted_egress_has_no_finding(self) -> None:
        record = canonical(
            "a",
            "2026-07-12T10:00:00Z",
            action="network:egress",
            attributes={"destination": "updates.example.test", "destination_allowlisted": True},
        )
        self.assertEqual((), reconstruct([record]).findings)

    def test_attack_mapping_and_titles(self) -> None:
        event = normalize_records(
            [
                canonical(
                    "a",
                    "2026-07-12T10:00:00Z",
                    action="create:pods",
                    attributes={"privileged": True},
                )
            ]
        )[0]
        self.assertEqual(("T1610", "T1611"), techniques_for(event))
        self.assertEqual("Deploy Container", title_for("T1610"))
        self.assertEqual("T0000", title_for("T0000"))

    def test_blast_radius_and_containment_are_evidence_scoped(self) -> None:
        report = reconstruct(lab_records())
        self.assertEqual(("aws", "azure", "kubernetes"), report.blast_radius["providers"])
        actions = {item["action"] for item in report.containment_actions}
        self.assertEqual(4, len(actions))
        self.assertTrue(any("Disable" in item for item in actions))

    def test_report_dictionary_is_json_safe(self) -> None:
        value = reconstruct(lab_records()).to_dict()
        self.assertEqual("1.0", value["schema_version"])
        self.assertFalse(value["diagnostics"]["llm_used_for_causality"])
        self.assertIsInstance(value["events"][0]["timestamp"], str)
