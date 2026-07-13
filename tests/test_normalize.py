from __future__ import annotations

import unittest

from cloud_breach_reconstructor.errors import EvidenceError
from cloud_breach_reconstructor.models import CanonicalEvent, parse_timestamp, timestamp_text
from cloud_breach_reconstructor.normalize import detect_format, normalize_record

from .helpers import canonical


class NormalizationTests(unittest.TestCase):
    def test_timestamp_normalizes_to_utc(self) -> None:
        self.assertEqual(
            "2026-07-12T08:00:00.000Z", timestamp_text(parse_timestamp("2026-07-12T10:00:00+02:00"))
        )

    def test_naive_and_invalid_timestamps_fail_closed(self) -> None:
        for value in ("2026-07-12T10:00:00", "not-a-date"):
            with self.subTest(value=value), self.assertRaises(EvidenceError):
                parse_timestamp(value)

    def test_normalized_record(self) -> None:
        event = normalize_record(canonical("n1", "2026-07-12T10:00:00Z"))
        self.assertEqual("n1", event.event_id)
        self.assertEqual("aws", event.provider)
        self.assertEqual(64, len(event.raw_sha256))

    def test_normalized_provider_and_attributes_are_bounded(self) -> None:
        with self.assertRaises(EvidenceError):
            normalize_record(canonical("n1", "2026-07-12T10:00:00Z", provider="gcp"))
        with self.assertRaises(EvidenceError):
            normalize_record(canonical("n2", "2026-07-12T10:00:00Z", attributes=[]))
        with self.assertRaises(EvidenceError):
            normalize_record(
                canonical("n3", "2026-07-12T10:00:00Z", attributes={str(i): i for i in range(129)})
            )

    def test_missing_canonical_fields_and_outcome_fail(self) -> None:
        with self.assertRaises(EvidenceError):
            normalize_record(canonical("", "2026-07-12T10:00:00Z"))
        with self.assertRaises(EvidenceError):
            CanonicalEvent(
                "x",
                parse_timestamp("2026-07-12T10:00:00Z"),
                "aws",
                "test",
                "a",
                "b",
                "r",
                "invalid",
            )

    def test_aws_cloudtrail_adapter_extracts_credential_lineage(self) -> None:
        raw = {
            "eventID": "aws-1",
            "eventTime": "2026-07-12T10:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "eventType": "AwsApiCall",
            "sourceIPAddress": "192.0.2.1",
            "requestID": "req-1",
            "recipientAccountId": "123",
            "userIdentity": {"arn": "arn:aws:iam::123:user/a", "accessKeyId": "OLD"},
            "requestParameters": {"userName": "a"},
            "responseElements": {"accessKey": {"accessKeyId": "NEW"}},
            "readOnly": False,
        }
        event = normalize_record(raw)
        self.assertEqual("aws", detect_format(raw))
        self.assertEqual("NEW", event.attributes["issued_credential"])
        self.assertEqual("OLD", event.credential_id)
        self.assertEqual("a", event.resource)
        self.assertEqual("success", event.outcome)

    def test_aws_adapter_extracts_resource_and_failure(self) -> None:
        raw = {
            "eventID": "aws-2",
            "eventTime": "2026-07-12T10:00:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "sourceIPAddress": "192.0.2.1",
            "errorCode": "AccessDenied",
            "resources": [{"ARN": "arn:aws:s3:::bucket/key"}],
            "userIdentity": {"principalId": "principal"},
        }
        event = normalize_record(raw)
        self.assertEqual("failure", event.outcome)
        self.assertEqual("arn:aws:s3:::bucket/key", event.resource)

    def test_aws_adapter_handles_assumed_role_and_issued_identity(self) -> None:
        raw = {
            "eventID": "aws-3",
            "eventTime": "2026-07-12T10:00:00Z",
            "eventSource": "sts.amazonaws.com",
            "eventName": "AssumeRole",
            "userIdentity": {"sessionContext": {"sessionIssuer": {"arn": "arn:issuer"}}},
            "responseElements": {
                "issuedIdentity": "workload",
                "credentials": {"accessKeyId": "TEMP"},
            },
        }
        event = normalize_record(raw)
        self.assertEqual("arn:issuer", event.actor)
        self.assertEqual("workload", event.attributes["issued_identity"])
        self.assertEqual("TEMP", event.attributes["issued_credential"])

    def test_azure_activity_adapter(self) -> None:
        raw = {
            "eventDataId": "az-1",
            "eventTimestamp": "2026-07-12T10:00:00Z",
            "correlationId": "corr-1",
            "caller": "alice@example.test",
            "callerIpAddress": "192.0.2.2",
            "operationName": {"value": "Microsoft.KeyVault/vaults/secrets/read"},
            "resourceId": "/vault/secret",
            "subscriptionId": "sub",
            "status": {"value": "Succeeded"},
            "claims": {"sid": "session"},
            "properties": {"issuedIdentity": "spn:test", "issuedCredential": "cred"},
        }
        event = normalize_record(raw)
        self.assertEqual("azure", detect_format(raw))
        self.assertEqual("success", event.outcome)
        self.assertEqual("corr-1", event.request_id)
        self.assertEqual("spn:test", event.attributes["issued_identity"])

    def test_azure_adapter_fallbacks_and_failure(self) -> None:
        raw = {
            "id": "az-2",
            "eventTimestamp": "2026-07-12T10:00:00Z",
            "correlationId": "corr",
            "operationName": {"localizedValue": "write"},
            "resourceUri": "/resource",
            "status": {"localizedValue": "Failed"},
            "claims": {"oid": "object-id"},
            "properties": {"ipAddress": "192.0.2.3", "credentialId": "c"},
        }
        event = normalize_record(raw)
        self.assertEqual("object-id", event.actor)
        self.assertEqual("failure", event.outcome)
        self.assertEqual("c", event.credential_id)

    def test_kubernetes_audit_adapter(self) -> None:
        raw = {
            "auditID": "audit-1",
            "stage": "ResponseComplete",
            "stageTimestamp": "2026-07-12T10:00:00Z",
            "verb": "create",
            "user": {"username": "system:serviceaccount:prod:ci"},
            "sourceIPs": ["192.0.2.4"],
            "objectRef": {"namespace": "prod", "resource": "pods", "name": "demo"},
            "responseStatus": {"code": 201},
            "annotations": {
                "cloud.example/parent-event-id": "aws-1",
                "cloud.example/session-id": "session",
                "cloud.example/account-id": "cluster",
                "security.example/privileged": "true",
            },
        }
        event = normalize_record(raw)
        self.assertEqual("kubernetes", detect_format(raw))
        self.assertEqual("audit-1:ResponseComplete", event.event_id)
        self.assertEqual("prod/pods/demo", event.resource)
        self.assertTrue(event.attributes["privileged"])
        self.assertEqual("aws-1", event.parent_event_id)

    def test_kubernetes_failure_and_timestamp_fallback(self) -> None:
        raw = {
            "auditID": "audit-2",
            "requestReceivedTimestamp": "2026-07-12T10:00:00Z",
            "verb": "get",
            "user": {"username": "user"},
            "objectRef": {"resource": "secrets"},
            "responseStatus": {"code": 403},
        }
        event = normalize_record(raw)
        self.assertEqual("failure", event.outcome)
        self.assertEqual("audit-2:unknown", event.event_id)

    def test_unknown_format_and_non_serializable_record_fail(self) -> None:
        with self.assertRaises(EvidenceError):
            detect_format({"hello": "world"})
        with self.assertRaises(EvidenceError):
            normalize_record({"event_id": "x", "timestamp": {1, 2}})
