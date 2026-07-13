from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .errors import EvidenceError
from .models import CanonicalEvent, parse_timestamp

SUPPORTED_PROVIDERS = frozenset({"aws", "azure", "kubernetes", "normalized"})
MAX_RECORD_BYTES = 1_000_000
MAX_ATTRIBUTES = 128


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str | int | float | bool):
        return str(value)
    return ""


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _canonical_bytes(record: Mapping[str, Any]) -> bytes:
    try:
        value = json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    except (TypeError, ValueError) as error:
        raise EvidenceError("record is not JSON serializable") from error
    if len(value) > MAX_RECORD_BYTES:
        raise EvidenceError(f"record exceeds {MAX_RECORD_BYTES} bytes")
    return value


def _outcome(value: str, *, failed: bool = False) -> str:
    if failed:
        return "failure"
    lowered = value.casefold()
    if lowered in {"success", "succeeded", "ok", "allowed", "200", "201", "202"}:
        return "success"
    if lowered in {"failure", "failed", "error", "denied", "forbidden", "401", "403"}:
        return "failure"
    return "unknown"


def _resource_from_aws(record: Mapping[str, Any]) -> str:
    resources = record.get("resources")
    if isinstance(resources, list) and resources and isinstance(resources[0], Mapping):
        return _text(resources[0].get("ARN") or resources[0].get("arn"))
    request = _mapping(record.get("requestParameters"))
    for key in (
        "secretId",
        "resourceArn",
        "functionName",
        "roleName",
        "bucketName",
        "clusterName",
        "userName",
    ):
        if _text(request.get(key)):
            return _text(request.get(key))
    return _text(record.get("recipientAccountId"))


def _normalize_aws(record: Mapping[str, Any], digest: str) -> CanonicalEvent:
    identity = _mapping(record.get("userIdentity"))
    session_context = _mapping(identity.get("sessionContext"))
    issuer = _mapping(session_context.get("sessionIssuer"))
    response = _mapping(record.get("responseElements"))
    access_key = _mapping(response.get("accessKey"))
    credentials = _mapping(response.get("credentials"))
    attributes: dict[str, Any] = {
        "event_source": _text(record.get("eventSource")),
        "event_type": _text(record.get("eventType")),
        "user_agent": _text(record.get("userAgent")),
        "read_only": record.get("readOnly"),
    }
    issued = _text(access_key.get("accessKeyId") or credentials.get("accessKeyId"))
    if issued:
        attributes["issued_credential"] = issued
    issued_identity = _text(response.get("issuedIdentity"))
    if issued_identity:
        attributes["issued_identity"] = issued_identity
    additions = _mapping(record.get("additionalEventData"))
    if additions:
        attributes["additional_event_data"] = dict(additions)
    return CanonicalEvent(
        event_id=_text(record.get("eventID")),
        timestamp=parse_timestamp(_text(record.get("eventTime"))),
        provider="aws",
        source_type="cloudtrail",
        actor=_text(identity.get("arn") or identity.get("principalId") or issuer.get("arn")),
        action=f"{_text(record.get('eventSource'))}:{_text(record.get('eventName'))}",
        resource=_resource_from_aws(record),
        outcome=_outcome("success", failed=bool(record.get("errorCode"))),
        session_id=_text(identity.get("accessKeyId") or record.get("sharedEventID")),
        request_id=_text(record.get("requestID")),
        source_ip=_text(record.get("sourceIPAddress")),
        credential_id=_text(identity.get("accessKeyId")),
        account_id=_text(record.get("recipientAccountId") or identity.get("accountId")),
        attributes=attributes,
        raw_sha256=digest,
    )


def _normalize_azure(record: Mapping[str, Any], digest: str) -> CanonicalEvent:
    operation = _mapping(record.get("operationName"))
    status = _mapping(record.get("status"))
    claims = _mapping(record.get("claims"))
    properties = _mapping(record.get("properties"))
    authorization = _mapping(record.get("authorization"))
    event_id = _text(record.get("eventDataId") or record.get("id"))
    actor = _text(record.get("caller") or claims.get("name") or claims.get("oid"))
    action = _text(
        operation.get("value") or operation.get("localizedValue") or record.get("operationName")
    )
    attributes: dict[str, Any] = {
        "category": _text(record.get("category")),
        "subscription_id": _text(record.get("subscriptionId")),
        "authorization_action": _text(authorization.get("action")),
    }
    if _text(properties.get("issuedCredential")):
        attributes["issued_credential"] = _text(properties.get("issuedCredential"))
    if _text(properties.get("issuedIdentity")):
        attributes["issued_identity"] = _text(properties.get("issuedIdentity"))
    return CanonicalEvent(
        event_id=event_id,
        timestamp=parse_timestamp(_text(record.get("eventTimestamp") or record.get("time"))),
        provider="azure",
        source_type="activity-log",
        actor=actor,
        action=action,
        resource=_text(record.get("resourceId") or record.get("resourceUri")),
        outcome=_outcome(_text(status.get("value") or status.get("localizedValue"))),
        session_id=_text(
            claims.get("sid") or properties.get("sessionId") or record.get("correlationId")
        ),
        request_id=_text(record.get("correlationId")),
        source_ip=_text(record.get("callerIpAddress") or properties.get("ipAddress")),
        credential_id=_text(properties.get("credentialId")),
        account_id=_text(record.get("subscriptionId") or record.get("tenantId")),
        attributes=attributes,
        raw_sha256=digest,
    )


def _normalize_kubernetes(record: Mapping[str, Any], digest: str) -> CanonicalEvent:
    user = _mapping(record.get("user"))
    object_ref = _mapping(record.get("objectRef"))
    status = _mapping(record.get("responseStatus"))
    annotations = _mapping(record.get("annotations"))
    namespace = _text(object_ref.get("namespace"))
    resource_kind = _text(object_ref.get("resource"))
    name = _text(object_ref.get("name"))
    resource = "/".join(part for part in (namespace, resource_kind, name) if part)
    sources = record.get("sourceIPs")
    source_ip = _text(sources[0]) if isinstance(sources, list) and sources else ""
    code = _text(status.get("code"))
    attributes: dict[str, Any] = {
        "stage": _text(record.get("stage")),
        "namespace": namespace,
        "api_group": _text(object_ref.get("apiGroup")),
        "subresource": _text(object_ref.get("subresource")),
        "request_uri": _text(record.get("requestURI")),
        "privileged": str(annotations.get("security.example/privileged", "")).casefold() == "true",
    }
    parent = _text(annotations.get("cloud.example/parent-event-id"))
    issued_identity = _text(annotations.get("cloud.example/issued-identity"))
    if issued_identity:
        attributes["issued_identity"] = issued_identity
    return CanonicalEvent(
        event_id=f"{_text(record.get('auditID'))}:{_text(record.get('stage') or 'unknown')}",
        timestamp=parse_timestamp(
            _text(record.get("stageTimestamp") or record.get("requestReceivedTimestamp"))
        ),
        provider="kubernetes",
        source_type="audit",
        actor=_text(user.get("username")),
        action=f"{_text(record.get('verb'))}:{resource_kind}",
        resource=resource,
        outcome=_outcome(code, failed=bool(code and not code.startswith("2"))),
        session_id=_text(annotations.get("cloud.example/session-id") or record.get("auditID")),
        request_id=_text(record.get("auditID")),
        source_ip=source_ip,
        credential_id=_text(annotations.get("cloud.example/credential-id")),
        parent_event_id=parent,
        account_id=_text(annotations.get("cloud.example/account-id")),
        attributes=attributes,
        raw_sha256=digest,
    )


def _normalize_canonical(record: Mapping[str, Any], digest: str) -> CanonicalEvent:
    attributes = record.get("attributes", {})
    if not isinstance(attributes, Mapping):
        raise EvidenceError("attributes must be a JSON object")
    if len(attributes) > MAX_ATTRIBUTES:
        raise EvidenceError(f"attributes exceeds {MAX_ATTRIBUTES} entries")
    provider = _text(record.get("provider")).casefold()
    if provider not in SUPPORTED_PROVIDERS - {"normalized"}:
        raise EvidenceError(f"unsupported normalized provider: {provider!r}")
    return CanonicalEvent(
        event_id=_text(record.get("event_id")),
        timestamp=parse_timestamp(_text(record.get("timestamp"))),
        provider=provider,
        source_type=_text(record.get("source_type") or "normalized"),
        actor=_text(record.get("actor")),
        action=_text(record.get("action")),
        resource=_text(record.get("resource")),
        outcome=_outcome(_text(record.get("outcome"))),
        session_id=_text(record.get("session_id")),
        request_id=_text(record.get("request_id")),
        source_ip=_text(record.get("source_ip")),
        credential_id=_text(record.get("credential_id")),
        parent_event_id=_text(record.get("parent_event_id")),
        account_id=_text(record.get("account_id")),
        attributes=dict(attributes),
        raw_sha256=digest,
    )


def detect_format(record: Mapping[str, Any]) -> str:
    if "eventTime" in record and "eventName" in record:
        return "aws"
    if "auditID" in record and "verb" in record:
        return "kubernetes"
    if "eventTimestamp" in record or (
        "correlationId" in record and "operationName" in record and "timestamp" not in record
    ):
        return "azure"
    if "event_id" in record and "timestamp" in record:
        return "normalized"
    raise EvidenceError("record format is not recognized")


def normalize_record(record: Mapping[str, Any]) -> CanonicalEvent:
    raw = _canonical_bytes(record)
    digest = hashlib.sha256(raw).hexdigest()
    provider = detect_format(record)
    if provider == "aws":
        return _normalize_aws(record, digest)
    if provider == "azure":
        return _normalize_azure(record, digest)
    if provider == "kubernetes":
        return _normalize_kubernetes(record, digest)
    return _normalize_canonical(record, digest)
