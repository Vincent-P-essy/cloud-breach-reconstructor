from __future__ import annotations

from dataclasses import dataclass

from .models import CanonicalEvent

ATTACK_KNOWLEDGE_DATE = "2026-07-13"


@dataclass(frozen=True, slots=True)
class AttackRule:
    technique_id: str
    title: str
    action_terms: tuple[str, ...]


RULES: tuple[AttackRule, ...] = (
    AttackRule("T1078", "Valid Accounts", ("consolelogin", "signin", "login")),
    AttackRule(
        "T1087.004", "Cloud Account Discovery", ("listusers", "listroles", "roleassignments/read")
    ),
    AttackRule(
        "T1098.001", "Additional Cloud Credentials", ("createaccesskey", "credentials/write")
    ),
    AttackRule(
        "T1526", "Cloud Service Discovery", ("describ", "listclusters", "subscriptions/read")
    ),
    AttackRule(
        "T1555.006",
        "Cloud Secrets Management Stores",
        ("getsecret", "secrets/read", "get:secrets"),
    ),
    AttackRule("T1610", "Deploy Container", ("create:pods", "deployments/write", "runpod")),
    AttackRule("T1611", "Escape to Host", ("privilegedpod", "hostpath", "nodes/proxy")),
    AttackRule("T1530", "Data from Cloud Storage", ("getobject", "blob/read", "downloadobject")),
    AttackRule("T1041", "Exfiltration Over C2 Channel", ("c2:egress", "exfiltration:c2")),
    AttackRule(
        "T1562.001", "Impair Defenses", ("stoplogging", "deleteaudit", "diagnosticsettings/delete")
    ),
)


def techniques_for(event: CanonicalEvent) -> tuple[str, ...]:
    if event.outcome != "success":
        return ()
    action = event.action.casefold().replace(" ", "")
    matches = {
        rule.technique_id for rule in RULES if any(term in action for term in rule.action_terms)
    }
    host_path = event.attributes.get("host_path")
    host_escape_evidence = event.attributes.get("host_escape") is True or (
        event.attributes.get("privileged") is True
        and isinstance(host_path, str)
        and host_path in {"/", "/proc", "/sys", "/var/run/docker.sock"}
    )
    if host_escape_evidence:
        matches.add("T1611")
    if event.attributes.get("exfiltration") is True and event.attributes.get("c2_channel") is True:
        matches.add("T1041")
    return tuple(sorted(matches))


def title_for(technique_id: str) -> str:
    return next((rule.title for rule in RULES if rule.technique_id == technique_id), technique_id)
