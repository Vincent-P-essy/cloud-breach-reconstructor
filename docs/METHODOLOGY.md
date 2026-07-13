# Methodology

## Correlation rules

All edges require strict timestamp precedence. Except for explicit parents, the
rules require a non-empty account identifier.

| Rule | Confidence | Required evidence and scope | Bound |
|---|---:|---|---:|
| Explicit parent | 1.00 | exact known `parent_event_id` | unbounded |
| Credential lineage | 0.98 | same provider/account, successful issuance, first matching use | unbounded |
| Workload identity lineage | 0.97 | same provider/account, successful issuance, first actor use | unbounded |
| Request correlation | 0.95 | same provider/account/request ID | 10 min |
| Resource lineage | 0.88 | same provider/account/resource; successful mutation then use | 30 min |
| Session sequence | 0.86 | same provider/account/session; nearest predecessor | 20 min |

Confidence values are deterministic rule weights, not calibrated posterior
probabilities. When several rules produce the same pair, only the strongest
typed edge is retained. Output includes the actual delta and configured maximum.

## Detection and ATT&CK

Failed and unknown operations never generate findings or ATT&CK mappings and
never establish successful mutation or issuance state. New-location detection
requires a successful authentication action, a prior observed actor geography,
and a simultaneously unseen source address. Secret retrieval maps to the current
cloud-specific `T1555.006`. A privileged container maps to `T1611` only when an
explicit host-path/escape signal accompanies it. `T1041` requires explicit
exfiltration plus C2-channel attributes; generic network egress is not enough.

These mappings remain analytical hypotheses. They describe the evidence matched
by a small deterministic rule set and do not prove adversary intent.

## Incidents, confidence and risk

A finding is the incident seed. The engine expands from seeds across typed edges
to preserve causal context; edge-only benign components are discarded. Incident
confidence is the arithmetic mean of its finding confidences and internal edge
weights. Risk is a transparent heuristic: low/medium/high/critical findings add
8/18/30/42 points, internal edges add two points each up to 20, and the result is
capped at 100. These values are triage priorities, not actuarial probabilities.

Containment is deduplicated by action type and scope. Multiple accessed secrets,
workloads, credentials or destinations therefore retain separate actions and
evidence events instead of overwriting one another.

## Ground truth and benchmark

Ground-truth schema 1.1 enumerates every expected `(source, target, kind)` edge,
finding signature, ATT&CK-mapped event ID and technique. The benchmark reports
precision, recall, false-positive rate, explicit false positives and false
negatives for all four dimensions. A missing/old schema, duplicate label, or
partially specified edge fails closed. The CLI quality threshold is the minimum
of all eight precision/recall values.

The fixture uses documentation addresses, `.invalid` destinations, inert
identifiers and synthetic labels. Labels are retained for human review but are
not read by the engine. The 100-run snapshot removes only the generation clock
from its functional digest. Latency includes normalization, graph construction,
findings, incident/blast-radius analysis and dictionary serialization; it
excludes file I/O and dashboard rendering and is host-dependent.
