# Methodology

## Correlation rules

| Rule | Confidence | Required evidence | Bound |
|---|---:|---|---:|
| Explicit parent | 1.00 | known `parent_event_id` and temporal precedence | none |
| Credential lineage | 0.98 | prior `issued_credential`, first matching use | none |
| Workload identity lineage | 0.97 | prior `issued_identity`, first actor use | none |
| Request correlation | 0.95 | same provider and request/correlation ID | 10 min |
| Resource lineage | 0.88 | same provider/account/resource; mutation then use | 30 min |
| Session sequence | 0.86 | same provider/account/session; nearest predecessor | 20 min |

The confidence values are deterministic rule weights, not empirically calibrated
posterior probabilities. When several rules produce the same pair, only the
strongest typed edge is retained and its evidence remains visible.

## Detection and ATT&CK

Findings are separate from causal links. New-location detection requires a prior
actor geography and a simultaneously unseen IP. Credential creation, secret
reads, privileged Kubernetes workloads, and non-allowlisted egress use explicit
action or attribute evidence. ATT&CK mappings are versioned in code with a
knowledge date and do not infer tactics from free text.

## Ground truth

The reference dataset uses RFC 5737 documentation addresses, `.invalid`
destinations, inert resource identifiers, and synthetic labels. Its 16 expected
edges model two attack components and deliberately omit three unrelated benign
records. Precision is `correct inferred / all inferred`; recall is `correct
inferred / expected`; false-link rate is `1 - precision`.

The 100-run snapshot records one functional digest after removing only the
generation clock. Latency includes normalization, graph construction, findings,
blast-radius analysis, and serialization to a dictionary. It excludes file I/O
and dashboard rendering and is explicitly host-dependent.
