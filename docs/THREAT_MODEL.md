# Threat model

## Protected assets

- integrity of canonical evidence, causal links and benchmark labels;
- confidentiality of identities, resources and source addresses;
- availability of the local analysis API;
- integrity of generated Markdown, CSV and Graphviz projections;
- provenance and reproducibility of published measurements.

## Adversary-controlled inputs

An attacker may inject oversized or deeply nested JSON, duplicate keys,
non-finite numbers, malformed timestamps, conflicting IDs, unsupported schema
versions/outcomes, report metacharacters, formula prefixes, misleading shared
identifiers, extreme attributes, reordered events, and equal timestamps.

Bounds, finite strict parsing, canonical hashes, immutable models, tenant-scoped
correlations, success-state checks, strict timestamp precedence, DAG validation,
projection-specific escaping, restrictive HTTP headers and request timeouts
address these cases. The container adds a read-only filesystem, non-root UID,
dropped capabilities, `no-new-privileges`, and CPU/memory/PID limits.

## Out of scope

The engine cannot prove provider-log collection integrity, detect a compromised
audit plane, decrypt evidence, establish legal chain of custody, or attribute a
human operator. TLS, authentication, tenant isolation and distributed rate
limiting belong at a reverse proxy if the intentionally local API is exposed.
Raw secrets should be redacted before ingestion because reports preserve
selected evidence values.
