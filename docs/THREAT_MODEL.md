# Threat model

## Protected assets

- integrity of the causal graph and raw-evidence binding;
- confidentiality of cloud identities, resources, and source addresses;
- availability of the local analysis API;
- provenance of benchmark claims.

## Adversary-controlled inputs

An attacker may inject oversized JSON, duplicate keys, malformed timestamps,
conflicting event IDs, HTML-like strings, misleading session identifiers,
extreme attribute counts, or reordered events. Bounds, strict parsing, canonical
hashes, immutable models, output escaping, temporal checks, and DAG validation
address these cases.

## Out of scope

The engine cannot prove that a provider log was collected correctly, detect a
compromised audit plane, decrypt evidence, establish legal chain of custody, or
attribute a human operator. TLS and authentication belong at a reverse proxy if
the intentionally local API is exposed. Raw secrets should be redacted before
ingestion because reports preserve selected values.
