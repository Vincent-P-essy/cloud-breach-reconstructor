# Limitations

- The native adapters implement documented fields used by the lab, not every
  version or nested variant of CloudTrail, Activity Log, or Kubernetes audit.
- Session, request, credential, and resource identifiers can be missing, reused,
  or attacker-controlled. A correlation is a hypothesis, even at confidence 1.0.
- Timestamp ordering assumes normalized provider clocks; no automatic clock-skew
  correction or probabilistic partial ordering is implemented.
- New-location detection uses synthetic country labels supplied by evidence; the
  project performs no IP geolocation lookup.
- ATT&CK action matching is intentionally small and deterministic. It is not a
  complete cloud ATT&CK classifier.
- Blast radius lists observed entities only. It does not enumerate unlogged IAM
  reachability; combine it with an identity attack graph for that purpose.
- The perfect benchmark result applies only to 21 labeled synthetic records. It
  is proof of reproducibility and internal correctness, not real-world accuracy.
- The dashboard is a local demonstrator and has no multi-user authentication,
  durable case management, or evidence retention policy.
