# Limitations

- Native adapters cover documented fields used by the lab, not every historic
  or nested variant of CloudTrail, Activity Log or Kubernetes audit.
- Session and correlation identifiers may still be missing, reused or
  attacker-controlled inside one provider/account. Every edge is a hypothesis,
  even at rule confidence 1.0.
- Explicit-parent and first-use lineage rules are intentionally unbounded. Their
  observed deltas are exposed so analysts can apply case-specific limits.
- Ordering assumes normalized provider clocks. Equal timestamps are kept
  unordered; there is no clock-skew correction or probabilistic partial order.
- New-location analysis consumes country labels already present in evidence; it
  performs no IP geolocation and does not calculate impossible travel.
- Findings and ATT&CK mappings are a small deterministic rule set. Success and
  explicit attributes reduce obvious false claims, but legitimate administrative
  actions can still match. They are not a complete classifier or proof of intent.
- Risk and confidence are documented heuristics, not probabilities calibrated on
  production incidents.
- Blast radius lists entities observed inside finding-seeded causal components.
  It does not enumerate unlogged IAM reachability.
- The perfect reference metrics apply only to 21 synthetic records. They prove
  fixture consistency and reproducibility, not production accuracy.
- The canonical record digest binds parsed JSON semantics, not original byte
  layout, collection provenance, or legal chain of custody.
- The local dashboard has no multi-user authentication, durable case management,
  evidence-retention policy, or horizontal rate limiter.
