# Contributing

Changes to a normalizer or causal rule require a positive fixture, a negative
fixture proving that unrelated events stay disconnected, a declared bounded or
unbounded time contract, and an update to the methodology. Unbounded rules must
expose that fact and the observed delta. Benchmark changes must update complete
schema-1.1 labels (edge kind, finding, mapped event and technique), preserve the
previous snapshot or explain why labels changed, and include a false-positive
regression.

Run `make test`, `make quality`, the isolated wheel/sdist smoke tests, and the
constrained container benchmark before opening a pull request. Never commit real
cloud identifiers, tokens, secrets, or customer logs.
