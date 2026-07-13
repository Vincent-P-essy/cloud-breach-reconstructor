# Contributing

Changes to a normalizer or causal rule require a positive fixture, a negative
fixture proving that unrelated events stay disconnected, an explicit time bound,
and an update to the methodology. Benchmark changes must preserve the previous
snapshot or explain why labels changed.

Run `make test`, `make quality`, and the constrained container benchmark before
opening a pull request. Never commit real cloud identifiers, tokens, secrets, or
customer logs.
