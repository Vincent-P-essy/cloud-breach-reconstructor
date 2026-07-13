# Architecture

## Trust boundaries

Raw provider records are untrusted evidence. `io.py` bounds files and individual
records, rejects duplicate JSON keys, and never evaluates record content. The
normalizer converts only explicit schema fields into immutable canonical events
and binds every record to a canonical SHA-256 digest.

The inference engine is a pure in-process function. It has no network client,
shell invocation, plugin loading, template evaluation, database, or mutable
global state. Reports escape dashboard content before rendering; the HTTP layer
adds CSP, frame, MIME, referrer, and no-store headers.

## Causal DAG

Events are sorted by UTC timestamp and stable event ID. Each rule creates an edge
only from an earlier event to a later event. A topological pass independently
rejects cycles and references to missing evidence. Duplicate IDs with different
raw hashes fail closed.

The engine conservatively connects the first use of newly issued credentials or
workload identities, then relies on nearest-event session sequencing. This
avoids a dense star from the issuer to every later use while retaining the
credential boundary as explicit evidence.

## Output contract

`Reconstruction` is the single source of truth. Markdown, CSV, DOT, API, and the
dashboard are projections of that object. Every written artifact is listed in a
SHA-256 manifest. The generation timestamp is excluded only from the benchmark's
functional digest; it remains present in operational reports.
