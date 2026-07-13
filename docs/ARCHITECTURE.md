# Architecture

## Trust boundaries

Provider records and normalized fixtures are untrusted evidence. `io.py` bounds
files and lines, rejects duplicate keys, non-finite numbers and JSON deeper than
64 levels. The normalizer accepts only the documented normalized schema and
binds each record to a deterministic SHA-256 of its canonical JSON semantics.
That digest is not represented as a hash of the original bytes.

The inference engine is a pure in-process function. It has no network client,
shell invocation, plugin loading, template evaluation, database, or mutable
global state. Dashboard values are HTML-escaped, DOT identifiers and labels are
quoted, Markdown active content is neutralized, and CSV formula prefixes are
made inert. The HTTP layer adds CSP, frame, MIME, referrer and no-store headers,
removes the Python version banner, and applies body, depth and socket-time limits.

## Causal DAG

Events are rendered in UTC timestamp/event-ID order, but event IDs never create
causal precedence. An edge requires `source.timestamp < target.timestamp`; equal
timestamps remain unordered. A topological pass independently rejects cycles,
unknown evidence, reverse edges, and equal-time edges. Duplicate IDs with
different canonical hashes fail closed.

Request, session, credential, identity and resource correlations require a
non-empty account scope. Request, credential and identity keys include provider
and account, preventing tenant collisions. An explicit parent may cross those
boundaries because it names the exact source event. Only successful events can
register a resource mutation or newly issued credential/identity.

Each edge exposes its type, evidence, confidence, measured delta in milliseconds
and maximum permitted delta. Explicit parent and first-use lineage are marked
unbounded rather than pretending to have a time window.

## Incident boundary

Correlation is context, not compromise. Only a deterministic finding seeds an
incident; the connected causal component is then retained as explicit context.
A benign session component with no finding produces no incident and contributes
nothing to blast radius. ATT&CK mapping is also restricted to successful events.

## Output and package contract

`Reconstruction` schema 1.1 is the single source of truth. Markdown, CSV, DOT,
API and dashboard responses are projections of that object. Written analysis
artifacts are covered by a SHA-256 manifest. The generation timestamp is omitted
only from the benchmark functional digest. The wheel embeds the inert lab events
and ground truth under package resources; CI exercises the installed wheel from
an unrelated working directory and runs the test suite from the source archive.
