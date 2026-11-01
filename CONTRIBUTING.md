# Contributing to Maratus

Maratus analyzes hostile input, so parser safety and evidence quality matter as
much as feature coverage. Small, well-tested changes are easier to review than
large recognizer bundles.

## Before you start

- Use Go 1.26.10 or newer.
- Open an issue before changing the report schema, rule language, behavior
  vocabulary, or execution model.
- Never commit malware, private reports, credentials, live infrastructure, or
  sample-derived content. Use minimized inert fixtures.
- Report security issues privately as described in [SECURITY.md](SECURITY.md).

## Build and test

```sh
go build ./cmd/maratus
go test ./...
go test -race ./...
go vet ./...
```

Before submitting a change, also run:

```sh
gofmt -w path/to/changed.go
go generate ./internal/rules
git diff --check
```

Generated rule-catalog changes belong in the same commit as the rule change.
CI regenerates the catalog from a clean checkout and fails if the committed
file is stale.

## What a good analysis change includes

Every recognizer or parser change should have:

- a minimized inert positive;
- a close negative that differs by one important condition;
- a malformed or budget-bound case when hostile input can reach the code;
- a benign control for a shared API, framework, or packaging technology; and
- assertions for evidence location, support, scope, architecture, execution
  connectivity, and coverage where applicable.

Do not add family names, sample hashes, filenames, or one-off strings as
recognition logic. Model the reusable format, host rule, API, or semantic
pattern instead.

## Design boundaries

- Artifact structure and execution semantics stay separate.
- Evidence and low-level features do not become operations without a semantic
  recognizer.
- Capability matches must be backed by modeled operations.
- `CONNECTED` means static ownership by an execution root, not observed
  execution.
- Unknown or unsupported analysis must remain visible through coverage.
- Work over attacker-controlled collections must be bounded and deterministic.
- Rules use the existing typed Go AST. Do not add a second evaluator or an
  external rule format.

See [docs/architecture.md](docs/architecture.md) for the model and
[docs/extending.md](docs/extending.md) for implementation guidance.

## Pull requests

Explain the reusable behavior being added or corrected, the trust boundary it
touches, and the tests that establish both the positive and negative cases.
Call out report-schema or output changes explicitly. Keep unrelated cleanup in
a separate change.
