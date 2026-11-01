# Extending Maratus

Add support at the lowest layer that can make the claim honestly. A parser
should produce structure or evidence. A recognizer should produce operations.
A rule should interpret existing operations. Skipping a layer usually creates
an overconfident result.

Read [Architecture](architecture.md) and [CONTRIBUTING.md](../CONTRIBUTING.md)
before changing the model.

## Choose the right layer

| You need to add | Primary package |
| --- | --- |
| Container or physical format | `internal/artifact` |
| Host-selection or invocation contract | `internal/artifact`, then `internal/extract` |
| String, import, API, selector, or metadata fact | `internal/extract` |
| Operation, resource, or relation vocabulary | `internal/behavior` |
| Capability interpretation | `internal/rules` |
| Report validation or presentation | `internal/report` |
| HTML projection | `internal/visualization` |

Do not add recognition based on a malware family, filename, sample hash, or a
string unique to one specimen. Model the reusable format, API, host rule, or
semantic relationship.

## Add a format or container

1. Detect from bounded structure or magic bytes. Treat extensions as hints.
2. Validate counts, offsets, lengths, arithmetic, and nesting before allocating
   or handing data to a general parser.
3. Create typed artifact nodes and edges. Keep logical and physical paths
   separate.
4. Preserve member ordering when it has loader meaning.
5. Charge compressed input, expanded bytes, nodes, depth, and decode work to
   the shared budgets.
6. Report unsupported or malformed children as `partial` or `skipped` where
   safe siblings can continue.
7. Add a root only when the format or a documented host rule selects an entry.

Tests should cover valid content, misleading extensions, duplicate and
ambiguous declarations, traversal paths, symlinks or special files where
relevant, malformed lengths, excessive counts, nested-budget exhaustion, and
deterministic ordering.

## Add a host adapter

A host adapter connects a declaration to an execution root or exact invoked
target. Keep it versioned when host behavior can change.

An adapter must state:

- the artifact shape it accepts;
- the documented host behavior and version boundary;
- the exact declaration fields and argument forms it understands;
- how paths and working directories are resolved;
- which runtime conditions remain unknown; and
- what makes the declaration malformed, ambiguous, or unsupported.

Do not fall back from a rejected structural declaration to filename or body
heuristics. If an interpreter argument means the retained target is not the
program being executed, do not create target semantics for it.

## Add a feature or recognizer

Evidence comes first. Locate the original bytes or decoded field and preserve
its node, scope, function, architecture, method, and value where known. For fat
Mach-O files, byte offsets are relative to the outer artifact, not the slice
buffer.

Features are inexpensive facts and may remain useful without an operation. An
operation requires stronger semantics, such as an exact called API, a supported
command form, or a declaration whose role is defined by the format.

Prefer small tables for exact APIs, selectors, command names, and resource
roles when their behavior is uniform. Use a focused recognizer when argument
flow, lifecycle, ordering, receiver identity, or invalidation matters.

Package-host adapters must prove both the package envelope and the host's
selection rule. The Cargo adapter is an example: mature TOML parsing validates
syntax and types, while a deliberately narrower located-key profile preserves
exact byte lineage. Merely finding a file named `build.rs`, a Rust API spelling,
or a dependency declaration is not enough to create an execution root.

Close negatives are essential. Test metadata-only references, similar but
unsupported names, wrong argument registers, different scopes, overwritten
state, branch boundaries, malformed instructions, ambiguous resources, and
budget exhaustion as applicable.

## Add an operation, resource, or relation

Behavior vocabulary is closed and neutral. Add the smallest primitive that
describes the static action without asserting intent or success.

For an operation:

1. define the kind and compatible resource roles in `internal/behavior`;
2. retain exact evidence and context;
3. keep unresolved resource values empty rather than guessing;
4. derive support from the weakest required fact; and
5. let execution ownership come from the root model.

For a relation, define its endpoint types, resource-role requirements, context
compatibility, evidence requirements, and deterministic work bound. A relation
must not be inferred from simple co-occurrence. Ordering and flow relations
need evidence from both endpoints.

If a new operation can create, replace, remove, or relocate exact file
contents, update the operation-relation linker's mutation invalidation table and
its exhaustive close-negative test. A download-to-execute or archive-to-upload
claim is valid only while no same-context mutation of that resource can fall
between producer and consumer. Read-only access and metadata-only changes must
not be added merely because they mention the same path.

Update vocabulary, graph, loader, projection, and close-negative tests together.

## Add a rule

Rules are top-level typed Go `Spec` declarations in
`internal/rules/specs.go`. There is no separate registration table and no
runtime YAML or JSON rule format.

```go
var MacOSExampleCapability = Spec{
	Metadata: Metadata{
		ID:          "macos.example-capability",
		Title:       "Example capability",
		Namespace:   "macos.example",
		Description: "What the matched static behavior establishes.",
	},
	Kind: CapabilityRule,
	Match: Operation(behavior.OperationProcessExecute),
	MinimumSupport: behavior.SupportCorroborated,
}
```

The current AST supports operation, feature, and execution-root patterns;
`Any`; scoped `Each` joins; explicit `Relate` joins; typed resource bindings;
reusable library rules; and bounded `ResourceFlow` paths. Use
`maratus rules vocab --format json` for the authoritative vocabulary.

After editing a rule:

```sh
go generate ./internal/rules
go run ./cmd/maratus rules check macos.example-capability --format json
go test ./internal/rules ./internal/rules/cmd/rulegen
```

Commit the regenerated `catalog_gen.go` with the rule declaration. CI repeats
generation from a clean checkout and rejects stale output.

Capability rules must require an operation. They cannot construct their own
public matches, strengthen support or connectivity, reopen artifacts, or walk
unbounded graph data. The engine creates the match and its explanation trace.

Rule tests need a positive, a one-clause close negative, support and
connectivity boundaries, scope/root/architecture negatives for correlated
facts, and a high-candidate budget case.

## Change public output

Treat these as public contracts:

- report JSON and schema identifier;
- rule catalog, vocabulary, and normalized catalog digest;
- operation, resource, relation, support, and connectivity vocabularies;
- CLI flags and exit behavior; and
- HTML projection identifiers.

For a schema change, update the producer, strict loader, projection,
documentation, and forged-report tests in one change. Decide explicitly
whether old reports are rejected or migrated. Never loosen the loader merely
to accept output that the current builder would refuse.

Terminal wording can evolve, but its sections must stay bounded and safe for
sample-derived text. JSON field names and semantics require a schema decision.

## Validate the change

At minimum:

```sh
gofmt -w path/to/changed.go
go generate ./internal/rules
go test ./...
go test -race ./...
go vet ./...
git diff --check
```

Run focused fuzzing for parsers or report-loading code that changed. For a
semantic change, inspect a benign control that uses the same API or packaging
technology. Private malware corpora are release validation, not committed test
fixtures or ground truth.

Keep acquisition and sample handling outside semantic recognizers; filenames,
family labels, hashes, and sample-specific helper names are never recognition
inputs.
