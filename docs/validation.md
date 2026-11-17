# Testing and validation

The test suite uses inert source and synthetic artifacts to check parsing,
execution modeling, evidence references, resource limits, and report output.
Malware samples and sample-derived reports do not belong in the repository.

## Automated checks

Use the Go version required by `go.mod` or a newer supported version:

```sh
go mod verify
go generate ./internal/rules
git diff --exit-code -- internal/rules/catalog_gen.go
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/maratus
```

Run `gofmt` on changed Go files. CI also runs staticcheck, govulncheck,
bounded parser/report fuzzing, the optional differential helper, and
cross-builds for the release targets. Tests run on Linux and macOS.

For parser changes, include malformed and oversized inputs alongside a valid
control. For analysis changes, include a supported positive, a close negative,
and a benign control using the same API or packaging format. See
[Extending Maratus](extending.md) for evidence and scope requirements.

## Review coverage

Start a change review by mapping each changed contract to its consumers and
adjacent failure cases. Record the checks performed and unresolved limitations;
a green test run alone does not establish semantic coverage.

| Area | Required comparisons |
| --- | --- |
| Parser boundaries | Valid, truncated, malformed, exact-limit, over-limit, repeated offsets, and cumulative work or allocation |
| Native evidence | Per-slice identity, address/file-offset bounds, supported and unsupported metadata, signing integrity versus trust |
| Source semantics | Exact call versus lookalike; import, alias, rebinding, member mutation, escape, reimport, and scope; known versus unresolved operands |
| Activation | Declared entry versus containment, selected versus ambiguous target, connected versus unconnected operation |
| Reports | Exact evidence lineage, explicit coverage loss, deterministic JSON, strict reload, and rendered output |
| Documentation and packaging | Executable examples, stated limits, local links, portable skill layout, and complete release contents |

For a confirmed defect, vary the failing dimension across the other consumers
of the same proof or parser. Include a nearby valid control to catch excessive
invalidation. Stop at the documented model boundary: unsupported forms need an
explicit limitation, not speculative interpretation. Record platform checks that
cannot be performed locally as outstanding release requirements.

The optional [Mach-O comparison helper](https://github.com/0x4D31/maratus/tree/main/tools/differential) supplies
an independent parser view during development. It is not a runtime dependency
or a replacement for source-backed controls.

## Testing real artifacts

Use an isolated, disposable environment with outbound networking denied and
CPU, memory, file-size, file-descriptor, core-dump, and wall-clock limits.
Verify that the network policy is inherited by child processes before
scanning. The built-in worker provides resource supervision; the surrounding
environment supplies filesystem and network isolation. Follow
[SECURITY.md](../SECURITY.md) for handling requirements.

Keep samples and complete reports outside the checkout in private storage.
Record the source revision, input size and SHA-256, Maratus commit and binary
SHA-256, Go version, platform, and analysis settings. Use immutable source
references and verify published checksums when available. A locally calculated
hash identifies received bytes; it does not authenticate their publisher.
Keep malware and benign-control results separate.

Start with default analysis settings and leave DMG mounting disabled. For
encrypted ZIPs, use `MARATUS_ZIP_PASSWORD` rather than a command-line password.
Record any later budget or coverage adjustment as a separate run.

## Report checks

Inspect each artifact twice in separate constrained processes:

```sh
maratus inspect /path/to/sample.zip --format json -o /path/to/case/first.json
maratus inspect /path/to/sample.zip --format json -o /path/to/case/second.json
cmp /path/to/case/first.json /path/to/case/second.json
```

Strictly reload and render the saved report:

```sh
maratus render /path/to/case/first.json --format json -o /path/to/case/reloaded.json
cmp /path/to/case/first.json /path/to/case/reloaded.json
maratus render /path/to/case/first.json --color never
maratus render /path/to/case/first.json --format html -o /path/to/case/report.html
```

These commands are the scan payload, not an isolation wrapper. Run every
process under the environment and limits described above. Record exit status,
duration, peak memory, report hashes, and partial or skipped coverage.

When comparing versions, review changes in artifact structure, execution
roots, invoked targets, evidence, operations, relations, capabilities, and
coverage. More findings are not automatically better; each new conclusion
needs supporting evidence. A panic, timeout, invalid or nondeterministic
report, broken reference, silent coverage loss, or false execution association
requires investigation before release.

Corpus runs measure stability and regressions. Detection accuracy or coverage
rates require a separately annotated evaluation set.
