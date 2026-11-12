# CLI and output

Use terminal text for interactive review and versioned JSON for automation.
Run `maratus help COMMAND` for the authoritative flags, accepted values, and
defaults for the installed build.

## Commands

| Command | Purpose |
| --- | --- |
| `maratus inspect INPUT` | Analyze one file, directory, bundle, or container |
| `maratus inspect --stdin --input-kind KIND` | Analyze one explicitly typed, bounded in-memory artifact |
| `maratus render REPORT` | Validate and present a saved report without rescanning |
| `maratus rules list` | List built-in capability and library rules |
| `maratus rules check [RULE_ID]` | Validate generated rule declarations |
| `maratus rules vocab` | Print the rule and semantic vocabularies |
| `maratus version` | Print build and version information |

## Common output choices

| Need | Command |
| --- | --- |
| Triage summary | `maratus inspect INPUT` |
| Matches and evidence | `maratus inspect INPUT --detail evidence` |
| Artifact graph and lower-level facts | `maratus inspect INPUT --detail full` |
| Complete report | `maratus inspect INPUT --format json` |
| Agent-friendly projection | `maratus inspect INPUT --format summary-json` |
| Project a saved report for an agent | `maratus render REPORT --format summary-json` |
| Complete private case bundle | `maratus inspect INPUT --output-dir CASE` |
| Direct offline overview | `maratus inspect INPUT --format html -o analysis.html` |
| Recheck a saved report | `maratus render REPORT --format json` |
| Offline analyst review | `maratus render REPORT --format html -o analysis.html` |

Human-readable text is bounded and may change for clarity. Do not scrape it as
an API. JSON is deterministic and contains the complete public report. Summary
JSON currently uses `maratus.summary.v0.1-preview.9`; consumers must check the
version before interpreting projection fields.

Summary JSON retains the producing build, rule catalog digest, and analysis
settings. Its behavior and capability rows preserve artifact, execution-owner,
and architecture associations. `requested_arguments` retains known API operands
when launch options prevent resolving the executable; it is not an execution
binding. The HTML overview groups related conclusions compactly; expand a group
to inspect each rendered instance and open that exact record in the graph.
Instances excluded by the HTML limits remain in canonical JSON.

The summary projection categorizes operation-backed matches as `behavior`,
`technical-primitive`, or `runtime-support`. This is presentation context, not
a second rule decision. Exact non-runtime Go function identity may also appear
under `code_context`; those rows reference retained call Features and do not
claim behavior or application ownership. `coverage_gaps_and_limits` contains
only `partial` and `skipped` exceptions; complete per-scope coverage remains in
the canonical report.

## Inspection options

The most commonly used analysis options are:

| Option | Effect |
| --- | --- |
| `--expand-containers=BOOL` | Expand supported packages and archives; default `true` |
| `--include-unreferenced` | Analyze additional bundled code and resources without creating roots |
| `--architecture VALUE` | Select `arm64`, `x86_64`, `i386`, or `all` |
| `--zip-password VALUE` | Supply a classic ZIP password; prefer `MARATUS_ZIP_PASSWORD` |
| `--allow-dmg-mount` | Permit an explicit read-only `hdiutil` mount on macOS |
| `--max-*` | Adjust byte, depth, compression, node, evidence, and work limits |

Default limits include 128 MiB per file, 64 MiB per archive and expanded
archive set, 256 MiB total retained content, archive depth 4, directory depth
32, compression ratio 100, and 20,000 artifact nodes and evidence records.
Size values accept bytes or `KiB`, `MiB`, and `GiB`.

Declared payloads and supported invoked targets are analyzed without
`--include-unreferenced`. Enabling it changes coverage, not execution
connectivity.

## Text detail

The default view is capability-first. It contains target identity,
operation-backed capabilities, ATT&CK mappings where the rule establishes
enough context, conditional activation, network behavior, static observables,
and artifact properties. If analysis is incomplete, one compact `Analysis`
line reports the number of limited scopes and diagnostics without printing
generic advice or detailed parser notes. A separate
additional-behavior section retains heuristic operations, unmatched operations,
and concretely bound operations that are not already represented by a
capability. This avoids repeating every low-level API call twice while ensuring
that a zero-match report does not hide useful modeled behavior.

In HTML, **Technical capabilities** are rule-backed conclusions derived from
one or more operations. **Underlying modeled operations** are the lower-level
actions retained directly from recognizers, including unmatched and heuristic
records. The summary JSON preserves both planes separately and retains exact
capability-match and operation IDs for canonical-report lookup.

- `--detail evidence` adds provenance, execution roots, invoked targets,
  individual matches, mappings, and evidence.
- `--detail full` also adds artifact nodes and edges, modeled operations,
  relations, features, and complete coverage detail.
- `--color auto|always|never` affects presentation only.

An inspection with no matches still exits successfully. It is not a statement
that the artifact is safe.

## Saved reports

The current report schema is `maratus.report.v0.3-preview.2`. A report records:

- producer, settings, ruleset, and normalized rule-catalog identity;
- artifact nodes, relationships, analysis selections, scopes, execution roots,
  and invoked targets;
- evidence, features, operations, resource bindings, relations, and capability
  matches;
- artifact properties and network/TLS implementation observations; and
- coverage and diagnostics.

Every capability match references supporting operations and includes a bounded
successful-match trace. The trace explains static support; it is not a runtime
trace.

`maratus render` treats the report as untrusted input. It rejects unsupported
schemas, unknown fields, malformed or trailing JSON, structural-limit
violations, dangling references, invalid evidence ownership, inconsistent
relations, and invalid capability projections. When the report carries the
current rule-catalog identity, the loader also replays the typed rules and
requires the capability set to match.

Strict validation proves internal consistency, not authenticity. Reports are
unsigned. Verify custody and an external digest or signature before relying on
a report received from someone else.

## Support, connectivity, and coverage

| Field | Values | Meaning |
| --- | --- | --- |
| Support | `DIRECT`, `CORROBORATED`, `HEURISTIC` | Strength of the static support |
| Connectivity | `CONNECTED`, `UNCONNECTED`, `UNKNOWN` | Connection to a retained execution root |
| Coverage | `analyzed`, `partial`, `skipped` | Status of a supported analysis area for a node or scope |

Support and connectivity are not severity scores. `CONNECTED` is static
reachability, not observed execution. `UNCONNECTED` describes the retained
model, not every possible runtime path. Review coverage before interpreting an
absent operation or match. `analyzed` means the supported analysis completed;
it does not mean that every possible behavior or syntax form was modeled.
An absence of reported gaps is not a completeness certificate.

## HTML

`inspect --format html` and `render --format html` create a deterministic,
self-contained analyst review from a strictly validated report. It does not
open a browser or load remote scripts, fonts, or other assets. The default page
uses a single-column report flow with compact, collapsible sections for
behavior, activation, network evidence, static observables, and artifact
context. A collapsed analysis-notes section appears only when the scan records
a real limitation or diagnostic. Exact Mach-O runtime paths and non-system
dependency declarations have their own collapsed loader-context section.
Technical API, runtime, and operation inventories remain available without
competing with first-pass triage. Repeated matches across
slices or artifacts are folded into one review row while the canonical report
retains every match. The secondary evidence graph provides fact-level lineage,
bounded views, and an on-demand details drawer without a permanent third
column.

The report follows the operating-system color preference by default. Its
theme control cycles through automatic, dark, and light rendering without
persisting state or loading external assets. Section accents and disclosure
arrows distinguish collapsed report groups without changing their
semantic ordering or underlying projection.

HTML is a review aid, not a complete or redacted copy of the report. It can
contain sample-derived paths, commands, destinations, signing data, and
diagnostics.

## Streams and exit status

- Normal output goes to stdout unless `-o FILE` is used. `--output-dir` does
  not suppress it.
- Errors go to stderr.
- Exit `0` means the command completed.
- Exit `1` means input, analysis, validation, or output failed.
- Exit `2` means command-line usage or flag validation failed.

Output files are written privately and replaced atomically. `inspect` and
`render` refuse to replace their input file, including through a symlink or
hardlink alias. For directory and app-bundle inputs, `inspect` requires output
files and case bundles outside the input tree. A separate output file must also
stay outside the requested case bundle so it cannot invalidate the manifest.
An inspection case bundle is assembled privately and renamed into place only
after all five deterministic members are complete; an existing destination is
refused. Its manifest records the normalized settings and pins the running
Maratus executable, settings object, root input, and four generated outputs by
SHA-256. `maratus.bundle.v0.1-preview.2` also records the deterministic worker
protocol and configured supervision upper bounds. It does not claim that the Go
memory target is a hard RSS ceiling or that worker supervision denies network
or filesystem access.
