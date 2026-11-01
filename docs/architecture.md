# Architecture

Maratus is a bounded static analyzer for macOS artifacts. Its central design
choice is to keep artifact structure, execution semantics, extracted facts,
modeled behavior, and capability rules as separate layers.

```text
hostile input
  -> artifact graph
  -> execution roots and invoked targets
  -> evidence and scoped features
  -> operations, resources, and relations
  -> capability matches
  -> validated report and presentation
```

This separation prevents a useful clue from becoming a stronger claim by
accident. A URL is evidence and a feature. A supported call may establish a
network operation. A rule may interpret that operation as a capability. None
of those records says the operation happened at runtime.

## Invariants

Changes to Maratus must preserve these properties:

1. **Static only.** Inspection does not execute code, import packages, run
   hooks, install software, or contact sample infrastructure.
2. **Bounded work.** Every parser and graph walk over attacker-controlled data
   has explicit size, depth, count, or work limits.
3. **Exact lineage.** Semantic records retain the evidence, artifact, scope,
   function, architecture, and execution ownership that support them.
4. **Structure is not execution.** Containment and materialization edges do not
   create execution semantics. Roots and invoked targets require a supported
   format or host-selection rule.
5. **Operations are neutral.** File, process, network, archive, and interpreter
   operations describe static semantics. They are not malicious verdicts.
6. **Capabilities are operation-backed.** A public capability match cannot be
   created from a string or feature alone.
7. **Coverage is part of the result.** Unsupported, malformed, ambiguous,
   excluded, and over-budget work remains visible as `partial` or `skipped`.
8. **Output is deterministic.** The same input, build, settings, and environment
   produce byte-identical JSON.

## Artifact graph

The artifact layer answers what is present and how it is packaged. It prefers
structure and magic bytes over filenames, then expands supported containers
within the configured budgets.

Each retained object is an artifact node. Typed edges describe relationships
such as archive membership, app ownership, package payloads, declared
executables, or generated representations. Logical paths preserve container
lineage, for example `sample.pkg!/Scripts/postinstall`.

The graph does not assume that an archive member, bundle resource, or
executable-looking file will run. Unreferenced runnable candidates may be
analyzed for useful facts, but their operations remain unconnected unless a
separate declaration selects them.

Supported expansion includes directories, app bundles, flat packages, ZIP and
VSIX, TAR and compressed TAR, GZIP, CPIO, ASAR, fully validated indexed-gzip
bundles, and selected embedded representations. DMGs are identified without
mounting by default.

## Execution model

For native executables, bounded function analysis accepts `LC_MAIN` or one
complete x86_64 `LC_UNIXTHREAD` general-register state. Legacy thread entries
must map uniquely into executable, file-backed segment bytes. Duplicate or
conflicting entry commands and unsupported thread layouts do not seed analysis.
The declared entry remains static metadata; it does not establish that the
program ran or connect an otherwise unselected artifact to a host root.

When Mach-O preflight rejects retained bytes, the shared raw-observation lane
may still report bounded heuristic URL and IP candidates. Those candidates have
no architecture or function attribution and never create operations. The parse
failure and raw-string boundary limitations remain explicit in coverage.

An `ExecutionRoot` is a static starting point declared by an artifact format or
a versioned host adapter. Examples include an app main executable, package
install script, launchd command, npm lifecycle hook, Node package-root entry,
VS Code extension main, Xcode Run Script phase, or explicitly typed stdin.

An `InvokedTarget` is an exact retained artifact selected from a root or other
supported invocation. It is not promoted to a new root. The distinction keeps
ownership intact across wrappers, interpreters, scripts, and nested payloads.

Execution connectivity has three values:

- `CONNECTED`: the retained static model links the operation to one or more
  execution roots;
- `UNCONNECTED`: the retained model establishes no such path; and
- `UNKNOWN`: the analysis could not determine the relationship.

`CONNECTED` never means that a user launched the artifact, a host selected it
on a real machine, or the operation succeeded.

Host adapters are deliberately narrow. They model a documented selection rule
and reject unsupported arguments, ambiguous paths, dynamic values, malformed
siblings, or unresolved working directories. The current adapters cover
selected app, package, launchd, Node/npm, VS Code, Xcode, Claude Code, Codex, Gemini CLI,
Python wheel and source-build, Cargo package build scripts, and facade-specific
contracts. Each adapter records its unresolved runtime conditions in coverage.

Invocation arguments retain their boundaries. Shell-derived argument bindings
use `argument_encoding=shell-quoted`; consumers may decode that representation
as argv, but must never parse an ordinary display string or a file binding as a
shell program. A typed `local_input` identifies an interpreter operand; it does
not by itself establish which retained artifact occupies that runtime path.

Relative script targets require an established host directory and exact target
policy. The npm lane accepts a bounded list of simple commands rooted at the
manifest directory; directory-changing commands, sourced code, unsupported
shell state, and package-manager prefix/workspace/configuration switches leave
associations unresolved. GYP and project-host adapters supply their own exact
target policies. Generic child scripts do not inherit their source directory as
an assumed working directory. Absolute paths can match an exact retained disk
file or a same-component PKG destination derived from PackageInfo. A unique
basename in an archive is never an installed-path mapping. Selecting a script
promotes only its module/start scope; supported direct function calls are
handled separately, and general JavaScript call-graph recovery remains absent.

Literal inline Python Base64 decoding accepts the closed, single-line program
`import base64; exec(base64.b64decode(<string literal>))`, with standard Base64,
bounded text bytes, valid UTF-8, and at most two nested wrappers. Substring
matches inside comments, strings, functions, rebound names, and other program
shapes do not establish a decoded execution stage. This is a small static
recognizer, not general Python evaluation or deobfuscation.

The Cargo adapter accepts only a complete root `.crate` gzip TAR whose
filename, single top-level directory, and ordinary `[package]` name/version
agree exactly. It applies Cargo's documented `package.build` rule, including
the default `build.rs`, an exact safe custom path, and `build=false`. A retained
top-level `fn main` becomes the conditional first source entry. Dependency and
lockfile resolution, registry/cache state, Cargo configuration, command
occurrence, compilation, execution, and success remain explicit unknowns.
Nested crates and workspace-inherited or unusually encoded manifests do not
create roots.

The Python wheel adapter prioritizes installation metadata and executable
`.pth` members before bulky native or data members can consume the archive
budget. It connects site-startup execution only after the complete wheel
inventory, filename tag, one unambiguous `WHEEL`/`RECORD` pair, and required
member hashes validate. Closed `.pth` forms may derive a bounded literal Python
stage with every source evidence ID retained. An incomplete inventory can still
yield Features and neutral operations, but it cannot create a wheel execution
root. Python API recognition then uses a forward-only, indentation-scoped
binding timeline. Exact imports may feed supported calls later in the same
module, function, or contiguous conditional suite; rebinding, dynamic namespace
changes, malformed indentation, and event-budget exhaustion fail closed.

The indexed-gzip artifact adapter recognizes a complete generic structure: a
six-byte opaque envelope whose final byte is a bounded member count, followed
by tagged little-endian declared/compressed lengths and independent gzip
streams that consume the carrier exactly. The prefix and tags have no producer,
version, platform, architecture, or execution meaning in Maratus. Each gzip
stream and declared output size is verified before decoded bytes are
content-classified. A nested Mach-O is analyzed by default because it is
directly useful on macOS, but retains a `packaged-content` role and `UNKNOWN`
connectivity. The envelope alone never establishes which member a loader
selected, wrote, or executed; that requires a separate supported loader
relationship.

## Evidence and features

`Evidence` locates the bytes or decoded metadata used by the analysis. Depending
on the source, it may carry a logical path, physical path, line, byte offset,
virtual address, function, architecture, method, kind, and matched value.

`Feature` is the inexpensive fact plane. Imports, strings, selectors,
entitlements, dependencies, signing fields, URLs, and API references remain
useful even when Maratus cannot prove the surrounding semantics.

Evidence and features are scoped. Function-bearing records require an exact
function scope. Architecture-bearing records cannot cross slices. Cross-node
evidence is accepted only through a typed structural adapter that owns the
relationship. The report loader rechecks these constraints instead of trusting
serialized IDs.

JavaScript uses a bounded structural index rather than evaluating source.
An ordinary Unicode identifier is retained as one token without normalization;
escaped identifiers and unsupported code points remain outside the grammar.
Structural tokens use a compact layout with a fixed count bounded by a 64 MiB
retained-token payload allowance; this is not a limit on total process memory.
Opaque-use inventory streams occurrences and deduplicates by scope and name,
preserving later writes while bounding the number of retained distinct uses.

An exact zero-argument whole-program IIFE may be treated as the module wrapper.
A closed numeric bundle adapter can then connect exact CommonJS wrappers,
loader dispatch, aliases, and supported calls through ordinary Features and
operations. Exact bundled module wrappers remain useful `UNKNOWN` observations
even when an alias occurs inside unsupported control flow; that case is
reported as partial and never promoted to an operation.

An exact call through a proven `child_process` binding may retain a neutral
`process.execute` operation when its command or argv cannot be resolved. The
operation records the API and unresolved-argument coverage. Partial arguments
are limited to identifiers and closed literal/identifier argv arrays. A separately proven
executable argument can be retained without inventing argv. Binding ambiguity,
malformed call syntax and exhausted proof budgets still prevent promotion;
unresolved commands do not produce shell behavior or downstream resource flow.
Nonempty or unresolved process options also prevent command expansion because
they can change the working directory, shell and program selection. Such calls
retain only the proven API primitive with an explicit options limitation.

A separate closed Node builtin adapter resolves immutable ESM and CommonJS
bindings for selected `fs`, `fs/promises`, `os`, `dns`, and `dns/promises`
APIs. It applies the same typed file, discovery, user, and name-resolution
operations used by the other language adapters. Calls require documented
arity plus both binding and call evidence. Dynamic paths remain empty typed
resources, and any alias escape, shadowing, member replacement, computed
property, spread, malformed call, or unsupported bundle control flow prevents
promotion. Inherited module bindings are checked across the retained program
so textual function order cannot conceal a later member replacement.

When a large JavaScript source reaches the structural token ceiling, a second
bounded lexical pass may retain only exact ordinary quoted URL and sensitive
path literals from the already capped source bytes. These records are unscoped
`DIRECT` Features with `UNKNOWN` connectivity. Slash-ambiguous syntax,
malformed literals, family limits, and value limits fail closed. This lane does
not infer imports, calls, operations, communication, or capability matches.

## Operations, resources, and relations

Semantic recognizers turn supported facts into neutral operations. Common
operation families include:

- process and interpreter invocation;
- file read, write, copy, permission change, and metadata change;
- network communication and download;
- archive creation or extraction;
- credential-store access and user prompts; and
- persistence-related configuration.

Script command adapters model a supported literal command form and its static
arguments. A bare command token does not prove how a runtime `PATH`, alias, or
shell function would resolve it, and a path-qualified token does not
authenticate the executable bytes at that path. The resulting operation is a
conditional command attempt, not observed execution or successful effect;
incident attribution still needs endpoint context that identifies the selected
image when command resolution matters.

Shell grammar words are recognized before quote removal. The bounded literal
variable model preserves complete assignment values and invalidates dynamic,
conditional, and namespace-changing writes. It does not reparse variable
contents as shell operators or expand single-quoted and escaped dollar signs.
Variable-derived operation evidence retains both the assignment and the use.
Mutable globals are not inherited into shell function bodies as exact values.
Unquoted values requiring field splitting remain unresolved. This is not a
full shell evaluator: arbitrary function effects, environment state, arrays,
and general parameter expansion remain outside the supported model.

Inline-code recognition and interpreter file selection share the same bounded
option parser. Options after a script operand belong to the script. Validation,
help, module, unknown-option, and missing-argument modes cannot establish an
inline program merely because a later argument resembles `-c` or `-e`.

Launchd command selection preserves literal argument types, empty arguments,
and whitespace. `Program` selects the executable independently of
`ProgramArguments[0]`; the execution-root command view uses that executable
followed by `ProgramArguments[1:]`. A missing `Program` selects the first
argument instead. Malformed declarations remain partial coverage. This models
a declaration, not proof that launchd accepted, loaded, or started the job.


The Mach-O adapter also has closed tables for exact called native primitives:
filesystem access, descriptor and stream I/O, sockets, name resolution,
dynamic loading, hashing, cryptography, compression, randomness, and tracing.
These become operation-backed technical capabilities at `CORROBORATED`
support, but they stop at the action proven by the call. A descriptor read is
not promoted to `file.read` without descriptor provenance; a socket connect is
not promoted to network or C2 communication without address-family and
destination provenance; and a cryptographic call is not labeled ransomware
without exact resource flow and destructive behavior.

Operations bind typed resources by role. A file can be an executable, input,
output, source, or destination without changing its physical kind. Semantic
classifications such as a browser cookie store refine a resource but never
replace its physical identity.

Relations record facts that are stronger than co-occurrence. Current examples
include direct calls, produces, consumes, precedes, and pipes-to. Relation
creation requires evidence from the relevant endpoints and compatible node,
scope, architecture, and execution context. Ambiguous correlations are omitted
or reported as partial rather than guessed.

Network operations and network implementation observations are separate. A
destination belongs to an operation only when it is bound by supported
semantics. HTTP libraries, TLS providers, and standalone URL/domain/IP features
remain useful facts without implying that a connection used them.

## Rules

Rules are written as typed Go `Spec` values over one closed pattern AST. The
engine supports operation patterns, scoped feature joins, execution-root joins,
explicit operation relations, reusable library rules, and bounded resource
flows.

The rule engine, not a rule author, constructs public matches. It projects the
supporting operation IDs, evidence, resources, relations, roots, support, and
connectivity into a bounded match trace. A match cannot be stronger or more
connected than its weakest required fact.

Rules remain in Go while the intermediate representation is evolving. The
compiler and generator provide one vocabulary, one evaluator, deterministic
catalog generation, and source-level validation. Maratus intentionally has no
parallel YAML, JSON, CEL, or runtime rule engine.

That is an integrity boundary rather than an authoring limitation. Resource
roles, classifications, relations, scope joins, support thresholds, and
bounded flows are compile-time Go values; a second serialized rule language
would need to duplicate those types and their validation while adding runtime
parsing, schema migration, and untrusted-rule loading. Simple rules remain a
short `Spec` declaration, and `rules vocab`, `rules check`, generation tests,
and the catalog digest provide the discoverability and reproducibility usually
sought from a data-file format.

This produces two useful levels of results without weakening the evaluator.
Technical rules inventory exactly called primitives in a capa-like form.
Higher-level rules remain sparse until operations, resources, order, and
execution context establish the stronger behavior. Both levels use the same
typed operations and the same minimum support threshold.

## Mach-O path

Mach-O analysis follows the same layers as other formats:

1. A raw preflight validates headers, load-command bounds, slice ranges,
   segments, sections, mappings, and count limits before `debug/macho` is used.
2. Thin and fat slices keep their architecture and outer-file offset so
   evidence locations remain artifact-relative.
3. Structure extraction records imports, libraries, signing metadata,
   entitlements, symbols, strings, and function boundaries. Modern
   `LC_DYLD_CHAINED_FIXUPS` import-name tables are recovered under independent
   extent, count, string, and format limits. For validated 64-bit userland
   pointer formats, a second bounded walk may associate an exact bind-fixup
   slot with an exact imported symbol. Rebase values are not applied. An
   import name or bind slot remains structural metadata: neither is a call or
   execution by itself.
4. Bounded x86_64 and arm64 decoding recovers selected direct calls, string
   references, and argument provenance. x86_64 also accepts the one canonical
   RIP-relative indirect-call encoding when its destination is an exact
   `S_NON_LAZY_SYMBOL_POINTERS` or `S_LAZY_SYMBOL_POINTERS` slot backed by an
   undefined external symbol; arbitrary indirect calls remain unsupported.
   Supported native C-string arguments
   retain separate reference-instruction and literal evidence before binding a
   typed resource. Exact `execv`/`execve`/`execvp` calls may bind a complete,
   NUL-terminated static pointer-array `argv` under fixed entry and byte
   budgets. Direct `connect(2)` calls may bind a structurally validated static
   Darwin IPv4/IPv6 `sockaddr`; Unix sockets, `connectx` endpoint structures,
   and dynamic addresses remain unresolved. Unknown instructions and
   control-flow boundaries invalidate state conservatively. On arm64, the
   closed Objective-C receiver model also understands exact x29-relative
   64-bit compiler spills and reloads. Stores from unknown values, stack/frame
   alias escape, branches, decode gaps, and function changes invalidate the
   affected state.
5. Recognizers promote only supported call and argument patterns into
   operations. Exact static `__cfstring` method arguments retain the register
   reference, CFString object, and length-delimited backing bytes. A closed set
   of path-taking Foundation selectors may bind that value to a neutral
   operation, but unresolved receiver identity keeps the operation heuristic
   and below capability-rule support. `NSTask setLaunchPath:` is retained as
   visible configuration only until an exact imported class reference, linear
   receiver lifecycle, path/argument resources, and later launch on the same
   receiver are all proven. A chained class bind can establish class-slot
   identity, but it cannot establish the message send or execution on its own.
6. Direct-call, execution-root, and relation linking preserves the exact slice,
   function, scope, and evidence used for the conclusion.

This is not a decompiler or a general control-flow engine. Unsupported
architectures, general register/vtable/function-pointer indirect calls, dynamic
dispatch, data-dependent values, and budget exhaustion remain visible in
coverage.

For Go Mach-O binaries, Maratus decodes the modern inline `__go_buildinfo`
record under fixed byte, line, and record budgets. Toolchain, package,
main-module, dependency, replacement, and build-setting values retain exact
section offsets. A separate bounded Go 1.18+ `__gopclntab` enricher validates
the exact name table, function table, executable-text base, ranges, count, and
cumulative name budget before contributing compiler function names and
boundaries to the ordinary Mach-O scopes and call graph. Operations record
whether their source function was conservatively classified as Go
runtime/compiler support, a known standard-library package, or other Go code.
The last category deliberately does not claim application ownership. Pclntab
metadata never creates reachability or an operation by itself.

A closed Go semantic enricher can combine that exact function identity with a
decoded direct call and fresh ABIInternal pointer/length registers. It reads at
most 4,096 exact printable bytes from validated image sections and emits normal
resource-bound operations for selected stable standard-library APIs. Supported
examples include file reads/writes/removal/metadata, directory creation and
enumeration, rename, network destinations, and process APIs. Each concrete
resource binding references its own pointer, length, and literal evidence.
`net.Dial` requires both an exact supported Internet network kind and an exact
destination, so a Unix-domain path cannot be mislabeled as an Internet
endpoint. HTTP helpers require an absolute HTTP(S) URL with a host, so relative
or non-network URLs remain observations. `os/exec.Command` is only
`process.launch.configure`; it becomes
`process.execute` only when its returned receiver is consumed by an immediately
adjacent exact `(*exec.Cmd).Run`, `Start`, `Output`, or `CombinedOutput` call.
The two operations retain a `PRECEDES` relation. Variadic argv remains
unresolved and is stated in the operation qualifiers and summary projections.

This is not general Go data-flow recovery. Interface values, slices, closures,
indirect calls, dynamic dispatch, stack spills, branches, interprocedural
values, and unsupported compiler layouts invalidate or omit the semantic
context. The exact decoded call remains available as a Feature, and coverage
states the missing semantics.

Direct-call Feature retention reserves bounded capacity for non-runtime callers
instead of letting address-ordered Go runtime code consume the whole correlation
budget. Runtime/compiler and standard-library caller pairs have separate caps;
additional exact decoded edges still participate in reachability but are not
available to cross-function rules, and that loss is reported as partial
coverage. Summary text/JSON/HTML also separate behavioral capabilities,
technical primitives, and runtime/compiler support. Exact non-runtime Go
function names participating in retained calls are shown as code context only,
never as behavior or proof of application ownership.

Mach-O symbol enrichment applies the same boundary to Rust. Maratus accepts
only rustc's unambiguous `_R` v0 prefix or a legacy `_ZN...17h<hash>E` name
that passes the pinned in-process demangler's conservative Rust checks. Input
and output lengths are bounded. The readable function name, mangling version,
crate/module prefix, runtime/standard/other classification, and exact original
linker symbol are attached to ordinary function scopes, calls, xrefs, and
operations; there is no second Rust IR or evaluator. Rust runtime and standard-
library operations are separated in summaries, while other crate identity is
explicitly not treated as application ownership. Symbol metadata does not
create a call, operation, reachability, or capability. Stripped Rust binaries
without an exact surviving language marker remain generic Mach-O rather than
being guessed from strings or behavior.

The same ordinary function/call pipeline can enrich exact Itanium C++ linker
symbols. A pinned in-process demangler supplies a bounded readable display
name, top-level namespace, and runtime/compiler, standard-library, or other
origin. The normalized raw linker symbol remains the canonical scope and call
identity so long template names cannot displace exact facts under report
budgets. Rust-shaped legacy names are rejected before C++ classification.
Readable C++ names improve analyst navigation and runtime-noise separation;
they do not create calls, resolve virtual dispatch, establish application
ownership, or prove behavior. RTTI and vtable recovery remain deferred until
they measurably improve typed operation recovery.

Swift enrichment stays narrower than demangling. Maratus recognizes the four
documented Swift 4+ symbol prefixes and decodes only the exact leading module
production within the shared symbol-input bound. The raw mangled name remains
the canonical function and call identity; module and mangling generation are
ordinary qualifiers. Swift standard-library and foreign-bridge contexts are
separated from other modules in summaries, while every other module is
explicitly not treated as application ownership. Maratus does not invoke
`swift-demangle`, load `libswiftDemangle`, accept symbolic references, or infer
behavior from a symbol. A future full in-process demangler or reflection parser
must show additional operation recovery on malicious and source-backed benign
controls before expanding this boundary.

Rust source receives a separate conservative boundary. Exact bounded lexical
proof can retain neutral calls to selected stable APIs, including fully
qualified `std::fs` read, enumerate, metadata, create, write, delete,
permission, copy, and rename forms. Each recognizer requires the documented
argument count; copy and rename keep independently evidenced source and
destination bindings. Exact `Command::new` chains retain bounded literal or
immutable-bound `.arg` values and exact array-literal `.args` values as a typed
JSON argv resource; any dynamic, oversized, or unsupported argv builder leaves
the complete argument vector explicitly unresolved. Without rustc name
resolution or macro expansion those operations remain `HEURISTIC` and below
capability-rule support. Dynamic paths
and destinations stay empty. For a Cargo-selected build script, only its exact
`main` scope and exact function scopes reached by the bounded direct-call
feature graph can inherit the conditional root. Platform and branch
feasibility are not resolved, and `CONNECTED` still does not mean Cargo ran or
a call succeeded.

Rust constant observations use one format-neutral transformation boundary:
complete immutable string or string-array initializers may be canonically
base64-decoded within fixed declaration, fragment, input, and output budgets.
Every decoded URL, IP address, or content fingerprint retains all source
literal evidence. Dynamic expressions, macro-generated values, malformed or
noncanonical encodings, and cross-declaration concatenation are rejected. The
recognizer contains no family, filename, hash, or incident-specific values,
and decoded observables are never bound to a network operation without exact
argument flow.

Other supported source formats may retain the same canonical Base64-derived
observables from a complete line-oriented assignment. A bounded language-aware
lexical guard rejects assignments inside comments, quoted examples, Python
docstrings, shell heredocs, and native multiline strings; unknown source
syntaxes are not decoded. This path also remains Feature-only.

## Coverage and limits

Budgets exist at both the artifact and semantic layers. They bound file bytes,
expanded bytes, compression ratios, nesting depth, node and evidence counts,
derived text, instruction decoding, call graphs, relations, and rule
evaluation. A parser should stop one local task when possible and continue with
safe siblings.

Coverage records name the affected node or scope, status, and reason. Limits
must never be converted into a clean no-match result. Invalid producer context
and invalid report references fail closed rather than being mislabeled as
budget exhaustion.

Go's standard `debug/macho` parser is not hardened for adversarial input. The
raw preflight reduces that exposure. The normal `maratus inspect` path therefore
executes analysis in a fresh same-binary worker with a versioned private JSON
request, wall deadline, conservative inherited-or-lower resource limits,
bounded output, process-group termination, a minimal non-inherited environment,
and strict report validation in the parent. Worker supervision contains parser
failure and resource runaway while withholding unrelated ambient credentials;
the archive password, when required, still crosses in the private worker
request. This is not a replacement for an OS filesystem/network sandbox or an
isolated analysis host. `maratus render` stays in-process because it accepts
only bounded, strictly validated report data and does not invoke artifact
parsers.

## Reports and determinism

Finalization sorts set-like collections, assigns stable IDs, projects only
referenced evidence, and validates every reference. Saved JSON includes the
tool identity, settings, schema, ruleset, normalized rule-catalog digest, and
coverage that affected the result.

`maratus render` treats a saved report as untrusted input. It checks schema,
limits, identifiers, node and scope ownership, evidence lineage, relation
proofs, match projections, and rule replay when the catalog identity matches.
Validation establishes internal consistency, not authenticity.

Text is a bounded presentation for people. JSON is the complete automation
interface. HTML is a deterministic, self-contained projection of a validated
report and loads no remote assets.

## Package map

| Package | Responsibility |
| --- | --- |
| `cmd/maratus` | CLI parsing, help, output selection, and atomic file writing |
| `internal/artifact` | Classification, containment, expansion, graph construction, and structural roots |
| `internal/extract` | Features, host adapters, semantic recognizers, native analysis, and linking |
| `internal/behavior` | Typed evidence, execution, operations, resources, relations, and graph invariants |
| `internal/rules` | Typed rule AST, generated catalog, bounded evaluation, and match traces |
| `internal/report` | Inspection orchestration, finalization, validation, and text/JSON presentation |
| `internal/visualization` | Offline HTML projection |
| `internal/machox`, `plistx`, `shellparse` | Small hardened parsing helpers |

## Change boundaries

New support should enter at the lowest layer that can express it honestly. Add
a parser or feature before adding an operation; add an operation before adding
a capability rule. Reusable semantic patterns belong in tables or focused
recognizers, not family, hash, or sample-name checks.

See [Extending Maratus](extending.md) for the implementation and test workflow.
