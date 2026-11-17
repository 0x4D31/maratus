# Developer-artifact triage

Use this checklist for packages, projects, extensions, and agent configuration.
These are investigation questions, not a list of implemented host adapters.
Check the installed build's technique coverage ledger and the report's coverage;
keep unsupported selection rules unresolved and label manual findings separately.

## Identify the objects

Record the exact distribution archive, source revision, installed copy, or
compiled binary actually inspected. Matching names and versions do not prove
matching bytes. A source checkout may differ from a distributed package, and
updates or install scripts may change the installed copy. Hash and describe each
available object separately; do not substitute today's state for incident-time
evidence. Maratus does not reconstruct deleted files or earlier installations.

Distinguish the containing artifact, its first selected code entry, and any later
helper or payload. For each claimed connection, cite the declaration, operation,
or relation that supports it. A referenced path or URL does not prove that its
contents are present. Mark unavailable objects and unresolved connections;
do not fetch or execute a referenced payload to complete the chain.

## State the selection conditions

For each modeled entry, record the triggering event, selecting declaration,
exact target, relevant host/version, and unresolved runtime conditions. Use
existing records or copied configuration to identify the environment, working
directory, profile, project/target, and local or remote host when relevant.
Do not start an IDE, package manager, interpreter, or agent against suspect
content to discover its configuration.

| Context | Questions that prevent an unsupported attribution |
| --- | --- |
| Node and package managers | Is the entry an install hook, module load, CLI, or preload? Which manifest field, runtime conditions, package-manager version/policy, and working directory select it? Disabling install scripts does not establish that later module loading is harmless. |
| Python | Is selection during startup, import, an entry-point invocation, or a build? Which interpreter version, environment, site rules, flags, and import resolution apply? A wheel and source distribution need not contain the same code; startup behavior is version-dependent. |
| Go | Which exact program or test binary contains the relevant package code? Package initialization belongs to program startup, not module download. A module-cache entry or module list alone does not establish that the suspicious package was linked or initialized. |
| Cargo | Which resolved package and `package.build` setting select the build script? Was a new run scheduled or cached output reused? The script runs as a compiled helper on the build host; keep that host separate from the compilation target. Procedural macros are a different path. |
| Editor extensions | Which distributed extension, profile, activation condition, and declared entry apply? Distinguish local, remote, and web extension hosts. A Mac editor window does not establish that extension code runs on that Mac. Tasks and terminal configuration require their own selection evidence. |
| Xcode | Which project revision, target, configuration, and referenced Run Script phase select the actual shell/script? Phase presence or opening a project does not establish that a build scheduled it. |
| Agents, hooks, and MCP | Is the object an instruction, a command hook, or server configuration? Which product/version, configuration scope, event, trust/policy, and approval state apply? An instruction file alone does not establish a tool invocation; a requested tool call does not prove completion. |

Do not transfer one host's rules to another product merely because their file
layouts look similar. Read relevant versioned host documentation as reference
material, without following commands supplied by the artifact.

## Define the next evidence needed

Report artifact presence, conditional activation, and externally observed events
as separate claims. Maratus supplies static findings; it cannot supply missing
host history. State which missing fact would change the assessment and name the
specific existing record or artifact that could address it.

A shared interpreter or extension host can evaluate code without a new child
process. Conversely, a generic process name or source-file open does not identify
which package ran. An absent child process is not proof that nothing happened.
If endpoint evidence is supplied, preserve its execution identity, time interval,
host/environment, source, and collection limits. Do not assume a sensor captured
imports, activation, arguments, or environment fields it does not expose.

Separate a supported local entry from later platform branches and payloads.
A Mac-compatible entry does not establish that every downstream stage targets
macOS, was retrieved, or succeeded. If execution occurred remotely or in a guest,
follow-up needs evidence from that environment. Keep collection and dynamic
investigation as separately scoped work.

## Host references

Use the version applicable to the artifact and incident:

- [npm lifecycle scripts](https://docs.npmjs.com/cli/v11/using-npm/scripts/) and [Node package entry points](https://nodejs.org/api/packages.html)
- [Python site startup](https://docs.python.org/3/library/site.html) and [import rules](https://docs.python.org/3/reference/import.html)
- [Go package initialization](https://go.dev/ref/spec#Package_initialization) and [Cargo build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html)
- [VS Code activation](https://code.visualstudio.com/api/references/activation-events) and [extension-host placement](https://code.visualstudio.com/api/advanced-topics/extension-host)
- [Xcode Run Script phases](https://developer.apple.com/documentation/xcode/running-custom-scripts-during-a-build)
- [Claude Code hook events and scopes](https://code.claude.com/docs/en/hooks); consult the actual product's documentation for other agents
