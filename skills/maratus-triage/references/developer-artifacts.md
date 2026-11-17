# Developer-artifact triage

Use this when a package, project, extension, or agent configuration raises a
question about which code a host selects. It supplements Maratus findings;
it does not expand the tool's supported adapters. Check the installed build's
coverage ledger, keep unsupported rules unresolved, and label manual findings.

## Identify the bytes and the missing links

Record whether the input is a distribution archive, source revision, installed
copy, or compiled binary. Matching names and versions do not prove matching
bytes. A checkout may differ from a distributed package, and an installation
may have changed. Describe each available object separately; Maratus cannot
reconstruct deleted files or establish what was present during an earlier event.

Distinguish the container, first selected entry, and later helper or payload.
Cite a declaration, operation, or relation for each claimed connection. A path
or URL does not establish that its contents were retained. Mark missing objects
and unresolved links; do not fetch or execute a payload to complete the chain.

## Explain the activation condition

Record the trigger, selecting declaration, exact target, and relevant host
version/context. Use existing records or copied configuration. Do not start
an IDE, package manager, interpreter, or agent against suspect content to
identify its settings. Select only the relevant row below; use documentation
for the actual product and version.

| Context | Check before attributing activation |
| --- | --- |
| [npm](https://docs.npmjs.com/cli/v11/using-npm/scripts/) / [Node](https://nodejs.org/api/packages.html) | Distinguish an install hook from a module load, CLI, or preload. Retain the selecting manifest field, applicable policy, and working directory. Disabling install scripts does not rule out later module execution. |
| [Python startup](https://docs.python.org/3/library/site.html) / [imports](https://docs.python.org/3/reference/import.html) | Distinguish startup, import, entry-point, and build paths. Identify interpreter version, environment, flags, and applicable site/import rules. Do not assume a wheel matches its source distribution. |
| [Go](https://go.dev/ref/spec#Package_initialization) | Package initialization belongs to program startup. A module download or module list alone does not prove that the relevant package was linked or initialized; identify the exact binary and build evidence. |
| [Cargo](https://doc.rust-lang.org/cargo/reference/build-scripts.html) | Identify the resolved package, `package.build` selection, and whether a run was scheduled or output reused. The compiled build-script helper runs on the build host, which may differ from the compilation target. |
| [Editor extensions](https://code.visualstudio.com/api/advanced-topics/extension-host) | Identify the distributed extension, profile, activation condition, entry, and local/remote/web host. A Mac editor window does not establish local extension execution. Tasks and terminal settings need separate selection evidence. |
| [Xcode](https://developer.apple.com/documentation/xcode/running-custom-scripts-during-a-build) | Identify the project revision, target, configuration, referenced phase, and actual shell/script. A phase declaration or project open does not establish that a build scheduled it. |
| [Agent hooks](https://code.claude.com/docs/en/hooks) and configuration | Distinguish instructions, command hooks, and server configuration. Identify product/version, configuration scope, event, and relevant trust/approval state. An instruction or requested tool call does not prove a completed action. |

## Name the evidence needed next

Maratus reports static relationships. If the question concerns actual execution,
name the missing host, environment, activation/build record, or exact downstream
object that could resolve it. Keep that proposed follow-up separate from the
inspection and attribute supplied external evidence to its own source.

A shared interpreter or extension host can evaluate code without a child
process. A generic process name or file open does not identify which package
ran; an absent child does not prove inactivity. A Mac-compatible entry also
does not establish that every later stage targets macOS or succeeded. Preserve
those uncertainties instead of completing the narrative from nearby clues.
