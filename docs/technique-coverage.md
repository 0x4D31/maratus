# Technique coverage ledger

This ledger is the implementation contract for security-relevant semantics.
`supported` means at least one bounded adapter can emit the named typed
operation with exact evidence. It does not mean every syntax, library, dynamic
dispatch form, or artifact is supported. `observational` means retained
Features may help an analyst but are deliberately too weak for an operation.

Capability rules require operation-backed `CORROBORATED` support. A static
`CONNECTED` result means only that the retained graph reaches the operation
from a declared root; it is never observed execution or successful effect.

`osascript` file, inline, stdin, and appended-target selection share one bounded
option profile. Interactive mode loads a supplied program without automatically
executing it; that input does not become an execution target. Unsupported
languages, option aliases, malformed options, and exhausted parsing budgets do
not establish program execution. Script arguments do not change host options.

Native static argument vectors require a terminating null pointer and bounded
NUL-terminated strings, including valid empty arguments. Their bindings retain
the vector terminator as evidence. Argument-dependent classifications require
the complete binding and its evidence to fit the report budgets.

Filesystem flow correlation requires compatible path interpretation as well as
source order and execution context. Shell relative paths join only within a
retained stable working-directory context; current-home expansion has a separate
context. Directory changes, HOME changes and unsupported state-changing syntax
invalidate the applicable proof. Quoted or escaped tilde paths are literal;
named-user and shell-specific tilde expansions remain unresolved for correlation.
Other adapters do not acquire a working-directory proof merely from equal
relative operand text. Intervening modeled mutations with unresolved file targets
also prevent attributing earlier produced bytes to a later consumer.

Command recognizers distinguish shell source from decoded executable argv.
Only exact raw shell words establish redirection or current-home expansion;
quoted operators and literal tilde/HOME operands do not establish startup-file
locations. Closed stdout/stderr file redirections and `tee` operands retain
neutral file writes, including ordinary overwrites that invalidate staged-file
lineage. Redirection words are removed from command argv. Input redirection and
heredoc byte consumption remain partial, as do unsupported embedded operators
and descriptor destinations. A complete decoded process request remains visible
when no more specific action is modeled. External wrappers do not acquire shell
builtin or assignment syntax merely from their executable operands.

JavaScript AST call operands support bounded primitive-string bindings from
unwritten lexical declarations and function-local variables, all-string
concatenation, untagged string templates, and complete literal argv arrays.
Declaration, transformation, and call evidence are retained. Top-level `var`
exposure, captured values, mutable bound arrays, dynamic coercions, and
incompatible function/block proof contexts remain unresolved. Existing host,
namespace, mutation, launch-option, and capability-support requirements apply.
Unpaired UTF-16 surrogates remain unresolved rather than becoming replacement
characters. A proved process API request remains visible when its command has
no more specific supported shell semantics; that alone does not resolve an
executable or establish downstream behavior.
AST namespace proofs from incompatible function scopes remain observational
with explicit coverage. Whole-file loader shadowing, namespace escapes, and
mutation checks also apply to leading IIFEs; a wrapper is not reparsed in
isolation to bypass those checks.

JavaScript HTTP API destinations require a complete supported URL operand.
URLs found inside prose or unsupported values remain observations; they are
not selected endpoints. An exact unshadowed `fetch` request with an unresolved
destination retains a neutral network operation with an unknown endpoint.
Neither the call nor its static connectivity establishes successful contact.

JXA Standard Additions shell calls reuse the bounded primitive-string resolver.
A stable program-level current-application receiver and preceding enablement
are still required. Assigned, returned, and chained call results are admitted;
function and branch calls retain their own scopes with unknown connectivity.
Receiver mutation, escape, dynamic host identity, and incompatible value proof
contexts prevent promotion. Helper returns, shell output, and native bridge APIs
are not evaluated, and Node API semantics are not applied to JXA.

| Area | Technique | Typed model | Adapters | Status and boundary |
| --- | --- | --- | --- | --- |
| Activation | App, package, project, extension, module, package lifecycle, Cargo build script | roots and invoked targets | artifact metadata | supported for documented bounded profiles; dependency selection and runtime success remain conditional |
| Activation | Compiled and run-only AppleScript | roots and invoked targets | applet structure and compiled-script classification | structural selection is supported, but bytecode semantics and commands are partial; Maratus does not decompile compiled AppleScript or infer behavior from adjacent strings |
| Execution | AppleScript and JXA Standard Additions shell commands | interpreter invocation and shared shell operations | bounded source statements and selected `osascript -e` programs | AppleScript requires an actual command form and a complete literal expression, with bounded concatenation, parentheses and `quoted form`; unresolved expressions retain an unknown command, never a command synthesized from fragments; handlers and branches have separate scopes with unknown reachability; application `tell`, script-object and terminology contexts remain partial; JXA requires a stable program-level `Application.currentApplication()` receiver with an exact preceding Standard Additions enablement and no receiver mutation, escape or dynamic namespace ambiguity; successive `-e` arguments are one program and an explicit JavaScript language selects JXA semantics; source keywords and URL literals alone are observational |
| Artifact structure | Indexed length-prefixed gzip bundle | typed containment, member inventory, and content-classified payload nodes | complete generic six-byte envelope, bounded tagged length table, independent gzip members, declared output sizes | supported structurally without interpreting the opaque prefix or tags; a decoded Mach-O member is analyzed by default with `packaged-content` provenance and `UNKNOWN` connectivity, while the envelope alone never proves member selection, write, invocation, or execution |
| Activation | Local AI coding-agent lifecycle hooks | conditional roots and invoked targets | Claude Code, Codex, and Gemini CLI project configuration | supported for closed documented hook profiles; effective settings precedence, compatible host version, project trust, lifecycle event occurrence, session working directory, selected shell, and runtime success remain conditional; an instruction or configuration file alone is never execution |
| Execution | Native process, interpreter, package install, download/execute | process/interpreter/package/network operations and exact resource flow | shell, Python, JavaScript/JXA, AppleScript, native source, Mach-O, Rust | supported; script command forms do not resolve runtime `PATH`, shell aliases/functions, or authenticate executable bytes; exact shell `rm`, `cp`, and `mv` mutations invalidate earlier same-path download lineage, while `mv` destinations remain unresolved because filesystem state decides whether the final operand is a filename or directory; Python uses a bounded forward-only, indentation-scoped binding timeline for exact module and local imports, including imports in the same contiguous conditional suite, while rebinding, sibling/dedented suites, dynamic namespaces, starred arguments, unsupported keywords, malformed indentation, and ambiguous call shapes remain partial; exact zero-argument whole-program JavaScript IIFEs and closed numeric CommonJS bundle wrappers/loaders are supported, while aliases inside unsupported control flow remain observational and partial; Mach-O binds complete static `argv` arrays for exact `execv`-family call arguments and exact Darwin IPv4/IPv6 `sockaddr` constants for direct `connect(2)` calls, while dynamic vectors, socket addresses, and `connectx` endpoint structures remain unresolved; Rust source remains heuristic without compiler semantics |
| Execution and configuration | Local AI coding-agent invocation, reduced-safeguard options, configuration/instruction changes, and transcript/history access | ordinary `process.execute`, `file.read`, `file.write`, `file.copy`, `file.move`, and `file.delete` operations with typed agent resources | exact shell, Python subprocess, bounded Node `child_process`, supported file APIs, and selected native resource recovery | supported for a closed product/CLI/path table covering documented Claude Code, Codex, Gemini CLI, Amazon Q, Copilot, Kiro, Cursor, MCP, hook, instruction, and transcript forms; results remain neutral and say only what executable/options or file target static semantics selected; they do not prove prompt acceptance, tool use, instruction ingestion, MCP connection, evidence tampering, malicious intent, or successful effect; Rust source remains visible but heuristic and cannot satisfy these rules |
| Technical primitives | Filesystem, descriptor/stream I/O, sockets, name resolution, dynamic loading, hashing, cryptography, compression, randomness, and process tracing | neutral primitive operations with unresolved typed resources where arguments are not recovered | exact located Mach-O import calls | supported closed API tables; exact C-string call arguments bind supported file, configuration, identifier, and library resources with separate instruction/literal evidence; primitive capabilities otherwise describe the call only and do not imply a concrete object, malicious intent, successful effect, network C2, or ATT&CK objective |
| Native provenance | Go compiler function identity, package-qualified scopes, and selected exact ABI strings | `go.pclntab`, function scopes, ordinary call Features, and resource-bound operations | Go 1.18+ Mach-O `__gopclntab` plus bounded arm64/x86_64 direct-call decoding | function recovery is supported under section, count, byte, range, name, and per-origin call-retention budgets; a closed recognizer combines exact pclntab targets with fresh ABIInternal pointer/length pairs for selected stable standard-library file, directory, network, and process APIs; resource bindings retain their pointer, length, and literal evidence; `net.Dial` requires an exact supported Internet network kind as well as its destination; `os/exec.Command` is configuration only unless its exact returned receiver is immediately consumed by a supported `*Cmd` execution method; variadic argv, interfaces, slices, closures, stack spills, indirect calls, branches, dynamic values, and application ownership remain unresolved |
| Native provenance | Objective-C methods and calls | class/method metadata, selector references, typed message stubs, exact CFString and bounded CFString-array arguments, and receiver-qualified calls | Objective-C Mach-O metadata and native source | supported where section identity and call provenance are exact; arm64 direct stubs/calls and canonical x86_64 calls through typed indirect-symbol slots feed the same call model; bounded constant and compiler-generated stack arrays retain every exact element; classic dyld and supported modern chained-bind slots can recover an exact imported class reference, and conservative linear object flow correlates supported `alloc`/`init`, setter, and launch messages on the same receiver; arm64 additionally supports exact x29-relative compiler spills/reloads with conservative invalidation; only an exact `NSTask` class, exact launch path/arguments, and same-receiver launch is `CORROBORATED`, while unresolved class/path/receiver cases remain heuristic; rebases, general aliasing, branches, and general Objective-C object flow remain unsupported |
| Native provenance | Swift compiler/runtime identity | exact raw function scopes, documented mangling generation, leading module, runtime/standard/other origin, and ordinary calls/xrefs/operations | bounded Mach-O symbols and the documented Swift 4+ prefix/module grammar | supported when an exact symbol with a directly encoded leading module survives; word-substituted modules, malformed/over-budget names, symbolic references, and stripped binaries are not guessed; no full demangling is claimed, and module identity never creates behavior or establishes application ownership; reflection/conformance parsing remains deferred pending measured operation gains |
| Native provenance | Rust compiler/runtime identity | exact demangled function scopes, raw linker symbols, mangling version, crate/module prefix, runtime/standard/other origin, and ordinary calls/xrefs/operations | bounded Mach-O symbols plus pinned in-process Rust v0/legacy demangler | supported when an exact rustc symbol survives; ordinary C++ `_ZN` lookalikes, malformed/over-budget names, and stripped binaries without an exact marker are not classified; non-runtime crate identity is not application ownership, and symbols alone never create behavior |
| Native provenance | C++ compiler/runtime identity | exact raw function scopes, bounded demangled display names, top-level namespace, runtime/standard/other origin, and ordinary calls/xrefs/operations | bounded Mach-O symbols plus pinned in-process Itanium demangler | supported when an exact Itanium symbol survives; Rust legacy lookalikes, malformed/over-budget names, and stripped binaries without an exact marker are not guessed; readable names are presentation/provenance metadata and never create behavior; RTTI, vtables, virtual dispatch, and ownership remain unresolved pending measured operation gains |
| Loader context | Imports, runtime search paths, and non-system dependencies | exact `macho.import`, `macho.rpath`, and `macho.dylib` Features plus exact supported bind-slot identities | Mach-O symbol/load-command/linkedit metadata | undefined symbols and bounded modern chained-fixup import names are supported as static observations; classic dyld bindings and validated 64-bit userland chained bind records can map an exact pointer slot to an import, while rebases are not applied; canonical x86_64 RIP-relative calls through typed slots can identify a called undefined external, but an import or binding never proves a call; a declaration does not prove dependency presence, resolution, loading, or a hijack |
| Artifact trust | Embedded signature, CodeDirectory integrity, identifier, team ID, and entitlements | artifact properties and coverage | Mach-O code-signature structures | supported for bounded offline structure and page-integrity checks; certificate-chain trust, notarization, ticket stapling, online revocation, and current Gatekeeper policy are host-state questions and are not claimed |
| Structured observables | Complete embedded X.509 certificates | `cryptographic.certificate` Feature with DER SHA-256 fingerprint and bounded identity fields | binary and text byte streams | supported only for a complete bounded PEM block that parses as X.509; summaries do not repeat certificate bytes, and trust, chain construction, revocation, signing use, and runtime use are not evaluated |
| Structured observables | Complete embedded private keys | `cryptographic.private_key` Feature with public-key SPKI SHA-256 fingerprint | binary and text byte streams | supported for bounded RSA, EC, and PKCS8 signing-key PEM material validated by the standard-library parsers, including blocks adjacent to pooled constants; key bytes are omitted, runtime use is not established, and OpenSSH private-key validation remains unsupported with explicit partial coverage |
| Structured observables | JavaScript literals beyond the structural token ceiling | unscoped `network.url` and `script.sensitive_resource` Features | bounded ordinary quoted literals in the already capped source bytes | observational only; exact URLs and supported sensitive paths retain direct evidence with `UNKNOWN` connectivity, while slash-ambiguous or malformed syntax fails closed and no import, call, operation, communication, or capability is inferred |
| Obfuscation | Exact encoded literals and encrypted/packed native content | derived Features with source lineage, or explicit coverage | bounded base64 decoding and Mach-O encryption metadata | canonical bounded base64 literals are supported; split constants, custom encodings, runtime decryption, packers, and encrypted Mach-O code remain partial rather than guessed |
| Anti-analysis | Debugger, VM, and environment checks | neutral process/system query operations and technical primitives | exact commands and located native API calls | technical primitives may be retained, but anti-analysis intent is not claimed without exact arguments and control-flow context; a `ptrace` or `sysctl` call alone is not an evasion verdict |
| Persistence | LaunchAgent and LaunchDaemon | `launchd.job.*` | plist, shell, package scripts, native source, Mach-O | supported when a declaration, installation, load, or registration action is established; shell path writes require a direct `.plist` child of a canonical system, root, or user launchd directory, reject staged/nested lookalikes, and leave `cp`/`mv`/`install` final identity unresolved while retaining the literal destination operand; a flat-PKG payload path is installed context only when the parsed XAR topology pairs it with the same component's bounded `PackageInfo` and an exact absolute `install-location`; ZIP lookalikes, malformed or missing metadata, relocated paths, and recursively embedded archives remain declarations; embedded plist data alone is observational |
| Persistence | Login item and `SMAppService` | `login-item.*`, `launchd.job.register` | Swift/Objective-C source, Mach-O, structural app metadata | supported where service kind and registration receiver are exact; legacy `SMLoginItemSetEnabled` requires a literal `true` argument in source, while `false`, dynamic booleans, and the ambiguous binary call remain non-capabilities; unresolved Objective-C receiver identity remains heuristic |
| Persistence | Shell startup file | `shell.profile.modify` | shell and exact command expansion from supported script adapters | supported for a closed set of canonical macOS zsh, bash, and fish user/system profile paths; staging-tree suffix lookalikes are rejected, and `cp`/`mv`/`install` final identity remains unresolved while the destination operand is retained |
| Persistence | Cron | `scheduled-job.register` | shell and exact command expansion from supported script adapters | supported for exact `crontab` registration; later acceptance and execution are not established |
| Persistence | Emond, legacy StartupItems, authorization plugins, reopened apps | none | none | deferred pending pinned representative samples and exact host-selection semantics |
| Persistence | Dylib hijacking | plist modification or observational Features | plist/source/Mach-O | exact `LSEnvironment`/DYLD configuration can be retained; no persistence match without the complete host relationship |
| Discovery | System, user, network configuration, process, software, file/directory | typed query/enumeration operations | shell, supported script calls, exact native calls | supported closed tables only; Python's table requires a stable exact module binding plus a documented call/parameter shape, keeps unresolved resources empty rather than guessing, and covers selected `os`, `glob`, `platform`, `pwd`, `shutil`, and `socket` calls; JavaScript applies the same proof boundary to selected immutable Node `fs`, `fs/promises`, `os`, `dns`, and `dns/promises` bindings and exact calls, including exact closed bundle aliases; network configuration is distinct from communication and covers closed commands plus exact `getifaddrs`, `if_nameindex`, Python `socket.if_nameindex`, Node `os.networkInterfaces`, and Go `net.Interfaces` calls; process discovery requires a concrete `NSWorkspace` receiver expression in source, while selector-only binary results remain heuristic because receiver identity is unresolved; arbitrary reflection and dynamic command construction remain partial |
| Credential access | Keychain, browser credentials, SSH, cloud/developer tokens, wallets | credential/file reads with classified resources | shell, Python, JavaScript/JXA, AppleScript, native source, Mach-O | supported when the read and concrete resource identity are both evidenced; Python's direct builtin `open(...).read(...)` profile requires unshadowed identity, an exact pathname, an `r`-family mode, no custom opener, supported static I/O options, and an omitted/`None`/nonzero integer read size; other shapes remain partial; `SecKeychainFindGenericPassword` and `SecKeychainFindInternetPassword` are credential-specific, while generic `SecItemCopyMatching` is reported separately as a neutral Keychain item query because its item class may be a key, identity, certificate, or password; static resource observations also cover common Chromium-family, Firefox, messaging, wallet, SSH, Azure, Kubernetes, GitHub, Cargo, RubyGems, and Git credential paths, but a path alone never becomes access or collection |
| Collection | Clipboard read/write, generic pasteboard item access, screen capture, application data | typed read/write/capture operations | shell, supported script APIs, native imports/selectors | supported closed tables; exact bounded `screencapture(1)` argv binds static output files while clipboard/default/UI modes remain output-less and unsupported output syntax is partial; screen video outputs remain unclassified files rather than screenshots; only a concrete general `NSPasteboard` expression is clipboard access; Carbon APIs with an unresolved `PasteboardRef` are neutral pasteboard-item operations because the reference may be a named or drag-and-drop pasteboard; clipboard and pasteboard writes remain neutral and never imply theft or replacement intent |
| Collection | Quartz input-event tap creation | `input-event.tap.create` | native source and exact called Mach-O imports | supported as a neutral event-tap operation; event mask and callback behavior are unresolved, so no keylogging or ATT&CK input-capture claim is made |
| Collection | Camera photo capture | `camera.capture` | receiver-qualified native source and exact AVFoundation Objective-C selectors | supported for source lines that retain the AVFoundation class and capture call together; Mach-O selector-only operations remain `HEURISTIC` because receiver/class identity is unresolved and cannot satisfy the capability rule |
| Collection | Audio recording queue creation | `audio.recording-queue.create` | native source and exact called Mach-O imports | supported for `AudioQueueNewInput` APIs as a neutral media primitive; this does not establish permission, queue start, captured audio, or a written recording and therefore carries no Audio Capture ATT&CK mapping |
| Staging | Copy and archive local data | file copy and archive creation with source/output bindings | shell and supported script APIs, including fully qualified Rust `std::fs::copy` | supported only for exact operands; generic archive creation is a neutral technical capability and receives an Archive Collected Data mapping only when at least one exact source has a retained sensitive-data classification; Rust source preserves separate bindings but remains heuristic and below capability-rule support without compiler semantics; archive strings/imports alone are observational |
| Staging | Archive extraction | `archive.extract` with source and output bindings when exact | shell and bounded Python `zipfile.ZipFile(...).extractall(...)` / `tarfile.open(...).extractall(...)` chains | supported as a neutral operation; Python requires a forward-only exact module binding, a documented read mode, and supported constructor/consumer options; source-object overrides, custom member iterables/filters, and unsupported argument shapes remain partial; unresolved source or destination resources stay empty rather than guessed, and extraction does not imply payload execution or successful effect |
| Transfer | Network connect/download/upload and staged upload | network operations and exact resource flow | shell, supported script APIs, Mach-O imports, Rust source | supported; Python network calls require an exact canonical binding that remains valid at the call under the forward-only scope timeline, and JavaScript requires an unshadowed global `fetch` or an immutable exact `axios` binding; dynamic destinations stay explicit unresolved resources; local module shadowing, dependency substitution, and runtime package resolution are not authenticated, just as command adapters do not authenticate `PATH` targets; literal URLs, unbound API-looking names, and JXA `fetch` text remain observations; archive-to-upload attribution requires exact identity, context, order, and no intervening or unorderable write to the staged path; the resulting flow is transfer, not proof of exfiltration, C2, data sensitivity, or successful effect |
| Privacy configuration | TCC authorization reset | `privacy.authorization.reset` | shell and exact command expansion from supported script adapters | supported for closed `tccutil reset service [bundle_id]` argv; this models removal of remembered decisions and possible future prompting, not a permission grant, TCC bypass, or successful effect |
| Defense evasion | Quarantine, Gatekeeper, hidden filesystem attributes, plist modification, permissions, deletion | typed configuration/file operations | shell, supported script calls, native imports | exact `SetFile -a V` and `chflags hidden` forms are supported; generic deletion and property-list modification remain neutral, and a plist change carries no persistence/ATT&CK mapping without a proven host relationship |
| Impact | Encryption, destructive overwrite, ransomware behavior | none | observational strings/imports only | deferred until exact reusable write/encryption/resource-flow semantics are justified |

Technical primitive capability rules intentionally differ from behavioral
objective rules. For example, an exact called `connect` proves a socket-connect
primitive, but not an Internet destination or C2 channel; `read` proves input
from a descriptor or stream, but not which file supplied that descriptor; and
a called cryptographic API proves data transformation support, not ransomware.
Concrete resource and operation-flow rules remain responsible for those
stronger conclusions.

AppleScript local string resolution retains exact `set` assignments, immutable
text aliases, concatenation, parentheses, and `quoted form`, with declaration
and call evidence. Names are case-insensitive. Unknown writes, opaque calls,
and context changes invalidate retained local values; persistent property/global
identifiers and cross-handler propagation remain unresolved. Masked-input
dialogs support complete bounded result-accessor wrappers and label-call syntax
without evaluating helpers or inferring their return values. Scoped derived
handlers that cannot retain valid causal context remain explicitly partial.
When source encoding is unresolved, only ASCII string operands are resolved;
legacy Unicode values are not decoded by guesswork.

Endpoint state is intentionally outside this artifact analyzer. Background
Task Management records, process ancestry, EndpointSecurity events, current
trust decisions, and other host telemetry can confirm or reject a static
hypothesis, but they are not synthesized into an artifact capability. The
report instead exposes the roots, targets, resources, observables, and gaps an
investigator should use to request that evidence.

For every new row promoted to `supported`, add inert positives, close
negatives, benign controls, malformed inputs, budget cases, and at least one
test proving that a weaker neighboring pattern remains observational or
explicitly partial.
