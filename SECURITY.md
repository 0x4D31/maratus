# Security policy

Security fixes apply to the latest tagged release and `main`. A prerelease is
supported until a newer prerelease or final release replaces it.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/0x4D31/maratus/security/advisories/new).
If private reporting is unavailable, contact the repository owner through an
established private channel. Do not publish details in an issue, discussion,
pull request, report, or conference material.

Include the affected version/commit and OS, a minimal inert reproducer,
expected and observed behavior, security impact, relevant limits, and a
redacted diagnostic or stack trace. Do not attach live malware to GitHub; send
hashes and coordinate any necessary transfer privately.

## Threat model

Maratus is static, but every input is attacker-controlled. It parses compressed
containers, paths, scripts, plists, manifests, Mach-O structures, signatures,
and instruction bytes. Parser confusion, unsafe paths, output injection,
reference-validation bugs, system-tool delegation, and resource exhaustion are
in scope.

The normal path does not execute inspected code, import packages, run hooks,
preview files, or use the network. Static analysis reduces exposure; it does
not make hostile parser input safe.

By default, `maratus inspect` performs analysis in a fresh same-binary worker.
The parent enforces a wall deadline and bounded stdout/stderr, terminates the
worker process group on timeout, and strict-loads the returned canonical report
before rendering it. The worker applies conservative inherited-or-lower CPU,
file-size, open-file and core-dump limits and a 1 GiB-or-lower Go runtime memory
target. It starts with a minimal environment instead of inheriting unrelated
caller credentials; a supplied archive password still crosses inside the
private worker request because parsing requires it. The memory target is not a
hard RSS ceiling, and these controls do not restrict what files or network
interfaces the worker can access.

For unknown samples:

- use an unprivileged account in an isolated disposable environment;
- retain or strengthen OS CPU, memory, process, filesystem, and wall limits;
- keep the case directory private and disable preview, indexing, sync, and
  backup services;
- keep default budgets unless a specific, recorded adjustment is necessary;
- leave `--allow-dmg-mount` disabled; and
- never execute extracted content to confirm a result.

`--allow-dmg-mount` is an explicit macOS-only exception. It asks `hdiutil` to
attach an image read-only, which exposes the host disk-image stack. Use it only
on a suitable isolated host. Read-only mounting does not make a malformed image
harmless. DMG mounts use scratch space separate from the ordinary worker
directory. If detach cannot be confirmed, Maratus leaves that private directory
in place and reports its path; parent cleanup never recursively traverses it.

For encrypted ZIPs, prefer `MARATUS_ZIP_PASSWORD` to `--zip-password` so the
secret is less likely to appear in shell history or process listings. Reports
record only whether a password was supplied.

## Output and report trust

Text, JSON, and HTML may contain local paths, URLs,
hostnames, signing IDs, commands, embedded credentials, evidence excerpts, and
diagnostics. Store outputs with restrictive permissions and sanitize them
before sharing. Self-contained HTML is offline, not redacted.

Saved reports are strictly schema- and reference-validated, but validation is
not authentication. Reports are unsigned, and valid producer, ruleset,
settings, and conclusion fields can be fabricated. Verify custody and an
external hash or signature before relying on a report from another party.

Maratus is not a sandbox, execution monitor, malware verdict, complete recovery
of dynamic behavior, or publication sanitizer. Always review coverage and
diagnostics. A report with no capability matches is not evidence that the
sample is safe.
