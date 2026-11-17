# Mach-O parser comparison helper

This optional developer tool emits structural facts using a second Mach-O
parser, [blacktop/go-macho](https://github.com/blacktop/go-macho). Developers can
compare its output with Maratus when investigating a parser regression. This
is called differential testing: run different implementations on the same
bytes and investigate disagreements.

The helper produces JSON; it does **not** run Maratus, compare reports
automatically, or decide which parser is correct. It is outside the Maratus
inspection pipeline and runtime dependency graph, is omitted from release
archives, and never supplies operations or capability matches. Ordinary triage
and agent-skill users do not need to build or run it.

Run differentials only on an exact, pre-extracted Mach-O node in an isolated,
offline, resource-limited process. Do not pass an archive, package, app, DMG, or
untrusted path tree to an external parser. Record the artifact SHA-256, external
tool revision, settings, duration, resource use, and output hash. A disagreement
is a review queue item, not evidence that either result is correct.

The checked-in [`go-macho`](go-macho) helper pins
`github.com/blacktop/go-macho` v1.1.282
(`cf6f9d9084c92c605f356f0fe151c4d2bcdd2430`). It emits a small versioned JSON
projection of sections, imports, linked libraries, and declared function-start
count. Build it from its independent module:

```sh
cd tools/differential/go-macho
go mod verify
CGO_ENABLED=0 go build -trimpath -o /tmp/maratus-go-macho-diff .
/tmp/maratus-go-macho-diff /path/to/exact-thin-macho > /tmp/go-macho.json
```

The harness intentionally does not invoke mutation/export APIs, demanglers,
Objective-C or Swift deep parsing, or heuristic arm64 function generation.
It rejects symlinks and fat/container inputs, opens the exact regular file once,
checks thin Mach-O magic and size, and retains a panic boundary. These checks
are defense in depth, not a substitute for the surrounding process and
filesystem limits.

## What to compare

Match the exact member bytes and architecture first. Compare section extents,
linked-library names, imported symbols, and function-start counts with the
corresponding Maratus evidence. Account for parser limits, unsupported import
encodings, and different function-recovery methods before treating a mismatch
as a defect. The helper's `import_error` means imports were not fully recovered;
an empty list in that case is not evidence of no imports.
`function_starts_present: false` means the command is absent; the zero count
then says nothing about how many functions the binary contains.

CI tests, vets, builds, and vulnerability-checks this separate Go module. The
helper stays small so it remains a useful independent control without adding
a second parser to normal artifact inspection.
