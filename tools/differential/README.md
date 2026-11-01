# Development differentials

These helpers compare structural facts produced by independent analyzers. They
are **not** part of the Maratus inspection pipeline, are not shipped in release
binaries, and never supply operations or capability matches.

Run differentials only on an exact, pre-extracted Mach-O node in an isolated,
offline, resource-limited process. Do not pass an archive, package, app, DMG, or
untrusted path tree to an external parser. Record the artifact SHA-256, external
tool revision, settings, duration, resource use, and output hash. A disagreement
is a review queue item, not evidence that either result is correct.

The checked-in [`go-macho`](go-macho) helper pins
`github.com/blacktop/go-macho` v1.1.282
(`cf6f9d9084c92c605f356f0fe151c4d2bcdd2430`). It emits a small versioned JSON
projection of sections, imports, linked libraries, and generic function-start
count. Build it from its independent module:

```sh
cd tools/differential/go-macho
go mod verify
CGO_ENABLED=0 go build -trimpath -o /private/tmp/maratus-go-macho-diff .
/private/tmp/maratus-go-macho-diff /path/to/exact-thin-macho > /private/tmp/go-macho.json
```

The harness intentionally does not invoke mutation/export APIs, demanglers,
Objective-C or Swift deep parsing, or heuristic arm64 function generation.
It rejects symlinks and fat/container inputs, opens the exact regular file once,
checks thin Mach-O magic and size, and retains a panic boundary. These checks
are defense in depth, not a substitute for the surrounding process and
filesystem limits.
