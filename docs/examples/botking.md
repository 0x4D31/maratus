# BotKing: native calls and embedded launchd data

This example inspects an archive containing one arm64 Mach-O payload.
Maratus recovers native API calls and an embedded launchd-shaped template,
with separate support for each finding.

- Input: `BotKing.zip`
- Archive SHA-256: `4abd1fc21cdc6b162b4f4c8476201c4cfad22c11e3c29dad354703a64f710471`
- Payload SHA-256: `74d3447e7cf99c99ea01a16332ec27432dfb0f491e10e67cd118065a60483306`
- Source: [Objective-See/Malware, pinned revision](https://github.com/objective-see/Malware/blob/16c4f3bf685b1ed95e83d39d6b92c6af64315531/BotKing.zip)
- Analyzer: [Maratus `cf7da12`](https://github.com/0x4D31/maratus/commit/cf7da12c3d3f0c2ea383de2cb085d43d922059a2), default analysis settings.

## Output excerpt

The following lines are copied from the terminal report. `[…]` marks omitted
lines. Full reports are not included.

```text
Results     3 artifacts · 0 execution roots · 0 invoked targets · 62 matches across 18 capabilities
Analysis    5 limited scopes; details in canonical JSON or --detail full

CAPABILITIES (1 capability · 2 matches)
  CAPABILITY                                                    NAMESPACE
  Calls native process-execution APIs (2 matches)               macos.execution
  Match status: execution: 2 unknown; support: 2 corroborated
[…]
NETWORK EVIDENCE (1 path)
  ◆ destination unresolved
    via connect
[…]
OBSERVABLES (3 static items)
  TYPE                            VALUE
  launchd config hash (partial)   sha256:005dcd910de04263bec6ed2757a5e2ec0750fb2248d3e21a9a2fc13f6b...
  launchd program (data)          /bin/zsh
  launchd trigger (data)          RunAtLoad
```

## What the report establishes

The two process-execution matches are backed by calls to `posix_spawnp` and
`execvp`. Their executable operands remain unresolved. The report also retains
socket and filesystem API primitives; a `connect` call has no recovered
destination. These findings identify code to examine, without supplying a
complete command line or proving communication occurred.

The embedded `/bin/zsh` and `RunAtLoad` fields are static data. The launchd
template is incomplete, and this scan establishes no installation, loading,
or persistence operation. It also establishes no trusted execution root for
the payload. Native call analysis and cross-function correlation are bounded;
the canonical report retains the affected coverage records.

## Inspect a separately obtained copy

```sh
MARATUS_ZIP_PASSWORD='infect3d' maratus inspect BotKing.zip --output-dir botking-report
```

This command analyzes the archive without running its payload. The output
directory contains the complete JSON, summary, and offline HTML report.
