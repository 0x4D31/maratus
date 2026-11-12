# Pymafka: Python source and download-to-interpreter flow

This archive includes a Python source distribution and an x86_64 Mach-O
payload. The excerpt highlights behavior recovered from `setup.py` inside the
source distribution.

- Input: `Pymafka.zip`
- Archive SHA-256: `240924898480a88fe40bd98644b62aed9d5e0a9d522b3ae73faaabf8d6cc7e35`
- Source: [Objective-See/Malware, pinned revision](https://github.com/objective-see/Malware/blob/16c4f3bf685b1ed95e83d39d6b92c6af64315531/Pymafka.zip)
- Analyzer: [Maratus `cf7da12`](https://github.com/0x4D31/maratus/commit/cf7da12c3d3f0c2ea383de2cb085d43d922059a2), default analysis settings.

## Output excerpt

These are terminal-report lines with one network destination replaced by
`[redacted network destination]`. `[…]` marks omitted lines.

```text
Results     13 artifacts · 0 execution roots · 0 invoked targets · 8 matches across 6 capabilities
Analysis    6 limited scopes; details in canonical JSON or --detail full

CAPABILITIES (4 capabilities · 5 matches)
  CAPABILITY                                                    NAMESPACE
  Communicates over a network                                   macos.communication
  Queries system information [platform.system]                  macos.discovery
  Executes a concrete file [subprocess.Popen] (2 matches)       macos.execution
  Pipes downloaded content into an interpreter                  macos.execution
  Match status: execution: 5 unknown; support: 2 direct · 3 corroborated
[…]
NETWORK EVIDENCE (1 path)
  ◆ [redacted network destination]
    via curl → curl/libcurl → libcurl-selected TLS backend
```

## What the report establishes

In `pymafka-1.0/setup.py`, line 42 supplies a subprocess command that downloads
content with `curl` and pipes it into `bash`. Maratus retains separate
`network.download` and `interpreter.invoke` operations with the same source
lineage; the flow-backed rule produces the interpreter capability above.
`DIRECT` describes that static source evidence. It does not mean that a
download or execution was observed.

Other source calls retain `chmod` and `/var/tmp/zad` as executable operands.
The `chmod` argument vector remains dynamic or unsupported. URLs found as
unlinked literals appear separately as static observables; their presence
does not establish communication.

The source contains platform-dependent branches. This report does not prove
which branch would run on a particular host. It records no trusted package
installation root, and the bundled Mach-O has limited native coverage.
The excerpt is therefore a source-behavior result, not a complete account of
the payload or an observed installation.

## Inspect a separately obtained copy

```sh
MARATUS_ZIP_PASSWORD='infect3d' maratus inspect Pymafka.zip --output-dir pymafka-report
```

Maratus reads the nested source without importing it or installing the package.
The output directory preserves the evidence references and the complete report.
