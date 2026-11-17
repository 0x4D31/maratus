# Pymafka: Python platform branches, executable operands, and pipe flow

This archive includes a Python source distribution and an x86_64 Mach-O
payload. Maratus recovers a Darwin branch that invokes `/var/tmp/zad`, plus a
separate Linux download-to-`bash` pipeline. Keeping those branches distinct
matters when reading the archive's combined findings.

- Input: `Pymafka.zip`
- Archive SHA-256: `240924898480a88fe40bd98644b62aed9d5e0a9d522b3ae73faaabf8d6cc7e35`
- Source: [Objective-See/Malware, pinned revision](https://github.com/objective-see/Malware/blob/16c4f3bf685b1ed95e83d39d6b92c6af64315531/Pymafka.zip)
- Analyzer: [Maratus `38b6978`](https://github.com/0x4D31/maratus/commit/38b6978697141b34a9c51d1cdf3fa152b6349229), default analysis settings. Terminal output rendered with [`551d6b9`](https://github.com/0x4D31/maratus/commit/551d6b9ddad39c25d822f539b37ab3339b7a13f7).

These are historical results from the builds pinned above. Counts, IDs, support
levels, and excerpts describe that run; a current scan may differ. See the
[current coverage ledger](../technique-coverage.md) for supported analysis.

## Terminal excerpt

Selected terminal lines follow. `[…]` marks omissions.

```text
Results     13 artifacts · 0 execution roots · 0 invoked targets · 8 matches across 6 capabilities
Analysis    6 limited scopes; details in canonical JSON or --detail full
Contains    macho (1), script (2)

CAPABILITIES (4 capabilities · 5 matches)
  CAPABILITY                                                    NAMESPACE
  Communicates over a network                                   macos.communication
  Queries system information [platform.system]                  macos.discovery
  Executes a concrete file [subprocess.Popen] (2 matches)       macos.execution
  Pipes downloaded content into an interpreter                  macos.execution
  Match status: execution: 5 unknown; support: 2 direct · 3 corroborated
```

## Darwin branch: concrete operands and source locations

The source member is `pymafka-3.0.tar.gz!pymafka-1.0/setup.py`. Retained guard
evidence at line 44 is `if platform.system()=="Darwin":`. These operations
come from the following source lines in that branch:

| Line | Operation ID | Modeled operation and bound operand |
| --- | --- | --- |
| 46 | `operation-0007` | `file.metadata.query` on `/var/tmp/zad`, from `os.path.exists` |
| 52 | `operation-0008` | `process.execute` with executable `chmod`; dynamic or unsupported argv remains unresolved |
| 53 | `operation-0009` | `file.write` with local output `/tmp/log` |
| 53 | `operation-0010` | `process.execute` with executable `/var/tmp/zad` |

These operations have `CORROBORATED` support and `UNKNOWN` connectivity.
Their evidence includes the source lines and the resolved import binding for
`os` or `subprocess`. This identifies the executable and log path retained
from the Darwin code without claiming its chmod arguments were recovered.

## Linux branch: an explicit download-to-interpreter relation

Line 41 contains the separate `Linux` guard. Its line 42 subprocess command
downloads content with `curl` and pipes it into `bash`. The report retains
`operation-0004` (`network.download`) and `operation-0005`
(`interpreter.invoke`, executable `bash`). Their shared evidence is the
subprocess import binding and the exact command source line.

This is the complete canonical relation record, with indentation normalized:

```json
{
  "id": "relation-0001",
  "kind": "pipes-to",
  "from": {"kind": "operation", "id": "operation-0004"},
  "to": {"kind": "operation", "id": "operation-0005"},
  "evidence_ids": ["ev-0013", "ev-0016"],
  "support": "DIRECT",
  "execution": {"connectivity": "UNKNOWN"}
}
```

The `macos.download-pipe-interpreter` rule uses those operations and that
relation. Its catalog name does not make this source branch macOS-specific.
`DIRECT` describes static source evidence, not an observed download or execution.

## Interpretation

The combined report does not establish a Linux-to-Darwin sequence or determine
branch feasibility on a particular host. It records no trusted package
installation root. Unlinked URLs remain static observables, and the bundled
Mach-O has limited native coverage. The source findings do not establish the
downloaded payload's behavior or a successful installation.

## Inspect a separately obtained copy

```sh
MARATUS_ZIP_PASSWORD='infect3d' maratus inspect Pymafka.zip --output-dir pymafka-report
```

Maratus reads the nested source without importing it or installing the package.
The output directory preserves the evidence references and the complete report.
