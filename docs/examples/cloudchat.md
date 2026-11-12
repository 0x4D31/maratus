# CloudChat: recovering commands from Go Mach-O binaries

Maratus recovers literal executable operands from this archive's Go Mach-O
code and associates them with named callers. This example focuses on the
x86_64 member `CloudChat/A/clip_.Safari_V8_config`; archive totals also include
other members.

- Input: `CloudChat.zip`
- Archive SHA-256: `2300dd2acf7d6a9c3a7dc012aa79af390c877ea24adbc995654287f70a87da9f`
- Focused member SHA-256: `ef1c7d6651996a3dccee755630add52c3f04a6e474ad15a999e132cafbf83f18`
- Source: [Objective-See/Malware, pinned revision](https://github.com/objective-see/Malware/blob/16c4f3bf685b1ed95e83d39d6b92c6af64315531/CloudChat.zip)
- Analyzer: [Maratus `38b6978`](https://github.com/0x4D31/maratus/commit/38b6978697141b34a9c51d1cdf3fa152b6349229), default analysis settings. Terminal output rendered with [`551d6b9`](https://github.com/0x4D31/maratus/commit/551d6b9ddad39c25d822f539b37ab3339b7a13f7).

## Terminal excerpt

Selected terminal lines follow. `[…]` marks omissions.

```text
Results     30 artifacts · 0 execution roots · 0 invoked targets · 20 matches across 6 capabilities
Analysis    17 limited scopes · 2 diagnostics; details in canonical JSON or --detail full
Contains    app-bundle (1), macho (6), script (1)

CAPABILITIES (1 capability · 7 matches)
  CAPABILITY                                                    NAMESPACE
  Executes a concrete file (7 matches)                          macos.execution
  Match status: execution: 7 unknown; support: 7 corroborated
[…]
  process.execute               1  CORROBORATED   UNKNOWN      executable: tar · variadic argv
                                                               unresolved · via os/exec.(*Cmd).Run, ...
                                                               evidence 0x110146c · main.compressLog...
```

## Scoped operations and their evidence

The canonical report retains the complete caller names and operands clipped
by the terminal view. These four pairs belong to the focused member:

| Caller | Configuration → execution operation IDs | Executable |
| --- | --- | --- |
| `main.copyAndCompressWalletPlugins` | `operation-0005` → `operation-0006` | `cp` |
| `main.compressLogsdata` | `operation-0007` → `operation-0008` | `tar` |
| `main.uploadLogsdata` | `operation-0009` → `operation-0010` | `curl` |
| `main.sendTelegramNotification` | `operation-0011` → `operation-0012` | `sh` |

Each configuration operation comes from a direct `os/exec.Command` call with
a recovered Go string pointer/length pair. The execution operation requires
an adjacent `os/exec.(*Cmd).Run` call using that returned command object.
The report keeps configuration and execution as separate operations.

For example, `operation-0008` is backed by these located evidence records:

| Evidence ID | Retained fact |
| --- | --- |
| `ev-1417` | Direct Go call to `os/exec.Command` |
| `ev-1418`, `ev-1419` | ABI references supplying the string pointer and length |
| `ev-1420` | The exact `tar` string bytes |
| `ev-1421` | Direct Go call to the consuming `(*Cmd).Run` |

This gives a concrete executable and a code location to inspect without
requiring Go source. Function names supply context; the call and operand
evidence supplies the modeled action.

## Interpretation

All four execution operations are `CORROBORATED`, with `UNKNOWN` execution
connectivity. Their variadic argument vectors remain unresolved. Consequently,
these command names do not identify which on-disk binaries `PATH` selects.
The `tar` operand and caller name do not establish which files are archived;
the `curl` operand and `uploadLogsdata` name do not establish an upload or its
destination. The report does not reconstruct those missing arguments.

The archive also exposes runtime/standard-library primitives in a separate
inventory. Those primitives do not establish application intent. No trusted
host-selection root was recovered for the focused payload, and no execution
or successful effect was observed.

## Inspect a separately obtained copy

```sh
MARATUS_ZIP_PASSWORD='infect3d' maratus inspect CloudChat.zip --output-dir cloudchat-report
```

The JSON and HTML retain the full scoped operation fields and evidence links.
