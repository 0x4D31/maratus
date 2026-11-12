# Aobo: a package postinstall script and its owned operations

This archive contains an application and several embedded installer variants.
The useful chain here is the flat `logKext-106.pkg` variant: its `postinstall`
entry owns concrete commands and a LaunchDaemon load operation.

- Input: `AoboKeylogger (Baoba).zip`
- Archive SHA-256: `7ee8801e033b886ba13e82719c9571d8aa033c12c9faabac5c26e38eb7cea1a5`
- `logKext-106.pkg` SHA-256: `a8ea6f20ebed0b692773892b5b1e6188087fc0cee3e5df2f25c5a5b9c8dc3c0d`
- Focused `postinstall` SHA-256: `88a98ca386693b38135205c53e1bba527e0cfd30684d71c463d2370ae1bf73e7`
- Source: [Objective-See/Malware, pinned revision](https://github.com/objective-see/Malware/blob/16c4f3bf685b1ed95e83d39d6b92c6af64315531/AoboKeylogger%20%28Baoba%29.zip)
- Analyzer: [Maratus `cf7da12`](https://github.com/0x4D31/maratus/commit/cf7da12c3d3f0c2ea383de2cb085d43d922059a2), default analysis settings.

## Terminal excerpt

These lines are copied from the terminal report. `[…]` marks omitted lines;
the tool's own `...` marks truncated display text. Network literals are omitted.

```text
Results     242 artifacts · 2 execution roots · 0 invoked targets · 55 matches across 5 capabilities
Analysis    12 limited scopes; details in canonical JSON or --detail full

CAPABILITIES (4 capabilities · 51 matches)
  CAPABILITY                                                    NAMESPACE
  Modifies a macOS property list [defaults] (4 matches)         macos.configuration
  Enumerates files or directories [find] (6 matches)            macos.discovery
  Executes a concrete file (35 matches)                         macos.execution
  Declares or configures LaunchAgent/LaunchDaem... (6 matches)  macos.persistence
  Match status: execution: 6 connected · 45 unknown; support: 51 corroborated
[…]
CONDITIONAL ACTIVATION (2 paths)
  pkg-script                AoboKeylogger (Baoba).zip!AoboKeylogger (Baoba)/AbkPro.app/Cont...  [root-0001]
  app-main                  AoboKeylogger (Baoba).zip!AoboKeylogger (Baoba)/AbkPro.app/Cont...  [root-0002]
[…]
ADDITIONAL MODELED BEHAVIOR (29 groups)
  OPERATION                 COUNT  SUPPORT        REACHABILITY  DETAIL
[…]
  launchd.job.load              1  CORROBORATED   CONNECTED    /Library/LaunchDaemons/logKext.plist
                                                               AoboKeylogger (Baoba).zip!AoboKeylogg...
```

## The conditional entry

Within `AbkPro.app`, the focused package is stored under
`Contents/Resources/LogKextInstaller.app/Contents/Resources/logKext-106.pkg`.
Its nested `logkext-1.pkg/Scripts/postinstall` is `root-0001` in this report.
If the installer processes that package's postinstall phase, this is the
artifact-supplied script selected by the modeled package rule.

The separate `app-main` root identifies the outer application's executable.
It does not establish that opening the application installs the nested package.

## Commands and resources retained from postinstall

All rows below belong to the same `106` variant, carry `CORROBORATED` support,
and retain `execution_root_ids: ["root-0001"]` with `CONNECTED` connectivity.
Locations are lines in that variant's `postinstall` member.

| Line | Operation IDs | Retained operation and operands |
| --- | --- | --- |
| 3 | `operation-0001`, `operation-0002` | `file.enumerate` on `/System/Library/Extensions/logKext.kext`; `/usr/bin/find` with arguments `/System/Library/Extensions/logKext.kext -exec /bin/chmod -R g-w '{}' ';'` |
| 4 | `operation-0003` | `process.execute`: `/sbin/kextunload`, arguments `-b com.fsb.kext.logKext` |
| 5 | `operation-0004` | `process.execute`: `/sbin/kextload`, arguments `/System/Library/Extensions/logKext.kext` |
| 6 | `operation-0005` | `process.execute`: `/Library/Application Support/logKext/logKextKeyGen` |
| 7 | `operation-0006` | `launchd.job.load`, job `/Library/LaunchDaemons/logKext.plist`, classified as a LaunchDaemon |

The corresponding source evidence is `ev-0451` through `ev-0455`. The
persistence match for this entry is backed by `operation-0006`; the other
concrete-file matches reference their individual execution operations. The
report therefore preserves both the package entry and the precise paths and
arguments requested by its script.

## Interpretation

`CONNECTED` describes ownership and static reachability from the conditional
postinstall root. It does not prove installation occurred or that a kernel
extension or daemon loaded. This is a legacy installer; the model does not
establish compatibility or successful execution on current macOS.

The archive also contains older package variants and `postflight` members.
Their similar operations remain `UNKNOWN` where host selection was not
established. They are not attached to `root-0001` or combined with its script
to form an observed installation sequence.

## Inspect a separately obtained copy

```sh
MARATUS_ZIP_PASSWORD='infect3d' maratus inspect 'AoboKeylogger (Baoba).zip' --output-dir aobo-report
```

This reads the embedded packages and scripts without installing the package.
