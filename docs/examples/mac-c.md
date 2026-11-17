# Mac.c: AppleScript credential requests and source evidence

This archive contains both a fat Mach-O and readable AppleScript source. The
interesting results below come from `Mac.c/stealer.scpt`: a Keychain request,
a hidden-answer dialog, and a system-information query. They are separate from
the binary's native API inventory.

- Input: `Mac.c.zip`
- Archive SHA-256: `327dc7e90ce3570f30915c9943b33aadd96ef4994a4a669d533b0e8daec04de4`
- Script SHA-256: `393acc8ef94ab8ba0abf7a769e451d5434d4acdbda0b60966bfac4b40e4d6875`
- Source: [Objective-See/Malware, pinned revision](https://github.com/objective-see/Malware/blob/16c4f3bf685b1ed95e83d39d6b92c6af64315531/Mac.c.zip)
- Analyzer: [Maratus `38b6978`](https://github.com/0x4D31/maratus/commit/38b6978697141b34a9c51d1cdf3fa152b6349229), default analysis settings. Terminal output rendered with [`551d6b9`](https://github.com/0x4D31/maratus/commit/551d6b9ddad39c25d822f539b37ab3339b7a13f7).

These are historical results from the builds pinned above. Counts, IDs, support
levels, and excerpts describe that run; a current scan may differ. See the
[current coverage ledger](../technique-coverage.md) for supported analysis.

## Terminal excerpt

Selected terminal lines follow. `[…]` marks omissions.

```text
Results     4 artifacts · 0 execution roots · 0 invoked targets · 8 matches across 5 capabilities
Analysis    5 limited scopes; details in canonical JSON or --detail full
Contains    macho-fat (1), script (1)

CAPABILITIES (4 capabilities · 5 matches)
  CAPABILITY                                                    NAMESPACE
  Accesses macOS Keychain credentials                           macos.credentials
  Prompts for credential input                                  macos.credentials
  Queries system information [system_profiler]                  macos.discovery
  Calls native process-e... [macho-symbol, system] (2 matches)  macos.execution
  Match status: execution: 2 unconnected · 3 unknown; support: 5 corroborated
[…]
  crypto-wallet                   /.electrum/wallets/
  keychain                        login.keychain-db
```

## From a capability to its backing statement

The canonical report ties each operation to a distinct statement in the same
script. The line numbers and evidence IDs below are retained report values.

| Operation | Source line | Retained detail | Evidence |
| --- | ---: | --- | --- |
| `credential.store.read` | 123 | `security … find-generic-password -ga` request naming Chrome | `ev-0093` |
| `credential.prompt` | 127 | Dialog titled System Preferences, using a hidden answer | `ev-0094` |
| `system.info.query` | 269 | `system_profiler` software, hardware and display queries | `ev-0097` |

For example, these are selected fields from the first operation, rather than
a conclusion inferred from the script's filename:

```json
{
  "id": "operation-0021",
  "subject_node_id": "node-0004",
  "scope_id": "scope-0042",
  "kind": "credential.store.read",
  "resource_bindings": [
    {
      "role": "source",
      "resource": {
        "kind": "credential-store",
        "classifications": ["keychain"]
      }
    }
  ],
  "evidence_ids": ["ev-0093"],
  "support": "CORROBORATED",
  "execution": {"connectivity": "UNKNOWN"},
  "line": 123
}
```

The statement names Chrome, but the modeled resource remains a general Keychain
store without a resolved item value. The report establishes the request and
prompt forms, not that a password was returned or entered. Their different
scopes do not establish a completed sequence of events.

The wallet and `login.keychain-db` rows are literal observations. There is no
corresponding operation proving those files were collected. Likewise, the
archive's binary is not automatically connected to the script: this snapshot
has no trusted execution root, and these three source operations are `UNKNOWN`.

## Inspect a separately obtained copy

```sh
MARATUS_ZIP_PASSWORD='infect3d' maratus inspect Mac.c.zip --output-dir mac-c-report
```

The HTML view opens the capability's backing operation and exact source
location. JSON preserves the resource classification and evidence references.
The command analyzes the archive without running either component.
