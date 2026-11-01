# CArchive and PyInstaller analysis

Maratus treats an embedded CArchive and a PyInstaller application as two
different facts. This distinction prevents a valid container, or a copied
magic value, from turning an arbitrary file into a claimed Python program.

The implementation is static and in-process. It never launches the carrier,
imports recovered Python objects, invokes a Python interpreter, writes members
to an executable location, or mounts a disk image.

## Evidence levels

The analysis progresses through increasingly strong claims:

1. A bounded parser validates the CArchive cookie and exact table-of-contents
   placement. The artifact graph records a neutral `carchive` container. Its
   status and coverage say whether the complete TOC, record framing, and every
   payload extent were also validated; a partial node may represent only a
   safely parsed prefix.
2. Members are inventoried with hostile names replaced by deterministic safe
   names. Supported stored and zlib payloads are decoded within shared byte,
   ratio, work, node, path, and depth limits.
3. PyInstaller attribution requires a fully validated candidate at the last
   cookie marker, structurally valid `MH_EXECUTE` slices with a file-backed
   executable segment and `LC_MAIN` or legacy `LC_UNIXTHREAD` process entry,
   compatible cookie and member metadata, and multiple exact bootloader markers
   located in the native prefix before the CArchive. Marker strings inside
   members do not count.
4. Only after attribution does the carrier receive the packaging-technology
   feature `PyInstaller`. Retained type-`m`/`M` bootstrap modules and type-`s`
   scripts become ordered loader targets of the carrier; they do not become
   additional execution roots. Packaging identity alone also does not turn an
   otherwise unreferenced nested carrier into a root.

A partial candidate may still contribute neutral inventory and coverage. It
cannot support packaging attribution or an execution relationship.

This follows the documented format rather than a malware-family signature.
PyInstaller's current writer defines the 88-byte cookie, 16-byte-aligned TOC
records, stored/zlib flag, member type codes, Python `s`/`m`/`M` records,
and `PYZ` payloads in
[`writers.py`](https://github.com/pyinstaller/pyinstaller/blob/v6.21.0/PyInstaller/archive/writers.py).
The corresponding structures and item codes are declared in the
[bootloader archive header](https://github.com/pyinstaller/pyinstaller/blob/v6.21.0/bootloader/src/pyi_archive.h).
Modern PyInstaller deliberately constructs the cookie magic at runtime so its
own archive search cannot match a copy embedded in the bootloader. Recognition
therefore supports exact, generation-specific loader error strings as well as
older retained symbol/magic profiles; it does not require the raw cookie magic
to occur in native code. See
[`pyi_archive.c`](https://github.com/pyinstaller/pyinstaller/blob/v6.21.0/bootloader/src/pyi_archive.c)
and
[`pyi_main.c`](https://github.com/pyinstaller/pyinstaller/blob/v6.21.0/bootloader/src/pyi_main.c).
For a universal Mach-O, every validated `MH_EXECUTE` slice must independently
contain the complete Python-API, runtime, and CArchive-loader marker profile.
Markers in another slice, fat padding, or an outer overlay cannot be combined
to establish producer attribution.
The current compatibility profile accepts the historical Python 2.4–2.7 range
and Python 3.3–3.15. PyInstaller 6.21 advertises Python 3.15 and free-threaded
build support in its
[release metadata](https://pypi.org/project/pyinstaller/6.21.0/); compatible
macOS `libpythonX.Yt.dylib` cookie names are therefore recognized without
loosening the exact basename and version checks.
The bootloader first import-executes type-`m`/`M` bootstrap modules in TOC
order, as shown in
[`pyi_python.c`](https://github.com/pyinstaller/pyinstaller/blob/v6.21.0/bootloader/src/pyi_python.c),
then iterates type-`s` records in TOC order, unmarshals each code object, and
evaluates it, as shown in
[`pyi_launch.c`](https://github.com/pyinstaller/pyinstaller/blob/v6.21.0/bootloader/src/pyi_launch.c).

## Member interpretation

Member type codes are hints, not permission to reinterpret arbitrary bytes.

| Record | Handling |
| --- | --- |
| `s` with a corroborated current 88-byte cookie | Retain as a Python marshal representation. Extract bounded URL/IP candidates, but do not parse it as source or emit modeled operations. Raw URL candidates are `HEURISTIC`: their printable-run boundary is unresolved and may include adjacent marshal bytes. |
| `m`, `M` with a corroborated current 88-byte cookie | Retain as a PyInstaller Python module record. Historical writers used either a full PYC header plus marshal data or direct marshal data under the same cookie layout, so the payload framing is deliberately left unresolved. |
| `s`, `m`, `M` with a corroborated legacy 24-byte cookie, or without producer attribution | Retain as representation-unknown CArchive Python records. The loader relationship can still be established for an attributed legacy carrier, but the bytes are not labeled marshal or treated as source. |
| `z` | Require compatible `PYZ` structure before naming it a PYZ representation. Module inventory and Python bytecode semantics remain explicit coverage gaps. |
| `Z`, `b`, `x`, `l` | Use content-first detection on successfully decoded bytes. Type `b` alone does not make a member executable or vendor code. |
| `d`, `o` | Retain metadata without treating its name or bytes as source code. |
| `n` | Inventory the symbolic-link record without following it. |
| unknown | Retain and content-classify supported decoded payloads; disclose unsupported flags or representations per member. |

An unsupported compression/encryption flag, malformed member, duplicate
extent, unsafe name, bad checksum, size mismatch, or exhausted limit does not
invalidate unrelated records. Maratus keeps the container and safe siblings,
marks the affected inventory partial, and states what was not decoded.

Direct `m`/`M`/`s` targets have the `runtime` source role. Other members have
the neutral `packaged-content` role unless a separate structural relationship
promotes them. Maratus inventories and content-classifies all retained members,
but its default behavior pass excludes unreferenced packaged content and emits
an explicit coverage record with the omitted-node count.
`--include-unreferenced` restores the
bounded behavior pass for those members. Raw-feature-only marshal/PYZ records
remain isolated from modeled operations and capability rules in either mode.

That packaged-content context propagates through recursively decoded ZIP, TAR,
ASAR, app, and package descendants. It is separate from execution-root
eligibility: crossing a CArchive boundary prevents any descendant declaration
from creating a new root. `--include-unreferenced` may expose modeled operations in such
content, but they remain `UNKNOWN` unless a supported invocation from an
existing root reaches the exact target. A reached target remains a target and
never becomes another root.

## Determinism and evasion resistance

The parser scans cookie markers with bounded aggregate validation work and
prioritizes plausible envelopes instead of accepting only a fixed prefix of
markers. Member selection is deterministic and role-aware. When a TOC exceeds
the modeled-entry ceiling, selection includes anchors and stable samples across
the full record set rather than the first records only. Omitted record and byte
counts remain visible.

Candidate hashing also uses a shared byte-work limit. Exact duplicate extents
reuse a digest; candidates that exceed the remaining hash budget keep an empty
digest and explicit partial coverage instead of causing unbounded extra work.

Exact payload aliases cannot multiply decompression work. Conflicting extents
are inventoried but not decoded. Candidate and member ordering is represented
explicitly, so canonical report sorting cannot destroy loader order.

## What a result means

- `kind: carchive` means the canonical envelope was established. The node's
  status and coverage determine whether the complete TOC and member extents
  were established too.
- `artifact.packaging_technology: PyInstaller` means the container and native
  bootloader evidence corroborated one another. It is a Feature, not a
  malware verdict or proof that the user launched the file.
- `loader-invokes` means the documented bootloader directly import-executes a
  retained `m`/`M` bootstrap target or evaluates a retained `s` script target.
  The relationship ordinal models that two-phase loader order; its located
  evidence separately preserves the original TOC ordinal and type byte.
- Partial Python marshal or PYZ coverage means Maratus has not claimed source,
  control flow, modeled operations, or capabilities from those bytes.

Real-sample hashes, expectations, reports, and variant notes belong in private
corpus records. Family names are analyst labels, never recognizer signatures.
