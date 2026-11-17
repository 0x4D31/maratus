# Static triage report template

Use this when reporting an artifact inspection or reviewing saved canonical
JSON. Replace brackets with observed values. Keep only sections needed for the
question; use “not assessed” or “unresolved” where evidence is unavailable.
Do not turn a coverage gap into a negative finding or label every observable
an indicator of compromise. The tables are optional for small cases.

## Assessment

**Question:** [What was requested?]

[One or two sentences describing what the static evidence supports, under which
activation conditions, and the main limit on that conclusion. State whether the
result comes from a fresh inspection or a saved report.]

## Input and analysis record

- Input: [Original name, detected format, size, and SHA-256 when available.]
- Hash scope: [Which exact file or retained member was hashed? A bundle or
  directory has no single file hash. Distinguish an archive hash from a member
  hash and a saved report hash.]
- Analysis: [Maratus version/commit and modified-build status, report schema,
  platform, relevant options, and nondefault limits. Record missing provenance.]
- Evidence record: [Private canonical report path and SHA-256, manifest path,
  and original input location or custody reference. Omit credentials and passwords.]
- Result: [Exit status, stderr or diagnostic notes, and material partial/skipped
  coverage. A successful exit is not a safety assessment.]

For a saved report, distinguish the producing build/settings from the build
used to validate and render it. Validation does not authenticate an unsigned
report. Do not imply that the original artifact was available or reexamined.

## Contents and activation

[Name the relevant containers and selected members, with logical paths and node
IDs. Explain the supported host event, declaration, root ID, selected target,
and unresolved selection conditions. Separate contained code from activated
code. For developer artifacts, this may be an install hook, build script,
project phase, extension activation, or agent hook.]

For Mach-O, identify the relevant slice and record material signing/integrity,
entry/initializer, library, or wrapper context. Signing and library declarations
are structural evidence, not trust or dependency-resolution conclusions. Do
not transfer a finding from one architecture to another.

## Supported findings

| Claim and activation condition | Canonical records | Source location | Support, connectivity, and limits |
| --- | --- | --- | --- |
| [Conditional behavior, with exact known operands] | [Capability/operation, evidence, node, scope, root/target IDs as applicable] | [Logical member path; source line or binary file offset/VA with architecture] | [Reported support and connectivity; unresolved operands or path conditions] |

Follow each cited ID in the canonical report. Use the source location actually
reported: file offsets and virtual addresses are different coordinates. Explain
how operations are related before describing a sequence. `CONNECTED` does not
prove runtime execution, path feasibility, success, or malicious intent. State
when a summary is selective or truncated; do not present its counts as a full
inventory without checking the canonical report.

## Other observations

| Value or metadata | Evidence and location | Role and interpretation |
| --- | --- | --- |
| [URL, domain, path, import, signing metadata, or other relevant observation] | [Evidence ID, member, line/offset, architecture if known] | [Raw string, declared dependency, selected argument, local output, etc.; what remains unproved] |

Only include observations relevant to the question. Do not contact endpoints or
upload a hash, sample, or report to enrich this section without separate scope
and authorization. Keep secrets out of copies intended for sharing.

## Coverage and follow-up

| Affected member/slice and analysis area | Status and reason | Consequence for the question | Next evidence needed |
| --- | --- | --- | --- |
| [Canonical coverage record] | [Partial, skipped, or supported analysis completed] | [What cannot be concluded] | [One specific, scoped check] |

Prioritize follow-up by what could change the assessment. For disassembly, name
the member hash, architecture, function/callsite, and missing argument, receiver,
branch, or dataflow fact. For runtime questions, name the needed process, file,
network, or host-event evidence. Keep proposed checks separate from completed
work and attribute findings from other tools to those tools.

[Close with unresolved questions only if they add information. “No supported
match was found in the analyzed content” does not mean “safe.”]
