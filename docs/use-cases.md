# Practical workflows

These examples use inert names and documentation-only network destinations.
Unknown artifacts should still be handled under the isolation guidance in
[SECURITY.md](../SECURITY.md).

## Triage an app, package, or archive

```sh
maratus inspect Suspicious.app
maratus inspect Installer.pkg --detail evidence
maratus inspect Samples.zip --include-unreferenced
```

Start with the default summary. Check coverage before following capability or
network results. Use `--detail evidence` for roots, targets, individual
matches, and source locations. Use `--detail full` only when you need the
artifact graph, operations, relations, and lower-level features.

`--include-unreferenced` is useful for broad bundle review. It analyzes more
content but does not create execution roots for files that no supported
declaration selects.

## Save a case report

```sh
umask 077
maratus inspect sample.zip --format json > sample.maratus.json
shasum -a 256 sample.maratus.json
```

Reopen the report without exposing the sample again:

```sh
maratus render sample.maratus.json --detail evidence --color never
maratus render sample.maratus.json --format html -o sample.html
maratus render sample.maratus.json --format json > reloaded.json
cmp sample.maratus.json reloaded.json
```

Strict reload checks structure and internal consistency, not authenticity.
Keep the report digest with the case notes.

## Turn a result into IR questions

Use the report as a collection guide, not as an execution verdict:

1. Conditional activation identifies the host rule and artifact entry whose
   presence, timestamps, parent process, project, extension, or package event
   should be checked.
2. Modeled behavior identifies exact APIs or commands and marks missing
   arguments as unresolved instead of filling them from nearby strings.
3. Static observables provide hashable paths, destinations, embedded
   configuration, and key fingerprints for targeted searches, while remaining
   separate from claimed behavior.
4. Build and signing properties help cluster binaries and verify whether a
   retained object matches the expected toolchain, module, entitlement, or
   CodeDirectory identity.
5. Loader context exposes exact non-system dependencies and runtime search
   paths for dependency collection and hijack review. These are declarations,
   not proof that a library existed, resolved, or loaded on an endpoint.
6. Evidence locations let a reverse engineer jump from a claim to the exact
   member, function, line, or artifact-relative byte offset.
7. Coverage says which negative conclusions are unsafe and what additional
   telemetry or manual analysis is still needed.

For example, an exact `execve` call with an unresolved executable proves the
native call site, but not its command line. Response should then collect argv,
process ancestry, EndpointSecurity exec events, shell history where applicable,
and the calling function's surrounding data flow. A nearby string is not used
as the command unless Maratus can prove the argument relationship.

Artifact analysis also cannot answer endpoint-state questions by itself. Use
the static result to target Background Task Management records, process and
file events, quarantine metadata, current signature/notarization checks, and
other host evidence. Keep those observations separate from Maratus's
conditional artifact claims.

## Inspect an encrypted ZIP

Pass the password through the environment so it is less likely to appear in
shell history or process listings:

```sh
export MARATUS_ZIP_PASSWORD='set-this-from-private-storage'
maratus inspect sample.zip --format json > sample.maratus.json
unset MARATUS_ZIP_PASSWORD
```

Never commit the password or place it in a report wrapper.

## Inspect a DMG

The safe default records the image and reports its contents as uninspected:

```sh
maratus inspect sample.dmg
```

`--allow-dmg-mount` is a macOS-only exception that asks `hdiutil` to attach the
image read-only. Read-only mounting still exposes the host disk-image stack to
hostile input. Use it only in a disposable isolated environment and never for
routine malware corpus runs. If Maratus cannot confirm detach, it reports and
retains the private DMG scratch directory for manual unmounting instead of
recursively cleaning through a possible mount.

## Analyze a command without running it

```sh
printf '%s\n' 'curl https://example.invalid/p -o /tmp/p' \
  | maratus inspect --stdin --input-kind shell --detail evidence
```

Stdin requires an explicit input kind and never follows paths named by the
content. Supported kinds are listed by `maratus help inspect`.

## Compare two analyses

Maratus does not currently define a report-diff schema. For a fixed binary,
settings, environment, and input, exact JSON comparison is appropriate:

```sh
maratus inspect sample.zip --format json > first.json
maratus inspect sample.zip --format json > second.json
cmp first.json second.json
```

When builds or settings differ, compare the producer, rule-catalog digest,
settings, coverage, operations, and matches explicitly. Do not treat a raw
JSON diff as a behavior verdict.

## Use Maratus in CI

Maratus exits `0` after a successful analysis whether or not it found
capabilities. Make policy decisions from JSON fields, not terminal text or the
process status.

```sh
maratus inspect release.pkg --format json > release.maratus.json
maratus render release.maratus.json --format json > /dev/null
```

Pin the Maratus version and record its normalized rule-catalog digest. Keep
coverage in the policy input so an unsupported or truncated analysis cannot
silently pass.

## Investigate a suspected miss

Work from the report before increasing limits:

1. Was the relevant member classified and retained?
2. Was its container expanded?
3. Did a supported declaration select it as a root or target?
4. Was its language or architecture analyzed?
5. Are the necessary evidence and features present?
6. Did semantic recognition create the expected operation and resource?
7. Did relation derivation and the rule have exact supporting facts?
8. Does coverage name an unsupported construct or exhausted budget?

Classify the gap as structure, traversal, host selection, feature extraction,
semantic recognition, connectivity, relation derivation, rule coverage, or
unavoidable static uncertainty. Fix the reusable semantic pattern and add
inert positives, close negatives, malformed cases, and benign controls.

## Hand off to another analyst

Share the Maratus version and commit, report digest, settings, input digest,
coverage notes, and the smallest relevant evidence projection. Reports and
HTML can contain sample-derived commands, paths, URLs, and identifiers, so
review and redact them before sharing.
