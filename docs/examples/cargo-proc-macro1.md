# proc-macro1: a conditional Cargo entry and heuristic Rust behavior

This crate illustrates how host selection and source-behavior support remain
separate. Maratus identifies `build.rs` as a conditional Cargo entry and retains
eight modeled operations, all below the capability support threshold.

- Input: `proc-macro1-1.0.107.crate`
- Crate SHA-256: `61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4`
- `build.rs` SHA-256: `cb7778eb6dda91028abf087eb7c3553f981a67e756769507d348e8c201805568`
- Public source record: [Marius Benthin's analysis, pinned revision](https://gist.github.com/marius-benthin/273aa302ac9fb36e1c309a9479c5a8cf/b683aea505737da9e6ca2574693897099eb36f87)
- Analyzer: [Maratus `cf7da12`](https://github.com/0x4D31/maratus/commit/cf7da12c3d3f0c2ea383de2cb085d43d922059a2), default analysis settings.

## Output excerpt

The following lines are copied from the terminal report. `[…]` marks omitted
lines. Network literals elsewhere in the report are omitted from this excerpt.

```text
Results     30 artifacts · 1 execution root · 0 invoked targets · 0 matches across 0 capabilities
Analysis    6 limited scopes; details in canonical JSON or --detail full

CAPABILITIES (0 capabilities · 0 matches)
  No capability matches are recorded in this report.
  This is not a security verdict; unmatched behavior and analysis limits may remain.

CONDITIONAL ACTIVATION (1 path)
  cargo-build-script        cargo  [root-0001]
[…]
ADDITIONAL MODELED BEHAVIOR (7 groups)
  OPERATION                 COUNT  SUPPORT        REACHABILITY  DETAIL
[…]
  network.download              1  HEURISTIC      CONNECTED    destination unresolved · via
                                                               ureq::Agent::get().call
[…]
NETWORK EVIDENCE (1 path)
  ◆ download API call; destination unresolved
    via ureq::Agent → ureq → ureq-selected TLS provider
```

## What the report establishes

Cargo's [documented build-script rule](https://doc.rust-lang.org/cargo/reference/build-scripts.html)
provides the host-selection model. It is conditional on this exact package
being selected and Cargo reaching its build-script phase. The scan does not
observe dependency resolution, compilation, or a Cargo command being run.

The modeled source operations include `std::fs::write`, process construction
through `std::process::Command::new`, and the download API above. Several
executables, arguments, output paths, and the download destination remain
unresolved. Separate retained network literals are static observations and
are not promoted into the unresolved download binding.

Rust recognition here uses bounded lexical patterns without rustc name/type
resolution, macro expansion, or platform/branch feasibility. The operations
remain `HEURISTIC`; capability rules require at least `CORROBORATED` support.
`CONNECTED` means modeled reachability from the conditional root, not observed
execution or a successful effect. Zero capability matches is expected here.

## Inspect a separately obtained copy

```sh
maratus inspect proc-macro1-1.0.107.crate --output-dir proc-macro1-report
```

This analyzes the crate as data. It does not compile or run `build.rs`.
