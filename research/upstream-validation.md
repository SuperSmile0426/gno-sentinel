# Upstream Gno validation

## Purpose

Before adding more rules or a live tx-indexer adapter, validate the v0.2 analyzer against real Gno realm code to measure parser compatibility and rule behavior outside synthetic fixtures.

## Pinned corpus

Repository: `gnolang/gno`  
Commit: `0de4fc2cd62e7066f68d29f3d6f7e931644f63c7`

Selected realm directories:

- `examples/gno.land/r/demo/disperse`
- `examples/gno.land/r/sys/namereg/v0`
- `examples/gno.land/r/gnoland/wugnot`
- `examples/gno.land/r/gnops/valopers`
- `examples/gno.land/r/gnoland/blog`
- `examples/gno.land/r/gnoland/boards2/v0`

These were chosen to exercise payment handling, caller identity, multi-file packages, and larger application code rather than only minimal demos.

## Method

The GitHub Actions workflow `.github/workflows/upstream-validation.yml` checks out the pinned upstream commit and runs the actual branch version of `gno-sentinel scan --format json` against each selected directory.

For every target it records:

- scanner exit code;
- finding count;
- parser/runtime diagnostics on stderr;
- complete JSON findings;
- an artifact containing all validation outputs.

The validation workflow is evidence, not a security audit of these upstream realms. A Sentinel finding is not automatically a confirmed vulnerability, and absence of findings is not proof of safety.

## Decision gate

After reviewing the results, classify each observation as one of:

- expected/high-signal;
- benign/false positive;
- parser/model limitation;
- likely false negative exposed by manual comparison with an official security pattern.

Use that evidence to choose the next analyzer investment: control-flow/SSA work, Gno type-resolution, or a narrower rule-specific improvement.
