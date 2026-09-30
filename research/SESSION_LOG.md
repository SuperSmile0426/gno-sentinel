# Session log

## 2026-09-30 — v0.2 analyzer hardening and upstream calibration

Work performed:

- Replaced file-at-a-time analysis with a parsed package model grouped by directory.
- Added a `SourceProvider` abstraction and kept local scanning offline/deterministic.
- Added optional `--gno-version` and `--network` metadata propagated into findings.
- Added source excerpts to findings.
- Hardened `GNO-PAY-001` so an unrelated earlier `IsUserCall()` invocation is no longer treated as a security guard.
- Added recognition for direct positive guards, rejecting negative guards, canonical `runtime.AssertOriginCall()`, and narrow local helper functions that reject non-`IsUserCall()` paths.
- Hardened `GNO-AUTH-001` with known-import filtering and one-hop local alias tracking.
- Hardened `GNO-STATE-001` to correlate pointer state and getters across multiple files in one package.
- Kept `GNO-REALM-001` import-alias aware under the package model.
- Added deterministic finding-order and metadata/reporting tests.
- Added a network-independent `ChainFeed` interface as the future tx-indexer boundary.
- Added a pinned upstream Gno validation workflow and evidence artifact.

Validation:

```sh
gofmt -w ./cmd ./internal
go test ./...
go vet ./...
go run ./cmd/gno-sentinel scan --gno-version v-test --network testnet ./testdata
```

Local CI remains green.

Upstream calibration against `gnolang/gno@0de4fc2`:

- first pass: 6 findings across six selected realm directories;
- after recognizing documented payment guard helpers: 3 findings;
- all selected upstream directories parsed with exit code 0;
- remaining findings: one canonical exported GRC20 token pointer and two `OriginCaller` authorization patterns.

Interpretation:

- the exported GRC20 token pointer demonstrates that `GNO-STATE-001` needs type/capability resolution;
- the valopers and boards2 `OriginCaller` detections require deterministic local PoCs before they can be called vulnerabilities;
- tx-indexer integration should wait until these precision questions are resolved.

Remaining limitations:

- no full CFG/dominance or SSA analysis;
- no Gno type-checker/capability integration yet;
- no verified historical version ranges;
- no live tx-indexer adapter;
- no execution-backed classification for the two upstream auth candidates.

Next concrete task: build local Gno PoCs for the valopers and boards2 `OriginCaller` hypotheses, while designing a type-aware capability model for pointer-exposure rules.
