# Session log

## 2026-09-30 — v0.2 analyzer hardening

Work performed:

- Replaced file-at-a-time analysis with a parsed package model grouped by directory.
- Added a `SourceProvider` abstraction and kept local scanning offline/deterministic.
- Added optional `--gno-version` and `--network` metadata propagated into findings.
- Added source excerpts to findings.
- Hardened `GNO-PAY-001` so an unrelated earlier `IsUserCall()` invocation is no longer treated as a security guard; recognized direct positive guarded branches and rejecting negative guards.
- Hardened `GNO-AUTH-001` with known-import filtering and one-hop local alias tracking.
- Hardened `GNO-STATE-001` to correlate pointer state and getters across multiple files in one package.
- Kept `GNO-REALM-001` import-alias aware under the package model.
- Added deterministic finding-order and metadata/reporting tests.
- Added a network-independent `ChainFeed` interface as the future tx-indexer boundary.

Validation:

```sh
gofmt -w ./cmd ./internal
go test ./...
go vet ./...
go run ./cmd/gno-sentinel scan --gno-version v-test --network testnet ./testdata
```

Result: all tests and vet pass; regression corpus yields the expected vulnerable findings and keeps fixed/benign fixtures clean.

Remaining limitations:

- no full CFG/dominance or SSA analysis;
- no Gno type-checker integration yet;
- no verified historical version ranges;
- no live tx-indexer adapter;
- pointer-mutator method sets are not type-resolved.

Next concrete task: validate v0.2 rules against a curated corpus of upstream Gno example realms, record false positives/negatives, and use that evidence to choose between CFG work and Gno type-resolution as the next analyzer milestone.
