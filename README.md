# Gno Sentinel

Gno Sentinel is a security analysis and monitoring toolkit for Gno.land realms.

The project starts with a deterministic, AST-based CLI scanner for high-confidence Gno-specific security patterns and is designed to grow into a version-aware pipeline that scans newly published realms and watches runtime activity through Gno.land indexing infrastructure.

## Status

**v0.2 prototype.** Do not treat a clean scan as proof that a realm is secure.

The scanner currently implements four deliberately narrow rules:

| Rule | Purpose |
|---|---|
| `GNO-PAY-001` | `OriginSend()` reachable without a recognized dominating `IsUserCall()` control-flow guard |
| `GNO-AUTH-001` | `OriginCaller()` / one-hop local alias used in direct auth comparisons |
| `GNO-STATE-001` | exported package pointers or exported getters that leak package-level pointer state, including cross-file getters |
| `GNO-REALM-001` | `unsafe.PreviousRealm()` used inside a function that accepts `realm` |

These checks are AST/package based, but they are not yet full CFG, SSA, or type-aware semantic analysis.

## Quick start

```sh
go test ./...
go run ./cmd/gno-sentinel scan ./path/to/gno/realm
```

Attach analysis context when known:

```sh
go run ./cmd/gno-sentinel scan \
  --gno-version v1.x \
  --network testnet \
  ./path/to/gno/realm
```

JSON output:

```sh
go run ./cmd/gno-sentinel scan --format json ./path/to/gno/realm
```

Fail CI on High findings:

```sh
go run ./cmd/gno-sentinel scan --fail-on high ./path/to/gno/realm
```

## v0.2 architecture

- `internal/source` loads all `.gno` files in a package together through a `SourceProvider` abstraction.
- Rules operate on the package model, enabling cross-file correlation.
- Findings can carry source excerpts, Gno-version context, and network context.
- `internal/ingest` defines a network-independent future `ChainFeed` boundary for tx-indexer integration.
- Local `scan` remains deterministic and offline.

## Project goals

1. Provide trustworthy Gno-native analysis rather than porting Solidity assumptions.
2. Tie every rule to an official Gno security invariant, vulnerable fixture, fixed fixture, and regression test.
3. Make rule behavior version-aware as Gno semantics evolve.
4. Integrate with Gno.land transaction indexing to scan newly published packages automatically.
5. Expose findings through CLI, JSON, API, CI, webhooks, and eventually a lightweight dashboard.

## Repository layout

```text
cmd/gno-sentinel/      CLI entrypoint
internal/analyzer/     analyzer orchestration
internal/source/       source providers + parsed package model
internal/model/        finding and analysis metadata models
internal/rules/        Gno-specific security rules
internal/report/       text and JSON output
internal/ingest/       future chain-feed boundary

testdata/              vulnerable/fixed regression fixtures
docs/                  architecture and rule specifications
research/              Gno security model, landscape, session log
evidence/              sanitized validation artifacts
findings/              project research/security findings
poc/                   isolated experiments
scripts/               development/research helpers
reports/               grant and external report drafts
```

## Design constraint

Gno Sentinel is not a replacement for manual review. The current official Gno audit-pattern harness is itself explicit that heuristic checks produce false positives and false negatives. Sentinel's direction is to improve precision with package/semantic analysis and combine static findings with observable chain/runtime signals.

## Upstream references

- Gno repository: https://github.com/gnolang/gno
- Gno grants: https://github.com/gnolang/grants
- Gno tx-indexer: https://github.com/gnolang/tx-indexer
- Gno security guide: https://github.com/gnolang/gno/blob/master/docs/resources/gno-security-guide.md
- Gno AI contract review guide: https://github.com/gnolang/gno/blob/master/docs/resources/gno-ai-contract-review.md
