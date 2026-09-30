# Gno Sentinel

Gno Sentinel is a security analysis and monitoring toolkit for Gno.land realms.

The project starts with a deterministic, AST-based CLI scanner for high-confidence Gno-specific security patterns and is designed to grow into a version-aware pipeline that scans newly published realms and watches runtime activity through Gno.land indexing infrastructure.

## Status

Early prototype. Do not treat a clean scan as proof that a realm is secure.

The current scanner implements four deliberately narrow rules:

| Rule | Purpose |
|---|---|
| `GNO-PAY-001` | `OriginSend()` without a preceding `IsUserCall()` guard in the same function |
| `GNO-AUTH-001` | `OriginCaller()` used directly in equality/inequality authorization logic |
| `GNO-STATE-001` | exported package pointers or exported getters that leak package-level pointer state |
| `GNO-REALM-001` | `unsafe.PreviousRealm()` used inside a function that accepts `cur realm` |

These checks are AST-based, but they are not yet full interprocedural or type-aware analysis.

## Quick start

```sh
go test ./...
go run ./cmd/gno-sentinel scan ./path/to/gno/realm
```

JSON output:

```sh
go run ./cmd/gno-sentinel scan --format json ./path/to/gno/realm
```

Fail CI on High findings:

```sh
go run ./cmd/gno-sentinel scan --fail-on high ./path/to/gno/realm
```

## Project goals

1. Provide a trustworthy Gno-native static analyzer rather than porting Solidity assumptions.
2. Tie every rule to an official Gno security invariant, vulnerable fixture, fixed fixture, and regression test.
3. Make rule behavior version-aware as Gno semantics evolve.
4. Integrate with Gno.land transaction indexing to scan newly published packages automatically.
5. Expose findings through CLI, JSON, API, CI, webhooks, and eventually a lightweight dashboard.

## Repository layout

```text
cmd/gno-sentinel/      CLI entrypoint
internal/analyzer/     file discovery, parsing, rule execution
internal/model/        finding and diagnostic models
internal/rules/        Gno-specific security rules
internal/report/       text and JSON output

testdata/              vulnerable/fixed regression fixtures
docs/                  architecture and product design
research/              Gno security model and ecosystem research
evidence/              sanitized validation artifacts
findings/              project security/research findings
poc/                   isolated experiments
scripts/               development/research helpers
reports/               grant and external report drafts
```

## Design constraint

Gno Sentinel is not a replacement for manual review. The current official Gno audit-pattern harness is itself explicit that heuristic checks produce false positives and false negatives. Sentinel's direction is to improve precision with AST/semantic analysis and combine static findings with observable chain/runtime signals.

## Upstream references

- Gno repository: https://github.com/gnolang/gno
- Gno grants: https://github.com/gnolang/grants
- Gno tx-indexer: https://github.com/gnolang/tx-indexer
- Gno security guide: https://github.com/gnolang/gno/blob/master/docs/resources/gno-security-guide.md
- Gno AI contract review guide: https://github.com/gnolang/gno/blob/master/docs/resources/gno-ai-contract-review.md
