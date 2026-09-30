# Architecture

## Product boundary

Gno Sentinel has two layers:

1. **Analyzer** — deterministic local analysis of Gno source packages.
2. **Monitor** — optional chain ingestion that discovers packages/transactions and feeds source or metadata into the analyzer and runtime rules.

The analyzer must remain usable without a network connection.

## Phase 0 architecture

```text
.gno files
   |
   v
file discovery
   |
   v
Go-compatible parser / AST
   |
   v
rule engine
   |
   +--> GNO-PAY-001
   +--> GNO-AUTH-001
   +--> GNO-STATE-001
   +--> GNO-REALM-001
   |
   v
normalized findings
   |
   +--> text
   +--> JSON
```

Gno currently uses Go parser/type-checker infrastructure in parts of its own tooling. The prototype therefore uses Go's parser for a dependency-light first implementation. This is an engineering convenience, not a claim that Go semantics equal Gno semantics.

## Target architecture

```text
             +---------------------+
             | local project / CI  |
             +----------+----------+
                        |
                        v
                 Source Provider
                        |
      +-----------------+-----------------+
      |                                   |
      v                                   v
local filesystem                  indexed package source
                                          ^
                                          |
Gno node --> tx-indexer --> ingestion ----+
                    |
                    +--> runtime observations

Source --> parser --> semantic model --> rule engine
                                  |          |
                                  |          +--> static findings
                                  +--------------> version metadata

runtime observations ---------------------------> runtime rules

findings/events --> storage --> API --> webhooks / CI / dashboard
```

## Non-duplication strategy

- **tx-indexer** remains the transaction/block indexing layer.
- Existing Gno explorers remain explorers.
- The official audit-pattern harness remains a useful upstream heuristic corpus.
- Sentinel focuses on normalized security rules, semantic analysis, versioning, automation, and security-specific runtime correlation.

## Interfaces to introduce next

```go
type SourceProvider interface {
    Packages(ctx context.Context) ([]Package, error)
}

type ChainFeed interface {
    SubscribePackages(ctx context.Context) (<-chan PackageEvent, error)
    SubscribeTransactions(ctx context.Context) (<-chan TxEvent, error)
}

type Rule interface {
    ID() string
    Analyze(*Context) []Finding
}
```

Network implementations must live outside the core AST/rule packages.
