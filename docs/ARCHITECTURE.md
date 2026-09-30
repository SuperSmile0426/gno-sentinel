# Architecture

## Product boundary

Gno Sentinel has two layers:

1. **Analyzer** — deterministic local analysis of Gno source packages.
2. **Monitor** — optional chain ingestion that discovers packages/transactions and feeds source or metadata into the analyzer and runtime rules.

The analyzer remains usable without a network connection.

## v0.2 local-analysis architecture

```text
filesystem / future source provider
              |
              v
        SourceProvider
              |
              v
      parsed package model
    (all .gno files in dir)
              |
              v
         rule engine
              |
     +--------+--------+
     |        |        |
     v        v        v
  source   version/  normalized
 excerpt   network   findings
              |
              v
          text / JSON
```

`internal/source` owns source loading and the parsed-package model. Rules no longer read files from disk directly, which makes fixture-backed and future indexed-source providers possible.

Gno currently uses Go parser/type-checker infrastructure in parts of its own tooling. The prototype therefore uses Go's parser for a dependency-light first implementation. This is an engineering convenience, not a claim that Go semantics equal Gno semantics.

## Optional ingestion boundary

`internal/ingest.ChainFeed` defines package and transaction event shapes without providing a network implementation yet. This keeps local scanning deterministic and prevents the analyzer from becoming dependent on a live node/indexer.

Target flow:

```text
Gno node --> tx-indexer --> ChainFeed --> source reconstruction --> Analyzer
                    |
                    +--> runtime observations --> runtime rules
```

## Non-duplication strategy

- **tx-indexer** remains the transaction/block indexing layer.
- Existing Gno explorers remain explorers.
- The official audit-pattern harness remains a useful upstream heuristic corpus.
- Sentinel focuses on normalized security rules, package/semantic analysis, versioning, automation, and security-specific runtime correlation.

## Next architecture step

Introduce verified fixture-backed provider/feed implementations first, then a real tx-indexer adapter. Network implementations must remain outside the core AST/rule packages and must not be required for `gno-sentinel scan`.
