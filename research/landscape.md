# Ecosystem and grant landscape

Research snapshot: 2026-09-29.

## Grant fit

The Gno.land grants repository explicitly prioritizes reusable builder tooling and lists an event system for real-time Gno contract monitoring and auditing among example projects. It also lists smart-contract safety work, fuzzing, IDE/tooling integrations, CI/CD, monitoring, and infrastructure.

Official program: https://github.com/gnolang/grants

## Existing components Sentinel should reuse, not duplicate

### tx-indexer

https://github.com/gnolang/tx-indexer

Capabilities include indexed blocks and transactions, GraphQL queries, real-time subscriptions, JSON-RPC/WS support, and querying `MsgAddPackage` transactions. Sentinel should consume it as a chain-data source.

### audit-pattern-harness

https://github.com/gnolang/gno/tree/master/misc/audit-pattern-harness

Use as a security-knowledge and fixture reference. Sentinel's value must come from stronger analysis, automation, versioning, and runtime correlation.

### explorers / wallets / DEX

Sentinel is security infrastructure, not another general explorer, wallet, or DEX.
