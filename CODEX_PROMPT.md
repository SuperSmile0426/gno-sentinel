# Codex implementation prompt — Gno Sentinel v0.1 → v0.2

You are working in the `gno-sentinel` repository, an open-source Gno.land security analysis project.

First read, in order:

1. `AGENTS.md`
2. `README.md`
3. `docs/ARCHITECTURE.md`
4. `docs/RULE_SPEC.md`
5. `research/security-model.md`
6. `research/landscape.md`

Then inspect the current implementation and run:

```sh
go test ./...
go vet ./...
go run ./cmd/gno-sentinel scan ./testdata
```

Your task is to harden the existing prototype without changing its safety boundaries.

## Primary objective

Turn the first-pass AST scanner into a reliable Gno-native analyzer foundation suitable for a public prototype and later Gno.land grant submission.

## Required work

### 1. Baseline and architecture

- Confirm the current CLI and tests actually work before changing them.
- Document any discrepancy in `research/SESSION_LOG.md`.
- Keep local scanning deterministic and offline.
- Do not add a network dependency to the core analyzer.

### 2. Rule precision

For each existing rule (`GNO-PAY-001`, `GNO-AUTH-001`, `GNO-STATE-001`, `GNO-REALM-001`):

- inspect the current official Gno security guidance and implementation semantics;
- add at least two additional vulnerable and two additional fixed/benign fixtures when they represent materially different syntax/control flow;
- document false-positive and false-negative boundaries;
- prefer AST/control-flow reasoning over text matching;
- do not broaden a rule unless tests demonstrate the broader pattern is valid.

### 3. Parser/source abstraction

Introduce a clean parsed-package model so rules can reason across all `.gno` files in one package. Preserve file positions and source excerpts.

Do not tightly couple rules to `os.ReadFile` or CLI flags.

### 4. Version metadata

Add a minimal version/applicability model:

- analyzer accepts optional Gno version/network metadata;
- findings can expose the analyzed Gno version/network when known;
- rule definitions can declare an applicability note/range, even if enforcement initially defaults to `unknown/current`.

Do not invent historical version boundaries. Unknown boundaries must stay unknown until verified.

### 5. Finding quality

Every finding should contain:

- rule ID;
- title;
- default severity;
- confidence;
- file and precise position;
- concise evidence/source excerpt;
- explanation;
- remediation;
- upstream reference(s);
- optional version/network metadata.

Keep JSON backward-compatible where practical.

### 6. CI and quality

Keep or improve:

```sh
gofmt -w ./cmd ./internal
go test ./...
go vet ./...
```

Add tests for stable finding ordering and JSON serialization.

## Do not do yet

- Do not build a React dashboard.
- Do not add an AI/LLM finding generator.
- Do not send transactions to mainnet/testnet.
- Do not build a custom blockchain indexer.
- Do not claim full semantic safety from a clean scan.
- Do not copy large amounts of upstream Gno code into this repo.

## Stretch goal after the analyzer is solid

Design (but do not require for local scans) a `ChainFeed` / `SourceProvider` interface and a small fixture-backed adapter shaped around `tx-indexer` `MsgAddPackage` data. The adapter must be testable without network access.

## Definition of done

- all tests pass;
- each rule has documented evidence and limitations;
- results are deterministic;
- no production/network side effects;
- `research/SESSION_LOG.md` records what changed, tests run, remaining limitations, and the next highest-value task.
