# Codex instructions — Gno Sentinel

Read `README.md`, `docs/ARCHITECTURE.md`, `docs/RULE_SPEC.md`, and `research/security-model.md` before non-trivial work.

## Mission

Build a production-quality, open-source Gno.land security analysis and monitoring toolkit. Prefer evidence-backed, version-aware checks over broad speculative warnings.

## Safety and integrity

- Work from public source code, local fixtures, local nodes, and explicitly authorized test networks/environments.
- Do not exploit live applications or users, probe third-party production systems, or send transactions with economic impact unless the user explicitly authorizes that exact test.
- Never claim a realm is secure because the scanner is clean.
- Never assign a severity higher than the demonstrated impact and prerequisites support.
- Separate static evidence, runtime evidence, and interpretation.
- Keep secrets, mnemonics, private keys, access tokens, and reusable signatures out of the repository.

## Rule quality bar

Every security rule must have:

1. a stable rule ID;
2. a threat model and affected Gno versions;
3. an official upstream reference or a clearly documented original research basis;
4. at least one vulnerable fixture;
5. at least one fixed fixture;
6. deterministic unit/regression tests;
7. explicit known false-positive and false-negative conditions;
8. remediation guidance;
9. no network dependency in unit tests.

Prefer AST/type/semantic analysis. Regex/text scanning may be used only as a documented fallback or pre-filter.

## Implementation rules

- Keep the analyzer deterministic.
- Do not fetch remote code during a local `scan` unless a separate explicit mode is introduced.
- Do not make the CLI depend on a running Gno node.
- Sort findings deterministically by file, line, column, then rule ID.
- Preserve machine-readable JSON output as a stable interface.
- Keep chain ingestion behind interfaces so testnet/mainnet indexer clients can be tested with fixtures.
- Treat Gno semantics as versioned. Do not assume today's `cur realm`, crossing, banker, or runtime behavior applies to older/future versions.
- When adopting code or behavior from `gnolang/gno`, verify the current upstream implementation and license before copying anything.

## Working method

1. Start from an explicit security invariant.
2. Create vulnerable and fixed Gno fixtures.
3. Add a failing test first when practical.
4. Implement the smallest rule that catches the vulnerable fixture without flagging the fixed fixture.
5. Test against realistic upstream/example realms and record false positives in `research/`.
6. Document limitations before expanding rule scope.
7. End substantial work by updating `research/SESSION_LOG.md`.

## Current priorities

1. Harden the four prototype rules.
2. Replace same-function approximations with semantic/interprocedural analysis where evidence justifies it.
3. Add a version metadata model.
4. Add package-source abstractions for local directories and indexed `MsgAddPackage` payloads.
5. Add tx-indexer ingestion without coupling the core analyzer to the network.
6. Build CI/SARIF support only after rule precision is measured.

## Verification

Before considering a change complete:

```sh
gofmt -w ./cmd ./internal
go test ./...
go vet ./...
go run ./cmd/gno-sentinel scan ./testdata
```

Do not weaken tests just to make a rule pass.
