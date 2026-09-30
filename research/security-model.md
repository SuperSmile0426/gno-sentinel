# Gno security model notes

Research snapshot: 2026-09-29.

Primary upstream references:

- https://github.com/gnolang/gno/blob/master/docs/resources/gno-security-guide.md
- https://github.com/gnolang/gno/blob/master/docs/resources/gno-ai-contract-review.md
- https://github.com/gnolang/gno/blob/master/misc/audit-pattern-harness/README.md
- https://github.com/gnolang/gno/blob/master/AGENTS.md

## High-yield Gno-specific families

The current upstream guidance identifies security-sensitive behavior around:

- caller identity and realm-context handling;
- `OriginSend` payment verification;
- mutable state/pointer exposure across realm/package boundaries;
- caller-provided callbacks and write-authority laundering;
- untrusted interfaces and canonical implementation checks;
- persistent `realm` values;
- unsafe previous-realm APIs;
- unsanitized `Render(path)` output;
- attacker-influenced gas cost from broad balance enumeration.

## Existing upstream detector

`misc/audit-pattern-harness` is valuable as a rule corpus and regression fixture model, but its README explicitly describes pattern detection as heuristic text scanning with expected false positives and false negatives.

Sentinel should treat that corpus as upstream evidence, not merely repackage the scanner.

## Sentinel differentiation

The project should improve along four dimensions:

1. AST and semantic analysis rather than line-oriented text matching.
2. Cross-file/interprocedural reasoning where useful.
3. Gno-version-aware rule applicability.
4. Correlation with indexed package publication and runtime transaction observations.
