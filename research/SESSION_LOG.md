# Session log

## 2026-09-29 — initial scaffold

- Defined product boundary: local analyzer first, chain monitor second.
- Added four narrow AST-based rules.
- Added vulnerable/fixed fixtures and regression tests.
- Added text/JSON CLI output and CI fail threshold.
- Documented known limitations and non-duplication strategy.

Next concrete task: measure the prototype rules against upstream Gno example realms, catalog false positives/negatives, then choose the first rule to upgrade with semantic/interprocedural reasoning.
