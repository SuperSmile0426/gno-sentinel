# Rule specification

## Severity policy

Prototype severities are defaults, not universal conclusions. A concrete application finding can be lowered or raised only with evidence about reachability, privileges, assets, and impact.

All v0.2 rules emit optional Gno version/network context when supplied by the caller. Exact historical applicability ranges remain `unknown` until verified rather than being invented.

## GNO-PAY-001 — OriginSend without a dominating direct-user guard

**Default severity:** High  
**Confidence:** High for the narrow recognized patterns

Detect a known `OriginSend()` call when it is reachable without either:

- a preceding rejecting `if !...IsUserCall() { panic(...) | return }` guard in the same block; or
- a direct `if ...IsUserCall() { ...OriginSend()... }` guarded branch.

The rule recognizes `OriginSend` through imports of `chain/runtime/unsafe` and `chain/banker`, including normal aliases.

Rationale: current Gno security guidance requires direct-user-call guarding for native-coin payment verification and warns against weaker user checks around the transaction-origin payment envelope.

**v0.2 improvement:** a merely earlier `IsUserCall()` invocation no longer suppresses the finding. The check must constrain control flow.

**Known limitations:** this is not a full CFG/dominance analysis. Helper-based guards, compound boolean guards, and custom terminating helpers can produce false positives. Complex control flow can still produce false negatives. The rule intentionally recognizes only narrow, auditable guard shapes.

## GNO-AUTH-001 — OriginCaller authorization comparison

**Default severity:** High  
**Confidence:** High for direct/one-hop local alias comparisons

Detect transaction-origin identity from the known `chain/runtime/unsafe` import when it appears in direct equality/inequality authorization-style comparisons. v0.2 also follows a one-hop local assignment such as:

```gno
caller := unsafe.OriginCaller()
if caller != owner { ... }
```

Benign reads that are not used in a comparison are not flagged.

**Known limitations:** no general SSA/data-flow analysis yet. Reassignment can cause false positives; multi-hop helpers, maps, switches, and richer authorization logic can be missed.

## GNO-STATE-001 — exported package-state pointer leak

**Default severity:** High  
**Confidence:** High when an exported getter directly aliases identified package-level pointer state

Detect:

- exported package-level pointer variables;
- exported functions returning pointer values that directly alias package-level pointer variables.

**v0.2 improvement:** analysis is package-level, so a state declaration in `state.gno` and a getter in `api.gno` are correlated.

**Known limitations:** mutator method sets, helper aliases, nested exported fields, slices/maps/interfaces, and imported `/p/` mutable types are not yet type-resolved.

## GNO-REALM-001 — unsafe.PreviousRealm with `realm` parameter

**Default severity:** High  
**Confidence:** High for the narrow pattern

Detect a function that accepts a parameter of type `realm` and calls `PreviousRealm()` through an import of `chain/runtime/unsafe`. Import aliases are handled.

**Known limitations:** wrapper/helper calls and cross-function data flow are not yet resolved.
