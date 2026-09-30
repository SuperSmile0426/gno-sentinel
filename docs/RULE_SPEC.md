# Rule specification

## Severity policy

Prototype severities are defaults, not universal conclusions. A concrete application finding can be lowered or raised only with evidence about reachability, privileges, assets, and impact.

## GNO-PAY-001 — OriginSend without direct user-call guard

**Default severity:** High  
**Confidence:** High for the narrow pattern

Detect an `OriginSend()` use in a function when no `IsUserCall()` call precedes it in that function.

Rationale: current Gno security guidance requires direct-user-call guarding for native-coin payment verification and warns against weaker user checks around the transaction-origin payment envelope.

Prototype limitation: same-function ordering only. It does not prove that the guard dominates every control-flow path and does not recognize helper-based guards.

## GNO-AUTH-001 — OriginCaller authorization comparison

**Default severity:** High  
**Confidence:** High for direct comparison

Detect `OriginCaller()` inside direct equality/inequality comparisons.

Prototype limitation: does not find helper-mediated authorization, switch statements, map lookups, or more complex data flow.

## GNO-STATE-001 — Exported package-state pointer leak

**Default severity:** High  
**Confidence:** High when an exported getter aliases an identified package-level pointer

Detect:

- exported package-level pointer variables;
- exported functions returning pointer values that directly alias package-level pointer variables.

Prototype limitation: does not yet infer mutator method sets, aliases through helpers/fields, interfaces, slices/maps, or imported `/p/` types.

## GNO-REALM-001 — unsafe.PreviousRealm with `cur realm`

**Default severity:** High  
**Confidence:** High for the narrow pattern

Detect a function that accepts a parameter of type `realm` and calls `PreviousRealm()` through an import of `chain/runtime/unsafe`.

Prototype limitation: import aliases are handled, but wrapper/helper calls and cross-file data flow are not.
