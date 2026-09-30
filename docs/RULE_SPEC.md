# Rule specification

## Severity policy

Prototype severities are defaults, not universal conclusions. A concrete application finding can be lowered or raised only with evidence about reachability, privileges, assets, and impact.

All v0.2 rules emit optional Gno version/network context when supplied by the caller. Exact historical applicability ranges remain `unknown` until verified rather than being invented.

## GNO-PAY-001 — OriginSend without a dominating direct-user guard

**Default severity:** High  
**Confidence:** High for the narrow recognized patterns

Detect a known `OriginSend()` call when it is reachable without a recognized direct-user control-flow guard.

Recognized safe shapes in v0.2:

- a preceding rejecting `if !...IsUserCall() { panic(...) | return }` guard;
- a direct `if ...IsUserCall() { ...OriginSend()... }` guarded branch;
- a preceding `runtime.AssertOriginCall()` call from the canonical `chain/runtime` import;
- a local helper function with a `realm` parameter that unconditionally rejects a direct `!...IsUserCall()` condition before returning.

The rule recognizes `OriginSend` through imports of `chain/runtime/unsafe` and `chain/banker`, including normal aliases.

Rationale: current Gno security guidance requires direct-user-call guarding for native-coin payment verification and warns against weaker user checks around the transaction-origin payment envelope. `runtime.AssertOriginCall()` is stricter but is also documented as rejecting intermediaries and MsgRun calls.

**v0.2 calibration result:** a merely earlier `IsUserCall()` invocation no longer suppresses the finding, while documented helper guards used by upstream Gno realms are recognized.

**Known limitations:** this is still not full CFG/dominance or SSA analysis. Local helper summaries are syntactic and intentionally narrow. Compound boolean guards, indirect function values, imported helper guards, and custom terminating helpers can still produce false positives or false negatives.

## GNO-AUTH-001 — OriginCaller authorization comparison

**Default severity:** High  
**Confidence:** High for direct/one-hop local alias comparisons

Detect transaction-origin identity from the known `chain/runtime/unsafe` import when it appears in direct equality/inequality authorization-style comparisons. v0.2 also follows a one-hop local assignment such as:

```gno
caller := unsafe.OriginCaller()
if caller != owner { ... }
```

Benign reads that are not used in a comparison are not flagged.

Upstream calibration found two real-world uses that need adversarial review rather than automatic dismissal: a validator operator registration guard and a board self-removal path. These remain investigation candidates because Gno's own unsafe API documents `OriginCaller` as transaction-origin state that should not be used as a general immediate-caller authorization primitive.

**Known limitations:** no general SSA/data-flow analysis yet. Reassignment can cause false positives; multi-hop helpers, maps, switches, and richer authorization logic can be missed. Static detection alone does not establish exploitability or impact.

## GNO-STATE-001 — exported package-state pointer leak

**Default severity:** High  
**Confidence:** High when an exported getter directly aliases identified package-level pointer state

Detect:

- exported package-level pointer variables;
- exported functions returning pointer values that directly alias package-level pointer variables.

**v0.2 improvement:** analysis is package-level, so a state declaration in `state.gno` and a getter in `api.gno` are correlated.

**Upstream calibration limitation:** the canonical wugnot realm exports `Token *grc20.Token`, while current Gno guidance describes GRC20 as a deliberately encapsulated safe `/p/` type. That means "exported pointer" alone is not enough to justify a high-confidence vulnerability conclusion. The next rule revision needs type/capability awareness so it can distinguish safe encapsulated public handles from pointers exposing dangerous exported mutators.

**Known limitations:** mutator method sets, helper aliases, nested exported fields, slices/maps/interfaces, imported `/p/` mutable types, and canonical safe-type metadata are not yet type-resolved.

## GNO-REALM-001 — unsafe.PreviousRealm with `realm` parameter

**Default severity:** High  
**Confidence:** High for the narrow pattern

Detect a function that accepts a parameter of type `realm` and calls `PreviousRealm()` through an import of `chain/runtime/unsafe`. Import aliases are handled.

**Known limitations:** wrapper/helper calls and cross-function data flow are not yet resolved.
