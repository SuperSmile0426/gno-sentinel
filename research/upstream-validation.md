# Upstream Gno validation

## Purpose

Validate the v0.2 analyzer against real Gno realm code before adding more rules or a live tx-indexer adapter. The goal is to measure parser compatibility and rule behavior outside synthetic fixtures, not to declare upstream applications vulnerable.

## Pinned corpus

Repository: `gnolang/gno`  
Commit: `0de4fc2cd62e7066f68d29f3d6f7e931644f63c7`

Selected realm directories:

- `examples/gno.land/r/demo/disperse`
- `examples/gno.land/r/sys/namereg/v0`
- `examples/gno.land/r/gnoland/wugnot`
- `examples/gno.land/r/gnops/valopers`
- `examples/gno.land/r/gnoland/blog`
- `examples/gno.land/r/gnoland/boards2/v0`

These exercise payment handling, transaction-origin identity, multi-file packages, and larger application code.

## Reproducible method

The GitHub Actions workflow `.github/workflows/upstream-validation.yml` checks out the pinned upstream commit and runs the actual branch version of:

```sh
gno-sentinel scan --format json --gno-version gnolang/gno@0de4fc2 --network upstream-example-corpus <realm-dir>
```

It records scanner exit code, finding count, stderr diagnostics, complete JSON findings, and a downloadable artifact.

All six selected directories parsed successfully with scanner exit code 0.

## Calibration results

### First v0.2 pass

Workflow run: `36678781310`

| Realm | Findings |
|---|---:|
| demo/disperse | 0 |
| sys/namereg/v0 | 0 |
| gnoland/wugnot | 2 |
| gnops/valopers | 3 |
| gnoland/blog | 0 |
| gnoland/boards2/v0 | 1 |
| **Total** | **6** |

Review showed three payment findings were rule-precision problems:

- wugnot uses canonical `runtime.AssertOriginCall()`, which is documented as a stricter direct-origin guard;
- valopers uses a local `assertPaidCallIsDirect` helper that panics unless `rlm.Previous().IsUserCall()`.

The analyzer was updated to recognize both shapes.

### Refined v0.2 pass

Workflow run: `36679162937`  
Evidence artifact: `gno-upstream-validation` / artifact ID `11081066728`

| Realm | Findings |
|---|---:|
| demo/disperse | 0 |
| sys/namereg/v0 | 0 |
| gnoland/wugnot | 1 |
| gnops/valopers | 1 |
| gnoland/blog | 0 |
| gnoland/boards2/v0 | 1 |
| **Total** | **3** |

The payment false positives were eliminated while the local vulnerable/fixed regression corpus remained green.

## Remaining observations

### wugnot — GNO-STATE-001

Observed:

```gno
Token *grc20.Token
```

Classification: **benign/capability-model limitation until proven otherwise**.

Current Gno security guidance treats the GRC20 design as a canonical safe encapsulation pattern, and effective Gno documentation uses the exported token handle pattern. Sentinel currently sees only "exported pointer" and cannot yet reason about the pointee's method set and internal authentication. This is direct evidence that `GNO-STATE-001` needs type/capability resolution rather than a wider textual rule.

### valopers — GNO-AUTH-001

Observed shape:

```gno
if runtime.ChainHeight() > 0 && unsafe.OriginCaller() != addr {
    panic(ErrOperatorSquatGuard)
}
```

Classification: **investigation candidate, not a confirmed vulnerability**.

The surrounding source explicitly states that the transaction origin is intentionally bound to the operator address as an anti-squatting guard. However, `OriginCaller` is transaction-origin state, so the remaining question is whether an intermediary realm called by the victim can invoke `Register(cross(cur), ..., addr=victim, ...)` and create an unintended registration. A local Gno PoC is needed before making any security claim.

### boards2/v0 — GNO-AUTH-001

Observed shape in `RemoveMember`:

```gno
origin := unsafe.OriginCaller()
...
if origin == member {
    removeMember()
    return
}
```

Classification: **higher-priority investigation candidate, not a confirmed vulnerability**.

This uses transaction origin to authorize "self removal." The specific hypothesis is that a user could call an intermediary realm which then calls `RemoveMember(cross(cur), boardID, originUser)`, potentially causing membership removal without a direct call to boards2. A deterministic local filetest/PoC is required.

## Decision for v0.3

Do **not** build the live tx-indexer adapter yet.

The evidence says the highest-value next work is:

1. build local Gno PoCs for the two `OriginCaller` candidates and classify them with execution evidence;
2. add type/capability awareness to `GNO-STATE-001` so canonical safe handles such as GRC20 can be distinguished from dangerous mutable pointers;
3. only after those precision improvements, connect the analyzer to tx-indexer for automatic package scanning.

This keeps Sentinel's grant story centered on high-confidence security intelligence rather than high-volume pattern matching.
