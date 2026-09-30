# boards2 OriginCaller intermediary-call PoC

## Result

**Confirmed on pinned upstream Gno source.**

Target:

- repository: `gnolang/gno`
- commit: `0de4fc2cd62e7066f68d29f3d6f7e931644f63c7`
- realm: `gno.land/r/gnoland/boards2/v0`
- function: `RemoveMember`

The current target authorizes self-removal using transaction origin:

```gno
origin := unsafe.OriginCaller()
caller := cur.Previous().Address()
...
if origin == member {
    removeMember()
    return
}
```

The PoCs execute:

```text
user -> unprivileged relay realm -> boards2.RemoveMember(..., member=user)
```

Both the ordinary guest-member case and the stronger sole realm-owner case pass against the pinned source.

A control patch changing only `origin == member` to `caller == member` rejects both relay PoCs as unauthorized while the existing direct-self-removal test and ordinary upstream boards2 tests remain green.

Reproducible workflow:

`.github/workflows/boards2-origin-poc.yml`

Evidence run:

`36680793119`

Full security analysis:

`findings/boards2-origin-caller-self-removal.md`

This is a local semantic test only. No live network, third-party account, or production state was touched.
