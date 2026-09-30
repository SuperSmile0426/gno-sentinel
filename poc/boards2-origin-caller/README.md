# boards2 OriginCaller intermediary-call PoC

This PoC tests a single authorization hypothesis against a pinned local checkout of `gnolang/gno`.

Target commit:

`0de4fc2cd62e7066f68d29f3d6f7e931644f63c7`

Target code:

`examples/gno.land/r/gnoland/boards2/v0/public.gno::RemoveMember`

The target authorizes self-removal with transaction origin:

```gno
origin := unsafe.OriginCaller()
...
if origin == member {
    removeMember()
    return
}
```

The PoC creates a board, adds `user` as a guest, then executes:

```text
user -> unprivileged relay realm -> boards2.RemoveMember(..., member=user)
```

The relay is not granted `PermissionMemberRemove`. If membership changes from true to false, the experiment demonstrates that transaction-origin identity can authorize the state change through an intermediary realm.

This is a local semantic test only. It does not target a live network, other users, or production state. Passing the PoC establishes the call-path behavior; severity and reportability still require impact analysis.
