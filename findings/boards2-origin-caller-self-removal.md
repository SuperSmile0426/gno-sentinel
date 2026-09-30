# Confirmed: boards2 RemoveMember trusts transaction origin across intermediary realms

## Status

Confirmed in a local deterministic Gno execution test.

- Upstream repository: `gnolang/gno`
- Pinned commit: `0de4fc2cd62e7066f68d29f3d6f7e931644f63c7`
- Affected realm: `gno.land/r/gnoland/boards2/v0`
- Function: `RemoveMember`
- Sentinel rule that surfaced it: `GNO-AUTH-001`
- Severity assessment: **High candidate**, subject to upstream/program triage
- Primary impact: unauthorized role removal and potential realm-wide administrative lockout
- Required attacker condition: victim must sign/call an attacker-controlled intermediary realm

## Summary

`boards2.RemoveMember` uses `unsafe.OriginCaller()` to decide whether a member is removing themselves:

```gno
origin := unsafe.OriginCaller()
caller := cur.Previous().Address()
...
if origin == member {
    removeMember()
    return
}
```

Because `OriginCaller()` remains the transaction origin across cross-realm calls, an unprivileged intermediary realm can call `RemoveMember` on behalf of the transaction origin.

The intermediary does not need `PermissionMemberRemove`. If the supplied `member` equals the transaction origin, the function enters the self-removal branch before the immediate caller is checked through `WithPermission`.

## Confirmed call path

```text
victim user
    |
    | signed call
    v
attacker-controlled / unprivileged relay realm
    |
    | cross-realm call
    v
boards2.RemoveMember(cur, boardID, member=victim)
    |
    | OriginCaller() == victim
    | cur.Previous().Address() == relay
    v
self-removal branch succeeds
```

## PoC 1 — ordinary member removal

The PoC creates a board, adds the victim as a guest, switches execution to the victim user realm, then calls an unprivileged relay realm.

The relay calls:

```gno
boards2.RemoveMember(cross(cur), boardID, victim)
```

Expected/observed state:

```text
before true
after  false
```

The filetest passes against the pinned upstream source, confirming that the relay causes removal even though it is not granted board removal permission.

PoC source:

- `poc/boards2-origin-caller/relay/relay.gno`
- `poc/boards2-origin-caller/z_intermediary_remove_member_filetest.gno`

## PoC 2 — sole realm-owner removal

The stronger PoC targets the realm DAO itself (`boardID = 0`):

1. the initial realm owner grants the victim `RoleOwner`;
2. the initial owner intentionally leaves, making the victim the sole realm owner;
3. the victim calls the unprivileged relay;
4. the relay calls `RemoveMember(..., boardID=0, member=victim)`.

Observed state:

```text
user-owner-before     true
initial-owner-before  false
user-owner-after      false
user-member-after     false
initial-owner-after   false
```

The filetest passes, so the intermediary can strip the last realm owner.

The realm permission initializer gives `RoleAdmin` only `PermissionBoardCreate`; owner-only capabilities are inherited from the super role. After the final owner is removed, there is no ordinary in-contract owner left to exercise permissions such as member/role administration or permission replacement.

PoC source:

- `poc/boards2-origin-caller/z_intermediary_remove_realm_owner_filetest.gno`

## Reproducible evidence

GitHub Actions workflow:

`.github/workflows/boards2-origin-poc.yml`

Successful evidence run:

`36680793119`

The vulnerable-source phase reports both Sentinel PoCs as PASS.

## Remediation control

The workflow applies one temporary change to the pinned upstream checkout:

```diff
- if origin == member {
+ if caller == member {
    removeMember()
    return
}
```

With this one-line control patch:

- both intermediary PoCs are rejected;
- the panic is:
  `unauthorized, user <relay-address> doesn't have the required permission`;
- the existing direct self-removal upstream test `z_remove_member_03_filetest.gno` still passes;
- the ordinary boards2 test suite still passes after the PoC files are removed.

This demonstrates that immediate-caller authorization blocks the intermediary path while preserving the documented direct self-removal behavior.

## Root cause

The function mixes two caller identities:

- `unsafe.OriginCaller()`: transaction origin;
- `cur.Previous().Address()`: immediate cross-realm caller.

The permissioned path correctly uses the immediate caller, but the self-removal shortcut uses transaction origin. This creates a transaction-origin authorization primitive similar to the classic `tx.origin` phishing/confused-deputy class.

## Impact

An attacker cannot trigger this without a victim-originated transaction. The practical attack requires convincing a member/owner to call an attacker-controlled realm or application.

Once that happens, the attacker-controlled realm can cause boards2 to remove the victim's membership without holding `PermissionMemberRemove`.

For ordinary members this is unauthorized role/membership removal.

For a sole realm owner, the reproduced result removes the last owner from `gPerms`, creating an administrative lockout condition. Recovery may require an out-of-band privileged migration or code/state intervention rather than an ordinary boards2 call.

## Recommended fix

Use immediate caller identity for self-removal:

```gno
caller := cur.Previous().Address()

if caller == member {
    removeMember()
    return
}
```

`OriginCaller` can remain in event metadata if transaction-origin attribution is desired, but it should not grant the self-removal authorization shortcut.

Add regression tests covering:

1. direct user self-removal succeeds;
2. user -> unprivileged relay -> RemoveMember(user) is rejected;
3. relay cannot strip a sole board or realm owner through transaction origin.

## Limitations

This research used only the pinned public source and local Gno filetests. No mainnet/testnet transaction was sent, no third-party account was targeted, and no production state was modified.

The severity label above is an assessment for research prioritization, not an upstream bounty decision.
