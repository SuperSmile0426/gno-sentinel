// PKGPATH: gno.land/r/gnoland/boards2/v0/filetests/z_sentinel_origin_caller_realm_owner_filetest

package z_sentinel_origin_caller_realm_owner_filetest

import (
	"testing"

	"gno.land/p/gnoland/boards/v0"

	boards2 "gno.land/r/gnoland/boards2/v0"
	relay "gno.land/r/sentinel/boards2relay"
)

const (
	initialOwner address = "g1skl80cuz8zq3lul9pgz5pc35l2pfzgxgfpsqkx"
	user         address = "g1us8428u2a5satrlxzagqqa5m6vmuze025anjlj"
	realmDAO            = boards.ID(0)
)

func init(cur realm) {
	testing.SetRealm(testing.NewUserRealm(initialOwner))

	// Make user an owner of the realm DAO.
	boards2.InviteMember(cross(cur), realmDAO, user, boards2.RoleOwner)

	// Initial owner intentionally leaves, making user the sole realm owner.
	boards2.RemoveMember(cross(cur), realmDAO, initialOwner)
}

func main(cur realm) {
	testing.SetRealm(testing.NewUserRealm(user))

	println("user-owner-before", boards2.HasMemberRole(realmDAO, user, boards2.RoleOwner))
	println("initial-owner-before", boards2.HasMemberRole(realmDAO, initialOwner, boards2.RoleOwner))

	// The unprivileged relay is the immediate caller to boards2, but the
	// transaction origin remains user. If RemoveMember trusts OriginCaller for
	// self-removal, this strips the sole realm owner through the intermediary.
	relay.RemoveMember(cross(cur), realmDAO, user)

	println("user-owner-after", boards2.HasMemberRole(realmDAO, user, boards2.RoleOwner))
	println("user-member-after", boards2.IsMember(realmDAO, user))
	println("initial-owner-after", boards2.HasMemberRole(realmDAO, initialOwner, boards2.RoleOwner))
}

// Output:
// user-owner-before true
// initial-owner-before false
// user-owner-after false
// user-member-after false
// initial-owner-after false
