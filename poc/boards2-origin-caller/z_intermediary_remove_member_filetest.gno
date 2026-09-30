// PKGPATH: gno.land/r/gnoland/boards2/v0/filetests/z_sentinel_origin_caller_intermediary_filetest

package z_sentinel_origin_caller_intermediary_filetest

import (
	"testing"

	"gno.land/p/gnoland/boards/v0"

	boards2 "gno.land/r/gnoland/boards2/v0"
	relay "gno.land/r/sentinel/boards2relay"
)

const (
	owner address = "g1skl80cuz8zq3lul9pgz5pc35l2pfzgxgfpsqkx"
	user  address = "g1us8428u2a5satrlxzagqqa5m6vmuze025anjlj"
)

var bid boards.ID

func init(cur realm) {
	testing.SetRealm(testing.NewUserRealm(owner))
	bid = boards2.CreateBoard(cross(cur), "sentinel-origin-caller-poc", false, false)
	boards2.InviteMember(cross(cur), bid, user, boards2.RoleGuest)
}

func main(cur realm) {
	testing.SetRealm(testing.NewUserRealm(user))

	println("before", boards2.IsMember(bid, user))

	// Call an unprivileged intermediary realm. The intermediary, not the user,
	// is the immediate caller observed by boards2 via cur.Previous().
	relay.RemoveMember(cross(cur), bid, user)

	println("after", boards2.IsMember(bid, user))
}

// Output:
// before true
// after false
