package boards2relay

import (
	"gno.land/p/gnoland/boards/v0"

	boards2 "gno.land/r/gnoland/boards2/v0"
)

// RemoveMember intentionally has no boards2 membership or removal permission.
// It relays a user-originated call into boards2 to test whether boards2
// authorizes self-removal from transaction origin instead of immediate caller.
func RemoveMember(cur realm, boardID boards.ID, member address) {
	boards2.RemoveMember(cross(cur), boardID, member)
}
