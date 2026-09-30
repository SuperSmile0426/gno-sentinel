package admin

import "chain/runtime/unsafe"

var owner address

func SetValue() {
	if unsafe.OriginCaller() != owner {
		panic("unauthorized")
	}
}
