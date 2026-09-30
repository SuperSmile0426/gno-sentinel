package admin

import "chain/runtime/unsafe"

var owner address

func SetValue() {
	caller := unsafe.OriginCaller()
	if caller != owner {
		panic("unauthorized")
	}
}
