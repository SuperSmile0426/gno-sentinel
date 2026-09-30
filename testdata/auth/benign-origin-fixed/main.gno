package admin

import "chain/runtime/unsafe"

func LogCaller() {
	caller := unsafe.OriginCaller()
	_ = caller
}
