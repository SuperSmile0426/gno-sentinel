package shop

import "chain/runtime/unsafe"

func Buy(cur realm) {
	if !cur.Previous().IsUserCall() {
		panic("direct user call required")
	}
	if unsafe.OriginSend().AmountOf("ugnot") < 1 {
		panic("payment required")
	}
}
