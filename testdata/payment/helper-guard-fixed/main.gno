package shop

import "chain/runtime/unsafe"

func assertPaidCallIsDirect(_ int, rlm realm) {
	if !rlm.Previous().IsUserCall() {
		panic("direct user call required")
	}
}

func Buy(cur realm) {
	assertPaidCallIsDirect(0, cur)
	if unsafe.OriginSend().AmountOf("ugnot") < 1 {
		panic("payment required")
	}
}
