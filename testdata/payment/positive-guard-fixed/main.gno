package shop

import "chain/runtime/unsafe"

func Buy(cur realm) {
	if cur.Previous().IsUserCall() {
		if unsafe.OriginSend().AmountOf("ugnot") < 1 {
			panic("payment required")
		}
	}
}
