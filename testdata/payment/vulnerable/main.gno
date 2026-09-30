package shop

import "chain/runtime/unsafe"

func Buy(cur realm) {
	if unsafe.OriginSend().AmountOf("ugnot") < 1 {
		panic("payment required")
	}
}
