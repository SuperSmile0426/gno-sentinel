package shop

import "chain/runtime/unsafe"

func Buy(cur realm) {
	checked := cur.Previous().IsUserCall()
	_ = checked
	if unsafe.OriginSend().AmountOf("ugnot") < 1 {
		panic("payment required")
	}
}
