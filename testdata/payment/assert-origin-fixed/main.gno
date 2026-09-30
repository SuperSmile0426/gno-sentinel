package shop

import (
	"chain/runtime"
	"chain/runtime/unsafe"
)

func Buy(cur realm) {
	runtime.AssertOriginCall()
	if unsafe.OriginSend().AmountOf("ugnot") < 1 {
		panic("payment required")
	}
}
