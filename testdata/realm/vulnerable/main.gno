package registry

import unsafe "chain/runtime/unsafe"

func Set(cur realm) {
	caller := unsafe.PreviousRealm().Address()
	_ = caller
}
