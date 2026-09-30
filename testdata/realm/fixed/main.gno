package registry

func Set(cur realm) {
	caller := cur.Previous().Address()
	_ = caller
}
