package admin

var owner address

func SetValue(cur realm) {
	if cur.Previous().Address() != owner {
		panic("unauthorized")
	}
}
