package vault

type State struct {
	Value int
}

var state = &State{}

func GetValue() int {
	return state.Value
}
