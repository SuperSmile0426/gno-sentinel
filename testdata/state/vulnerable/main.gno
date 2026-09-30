package vault

type State struct {
	Value int
}

var state = &State{}

func GetState() *State {
	return state
}
