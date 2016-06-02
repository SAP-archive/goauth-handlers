package session

//go:generate counterfeiter . Session

type Session interface {
	Name() string
	Values() map[string]string
	Clear()
}
