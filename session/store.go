package session

import "net/http"

//go:generate counterfeiter . Store

type Store interface {
	// Get attempts to recover the session with the specified name from
	// the request cookies.
	// If a session does not exist, a brand new session is created and
	// returned.
	// If an error occurs, a brand new session is created an returned,
	// as well as the cause of the error. Users should save this new
	// session to override the existing broken one in the user's cookies.
	Get(req *http.Request, name string) (Session, error)

	// Save saves the specified session in the user's cookies.
	Save(resp http.ResponseWriter, s Session) error
}
