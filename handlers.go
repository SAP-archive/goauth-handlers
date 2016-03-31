package goauth_handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/satori/go.uuid"

	"github.wdf.sap.corp/cloudfoundry/goauth_handlers/token"

	"golang.org/x/oauth2"
)

//go:generate counterfeiter . TokenProvider
//go:generate counterfeiter . TokenDecoder
//go:generate counterfeiter . SessionStore

// TokenProvider should be able to echange auth code for access token and
// generate login url from state string.
type TokenProvider interface {
	RequestToken(code string) (*oauth2.Token, error)
	LoginURL(state string) string
}

// TokenDecoder should be able to decode stored information in a JWT token.
type TokenDecoder interface {
	Decode(*oauth2.Token) (token.Info, error)
}

// SessionStore is wrapper for gorilla's Store interface.
type SessionStore interface {
	sessions.Store
}

// TODO(ivan): does this need to be public?
const SessionName = "goauth"
const sessionTokenField = "token"

type AuthorizationHandler struct {
	Handler        http.Handler
	Provider       TokenProvider
	Decoder        TokenDecoder
	Store          SessionStore
	RequiredScopes []string
	// TODO(ivan): Determine what Logger should include,
	// and allow one to pass in concrete implementation.
	Logger interface{}
}

func (h *AuthorizationHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	session, err := h.Store.Get(req, SessionName)
	// TODO(ivan): add test for this
	if err != nil {
		// TODO(ivan): log and fix response message
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	token, ok := h.getToken(session)
	if !ok || !token.Valid() {
		delete(session.Values, sessionTokenField)
		session.Values["targetUrl"] = req.URL.String()

		state := uuid.NewV4().String()
		session.Values["state"] = state
		session.Save(req, w)

		http.Redirect(w, req, h.Provider.LoginURL(state), http.StatusFound)
		return
	}

	info, err := h.Decoder.Decode(token)
	if err != nil {
		// TODO(ivan): log and fix response message
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if hasMissingScope(info.Scopes, h.RequiredScopes) {
		// TODO(ivan): log and fix response message
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
}

// TODO(ivan): maybe return token, bool and error?
func (h *AuthorizationHandler) getToken(session *sessions.Session) (*oauth2.Token, bool) {
	raw, ok := session.Values[sessionTokenField]
	if !ok {
		return nil, false
	}
	tokenStr, ok := raw.(string)
	if !ok {
		return nil, false
	}
	token := &oauth2.Token{}
	if err := json.Unmarshal([]byte(tokenStr), token); err != nil {
		return nil, false
	}
	return token, true
}

func hasMissingScope(actual, expected []string) bool {
	if len(expected) == 0 {
		return true
	}
	m := make(map[string]struct{})
	for _, scope := range expected {
		m[scope] = struct{}{}
	}

	for _, scope := range actual {
		delete(m, scope)
	}
	return len(m) != 0
}

type CallbackHandler struct {
	Provider TokenProvider
	Store    SessionStore
}

func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// TODO(ivan): why ignore err here?
	session, _ := h.Store.Get(req, SessionName)

	if errParam := req.FormValue("error"); errParam != "" {
		session.Values = nil
		session.Save(req, w)
		switch errParam {
		case "invalid_scope":
			http.Error(w, "You do not have the required authorization.", http.StatusForbidden)
		default:
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return
	}

	clearSession := sessionCleaner(session, w, req)
	state := req.FormValue("state")
	if state == "" {
		clearSession("Missing state query parameter.", http.StatusBadRequest)
		return
	}

	code := req.FormValue("code")
	if code == "" {
		clearSession("Missing code query parameter.", http.StatusBadRequest)
		return
	}

	// TODO(ivan): extract targetUrl as constant
	targetURL, ok := session.Values["targetUrl"].(string)
	if !ok {
		clearSession("Missing redirect URL.", http.StatusBadRequest)
		return
	}
	delete(session.Values, "targetUrl")

	expectedState, ok := session.Values["state"].(string)
	if !ok {
		clearSession("Missing state.", http.StatusBadRequest)
		return
	}
	delete(session.Values, "state")

	if state != expectedState {
		clearSession("Invalid state parameter.", http.StatusBadRequest)
		return
	}

	token, err := h.Provider.RequestToken(code)
	if err != nil {
		clearSession("Could not retrieve token from provider.", http.StatusInternalServerError)
		return
	}

	tokenBytes, err := json.Marshal(token)
	if err != nil {
		// should not happen
		clearSession(http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		panic(err)
	}

	session.Values["token"] = string(tokenBytes)
	session.Save(req, w)
	http.Redirect(w, req, targetURL, http.StatusFound)
}

func sessionCleaner(s *sessions.Session, w http.ResponseWriter, req *http.Request) func(string, int) {
	return func(error string, code int) {
		s.Values = nil
		s.Save(req, w)
		http.Error(w, error, code)
	}
}
