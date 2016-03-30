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
	}

	token, ok := h.getToken(session)
	if !ok || !token.Valid() {
		delete(session.Values, sessionTokenField)
		session.Values["targetUrl"] = req.URL.String()

		state := uuid.NewV4().String()
		session.Values["state"] = state
		session.Save(req, w)

		http.Redirect(w, req, h.Provider.LoginURL(state), http.StatusFound)
	}

	info, err := h.Decoder.Decode(token)
	if err != nil {
		// TODO(ivan): log and fix response message
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
	if hasMissingScope(info.Scopes, h.RequiredScopes) {
		// TODO(ivan): log and fix response message
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
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
	m := make(map[string]struct{})
	for _, scope := range expected {
		m[scope] = struct{}{}
	}

	for _, scope := range actual {
		delete(m, scope)
	}
	return len(m) != 0
}
