package goauth_handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/satori/go.uuid"

	"github.infra.hana.ondemand.com/cloudfoundry/goauth_handlers/token"

	"golang.org/x/oauth2"
)

//go:generate counterfeiter . TokenProvider
//go:generate counterfeiter . TokenDecoder
//go:generate counterfeiter . SessionStore
//go:generate counterfeiter . Logger

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

// Logger provides basic logging functionality. It should be safe for
// concurrent use by multiple goroutines.
type Logger interface {
	// Printf is used for info logging by a handler.
	Printf(format string, args ...interface{})
	// Errorf is used for logging errors that are handled by a handler.
	Errorf(format string, args ...interface{})
}

const sessionName = "goauth"
const tokenField = "token"
const targetURLField = "targetUrl"

type AuthorizationHandler struct {
	Handler        http.Handler
	Provider       TokenProvider
	Decoder        TokenDecoder
	Store          SessionStore
	RequiredScopes []string
	Logger         Logger
}

func (h *AuthorizationHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// We're ignoring the error resulted from decoding an
	// existing session: Get() always returns a session, even if empty.
	session, _ := h.Store.Get(req, sessionName)

	token, ok := h.getToken(session)
	if !ok || !token.Valid() {
		delete(session.Values, tokenField)
		session.Values[targetURLField] = req.URL.String()

		state := uuid.NewV4().String()
		session.Values["state"] = state

		if err := session.Save(req, w); err != nil {
			h.Logger.Errorf("AuthorizationHandler: error saving session: %v\n", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}

		http.Redirect(w, req, h.Provider.LoginURL(state), http.StatusFound)
		return
	}

	info, err := h.Decoder.Decode(token)
	if err != nil {
		if h.Logger != nil {
			h.Logger.Errorf("AuthorizationHandler: error extracting token info: %v\n", err)
		}
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if hasMissingScope(info.Scopes, h.RequiredScopes) {
		if h.Logger != nil {
			h.Logger.Printf("AuthorizationHandler: denying access because of missing scope.\n")
		}
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	h.Handler.ServeHTTP(w, req)
}

func (h *AuthorizationHandler) getToken(session *sessions.Session) (*oauth2.Token, bool) {
	raw, ok := session.Values[tokenField]
	if !ok {
		return nil, false
	}
	tokenStr, ok := raw.(string)
	if !ok {
		return nil, false
	}
	token := &oauth2.Token{}
	if err := json.Unmarshal([]byte(tokenStr), token); err != nil {
		h.Logger.Errorf("AuthorizationHandler: error decoding JWT token: %v", err)
		return nil, false
	}
	return token, true
}

func hasMissingScope(actual, expected []string) bool {
	if len(expected) == 0 {
		return false
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
	Logger   Logger
}

func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// We're ignoring the error resulted from decoding an
	// existing session: Get() always returns a session, even if empty.
	session, _ := h.Store.Get(req, sessionName)

	if errParam := req.FormValue("error"); errParam != "" {
		if h.Logger != nil {
			h.Logger.Errorf("CallbackHandler: OAuth provider error: %q\n", errParam)
		}
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

	clearSession := h.sessionCleaner(session, w, req)
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

	targetURL, ok := session.Values[targetURLField].(string)
	if !ok {
		clearSession("Missing redirect URL.", http.StatusBadRequest)
		return
	}
	delete(session.Values, targetURLField)

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
	if err := session.Save(req, w); err != nil {
		h.Logger.Errorf("CallbackHandler: error saving session: %v\n", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	http.Redirect(w, req, targetURL, http.StatusFound)
}

func (h *CallbackHandler) sessionCleaner(s *sessions.Session, w http.ResponseWriter, req *http.Request) func(string, int) {
	return func(error string, code int) {
		s.Values = nil
		if err := s.Save(req, w); err != nil {
			h.Logger.Errorf("CallbackHandler: error saving session: %v\n", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		http.Error(w, error, code)
	}
}
