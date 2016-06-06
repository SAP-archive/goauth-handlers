package goauth_handlers

import (
	"encoding/json"
	"net/http"

	"github.com/satori/go.uuid"

	"github.infra.hana.ondemand.com/cloudfoundry/goauth_handlers/logging"
	"github.infra.hana.ondemand.com/cloudfoundry/goauth_handlers/session"
	"github.infra.hana.ondemand.com/cloudfoundry/goauth_handlers/token"

	"golang.org/x/oauth2"
)

//go:generate counterfeiter . DelegateHandler
//go:generate counterfeiter . TokenProvider
//go:generate counterfeiter . TokenDecoder

type DelegateHandler interface {
	http.Handler
}

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

const SessionName = "goauth"
const SessionTokenKey = "token"
const SessionStateKey = "state"
const SessionURLKey = "url"
const DataUserInfoKey = "oauth.userinfo"
const DataTokenKey = "oauth.token"

type AuthorizationHandler struct {
	Handler        DelegateHandler
	Provider       TokenProvider
	Decoder        TokenDecoder
	Store          session.Store
	RequiredScopes []string
	Logger         logging.Logger
}

func (h *AuthorizationHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	session, err := h.Store.Get(req, SessionName)
	if err != nil {
		h.Logger.Warnf("Could not restore session due to '%s'.", err)
	}

	token, ok := h.getToken(session)
	if !ok || !token.Valid() {
		delete(session.Values(), SessionTokenKey)
		session.Values()[SessionURLKey] = req.URL.String()

		state := uuid.NewV4().String()
		session.Values()[SessionStateKey] = state

		if err := h.Store.Save(w, session); err != nil {
			h.Logger.Errorf("Could not save session due to '%s'.", err)
			http.Error(w, "Could not finalize request.", http.StatusInternalServerError)
		}

		http.Redirect(w, req, h.Provider.LoginURL(state), http.StatusFound)
		return
	}

	info, err := h.Decoder.Decode(token)
	if err != nil {
		h.Logger.Warnf("Could not decode token information due to '%s'.", err)
		http.Error(w, "Could not process token.", http.StatusInternalServerError)
		return
	}
	if hasMissingScope(info.Scopes, h.RequiredScopes) {
		h.Logger.Printf("Denying access because of missing scope.\n")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	h.Handler.ServeHTTP(w, req)
}

func (h *AuthorizationHandler) getToken(session session.Session) (*oauth2.Token, bool) {
	tokenStr, ok := session.Values()[SessionTokenKey]
	if !ok {
		return nil, false
	}

	token := &oauth2.Token{}
	if err := json.Unmarshal([]byte(tokenStr), token); err != nil {
		h.Logger.Errorf("Error decoding JWT token: %v", err)
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
	Store    session.Store
	Logger   logging.Logger
}

func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	session, err := h.Store.Get(req, SessionName)
	if err != nil {
		h.Logger.Warnf("Could not restore session due to '%s'.", err)
	}

	clearSession := h.sessionCleaner(session, w, req)

	if errParam := req.FormValue("error"); errParam != "" {
		switch errParam {
		case "invalid_scope":
			clearSession("You do not have the required authorization.", http.StatusForbidden)
		default:
			h.Logger.Errorf("UAA returned an error authorization grant response '%s'.", errParam)
			clearSession(http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return
	}

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

	targetURL, ok := session.Values()[SessionURLKey]
	if !ok {
		h.Logger.Warnf("User does not have an original request URL in their session.")
		clearSession("Missing redirect URL.", http.StatusBadRequest)
		return
	}
	delete(session.Values(), SessionURLKey)

	expectedState, ok := session.Values()["state"]
	if !ok {
		h.Logger.Warnf("User does not have a state value in their session.")
		clearSession("Missing state.", http.StatusBadRequest)
		return
	}
	delete(session.Values(), SessionStateKey)

	if state != expectedState {
		h.Logger.Warnf("State from UAA and state in user session do not match (Source IP: %s)!", req.RemoteAddr)
		clearSession("Invalid state parameter.", http.StatusBadRequest)
		return
	}

	token, err := h.Provider.RequestToken(code)
	if err != nil {
		h.Logger.Errorf("Could not retrieve token from UAA due to '%s'.", err)
		clearSession("Could not retrieve token from provider.", http.StatusInternalServerError)
		return
	}

	tokenBytes, err := json.Marshal(token)
	if err != nil {
		// should not happen
		clearSession(http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		panic(err)
	}

	session.Values()[SessionTokenKey] = string(tokenBytes)
	if err := h.Store.Save(w, session); err != nil {
		h.Logger.Errorf("Error saving session: %v\n", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	http.Redirect(w, req, targetURL, http.StatusFound)
}

func (h *CallbackHandler) sessionCleaner(s session.Session, w http.ResponseWriter, req *http.Request) func(string, int) {
	return func(error string, code int) {
		s.Clear()
		if err := h.Store.Save(w, s); err != nil {
			h.Logger.Errorf("Error saving session: %v\n", err)
		}
		http.Error(w, error, code)
	}
}
