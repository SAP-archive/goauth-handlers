package goauth_handlers_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"time"

	"golang.org/x/oauth2"

	. "github.wdf.sap.corp/cloudfoundry/goauth_handlers"
	"github.wdf.sap.corp/cloudfoundry/goauth_handlers/fakes"
	"github.wdf.sap.corp/cloudfoundry/goauth_handlers/token"

	"github.com/gorilla/sessions"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const sessionName = "goauth"
const tokenField = "token"
const targetURLField = "targetUrl"

type callCountHandler int

func (h *callCountHandler) ServeHTTP(http.ResponseWriter, *http.Request) {
	*h++
}

func (h *callCountHandler) CallCount() int {
	return int(*h)
}

var _ = Describe("AuthorizationHandler", func() {
	const loginURL = "http://login.here"
	const unsetResponseCode = -1

	var oauthToken *oauth2.Token
	var oauthTokenInfo token.Info

	var tokenProvider *fakes.FakeTokenProvider

	var tokenDecoder *fakes.FakeTokenDecoder

	var sessionStore *fakes.FakeSessionStore
	var session *sessions.Session

	var logger *fakes.FakeLogger

	var wrappedHandler *callCountHandler
	var handler http.Handler

	var request *http.Request
	var response *httptest.ResponseRecorder

	tokenToString := func(token *oauth2.Token) string {
		bytes, err := json.Marshal(token)
		Ω(err).ShouldNot(HaveOccurred())
		return string(bytes)
	}

	BeforeEach(func() {
		oauthToken = &oauth2.Token{
			AccessToken:  "SomeAccessToken",
			RefreshToken: "SomeRefreshToken",
			TokenType:    "bearer",
			Expiry:       time.Now().Add(time.Hour),
		}

		sessionStore = new(fakes.FakeSessionStore)
		session = sessions.NewSession(sessionStore, sessionName)
		session.Values[tokenField] = tokenToString(oauthToken)
		sessionStore.GetReturns(session, nil)

		tokenProvider = new(fakes.FakeTokenProvider)
		tokenProvider.LoginURLReturns(loginURL)

		oauthTokenInfo = token.Info{
			UserID:   "012345",
			UserName: "Patrick",
			Scopes:   []string{"logs", "messages"},
		}
		tokenDecoder = new(fakes.FakeTokenDecoder)
		tokenDecoder.DecodeReturns(oauthTokenInfo, nil)
		logger = new(fakes.FakeLogger)

		wrappedHandler = new(callCountHandler)
		handler = &AuthorizationHandler{
			Provider:       tokenProvider,
			Decoder:        tokenDecoder,
			Store:          sessionStore,
			RequiredScopes: []string{"logs", "messages"},
			Handler:        wrappedHandler,
			Logger:         logger,
		}

		var err error
		request, err = http.NewRequest("GET", "http://some/resource", nil)
		Ω(err).ShouldNot(HaveOccurred())
		response = httptest.NewRecorder()
		response.Code = unsetResponseCode
	})

	JustBeforeEach(func() {
		handler.ServeHTTP(response, request)
	})

	Context("when everything goes as planned", func() {
		It("should get a session", func() {
			Ω(sessionStore.GetCallCount()).Should(Equal(1))
			argRequest, argName := sessionStore.GetArgsForCall(0)
			Ω(argRequest).Should(Equal(request))
			Ω(argName).Should(Equal(sessionName))
		})

		It("should decode the token", func() {
			Ω(tokenDecoder.DecodeCallCount()).Should(Equal(1))
			argToken := tokenDecoder.DecodeArgsForCall(0)
			Ω(argToken).Should(Equal(oauthToken))
		})

		It("should not have written output", func() {
			Ω(response.Code).Should(Equal(unsetResponseCode))
			Ω(response.Body.Len()).Should(Equal(0))
		})

		It("should have called the wrapped handler", func() {
			Ω(wrappedHandler.CallCount()).Should(Equal(1))
		})
	})

	itShouldRedirectToLogin := func() {
		It("should remove token from session", func() {
			Ω(session.Values).ShouldNot(HaveKey(tokenField))
		})

		It("should store the request URL in the session", func() {
			Ω(session.Values["targetUrl"]).Should(Equal(request.URL.String()))
		})

		It("should store some random state parameter in the session", func() {
			state, exists := session.Values["state"]
			Ω(exists).Should(BeTrue())
			_, isString := state.(string)
			Ω(isString).Should(BeTrue())
		})

		It("should save the session", func() {
			Ω(sessionStore.SaveCallCount()).Should(Equal(1))
			argRequest, argResponse, argSession := sessionStore.SaveArgsForCall(0)
			Ω(argRequest).Should(Equal(request))
			Ω(argResponse).Should(Equal(response))
			Ω(argSession).Should(Equal(session))
		})

		It("should get login URL from provider", func() {
			Ω(tokenProvider.LoginURLCallCount()).Should(Equal(1))
			argState := tokenProvider.LoginURLArgsForCall(0)
			Ω(argState).Should(Equal(session.Values["state"]))
		})

		It("should redirect to login URL", func() {
			Ω(response.Code).Should(Equal(http.StatusFound))
			Ω(response.Header().Get("Location")).Should(Equal(loginURL))
		})
	}

	Context("when session does not contain token", func() {
		BeforeEach(func() {
			delete(session.Values, tokenField)
		})

		itShouldRedirectToLogin()
	})

	Context("when token in session is not string", func() {
		BeforeEach(func() {
			session.Values[tokenField] = 1
		})

		itShouldRedirectToLogin()
	})

	Context("when token in session is not a valid json", func() {
		BeforeEach(func() {
			session.Values[tokenField] = "{"
		})

		It("should log error", func() {
			Ω(logger.ErrorfCallCount()).Should(Equal(1))
			format, _ := logger.ErrorfArgsForCall(0)
			Ω(format).Should(Equal("AuthorizationHandler: error decoding JWT token: %v"))
		})

		itShouldRedirectToLogin()
	})

	Context("when token is expired", func() {
		BeforeEach(func() {
			oauthToken.Expiry = time.Now().Add(-time.Hour)
			session.Values[tokenField] = tokenToString(oauthToken)
		})

		itShouldRedirectToLogin()
	})

	Context("when token info extracting fails", func() {
		BeforeEach(func() {
			tokenDecoder.DecodeReturns(token.Info{}, errors.New("Could not parse token!"))
		})

		It("should log error", func() {
			Ω(logger.ErrorfCallCount()).Should(Equal(1))
			format, _ := logger.ErrorfArgsForCall(0)
			Ω(format).Should(Equal("AuthorizationHandler: error extracting token info: %v\n"))
		})

		It("should return internal server error", func() {
			Ω(response.Code).Should(Equal(http.StatusInternalServerError))
		})
	})

	Context("when token does not contain all required scopes", func() {
		BeforeEach(func() {
			oauthTokenInfo.Scopes = []string{"messages"}
			tokenDecoder.DecodeReturns(oauthTokenInfo, nil)
		})

		It("should log info", func() {
			Ω(logger.PrintfCallCount()).Should(Equal(1))
			format, _ := logger.PrintfArgsForCall(0)
			Ω(format).Should(Equal("AuthorizationHandler: denying access because of missing scope.\n"))
		})

		It("should return forbidden", func() {
			Ω(response.Code).Should(Equal(http.StatusForbidden))
		})
	})
})

var _ = Describe("CallbackHandler", func() {
	const unsetResponseCode = -1
	const originalURL = "http://some/resource/somewhere"
	const oauthState = "SOME_STATE_VALUE"
	const oauthCode = "SOME_OAUTH_CODE"

	var oauthToken *oauth2.Token
	var tokenProvider *fakes.FakeTokenProvider

	var sessionStore *fakes.FakeSessionStore
	var session *sessions.Session

	var logger *fakes.FakeLogger

	var handler http.Handler

	var request *http.Request
	var response *httptest.ResponseRecorder

	BeforeEach(func() {
		sessionStore = new(fakes.FakeSessionStore)
		session = sessions.NewSession(sessionStore, sessionName)
		session.Values[targetURLField] = originalURL
		session.Values["state"] = oauthState
		sessionStore.GetReturns(session, nil)

		oauthToken = &oauth2.Token{
			AccessToken:  "SomeAccessToken",
			RefreshToken: "SomeRefreshToken",
			TokenType:    "bearer",
			Expiry:       time.Now().Add(time.Hour),
		}
		tokenProvider = new(fakes.FakeTokenProvider)
		tokenProvider.RequestTokenReturns(oauthToken, nil)

		logger = new(fakes.FakeLogger)

		handler = &CallbackHandler{
			Provider: tokenProvider,
			Store:    sessionStore,
			Logger:   logger,
		}

		var err error
		request, err = http.NewRequest("GET", "http://some/resource", nil)
		Ω(err).ShouldNot(HaveOccurred())
		request.Form = make(map[string][]string)
		request.Form.Add("state", oauthState)
		request.Form.Add("code", oauthCode)

		response = httptest.NewRecorder()
		response.Code = unsetResponseCode
	})

	JustBeforeEach(func() {
		handler.ServeHTTP(response, request)
	})

	Context("when everything works as expected", func() {
		It("should get a session", func() {
			Ω(sessionStore.GetCallCount()).Should(Equal(1))
			argRequest, argName := sessionStore.GetArgsForCall(0)
			Ω(argRequest).Should(Equal(request))
			Ω(argName).Should(Equal(sessionName))
		})

		It("should remove state parameter from session", func() {
			Ω(session.Values).ShouldNot(HaveKey("state"))
		})

		It("should remove original url from session", func() {
			Ω(session.Values).ShouldNot(HaveKey(targetURLField))
		})

		It("should request a token", func() {
			Ω(tokenProvider.RequestTokenCallCount()).Should(Equal(1))
			argCode := tokenProvider.RequestTokenArgsForCall(0)
			Ω(argCode).Should(Equal(oauthCode))
		})

		It("should store token in session", func() {
			tokenObj, exists := session.Values[tokenField]
			Ω(exists).Should(BeTrue())
			tokenString, isString := tokenObj.(string)
			Ω(isString).Should(BeTrue())
			var token oauth2.Token
			err := json.Unmarshal([]byte(tokenString), &token)
			Ω(err).ShouldNot(HaveOccurred())
			Ω(token).Should(Equal(*oauthToken))
		})

		It("should save the session", func() {
			Ω(sessionStore.SaveCallCount()).Should(Equal(1))
			argRequest, argResponse, argSession := sessionStore.SaveArgsForCall(0)
			Ω(argRequest).Should(Equal(request))
			Ω(argResponse).Should(Equal(response))
			Ω(argSession).Should(Equal(session))
		})

		It("should redirect to original address", func() {
			Ω(response.Code).Should(Equal(http.StatusFound))
			Ω(response.Header().Get("Location")).Should(Equal(originalURL))
		})
	})

	itShouldDeleteSession := func() {
		It("should delete session", func() {
			Ω(session.Values).Should(BeNil())
			Ω(sessionStore.SaveCallCount()).Should(Equal(1))
			argRequest, argResponse, argSession := sessionStore.SaveArgsForCall(0)
			Ω(argRequest).Should(Equal(request))
			Ω(argResponse).Should(Equal(response))
			Ω(argSession).Should(Equal(session))
		})
	}

	itShouldReturnBadRequest := func() {
		It("should return bad request", func() {
			Ω(response.Code).Should(Equal(http.StatusBadRequest))
		})
	}

	itShouldReturnInternalServerError := func() {
		It("should return bad request", func() {
			Ω(response.Code).Should(Equal(http.StatusInternalServerError))
		})
	}

	itShouldReturnForbidden := func() {
		It("should return forbidden", func() {
			Ω(response.Code).Should(Equal(http.StatusForbidden))
		})
	}

	Context("when UAA responds with invalid_scope error param", func() {
		BeforeEach(func() {
			request.Form.Add("error", "invalid_scope")
		})

		itShouldDeleteSession()

		itShouldReturnForbidden()
	})

	Context("when UAA responds with error param other than invalid_scope", func() {
		BeforeEach(func() {
			request.Form.Add("error", "unauthorized_client")
		})

		It("should log the returned error", func() {
			Ω(logger.ErrorfCallCount()).Should(Equal(1))
			format, args := logger.ErrorfArgsForCall(0)
			Ω(format).Should(Equal("CallbackHandler: OAuth provider error: %q\n"))
			Ω(len(args)).Should(Equal(1))
			Ω(args[0]).Should(Equal("unauthorized_client"))
		})

		itShouldDeleteSession()

		itShouldReturnInternalServerError()
	})

	Context("when state parameter in request is missing", func() {
		BeforeEach(func() {
			request.Form.Del("state")
		})

		itShouldDeleteSession()

		itShouldReturnBadRequest()
	})

	Context("when a oauth code is missing in the request", func() {
		BeforeEach(func() {
			request.Form.Del("code")
		})

		itShouldDeleteSession()

		itShouldReturnBadRequest()
	})

	Context("when original URL parameter is missing from session", func() {
		BeforeEach(func() {
			delete(session.Values, targetURLField)
		})

		itShouldDeleteSession()

		itShouldReturnBadRequest()
	})

	Context("when target URL parameter in session is not string", func() {
		BeforeEach(func() {
			session.Values[targetURLField] = 1
		})

		itShouldDeleteSession()

		itShouldReturnBadRequest()
	})

	Context("when state parameter is missing from session", func() {
		BeforeEach(func() {
			delete(session.Values, "state")
		})

		itShouldDeleteSession()

		itShouldReturnBadRequest()
	})

	Context("when state parameter in session is not string", func() {
		BeforeEach(func() {
			session.Values["state"] = 1
		})

		itShouldDeleteSession()

		itShouldReturnBadRequest()
	})

	Context("when state parameter in request does not equal the session one", func() {
		BeforeEach(func() {
			session.Values["state"] = "some_other_value"
		})

		itShouldDeleteSession()

		itShouldReturnBadRequest()
	})

	Context("when provider fails to retrieve token", func() {
		BeforeEach(func() {
			tokenProvider.RequestTokenReturns(nil, errors.New("Could not get token"))
		})

		itShouldDeleteSession()

		itShouldReturnInternalServerError()
	})

})
