package goauth_handlers_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"time"

	"golang.org/x/oauth2"

	. "github.infra.hana.ondemand.com/cloudfoundry/goauth_handlers"
	fakes "github.infra.hana.ondemand.com/cloudfoundry/goauth_handlers/goauth_handlersfakes"
	"github.infra.hana.ondemand.com/cloudfoundry/goauth_handlers/session/sessionfakes"
	"github.infra.hana.ondemand.com/cloudfoundry/goauth_handlers/token"
	"github.infra.hana.ondemand.com/cloudfoundry/gologger/gologgerfakes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Handler", func() {
	const unsetResponseCode = -1

	var logger *gologgerfakes.FakeLogger

	var sessionStore *sessionfakes.FakeStore
	var session *sessionfakes.FakeSession

	var tokenProvider *fakes.FakeTokenProvider

	var oauthToken *oauth2.Token

	var request *http.Request
	var response *httptest.ResponseRecorder

	var handler http.Handler

	BeforeEach(func() {
		logger = new(gologgerfakes.FakeLogger)

		session = new(sessionfakes.FakeSession)
		session.NameReturns(SessionName)
		session.ValuesReturns(map[string]string{})

		sessionStore = new(sessionfakes.FakeStore)
		sessionStore.GetReturns(session, nil)

		tokenProvider = new(fakes.FakeTokenProvider)

		oauthToken = &oauth2.Token{
			AccessToken:  "SomeAccessToken",
			RefreshToken: "SomeRefreshToken",
			TokenType:    "bearer",
			Expiry:       time.Now().Add(time.Hour),
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

	itShouldReturnInternalServerError := func() {
		It("should return internal server error", func() {
			Ω(response.Code).Should(Equal(http.StatusInternalServerError))
		})
	}

	itShouldReturnForbidden := func() {
		It("should return forbidden", func() {
			Ω(response.Code).Should(Equal(http.StatusForbidden))
		})
	}

	itShouldSaveSession := func() {
		It("should save the session", func() {
			Ω(sessionStore.SaveCallCount()).Should(Equal(1))
			argResponse, argSession := sessionStore.SaveArgsForCall(0)
			Ω(argResponse).Should(Equal(response))
			Ω(argSession).Should(Equal(session))
		})
	}

	Describe("AuthorizationHandler", func() {
		const loginURL = "http://login.here"

		var oauthTokenInfo token.Info

		var tokenDecoder *fakes.FakeTokenDecoder

		var wrappedHandler *fakes.FakeDelegateHandler

		tokenToString := func(token *oauth2.Token) string {
			bytes, err := json.Marshal(token)
			Ω(err).ShouldNot(HaveOccurred())
			return string(bytes)
		}

		BeforeEach(func() {
			session.Values()[SessionTokenKey] = tokenToString(oauthToken)

			tokenProvider.LoginURLReturns(loginURL)

			oauthTokenInfo = token.Info{
				UserID:   "012345",
				UserName: "Patrick",
				Scopes:   []string{"logs", "messages"},
			}
			tokenDecoder = new(fakes.FakeTokenDecoder)
			tokenDecoder.DecodeReturns(oauthTokenInfo, nil)

			wrappedHandler = new(fakes.FakeDelegateHandler)
			handler = &AuthorizationHandler{
				Provider:               tokenProvider,
				Decoder:                tokenDecoder,
				Store:                  sessionStore,
				RequiredScopes:         []string{"logs", "messages"},
				Handler:                wrappedHandler,
				Logger:                 logger,
				StoreTokenInHeaders:    false,
				StoreUserInfoInHeaders: false,
			}
		})

		itShouldPerformAnAuthorizationFlow := func() {
			It("should get a session", func() {
				Ω(sessionStore.GetCallCount()).Should(Equal(1))
				argRequest, argName := sessionStore.GetArgsForCall(0)
				Ω(argRequest).Should(Equal(request))
				Ω(argName).Should(Equal(SessionName))
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
				Ω(wrappedHandler.ServeHTTPCallCount()).Should(Equal(1))
				argResp, argReq := wrappedHandler.ServeHTTPArgsForCall(0)
				Ω(argResp).Should(Equal(response))
				Ω(argReq).Should(Equal(request))
			})
		}

		Context("when everything goes as planned", func() {
			itShouldPerformAnAuthorizationFlow()

			It("should not save the token inside the headers", func() {
				Ω(request.Header).ShouldNot(HaveKey(HeaderOAuthAccessToken))
				Ω(request.Header).ShouldNot(HaveKey(HeaderOAuthRefreshToken))
				Ω(request.Header).ShouldNot(HaveKey(HeaderOAuthTokenType))
				Ω(request.Header).ShouldNot(HaveKey(HeaderOAuthTokenExpiry))
			})

			It("should not save user info inside the headers", func() {
				Ω(request.Header).ShouldNot(HaveKey(HeaderOAuthInfoUserID))
				Ω(request.Header).ShouldNot(HaveKey(HeaderOAuthInfoUserName))
				Ω(request.Header).ShouldNot(HaveKey(HeaderOAuthInfoScopes))
			})

			Context("when token should be stored", func() {
				BeforeEach(func() {
					handler.(*AuthorizationHandler).StoreTokenInHeaders = true
				})

				itShouldPerformAnAuthorizationFlow()

				It("should save the token inside the headers", func() {
					Ω(request.Header.Get(HeaderOAuthAccessToken)).Should(Equal(oauthToken.AccessToken))
					Ω(request.Header.Get(HeaderOAuthRefreshToken)).Should(Equal(oauthToken.RefreshToken))
					Ω(request.Header.Get(HeaderOAuthTokenType)).Should(Equal(oauthToken.TokenType))
					Ω(request.Header.Get(HeaderOAuthTokenExpiry)).Should(Equal(strconv.FormatInt(oauthToken.Expiry.UnixNano(), 10)))
				})
			})

			Context("when user info should be stored", func() {
				BeforeEach(func() {
					handler.(*AuthorizationHandler).StoreUserInfoInHeaders = true
				})

				itShouldPerformAnAuthorizationFlow()

				It("should save user info inside the headers", func() {
					Ω(request.Header.Get(HeaderOAuthInfoUserID)).Should(Equal(oauthTokenInfo.UserID))
					Ω(request.Header.Get(HeaderOAuthInfoUserName)).Should(Equal(oauthTokenInfo.UserName))
					Ω(request.Header[HeaderOAuthInfoScopes]).Should(Equal(oauthTokenInfo.Scopes))
				})
			})
		})

		Context("when getting session fails", func() {
			BeforeEach(func() {
				sessionStore.GetReturns(session, errors.New("Could not get session!"))
			})

			itShouldPerformAnAuthorizationFlow()
		})

		itShouldRedirectToLogin := func() {
			It("should remove token from session", func() {
				Ω(session.Values()).ShouldNot(HaveKey(SessionTokenKey))
			})

			It("should store the request URL in the session", func() {
				Ω(session.Values()).Should(HaveKey(SessionURLKey))
				Ω(session.Values()[SessionURLKey]).Should(Equal(request.URL.String()))
			})

			It("should store some random state parameter in the session", func() {
				Ω(session.Values()).Should(HaveKey(SessionStateKey))
				state, exists := session.Values()[SessionStateKey]
				Ω(exists).Should(BeTrue())
				Ω(state).ShouldNot(BeEmpty())
			})

			itShouldSaveSession()

			It("should get login URL from provider", func() {
				Ω(tokenProvider.LoginURLCallCount()).Should(Equal(1))
				argState := tokenProvider.LoginURLArgsForCall(0)
				Ω(argState).Should(Equal(session.Values()[SessionStateKey]))
			})

			It("should redirect to login URL", func() {
				Ω(response.Code).Should(Equal(http.StatusFound))
				Ω(response.Header().Get("Location")).Should(Equal(loginURL))
			})

			Context("when saving session fails", func() {
				BeforeEach(func() {
					sessionStore.SaveReturns(errors.New("Could not store session!"))
				})

				itShouldReturnInternalServerError()
			})
		}

		Context("when session does not contain token", func() {
			BeforeEach(func() {
				delete(session.Values(), SessionTokenKey)
			})

			itShouldRedirectToLogin()
		})

		Context("when token in session is not a valid json", func() {
			BeforeEach(func() {
				session.Values()[SessionTokenKey] = "{"
			})

			itShouldRedirectToLogin()
		})

		Context("when token is expired", func() {
			BeforeEach(func() {
				oauthToken.Expiry = time.Now().Add(-time.Hour)
				session.Values()[SessionTokenKey] = tokenToString(oauthToken)
			})

			itShouldRedirectToLogin()
		})

		Context("when token info extracting fails", func() {
			BeforeEach(func() {
				tokenDecoder.DecodeReturns(token.Info{}, errors.New("Could not decode token!"))
			})

			itShouldReturnInternalServerError()
		})

		Context("when token does not contain all required scopes", func() {
			BeforeEach(func() {
				oauthTokenInfo.Scopes = []string{"messages"}
				tokenDecoder.DecodeReturns(oauthTokenInfo, nil)
			})

			itShouldReturnForbidden()
		})
	})

	Describe("CallbackHandler", func() {
		const originalURL = "http://some/resource/somewhere"
		const oauthState = "SOME_STATE_VALUE"
		const oauthCode = "SOME_OAUTH_CODE"

		BeforeEach(func() {
			session.Values()[SessionURLKey] = originalURL
			session.Values()[SessionStateKey] = oauthState

			tokenProvider.RequestTokenReturns(oauthToken, nil)

			handler = &CallbackHandler{
				Provider: tokenProvider,
				Store:    sessionStore,
				Logger:   logger,
			}

			request.Form = make(map[string][]string)
			request.Form.Add("state", oauthState)
			request.Form.Add("code", oauthCode)
		})

		itShouldPerformAGrantFlow := func() {
			It("should get a session", func() {
				Ω(sessionStore.GetCallCount()).Should(Equal(1))
				argRequest, argName := sessionStore.GetArgsForCall(0)
				Ω(argRequest).Should(Equal(request))
				Ω(argName).Should(Equal(SessionName))
			})

			It("should remove original url from session", func() {
				Ω(session.Values()).ShouldNot(HaveKey(SessionURLKey))
			})

			It("should remove state parameter from session", func() {
				Ω(session.Values()).ShouldNot(HaveKey(SessionStateKey))
			})

			It("should request a token", func() {
				Ω(tokenProvider.RequestTokenCallCount()).Should(Equal(1))
				argCode := tokenProvider.RequestTokenArgsForCall(0)
				Ω(argCode).Should(Equal(oauthCode))
			})

			It("should store token in session", func() {
				Ω(session.Values()).Should(HaveKey(SessionTokenKey))
				tokenString := session.Values()[SessionTokenKey]
				var token oauth2.Token
				err := json.Unmarshal([]byte(tokenString), &token)
				Ω(err).ShouldNot(HaveOccurred())
				Ω(token).Should(Equal(*oauthToken))
			})

			itShouldSaveSession()

			It("should redirect to original address", func() {
				Ω(response.Code).Should(Equal(http.StatusFound))
				Ω(response.Header().Get("Location")).Should(Equal(originalURL))
			})

			Context("when saving session fails", func() {
				BeforeEach(func() {
					sessionStore.SaveReturns(errors.New("Could not store session!"))
				})

				itShouldReturnInternalServerError()
			})
		}

		Context("when everything works as expected", func() {
			itShouldPerformAGrantFlow()
		})

		Context("when getting session fails", func() {
			BeforeEach(func() {
				sessionStore.GetReturns(session, errors.New("Could not get session!"))
			})

			itShouldPerformAGrantFlow()
		})

		itShouldDeleteSession := func() {
			It("should delete session", func() {
				Ω(session.ClearCallCount()).Should(Equal(1))
				Ω(sessionStore.SaveCallCount()).Should(Equal(1))
				argResponse, argSession := sessionStore.SaveArgsForCall(0)
				Ω(argResponse).Should(Equal(response))
				Ω(argSession).Should(Equal(session))
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

			itShouldDeleteSession()

			itShouldReturnInternalServerError()
		})

		itShouldReturnBadRequest := func() {
			It("should return bad request", func() {
				Ω(response.Code).Should(Equal(http.StatusBadRequest))
			})
		}

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
				delete(session.Values(), SessionURLKey)
			})

			itShouldDeleteSession()

			itShouldReturnBadRequest()
		})

		Context("when state parameter is missing from session", func() {
			BeforeEach(func() {
				delete(session.Values(), SessionStateKey)
			})

			itShouldDeleteSession()

			itShouldReturnBadRequest()
		})

		Context("when state parameter in request does not equal the session one", func() {
			BeforeEach(func() {
				session.Values()[SessionStateKey] = "some_other_value"
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
})
