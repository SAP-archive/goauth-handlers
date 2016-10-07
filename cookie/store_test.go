package cookie_test

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	. "github.com/SAP/goauth-handlers/cookie"
	cookie_fakes "github.com/SAP/goauth-handlers/cookie/cookiefakes"
	"github.com/SAP/goauth-handlers/session"
	"github.com/SAP/gologger/gologgerfakes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Store", func() {
	var request *http.Request
	var response *httptest.ResponseRecorder
	var encryptor *cookie_fakes.FakeEncryptor
	var store session.Store
	var session session.Session
	var sessionGetErr error

	BeforeEach(func() {
		var err error
		request, err = http.NewRequest("GET", "http://example.org", nil)
		Ω(err).ShouldNot(HaveOccurred())
		response = httptest.NewRecorder()

		encryptor = new(cookie_fakes.FakeEncryptor)
		encryptor.EncryptStub = func(cookie *http.Cookie) error {
			cookie.Value = fmt.Sprintf("%s-encrypted", cookie.Value)
			cookie.Value = url.QueryEscape(cookie.Value)
			return nil
		}
		encryptor.DecryptStub = func(cookie *http.Cookie) error {
			var err error
			cookie.Value, err = url.QueryUnescape(cookie.Value)
			Ω(err).ShouldNot(HaveOccurred())
			cookie.Value = strings.TrimSuffix(cookie.Value, "-encrypted")
			return nil
		}

		logger := new(gologgerfakes.FakeLogger)

		store = NewStore(encryptor, logger)
	})

	itShouldNotError := func() {
		It("should not error", func() {
			Ω(sessionGetErr).ShouldNot(HaveOccurred())
		})
	}

	itSessionShouldBeEmpty := func() {
		It("session should be empty", func() {
			Ω(session.Values()).ShouldNot(BeNil())
			Ω(session.Values()).Should(BeEmpty())
		})
	}

	getResponseCookies := func(resp *httptest.ResponseRecorder) []*http.Cookie {
		header := http.Header{}
		for _, setCookieHeaderValue := range response.HeaderMap["Set-Cookie"] {
			header.Add("Set-Cookie", setCookieHeaderValue)
		}
		cookieResp := &http.Response{Header: header}
		return cookieResp.Cookies()
	}

	isValidHttpCookie := func(cookie *http.Cookie, name, value string) {
		Ω(cookie.Name).Should(Equal(name))
		Ω(cookie.Value).Should(Equal(value))
		Ω(cookie.Path).Should(Equal("/"))
		Ω(cookie.HttpOnly).Should(BeTrue())
	}

	isExpiresHttpCookie := func(cookie *http.Cookie, name string) {
		isValidHttpCookie(cookie, name, "")
		Ω(cookie.MaxAge).Should(Equal(-1))
		Ω(cookie.Expires).Should(BeTemporally("<", time.Now(), time.Second))
	}

	Context("given an empty session", func() {
		BeforeEach(func() {
			session, sessionGetErr = store.Get(request, "test-session")
			Ω(session).ShouldNot(BeNil())
		})

		itShouldNotError()

		It("session should have correct name", func() {
			Ω(session.Name()).Should(Equal("test-session"))
		})

		itSessionShouldBeEmpty()

		Context("when values are added", func() {
			BeforeEach(func() {
				session.Values()["hey"] = "now"
				session.Values()["duel"] = "of the fates"
			})

			It("they are preserved", func() {
				Ω(session.Values()).Should(HaveKey("hey"))
				Ω(session.Values()["hey"]).Should(Equal("now"))
				Ω(session.Values()).Should(HaveKey("duel"))
				Ω(session.Values()["duel"]).Should(Equal("of the fates"))
			})

			Context("when session is cleared", func() {
				BeforeEach(func() {
					session.Clear()
				})

				itSessionShouldBeEmpty()
			})
		})

		Context("when session is saved", func() {
			const expectedJsonStructure = "{\"key\":\"%s\"}"

			var jsonCharactersSize int
			var content string
			var saveErr error

			createRandomString := func(size int) string {
				const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
				result := make([]byte, size)
				for i := range result {
					result[i] = letters[rand.Intn(len(letters))]
				}
				return string(result)
			}

			JustBeforeEach(func() {
				session.Values()["key"] = content

				saveErr = store.Save(response, session)
			})

			BeforeEach(func() {
				jsonCharactersSize = len(fmt.Sprintf(expectedJsonStructure, ""))
				Ω(jsonCharactersSize).Should(Equal(10))
			})

			itSaveShouldNotError := func() {
				It("should not error", func() {
					Ω(saveErr).ShouldNot(HaveOccurred())
				})
			}

			Context("that has a content at the threshold size (MaxCookieValueSize)", func() {
				BeforeEach(func() {
					content = createRandomString(MaxCookieValueSize - jsonCharactersSize)
				})

				itSaveShouldNotError()

				It("should store the session as a single cookie", func() {
					expectedContent := fmt.Sprintf(expectedJsonStructure, content)
					Ω(expectedContent).Should(HaveLen(MaxCookieValueSize))

					cookies := getResponseCookies(response)
					Ω(cookies).Should(HaveLen(2))
					isValidHttpCookie(cookies[0], "goauth-test-session-1", fmt.Sprintf("%s-encrypted", url.QueryEscape(expectedContent)))
					isExpiresHttpCookie(cookies[1], "goauth-test-session-2")
				})
			})

			Context("that has a content above the threshold size (>MaxCookieValueSize)", func() {
				BeforeEach(func() {
					content = createRandomString(MaxCookieValueSize + 1 - jsonCharactersSize)
				})

				itSaveShouldNotError()

				It("should store the session as multuple cookies", func() {
					expectedContent := fmt.Sprintf(expectedJsonStructure, content)
					Ω(expectedContent).Should(HaveLen(MaxCookieValueSize + 1))

					cookies := getResponseCookies(response)
					Ω(cookies).Should(HaveLen(3))
					isValidHttpCookie(cookies[0], "goauth-test-session-1", fmt.Sprintf("%s-encrypted", url.QueryEscape(expectedContent[:MaxCookieValueSize])))
					isValidHttpCookie(cookies[1], "goauth-test-session-2", fmt.Sprintf("%s-encrypted", url.QueryEscape(expectedContent[MaxCookieValueSize:])))
					isExpiresHttpCookie(cookies[2], "goauth-test-session-3")
				})
			})

			Context("but encryption fails", func() {
				var fakeErr error

				BeforeEach(func() {
					content = "value"

					fakeErr = errors.New("Failed to encrypt cookie")
					encryptor.EncryptReturns(fakeErr)
				})

				It("should error", func() {
					Ω(saveErr).Should(Equal(fakeErr))
				})
			})
		})
	})

	Context("given an existing session", func() {
		JustBeforeEach(func() {
			session, sessionGetErr = store.Get(request, "test-session")
			Ω(session).ShouldNot(BeNil())
		})

		Context("when cookies contain valid session", func() {
			BeforeEach(func() {
				request.AddCookie(&http.Cookie{
					Name:  "goauth-test-session-1",
					Path:  "/",
					Value: url.QueryEscape("{\"hello\":\"world\",\"some-encrypted"),
				})
				request.AddCookie(&http.Cookie{
					Name:  "goauth-test-session-2",
					Path:  "/",
					Value: url.QueryEscape("thing\":\"spec-encrypted"),
				})
				request.AddCookie(&http.Cookie{
					Name:  "goauth-test-session-3",
					Path:  "/",
					Value: url.QueryEscape("ial\"}-encrypted"),
				})

				Ω(sessionGetErr).ShouldNot(HaveOccurred())
			})

			itShouldNotError()

			It("is possible to access existing", func() {
				Ω(session.Values()).Should(HaveKey("something"))
				Ω(session.Values()["something"]).Should(Equal("special"))
				Ω(session.Values()).Should(HaveKey("hello"))
				Ω(session.Values()["hello"]).Should(Equal("world"))
			})

			Context("when session is cleared", func() {
				JustBeforeEach(func() {
					session.Clear()
				})

				itSessionShouldBeEmpty()

				Context("when session is saved", func() {
					JustBeforeEach(func() {
						err := store.Save(response, session)
						Ω(err).ShouldNot(HaveOccurred())
					})

					It("should write an equal to the initial amount erasing cookies", func() {
						cookies := getResponseCookies(response)
						Ω(cookies).Should(HaveLen(3))
						isExpiresHttpCookie(cookies[0], "goauth-test-session-1")
						isExpiresHttpCookie(cookies[1], "goauth-test-session-2")
						isExpiresHttpCookie(cookies[2], "goauth-test-session-3")
					})
				})
			})
		})

		itShouldError := func() {
			It("should return error", func() {
				Ω(sessionGetErr).Should(HaveOccurred())
			})

			itSessionShouldBeEmpty()
		}

		Context("when cookies contain invalid content", func() {
			BeforeEach(func() {
				request.AddCookie(&http.Cookie{
					Name:  "goauth-test-session-1",
					Path:  "/",
					Value: url.QueryEscape("{\"he-encrypted"),
				})
				request.AddCookie(&http.Cookie{
					Name:  "goauth-test-session-2",
					Path:  "/",
					Value: url.QueryEscape("not_the_rest_of_the_json-encrypted"),
				})
			})

			itShouldError()
		})

		Context("when cookie decryption errors", func() {
			BeforeEach(func() {
				request.AddCookie(&http.Cookie{
					Name:  "goauth-test-session-1",
					Path:  "/",
					Value: url.QueryEscape("{\"hello\":\"world\"}-encrypted"),
				})

				encryptor.DecryptReturns(errors.New("Failed to decrypt cookie!"))
			})

			itShouldError()
		})
	})
})

type logger struct{}

func (l logger) Printf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (l logger) Warnf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (l logger) Errorf(format string, args ...interface{}) {
	log.Printf(format, args...)
}
