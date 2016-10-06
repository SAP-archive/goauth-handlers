package token_test

import (
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"

	. "github.com/SAP/goauth_handlers/token"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("Provider", func() {
	const clientId string = "admin"
	const clientSecret string = "admin-secret"

	var server *ghttp.Server
	var provider Provider
	var providerErr error

	BeforeEach(func() {
		server = ghttp.NewServer()
		provider = Provider{
			Config: oauth2.Config{
				ClientID:     clientId,
				ClientSecret: clientSecret,
				Endpoint: oauth2.Endpoint{
					AuthURL:  "http://doesnotmatter",
					TokenURL: fmt.Sprintf("http://%s", server.Addr()),
				},
				RedirectURL: "http://doesnotmatter",
				Scopes:      []string{},
			},
		}
	})

	AfterEach(func() {
		server.Close()
	})

	Describe("RequestToken", func() {
		const tokenCode = "TOKEN_CODE_VALUE"
		const accessToken = "TOKEN_ACCESS_VALUE"

		var token *oauth2.Token

		JustBeforeEach(func() {
			token, providerErr = provider.RequestToken(tokenCode)
		})

		Context("when the server responds with non-OK status", func() {
			BeforeEach(func() {
				server.AppendHandlers(ghttp.CombineHandlers(
					ghttp.RespondWith(http.StatusInternalServerError, "{}"),
				))
			})

			It("should have errored", func() {
				Ω(providerErr).Should(HaveOccurred())
			})
		})

		Context("when the server responds as expected", func() {
			BeforeEach(func() {
				server.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("POST", "/"),
					ghttp.VerifyBasicAuth(clientId, clientSecret),
					ghttp.VerifyForm(url.Values{
						"code": []string{tokenCode},
					}),
					ghttp.RespondWithJSONEncoded(http.StatusOK, struct {
						AccessToken string `json:"access_token"`
						TokenType   string `json:"token_type"`
						ExpiresIn   int    `json:"expires_in"`
					}{
						AccessToken: accessToken,
						TokenType:   "bearer",
						ExpiresIn:   3600,
					}),
				))
			})

			It("should not have errored", func() {
				Ω(providerErr).ShouldNot(HaveOccurred())
			})

			It("should have returned the correct token", func() {
				Ω(token.AccessToken).Should(Equal(accessToken))
				Ω(token.Valid()).Should(BeTrue())
			})
		})
	})

	Describe("LoginURL", func() {
		const state = "SOMESTATE"

		It("should return URL based on state parameter", func() {
			loginURL := provider.LoginURL(state)
			Ω(loginURL).Should(ContainSubstring(state))
		})
	})
})
