package token_test

import (
	. "github.infra.hana.ondemand.com/cloudfoundry/goauth_handlers/token"
	"golang.org/x/oauth2"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Decoder", func() {
	var decoder Decoder

	BeforeEach(func() {
		decoder = Decoder{}
		Ω(decoder).ShouldNot(BeNil())
	})

	Describe("Decode", func() {
		var info Info
		var decodeErr error
		var token *oauth2.Token

		JustBeforeEach(func() {
			info, decodeErr = decoder.Decode(token)
		})

		Context("when the token is an invalid string", func() {
			BeforeEach(func() {
				token = &oauth2.Token{
					AccessToken: "I AM NOT.A VALID.TOKEN",
				}
			})

			It("should fail to decode the token", func() {
				Ω(decodeErr).Should(HaveOccurred())
			})
		})

		Context("when the token does not have three segments", func() {
			BeforeEach(func() {
				token = &oauth2.Token{
					AccessToken: "eyJhbGciOiJSUzI1NiJ9eyJqdGkiOiIwYjlkYWQwYS05NmYyLTQyNWMtYmI2Yi00YTI3YWI0ZTI1ZTIiLCJzdWIiOiI2Yjc5ODFjYy1jN2UzLTQxYjAtOTJjYS02YTI5MTg2ZGQxNWYiLCJzY29wZSI6WyJzY2ltLnJlYWQiLCJjbG91ZF9jb250cm9sbGVyLmFkbWluIiwicGFzc3dvcmQud3JpdGUiLCJzY2ltLndyaXRlIiwib3BlbmlkIiwiY2xvdWRfY29udHJvbGxlci53cml0ZSIsImNsb3VkX2NvbnRyb2xsZXIucmVhZCIsImRvcHBsZXIuZmlyZWhvc2UiXSwiY2xpZW50X2lkIjoiY2YiLCJjaWQiOiJjZiIsImF6cCI6ImNmIiwiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIiwidXNlcl9pZCI6IjZiNzk4MWNjLWM3ZTMtNDFiMC05MmNhLTZhMjkxODZkZDE1ZiIsInVzZXJfbmFtZSI6ImFkbWluIiwiZW1haWwiOiJhZG1pbiIsImlhdCI6MTQ0NTUxMTI3NCwiZXhwIjoxNDQ1NTExODc0LCJpc3MiOiJodHRwczovL3VhYS4xMC4yNDQuMC4zNC54aXAuaW8vb2F1dGgvdG9rZW4iLCJ6aWQiOiJ1YWEiLCJhdWQiOlsiZG9wcGxlciIsInNjaW0iLCJvcGVuaWQiLCJjbG91ZF9jb250cm9sbGVyIiwicGFzc3dvcmQiLCJjZiJdfQKSqonwr0JVXbxttsoFOSSqCscW3h_y4uKGXi0DLTBihQKKZNkvBIF2A8BKzi175SutWcYQVFYPiK_PoSGkJh2Tj4qRspy9asm-tvOnAGPFJevdqOznQj3EqIcB4uDUsGR5PJmeXg4FGUCv6ZYFaV_3EhO8zRdDbUz4B2oLqisvE",
				}
			})

			It("should fail to decode the token", func() {
				Ω(decodeErr).Should(HaveOccurred())
			})
		})

		Context("when the payload segment has invalid JSON", func() {
			BeforeEach(func() {
				token = &oauth2.Token{
					AccessToken: "eyJhbGciOiJSUzI1NiJ9.KSqonwr0JVXbxttsoFOSSqCscW3h_y4uKGXi0DLTBihQKKZNkvBIF2A8BKzi175SutWcYQVFYPiK_PoSGkJh2Tj4qRspy9asm-tvOnAGPFJevdqOznQj3EqIcB4uDUsGR5PJmeXg4FGUCv6ZYFaV_3EhO8zRdDbUz4B2oLqisvE.KSqonwr0JVXbxttsoFOSSqCscW3h_y4uKGXi0DLTBihQKKZNkvBIF2A8BKzi175SutWcYQVFYPiK_PoSGkJh2Tj4qRspy9asm-tvOnAGPFJevdqOznQj3EqIcB4uDUsGR5PJmeXg4FGUCv6ZYFaV_3EhO8zRdDbUz4B2oLqisvE",
				}
			})

			It("should fail to decode the token", func() {
				Ω(decodeErr).Should(HaveOccurred())
			})
		})

		Context("when the token is valid", func() {
			BeforeEach(func() {
				token = &oauth2.Token{
					AccessToken: "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiIwYjlkYWQwYS05NmYyLTQyNWMtYmI2Yi00YTI3YWI0ZTI1ZTIiLCJzdWIiOiI2Yjc5ODFjYy1jN2UzLTQxYjAtOTJjYS02YTI5MTg2ZGQxNWYiLCJzY29wZSI6WyJzY2ltLnJlYWQiLCJjbG91ZF9jb250cm9sbGVyLmFkbWluIiwicGFzc3dvcmQud3JpdGUiLCJzY2ltLndyaXRlIiwib3BlbmlkIiwiY2xvdWRfY29udHJvbGxlci53cml0ZSIsImNsb3VkX2NvbnRyb2xsZXIucmVhZCIsImRvcHBsZXIuZmlyZWhvc2UiXSwiY2xpZW50X2lkIjoiY2YiLCJjaWQiOiJjZiIsImF6cCI6ImNmIiwiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIiwidXNlcl9pZCI6IjZiNzk4MWNjLWM3ZTMtNDFiMC05MmNhLTZhMjkxODZkZDE1ZiIsInVzZXJfbmFtZSI6ImFkbWluIiwiZW1haWwiOiJhZG1pbiIsImlhdCI6MTQ0NTUxMTI3NCwiZXhwIjoxNDQ1NTExODc0LCJpc3MiOiJodHRwczovL3VhYS4xMC4yNDQuMC4zNC54aXAuaW8vb2F1dGgvdG9rZW4iLCJ6aWQiOiJ1YWEiLCJhdWQiOlsiZG9wcGxlciIsInNjaW0iLCJvcGVuaWQiLCJjbG91ZF9jb250cm9sbGVyIiwicGFzc3dvcmQiLCJjZiJdfQ.KSqonwr0JVXbxttsoFOSSqCscW3h_y4uKGXi0DLTBihQKKZNkvBIF2A8BKzi175SutWcYQVFYPiK_PoSGkJh2Tj4qRspy9asm-tvOnAGPFJevdqOznQj3EqIcB4uDUsGR5PJmeXg4FGUCv6ZYFaV_3EhO8zRdDbUz4B2oLqisvE",
				}
			})

			It("should have successfully decoded the token", func() {
				Ω(decodeErr).ShouldNot(HaveOccurred())
				Ω(info).Should(Equal(Info{
					UserID:   "6b7981cc-c7e3-41b0-92ca-6a29186dd15f",
					UserName: "admin",
					Scopes: []string{
						"scim.read",
						"cloud_controller.admin",
						"password.write",
						"scim.write",
						"openid",
						"cloud_controller.write",
						"cloud_controller.read",
						"doppler.firehose",
					},
				}))
			})
		})
	})
})
