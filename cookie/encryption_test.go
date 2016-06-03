package cookie_test

import (
	"net/http"

	. "github.infra.hana.ondemand.com/cloudfoundry/goauth_handlers/cookie"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Encyptor", func() {
	const authenticationPassword = "o9pTIkOmETOEfekikEs63X89YFfgXasd"
	const encryptionPassword = "cN2uK5Tl9amDjda2ccapYOJETL4/O1yD"
	const originalValue = "SomethingToBeEncrypted"

	var cookie *http.Cookie
	var encryptor Encryptor

	BeforeEach(func() {
		cookie = &http.Cookie{
			Name:  "example",
			Value: originalValue,
		}

		Ω([]byte(authenticationPassword)).Should(HaveLen(EncryptorPasswordLength))
		Ω([]byte(encryptionPassword)).Should(HaveLen(EncryptorPasswordLength))
		encryptor = NewEncryptor([]byte(authenticationPassword), []byte(encryptionPassword))
		Ω(encryptor).ShouldNot(BeNil())
	})

	Describe("Encrypt", func() {
		BeforeEach(func() {
			err := encryptor.Encrypt(cookie)
			Ω(err).ShouldNot(HaveOccurred())
		})

		It("encrypted string should not match original one", func() {
			Ω(cookie.Value).ShouldNot(Equal(originalValue))
		})

		Describe("Descrypt", func() {
			BeforeEach(func() {
				err := encryptor.Decrypt(cookie)
				Ω(err).ShouldNot(HaveOccurred())
			})

			It("should have decrypted the encrypted string back to the original", func() {
				Ω(cookie.Value).Should(Equal(originalValue))
			})
		})
	})
})
