package goauth_handlers_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestGoauthHandlers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "GoauthHandlers Suite")
}
