package cookie_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestCookie(t *testing.T) {

	RegisterFailHandler(Fail)
	RunSpecs(t, "Cookie Suite")
}
