package state_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/SAP/goauth-handlers/state"
)

var _ = Describe("Generator", func() {
	var generator Generator

	It("should generate random value", func() {
		value, _ := generator.GenerateState()
		Ω(value).ShouldNot(BeEmpty())
	})
})
