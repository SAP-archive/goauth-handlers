package state

import (
	"fmt"

	uuid "github.com/satori/go.uuid"
)

type Generator struct{}

func (g Generator) GenerateState() (string, error) {
	value, err := uuid.NewV4()
	if err != nil {
		return "", fmt.Errorf("failed to generate uuid due to '%s'", err)
	}
	return value.String(), nil
}
