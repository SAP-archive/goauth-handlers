package token

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
)

type Decoder struct{}

type InvalidFormatError string

func (e InvalidFormatError) Error() string {
	return fmt.Sprintf("invalid token format: %q", string(e))
}

func (d Decoder) Decode(token *oauth2.Token) (Info, error) {
	segments := strings.Split(token.AccessToken, ".")
	if len(segments) != 3 {
		return Info{}, InvalidFormatError("token.AccessToken")
	}

	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return Info{}, err
	}

	info := Info{}
	if err := json.Unmarshal([]byte(payload), &info); err != nil {
		return Info{}, err
	}
	return info, nil
}
