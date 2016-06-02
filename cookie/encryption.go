package cookie

import (
	"net/http"

	"github.com/gorilla/securecookie"
)

// MaxCookieValueSize We need to make sure that the final encrypted string is smaller than 4096, as this is
// the maximum cookie size for some browsers.
// The encryption that is used via securecookie performs a base64 encoding, which increases
// the original message size by a factor of 4/3. Additionally, it adds a HMAC authentication
// key of roughly 20 characters. Finally, the encryption process is a stream cipher, which
// should guarantee an encrypted output of the same size as the input (unless a block padding is added).
// If we are to split the original text at 2048, we should have sufficient room for encryption
// and the final result should be below 4096.
const MaxCookieValueSize = 2048

const EncryptorPasswordLength = 32

//go:generate counterfeiter . Encryptor

type Encryptor interface {
	Encrypt(cookie *http.Cookie) error
	Decrypt(cookie *http.Cookie) error
}

type encryptor struct {
	codec securecookie.Codec
}

func NewEncryptor(authenticationPassword, encryptionPassword []byte) Encryptor {
	return &encryptor{
		codec: securecookie.New(authenticationPassword, encryptionPassword),
	}
}

func (e *encryptor) Encrypt(cookie *http.Cookie) error {
	sealedValue, err := e.codec.Encode(cookie.Name, cookie.Value)
	if err != nil {
		return err
	}
	cookie.Value = sealedValue
	return nil
}

func (e *encryptor) Decrypt(cookie *http.Cookie) error {
	var unsealedValue string
	if err := e.codec.Decode(cookie.Name, cookie.Value, &unsealedValue); err != nil {
		return err
	}
	cookie.Value = unsealedValue
	return nil
}
