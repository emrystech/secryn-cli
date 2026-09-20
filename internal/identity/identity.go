package identity

import (
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalidRecipientID = errors.New("invalid recipient ID")
	ErrInvalidPrivateKey  = errors.New("invalid recipient private key")
)

var base64URL = base64.RawURLEncoding.Strict()

// Identity is a local E2EE recipient. Its private key is deliberately not
// exportable through JSON or formatting interfaces.
type Identity struct {
	recipientID string
	privateKey  []byte
}

func Parse(recipientID, encodedPrivateKey string) (*Identity, error) {
	recipientID = strings.TrimSpace(recipientID)
	if !validRecipientID(recipientID) {
		return nil, ErrInvalidRecipientID
	}
	encodedPrivateKey = strings.TrimSpace(encodedPrivateKey)
	privateKey, err := base64URL.DecodeString(encodedPrivateKey)
	if err != nil || len(privateKey) != 32 {
		wipe(privateKey)
		return nil, ErrInvalidPrivateKey
	}
	return &Identity{recipientID: recipientID, privateKey: privateKey}, nil
}

func (i *Identity) RecipientID() string {
	if i == nil {
		return ""
	}
	return i.recipientID
}

// PrivateKey returns a copy owned by the caller. The caller must wipe it as
// soon as the operation completes.
func (i *Identity) PrivateKey() []byte {
	if i == nil {
		return nil
	}
	return append([]byte(nil), i.privateKey...)
}

func (i *Identity) Destroy() {
	if i == nil {
		return
	}
	wipe(i.privateKey)
	i.privateKey = nil
}

func (i *Identity) String() string {
	if i == nil {
		return "<nil>"
	}
	return fmt.Sprintf("recipient %s", i.recipientID)
}

// Format prevents diagnostic formatting verbs, including %#v, from exposing
// private key bytes.
func (i *Identity) Format(state fmt.State, _ rune) {
	_, _ = fmt.Fprintf(state, "recipient %s", i.RecipientID())
}

func validRecipientID(value string) bool {
	if len(value) != 36 || !utf8.ValidString(value) {
		return false
	}
	for index, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}
