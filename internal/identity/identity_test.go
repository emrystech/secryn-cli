package identity

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseIdentityAndDestroy(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	identity, err := Parse("11111111-1111-4111-8111-111111111111", encoded)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if identity.RecipientID() != "11111111-1111-4111-8111-111111111111" || len(identity.PrivateKey()) != 32 {
		t.Fatal("parsed identity metadata is invalid")
	}
	payload, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), encoded) {
		t.Fatal("serialized identity exposed private key")
	}
	if formatted := fmt.Sprintf("%#v", identity); strings.Contains(formatted, "privateKey") || strings.Contains(formatted, encoded) {
		t.Fatal("formatted identity exposed private key material")
	}
	identity.Destroy()
	if identity.PrivateKey() != nil {
		t.Fatal("destroyed identity retained private key")
	}
}

func TestParseIdentityRejectsMalformedInputs(t *testing.T) {
	tests := []struct {
		name        string
		recipientID string
		privateKey  string
		want        error
	}{
		{name: "empty recipient", privateKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), want: ErrInvalidRecipientID},
		{name: "header injection", recipientID: "11111111-1111-4111-8111-11111111\n111", privateKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), want: ErrInvalidRecipientID},
		{name: "padded base64", recipientID: "11111111-1111-4111-8111-111111111111", privateKey: base64.URLEncoding.EncodeToString(make([]byte, 32)), want: ErrInvalidPrivateKey},
		{name: "wrong key length", recipientID: "11111111-1111-4111-8111-111111111111", privateKey: base64.RawURLEncoding.EncodeToString(make([]byte, 31)), want: ErrInvalidPrivateKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(test.recipientID, test.privateKey)
			if !errors.Is(err, test.want) {
				t.Fatalf("Parse() error = %v, want %v", err, test.want)
			}
		})
	}
}
