package crypto

import "encoding/base64"

var base64URL = base64.RawURLEncoding.Strict()

func encodeBytes(value []byte) string {
	return base64URL.EncodeToString(value)
}

func decodeBytes(value string) ([]byte, error) {
	decoded, err := base64URL.DecodeString(value)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	return decoded, nil
}
