package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	nameIndexKDFDomain = "secryn/name-index/v1"
	nameIndexDomain    = "secryn:name-index:v1"
)

// NormalizeName removes leading and trailing Unicode whitespace, then applies
// Unicode NFKC. Case is preserved, so "API_KEY" and "api_key" remain
// distinct names. Interior whitespace is not modified.
func NormalizeName(name string) (string, error) {
	if !utf8.ValidString(name) {
		return "", ErrInvalidName
	}
	normalized := norm.NFKC.String(strings.TrimSpace(name))
	if normalized == "" {
		return "", ErrInvalidName
	}
	return normalized, nil
}

// NameIndex calculates a deterministic, vault-scoped HMAC-SHA-256 index. The
// result is 32 opaque bytes suitable for a binary unique index.
func NameIndex(vek []byte, vaultID, name string) ([]byte, error) {
	if len(vek) != VEKSize {
		return nil, ErrInvalidKey
	}
	if vaultID == "" || !utf8.ValidString(vaultID) {
		return nil, ErrInvalidVaultID
	}
	normalized, err := NormalizeName(name)
	if err != nil {
		return nil, err
	}

	indexKey, err := DeriveKey(vek, []byte(vaultID), []byte(nameIndexKDFDomain), sha256.Size)
	if err != nil {
		return nil, err
	}
	defer wipe(indexKey)

	message, err := frame([]byte(nameIndexDomain), []byte(vaultID), []byte(normalized))
	if err != nil {
		return nil, err
	}
	digest := hmac.New(sha256.New, indexKey)
	_, _ = digest.Write(message)
	return digest.Sum(nil), nil
}

func NameIndexHex(vek []byte, vaultID, name string) (string, error) {
	index, err := NameIndex(vek, vaultID, name)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(index), nil
}
