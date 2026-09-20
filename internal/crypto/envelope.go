package crypto

import (
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	EnvelopeVersion = 1
	VEKSize         = chacha20poly1305.KeySize
	DEKSize         = chacha20poly1305.KeySize

	resourceAADDomain = "secryn:resource:v1"
	dekWrapAADDomain  = "secryn:resource-key:v1"
)

// ResourceContext is the authenticated identity of an encrypted resource.
type ResourceContext struct {
	VaultID      string `json:"vault_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	AADVersion   int    `json:"aad_version"`
	KeyVersion   int    `json:"key_version"`
}

// WrappedKeyEnvelope contains a DEK encrypted under its vault's VEK.
type WrappedKeyEnvelope struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// ResourceEnvelope is the portable v1 representation of an encrypted resource.
// All binary values use unpadded Base64URL encoding.
type ResourceEnvelope struct {
	Version    int                `json:"version"`
	AADVersion int                `json:"aad_version"`
	KeyVersion int                `json:"key_version"`
	Nonce      string             `json:"nonce"`
	Ciphertext string             `json:"ciphertext"`
	WrappedDEK WrappedKeyEnvelope `json:"wrapped_dek"`
}

// EncryptResource encrypts plaintext with a random DEK and wraps that DEK with
// the VEK. context canonically identifies the vault, resource type, resource
// ID, AAD version, and vault-key version.
func EncryptResource(plaintext, vek []byte, context ResourceContext) (*ResourceEnvelope, error) {
	return EncryptResourceWithRandom(plaintext, vek, context, cryptorand.Reader)
}

// EncryptResourceWithRandom is equivalent to EncryptResource but accepts an
// entropy source so protocol test vectors can be deterministic.
func EncryptResourceWithRandom(plaintext, vek []byte, context ResourceContext, random io.Reader) (*ResourceEnvelope, error) {
	if len(vek) != VEKSize {
		return nil, ErrInvalidKey
	}
	if random == nil {
		return nil, ErrInvalidKey
	}
	if err := validateResourceContext(context); err != nil {
		return nil, err
	}

	dek := make([]byte, DEKSize)
	if _, err := io.ReadFull(random, dek); err != nil {
		return nil, errors.Join(ErrInvalidKey, err)
	}
	defer wipe(dek)

	payloadAAD, err := resourcePayloadAAD(context)
	if err != nil {
		return nil, err
	}
	wrapAAD, err := resourceKeyAAD(context)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext, err := seal(dek, plaintext, payloadAAD, random)
	if err != nil {
		return nil, err
	}
	wrapNonce, wrappedDEK, err := seal(vek, dek, wrapAAD, random)
	if err != nil {
		return nil, err
	}

	return &ResourceEnvelope{
		Version:    EnvelopeVersion,
		AADVersion: context.AADVersion,
		KeyVersion: context.KeyVersion,
		Nonce:      encodeBytes(nonce),
		Ciphertext: encodeBytes(ciphertext),
		WrappedDEK: WrappedKeyEnvelope{
			Nonce:      encodeBytes(wrapNonce),
			Ciphertext: encodeBytes(wrappedDEK),
		},
	}, nil
}

// DecryptResource authenticates and decrypts a resource envelope. It returns a
// deliberately nonspecific error for all authentication failures.
func DecryptResource(envelope ResourceEnvelope, vek []byte, context ResourceContext) ([]byte, error) {
	if len(vek) != VEKSize {
		return nil, ErrInvalidKey
	}
	if err := validateResourceContext(context); err != nil {
		return nil, err
	}
	if envelope.Version != EnvelopeVersion {
		return nil, ErrUnsupportedVersion
	}
	if envelope.AADVersion != context.AADVersion || envelope.KeyVersion != context.KeyVersion {
		return nil, ErrInvalidEnvelope
	}
	payloadNonce, err := decodeNonce(envelope.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := decodeBytes(envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	wrapNonce, err := decodeNonce(envelope.WrappedDEK.Nonce)
	if err != nil {
		return nil, err
	}
	wrappedDEK, err := decodeBytes(envelope.WrappedDEK.Ciphertext)
	if err != nil {
		return nil, err
	}
	if len(wrappedDEK) != DEKSize+chacha20poly1305.Overhead {
		return nil, ErrInvalidEnvelope
	}

	wrapAAD, err := resourceKeyAAD(context)
	if err != nil {
		return nil, err
	}
	dek, err := open(vek, wrapNonce, wrappedDEK, wrapAAD)
	if err != nil {
		return nil, err
	}
	defer wipe(dek)
	if len(dek) != DEKSize {
		return nil, ErrInvalidEnvelope
	}

	payloadAAD, err := resourcePayloadAAD(context)
	if err != nil {
		return nil, err
	}
	return open(dek, payloadNonce, ciphertext, payloadAAD)
}

// RewrapResourceDEK moves an existing resource DEK from oldVEK to newVEK
// without changing or decrypting the resource payload ciphertext.
func RewrapResourceDEK(envelope ResourceEnvelope, oldVEK, newVEK []byte, context ResourceContext, targetKeyVersion int) (*WrappedKeyEnvelope, error) {
	return RewrapResourceDEKWithRandom(envelope, oldVEK, newVEK, context, targetKeyVersion, cryptorand.Reader)
}

func RewrapResourceDEKWithRandom(envelope ResourceEnvelope, oldVEK, newVEK []byte, context ResourceContext, targetKeyVersion int, random io.Reader) (*WrappedKeyEnvelope, error) {
	if len(oldVEK) != VEKSize || len(newVEK) != VEKSize || targetKeyVersion <= 0 || random == nil {
		return nil, ErrInvalidKey
	}
	if envelope.Version != EnvelopeVersion || envelope.KeyVersion != context.KeyVersion || envelope.AADVersion != context.AADVersion {
		return nil, ErrInvalidEnvelope
	}
	if err := validateResourceContext(context); err != nil {
		return nil, err
	}
	oldNonce, err := decodeNonce(envelope.WrappedDEK.Nonce)
	if err != nil {
		return nil, err
	}
	wrappedDEK, err := decodeBytes(envelope.WrappedDEK.Ciphertext)
	if err != nil || len(wrappedDEK) != DEKSize+chacha20poly1305.Overhead {
		return nil, ErrInvalidEnvelope
	}
	oldAAD, err := resourceKeyAAD(context)
	if err != nil {
		return nil, err
	}
	dek, err := open(oldVEK, oldNonce, wrappedDEK, oldAAD)
	if err != nil {
		return nil, err
	}
	defer wipe(dek)

	targetContext := context
	targetContext.KeyVersion = targetKeyVersion
	newAAD, err := resourceKeyAAD(targetContext)
	if err != nil {
		return nil, err
	}
	newNonce, newWrappedDEK, err := seal(newVEK, dek, newAAD, random)
	if err != nil {
		return nil, err
	}
	return &WrappedKeyEnvelope{Nonce: encodeBytes(newNonce), Ciphertext: encodeBytes(newWrappedDEK)}, nil
}

func seal(key, plaintext, aad []byte, random io.Reader) ([]byte, []byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, ErrInvalidKey
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, nil, errors.Join(ErrInvalidKey, err)
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

func open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrInvalidKey
	}
	if len(nonce) != aead.NonceSize() || len(ciphertext) < aead.Overhead() {
		return nil, ErrInvalidEnvelope
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

func decodeNonce(encoded string) ([]byte, error) {
	nonce, err := decodeBytes(encoded)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, ErrInvalidEnvelope
	}
	return nonce, nil
}

func resourcePayloadAAD(context ResourceContext) ([]byte, error) {
	value, err := frame(
		[]byte(resourceAADDomain),
		[]byte(context.VaultID),
		[]byte(context.ResourceType),
		[]byte(context.ResourceID),
		[]byte("payload"),
		[]byte(strconv.Itoa(context.AADVersion)),
	)
	if err != nil {
		return nil, fmt.Errorf("build authenticated data: %w", err)
	}
	return value, nil
}

func resourceKeyAAD(context ResourceContext) ([]byte, error) {
	value, err := frame(
		[]byte(dekWrapAADDomain),
		[]byte(context.VaultID),
		[]byte(context.ResourceType),
		[]byte(context.ResourceID),
		[]byte(strconv.Itoa(context.KeyVersion)),
	)
	if err != nil {
		return nil, fmt.Errorf("build authenticated data: %w", err)
	}
	return value, nil
}

func validateResourceContext(context ResourceContext) error {
	if context.VaultID == "" || context.ResourceType == "" || context.ResourceID == "" ||
		context.AADVersion <= 0 || context.KeyVersion <= 0 ||
		!utf8.ValidString(context.VaultID) || !utf8.ValidString(context.ResourceType) ||
		!utf8.ValidString(context.ResourceID) {
		return ErrInvalidEnvelope
	}
	return nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}
