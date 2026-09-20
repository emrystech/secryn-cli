package crypto

import (
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	RecipientWrapAlgorithm = "X25519-HKDF-SHA256-XCHACHA20-POLY1305"
	recipientKDFDomain     = "secryn/recipient-wrap/v1"
	recipientAADDomain     = "secryn:vault-key:v1"
)

type RecipientContext struct {
	VaultID     string `json:"vault_id"`
	RecipientID string `json:"recipient_id"`
	KeyVersion  int    `json:"key_version"`
}

// RecipientKeyPair contains raw X25519 key material. The private key must only
// be persisted by an approved identity store and must never be logged.
type RecipientKeyPair struct {
	PrivateKey []byte `json:"-"`
	PublicKey  []byte `json:"public_key"`
}

// RecipientEnvelope contains a VEK encrypted for one X25519 recipient.
type RecipientEnvelope struct {
	Version            int    `json:"version"`
	KeyVersion         int    `json:"key_version"`
	Algorithm          string `json:"algorithm"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Nonce              string `json:"nonce"`
	Ciphertext         string `json:"ciphertext"`
}

func GenerateRecipientKeyPair() (*RecipientKeyPair, error) {
	return GenerateRecipientKeyPairWithRandom(cryptorand.Reader)
}

func GenerateRecipientKeyPairWithRandom(random io.Reader) (*RecipientKeyPair, error) {
	privateKey, err := readX25519PrivateKey(random)
	if err != nil {
		return nil, errors.Join(ErrInvalidKey, err)
	}
	return &RecipientKeyPair{
		PrivateKey: privateKey.Bytes(),
		PublicKey:  privateKey.PublicKey().Bytes(),
	}, nil
}

// RecipientPublicKey derives the raw X25519 public key for a persisted private
// identity without exposing or retaining another private-key copy.
func RecipientPublicKey(privateKey []byte) ([]byte, error) {
	key, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, ErrInvalidKey
	}
	return key.PublicKey().Bytes(), nil
}

func WrapVEKForRecipient(vek, recipientPublicKey []byte, context RecipientContext) (*RecipientEnvelope, error) {
	return WrapVEKForRecipientWithRandom(vek, recipientPublicKey, context, cryptorand.Reader)
}

func WrapVEKForRecipientWithRandom(vek, recipientPublicKey []byte, context RecipientContext, random io.Reader) (*RecipientEnvelope, error) {
	if len(vek) != VEKSize || random == nil {
		return nil, ErrInvalidKey
	}
	if err := validateRecipientContext(context); err != nil {
		return nil, err
	}
	curve := ecdh.X25519()
	recipient, err := curve.NewPublicKey(recipientPublicKey)
	if err != nil {
		return nil, ErrInvalidKey
	}
	ephemeralPrivate, err := readX25519PrivateKey(random)
	if err != nil {
		return nil, errors.Join(ErrInvalidKey, err)
	}
	ephemeralPrivateBytes := ephemeralPrivate.Bytes()
	defer wipe(ephemeralPrivateBytes)
	ephemeralPublic := ephemeralPrivate.PublicKey().Bytes()

	sharedSecret, err := ephemeralPrivate.ECDH(recipient)
	if err != nil {
		return nil, ErrInvalidKey
	}
	defer wipe(sharedSecret)

	kek, err := recipientKEK(sharedSecret, context.VaultID)
	if err != nil {
		return nil, err
	}
	defer wipe(kek)
	aad, err := recipientAAD(context, ephemeralPublic)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext, err := seal(kek, vek, aad, random)
	if err != nil {
		return nil, err
	}

	return &RecipientEnvelope{
		Version:            EnvelopeVersion,
		KeyVersion:         context.KeyVersion,
		Algorithm:          RecipientWrapAlgorithm,
		EphemeralPublicKey: encodeBytes(ephemeralPublic),
		Nonce:              encodeBytes(nonce),
		Ciphertext:         encodeBytes(ciphertext),
	}, nil
}

func UnwrapVEKForRecipient(envelope RecipientEnvelope, recipientPrivateKey []byte, context RecipientContext) ([]byte, error) {
	if err := validateRecipientContext(context); err != nil {
		return nil, err
	}
	if envelope.Version != EnvelopeVersion {
		return nil, ErrUnsupportedVersion
	}
	if envelope.KeyVersion != context.KeyVersion {
		return nil, ErrInvalidEnvelope
	}
	if subtle.ConstantTimeCompare([]byte(envelope.Algorithm), []byte(RecipientWrapAlgorithm)) != 1 {
		return nil, ErrInvalidEnvelope
	}
	curve := ecdh.X25519()
	privateKey, err := curve.NewPrivateKey(recipientPrivateKey)
	if err != nil {
		return nil, ErrInvalidKey
	}
	ephemeralPublicBytes, err := decodeBytes(envelope.EphemeralPublicKey)
	if err != nil {
		return nil, err
	}
	ephemeralPublic, err := curve.NewPublicKey(ephemeralPublicBytes)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	nonce, err := decodeNonce(envelope.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := decodeBytes(envelope.Ciphertext)
	if err != nil || len(ciphertext) != VEKSize+chacha20poly1305.Overhead {
		return nil, ErrInvalidEnvelope
	}

	sharedSecret, err := privateKey.ECDH(ephemeralPublic)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	defer wipe(sharedSecret)
	kek, err := recipientKEK(sharedSecret, context.VaultID)
	if err != nil {
		return nil, err
	}
	defer wipe(kek)
	aad, err := recipientAAD(context, ephemeralPublicBytes)
	if err != nil {
		return nil, err
	}
	vek, err := open(kek, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}
	if len(vek) != VEKSize {
		wipe(vek)
		return nil, ErrInvalidEnvelope
	}
	return vek, nil
}

func recipientKEK(sharedSecret []byte, vaultID string) ([]byte, error) {
	return DeriveKey(sharedSecret, []byte(vaultID), []byte(recipientKDFDomain), chacha20poly1305.KeySize)
}

func recipientAAD(context RecipientContext, ephemeralPublic []byte) ([]byte, error) {
	return frame(
		[]byte(recipientAADDomain),
		[]byte(context.VaultID),
		[]byte(context.RecipientID),
		[]byte(strconv.Itoa(context.KeyVersion)),
		ephemeralPublic,
	)
}

func validateRecipientContext(context RecipientContext) error {
	if context.VaultID == "" || context.RecipientID == "" || context.KeyVersion <= 0 ||
		!utf8.ValidString(context.VaultID) || !utf8.ValidString(context.RecipientID) {
		return ErrInvalidEnvelope
	}
	return nil
}

func readX25519PrivateKey(random io.Reader) (*ecdh.PrivateKey, error) {
	if random == nil {
		return nil, ErrInvalidKey
	}
	keyBytes := make([]byte, 32)
	if _, err := io.ReadFull(random, keyBytes); err != nil {
		return nil, errors.Join(ErrInvalidKey, err)
	}
	defer wipe(keyBytes)
	privateKey, err := ecdh.X25519().NewPrivateKey(keyBytes)
	if err != nil {
		return nil, ErrInvalidKey
	}
	return privateKey, nil
}
