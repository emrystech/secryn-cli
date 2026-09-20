package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

type protocolVectors struct {
	Protocol string `json:"protocol"`
	Encoding string `json:"encoding"`
	VEKHex   string `json:"vek_hex"`
	Resource struct {
		Context    ResourceContext  `json:"context"`
		Plaintext  string           `json:"plaintext_utf8"`
		EntropyHex string           `json:"entropy_hex"`
		Envelope   ResourceEnvelope `json:"envelope"`
	} `json:"resource"`
	Recipient struct {
		Context           RecipientContext  `json:"context"`
		PrivateEntropyHex string            `json:"private_entropy_hex"`
		PublicKeyHex      string            `json:"public_key_hex"`
		WrapEntropyHex    string            `json:"wrap_entropy_hex"`
		Envelope          RecipientEnvelope `json:"envelope"`
	} `json:"recipient"`
	NameIndexes []struct {
		VaultID        string `json:"vault_id"`
		InputName      string `json:"input_name"`
		NormalizedName string `json:"normalized_name"`
		IndexHex       string `json:"index_hex"`
	} `json:"name_indexes"`
}

func TestProtocolVectors(t *testing.T) {
	vectors := loadProtocolVectors(t)
	if vectors.Protocol != "secryn-e2ee-v1" || vectors.Encoding != "base64url-no-padding" {
		t.Fatalf("unexpected protocol metadata: %q %q", vectors.Protocol, vectors.Encoding)
	}
	vek := decodeHex(t, vectors.VEKHex)

	resourceEnvelope, err := EncryptResourceWithRandom(
		[]byte(vectors.Resource.Plaintext),
		vek,
		vectors.Resource.Context,
		bytes.NewReader(decodeHex(t, vectors.Resource.EntropyHex)),
	)
	if err != nil {
		t.Fatalf("encrypt resource: %v", err)
	}
	if !reflect.DeepEqual(*resourceEnvelope, vectors.Resource.Envelope) {
		got, _ := json.MarshalIndent(resourceEnvelope, "", "  ")
		want, _ := json.MarshalIndent(vectors.Resource.Envelope, "", "  ")
		t.Fatalf("resource envelope mismatch\ngot:  %s\nwant: %s", got, want)
	}
	plaintext, err := DecryptResource(*resourceEnvelope, vek, vectors.Resource.Context)
	if err != nil {
		t.Fatalf("decrypt resource: %v", err)
	}
	if string(plaintext) != vectors.Resource.Plaintext {
		t.Fatal("decrypted resource does not match vector plaintext")
	}

	keyPair, err := GenerateRecipientKeyPairWithRandom(bytes.NewReader(decodeHex(t, vectors.Recipient.PrivateEntropyHex)))
	if err != nil {
		t.Fatalf("generate recipient key: %v", err)
	}
	if got := hex.EncodeToString(keyPair.PublicKey); got != vectors.Recipient.PublicKeyHex {
		t.Fatalf("public key mismatch: got %s", got)
	}
	recipientEnvelope, err := WrapVEKForRecipientWithRandom(
		vek,
		keyPair.PublicKey,
		vectors.Recipient.Context,
		bytes.NewReader(decodeHex(t, vectors.Recipient.WrapEntropyHex)),
	)
	if err != nil {
		t.Fatalf("wrap VEK: %v", err)
	}
	if !reflect.DeepEqual(*recipientEnvelope, vectors.Recipient.Envelope) {
		got, _ := json.MarshalIndent(recipientEnvelope, "", "  ")
		want, _ := json.MarshalIndent(vectors.Recipient.Envelope, "", "  ")
		t.Fatalf("recipient envelope mismatch\ngot:  %s\nwant: %s", got, want)
	}
	unwrappedVEK, err := UnwrapVEKForRecipient(*recipientEnvelope, keyPair.PrivateKey, vectors.Recipient.Context)
	if err != nil {
		t.Fatalf("unwrap VEK: %v", err)
	}
	if !bytes.Equal(unwrappedVEK, vek) {
		t.Fatal("unwrapped VEK does not match vector VEK")
	}

	for _, vector := range vectors.NameIndexes {
		normalized, err := NormalizeName(vector.InputName)
		if err != nil {
			t.Fatalf("normalize %q: %v", vector.InputName, err)
		}
		if normalized != vector.NormalizedName {
			t.Fatalf("normalized name mismatch: got %q, want %q", normalized, vector.NormalizedName)
		}
		index, err := NameIndexHex(vek, vector.VaultID, vector.InputName)
		if err != nil {
			t.Fatalf("index %q: %v", vector.InputName, err)
		}
		if index != vector.IndexHex {
			t.Fatalf("name index mismatch: got %s, want %s", index, vector.IndexHex)
		}
	}
}

func TestResourceTamperingAndWrongContextFail(t *testing.T) {
	vectors := loadProtocolVectors(t)
	vek := decodeHex(t, vectors.VEKHex)
	envelope := vectors.Resource.Envelope

	t.Run("ciphertext tampering", func(t *testing.T) {
		tampered := envelope
		tampered.Ciphertext = tamperEncoded(t, tampered.Ciphertext)
		_, err := DecryptResource(tampered, vek, vectors.Resource.Context)
		if !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("expected decryption failure, got %v", err)
		}
	})

	t.Run("wrapped DEK tampering", func(t *testing.T) {
		tampered := envelope
		tampered.WrappedDEK.Ciphertext = tamperEncoded(t, tampered.WrappedDEK.Ciphertext)
		_, err := DecryptResource(tampered, vek, vectors.Resource.Context)
		if !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("expected decryption failure, got %v", err)
		}
	})

	t.Run("wrong authenticated resource ID", func(t *testing.T) {
		wrong := vectors.Resource.Context
		wrong.ResourceID = "secret_wrong"
		_, err := DecryptResource(envelope, vek, wrong)
		if !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("expected decryption failure, got %v", err)
		}
	})
}

func TestRecipientTamperingWrongRecipientAndContextFail(t *testing.T) {
	vectors := loadProtocolVectors(t)
	keyPair, err := GenerateRecipientKeyPairWithRandom(bytes.NewReader(decodeHex(t, vectors.Recipient.PrivateEntropyHex)))
	if err != nil {
		t.Fatalf("generate recipient key: %v", err)
	}
	privateKey := keyPair.PrivateKey
	envelope := vectors.Recipient.Envelope

	t.Run("ciphertext tampering", func(t *testing.T) {
		tampered := envelope
		tampered.Ciphertext = tamperEncoded(t, tampered.Ciphertext)
		_, err := UnwrapVEKForRecipient(tampered, privateKey, vectors.Recipient.Context)
		if !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("expected decryption failure, got %v", err)
		}
	})

	t.Run("wrong recipient", func(t *testing.T) {
		other, err := GenerateRecipientKeyPairWithRandom(bytes.NewReader(bytes.Repeat([]byte{0xd1}, 32)))
		if err != nil {
			t.Fatal(err)
		}
		_, err = UnwrapVEKForRecipient(envelope, other.PrivateKey, vectors.Recipient.Context)
		if !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("expected decryption failure, got %v", err)
		}
	})

	t.Run("wrong recipient ID", func(t *testing.T) {
		wrong := vectors.Recipient.Context
		wrong.RecipientID = "recipient_wrong"
		_, err := UnwrapVEKForRecipient(envelope, privateKey, wrong)
		if !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("expected decryption failure, got %v", err)
		}
	})
}

func TestNormalizeNameValidationAndSemantics(t *testing.T) {
	if _, err := NormalizeName(string([]byte{0xff})); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("expected invalid UTF-8 to fail, got %v", err)
	}
	if _, err := NormalizeName("\u2003 \t"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("expected whitespace-only name to fail, got %v", err)
	}
	upper, err := NormalizeName(" API_KEY ")
	if err != nil || upper != "API_KEY" {
		t.Fatalf("unexpected normalized uppercase name: %q, %v", upper, err)
	}
	lower, err := NormalizeName(" api_key ")
	if err != nil || lower != "api_key" || lower == upper {
		t.Fatalf("normalization must remain case-sensitive: %q, %v", lower, err)
	}
}

func loadProtocolVectors(t *testing.T) protocolVectors {
	t.Helper()
	data, err := os.ReadFile("testdata/e2ee-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors protocolVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func tamperEncoded(t *testing.T, value string) string {
	t.Helper()
	decoded, err := decodeBytes(value)
	if err != nil || len(decoded) == 0 {
		t.Fatalf("decode value to tamper: %v", err)
	}
	decoded[len(decoded)-1] ^= 1
	return encodeBytes(decoded)
}
