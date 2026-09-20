package crypto

import (
	"bytes"
	"testing"
)

func TestRewrapResourceDEKPreservesPayloadAndChangesKeyVersion(t *testing.T) {
	oldVEK := bytes.Repeat([]byte{0x21}, VEKSize)
	newVEK := bytes.Repeat([]byte{0x22}, VEKSize)
	context := ResourceContext{
		VaultID: "33333333-3333-4333-8333-333333333333", ResourceType: "secret",
		ResourceID: "22222222-2222-4222-8222-222222222222", AADVersion: 1, KeyVersion: 1,
	}
	envelope, err := EncryptResourceWithRandom([]byte(`{"name":"FIXTURE","value":"value"}`), oldVEK, context, bytes.NewReader(bytes.Repeat([]byte{0x31}, 80)))
	if err != nil {
		t.Fatal(err)
	}
	rewrapped, err := RewrapResourceDEKWithRandom(*envelope, oldVEK, newVEK, context, 2, bytes.NewReader(bytes.Repeat([]byte{0x41}, 24)))
	if err != nil {
		t.Fatal(err)
	}
	rotated := *envelope
	rotated.KeyVersion = 2
	rotated.WrappedDEK = *rewrapped
	targetContext := context
	targetContext.KeyVersion = 2
	plaintext, err := DecryptResource(rotated, newVEK, targetContext)
	if err != nil {
		t.Fatalf("decrypt rewrapped resource: %v", err)
	}
	if string(plaintext) != `{"name":"FIXTURE","value":"value"}` || rotated.Ciphertext != envelope.Ciphertext || rotated.Nonce != envelope.Nonce {
		t.Fatal("rewrap changed the payload or failed to preserve plaintext")
	}
	if _, err := DecryptResource(rotated, oldVEK, targetContext); err == nil {
		t.Fatal("rewrapped DEK remained decryptable with the old VEK")
	}
	if _, err := RewrapResourceDEKWithRandom(*envelope, newVEK, oldVEK, context, 2, bytes.NewReader(bytes.Repeat([]byte{0x51}, 24))); err == nil {
		t.Fatal("rewrap accepted the wrong old VEK")
	}
	if _, err := RewrapResourceDEKWithRandom(*envelope, oldVEK, newVEK, context, 0, bytes.NewReader(bytes.Repeat([]byte{0x51}, 24))); err == nil {
		t.Fatal("rewrap accepted an invalid target key version")
	}
}

func TestRecipientPublicKeyDerivesPersistedIdentity(t *testing.T) {
	keyPair, err := GenerateRecipientKeyPairWithRandom(bytes.NewReader(bytes.Repeat([]byte{0x61}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := RecipientPublicKey(keyPair.PrivateKey)
	if err != nil || !bytes.Equal(publicKey, keyPair.PublicKey) {
		t.Fatalf("RecipientPublicKey() mismatch: %v", err)
	}
	if _, err := RecipientPublicKey([]byte("short")); err == nil {
		t.Fatal("RecipientPublicKey() accepted malformed private key")
	}
}
