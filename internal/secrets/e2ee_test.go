package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/secryn/secryn-cli/internal/client"
	secryncrypto "github.com/secryn/secryn-cli/internal/crypto"
	"github.com/secryn/secryn-cli/internal/identity"
)

func TestE2EEServiceListsAndGetsDecryptedSecrets(t *testing.T) {
	fixture := newServiceFixture(t)
	defer fixture.server.Close()
	defer fixture.identity.Destroy()
	api, err := client.New(fixture.server.URL, "access-token", fixture.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewE2EE(api, fixture.identity)
	if err != nil {
		t.Fatal(err)
	}

	items, err := service.List(context.Background(), "vault-uri")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(items) != 1 || items[0].Name != fixture.name || items[0].Value != fixture.value {
		t.Fatal("List() did not return the expected locally decrypted secret")
	}
	item, err := service.Get(context.Background(), "vault-uri", fixture.name)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if item.Name != fixture.name || item.Value != fixture.value {
		t.Fatal("Get() did not return the expected locally decrypted secret")
	}
	if err := service.Test(context.Background(), "vault-uri"); err != nil {
		t.Fatalf("Test() error = %v", err)
	}
}

func TestE2EEServiceRejectsNameIndexMismatch(t *testing.T) {
	fixture := newServiceFixture(t)
	defer fixture.server.Close()
	defer fixture.identity.Destroy()
	fixture.item.NameIndex = strings.Repeat("f", 64)
	api, err := client.New(fixture.server.URL, "access-token", fixture.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewE2EE(api, fixture.identity)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.List(context.Background(), "vault-uri")
	if !errors.Is(err, ErrEnvelopeMismatch) {
		t.Fatalf("List() error = %v, want envelope mismatch", err)
	}
}

func TestE2EEServiceRejectsWrongRecipientPrivateKey(t *testing.T) {
	fixture := newServiceFixture(t)
	defer fixture.server.Close()
	defer fixture.identity.Destroy()
	wrongEncoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xee}, 32))
	wrongIdentity, err := identity.Parse("11111111-1111-4111-8111-111111111111", wrongEncoded)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongIdentity.Destroy()
	api, err := client.New(fixture.server.URL, "access-token", fixture.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewE2EE(api, wrongIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.List(context.Background(), "vault-uri"); err == nil {
		t.Fatal("List() accepted the wrong recipient private key")
	}
}

func TestE2EEServiceDecryptsStrictKeyAndCertificatePayloads(t *testing.T) {
	const (
		vaultID     = "33333333-3333-4333-8333-333333333333"
		recipientID = "11111111-1111-4111-8111-111111111111"
		keyID       = "44444444-4444-4444-8444-444444444444"
		certID      = "55555555-5555-4555-8555-555555555555"
	)
	keyPair, err := secryncrypto.GenerateRecipientKeyPairWithRandom(bytes.NewReader(bytes.Repeat([]byte{0x61}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	vek := bytes.Repeat([]byte{0x62}, 32)
	recipientEnvelope, err := secryncrypto.WrapVEKForRecipientWithRandom(vek, keyPair.PublicKey, secryncrypto.RecipientContext{
		VaultID: vaultID, RecipientID: recipientID, KeyVersion: 1,
	}, bytes.NewReader(bytes.Repeat([]byte{0x63}, 56)))
	if err != nil {
		t.Fatal(err)
	}
	keyItem := encryptResourceFixture(t, vek, vaultID, "key", keyID, "DEPLOY_KEY", map[string]any{
		"name": "DEPLOY_KEY", "material": map[string]any{"pemPrivate": "PRIVATE", "pemPublic": "PUBLIC"},
		"keyType": "RSA", "keySize": 2048, "outputFormat": "pem", "tags": []string{"ci"},
	}, 0x64)
	certItem := encryptResourceFixture(t, vek, vaultID, "certificate", certID, "TLS_CERT", map[string]any{
		"name": "TLS_CERT", "certificatePem": "CERTIFICATE", "privateKeyPem": "CERT_PRIVATE", "tags": []string{"tls"},
	}, 0x65)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/vaults/vault-uri/crypto/envelope":
			_ = json.NewEncoder(w).Encode(client.VaultKeyEnvelope{Version: 1, VaultID: vaultID, RecipientID: recipientID, KeyVersion: 1,
				Algorithm: recipientEnvelope.Algorithm, EphemeralPublicKey: recipientEnvelope.EphemeralPublicKey, Nonce: recipientEnvelope.Nonce, Ciphertext: recipientEnvelope.Ciphertext})
		case r.URL.Path == "/v2/vaults/vault-uri/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "resource_type": "key", "data": []client.EncryptedResource{keyItem}, "meta": map[string]any{"next_cursor": nil}})
		case strings.HasPrefix(r.URL.Path, "/v2/vaults/vault-uri/keys/by-index/") || r.URL.Path == "/v2/vaults/vault-uri/keys/"+keyID:
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "resource_type": "key", "data": keyItem})
		case r.URL.Path == "/v2/vaults/vault-uri/certificates":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "resource_type": "certificate", "data": []client.EncryptedResource{certItem}, "meta": map[string]any{"next_cursor": nil}})
		case strings.HasPrefix(r.URL.Path, "/v2/vaults/vault-uri/certificates/by-index/") || r.URL.Path == "/v2/vaults/vault-uri/certificates/"+certID:
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "resource_type": "certificate", "data": certItem})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	api, err := client.New(server.URL, "access-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ident, err := identity.Parse(recipientID, base64.RawURLEncoding.EncodeToString(keyPair.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	defer ident.Destroy()
	service, _ := NewE2EE(api, ident)
	keys, err := service.ListResources(context.Background(), "vault-uri", "key")
	if err != nil || len(keys) != 1 || keys[0].Material.PEMPrivate != "PRIVATE" || keys[0].KeySize != 2048 {
		t.Fatalf("key resources = %#v, %v", keys, err)
	}
	key, err := service.GetResourceByName(context.Background(), "vault-uri", "key", "DEPLOY_KEY")
	if err != nil || key.ID != keyID {
		t.Fatalf("key by name = %#v, %v", key, err)
	}
	certificate, err := service.GetResourceByID(context.Background(), "vault-uri", "certificate", certID)
	if err != nil || certificate.CertificatePEM != "CERTIFICATE" || certificate.PrivateKeyPEM != "CERT_PRIVATE" {
		t.Fatalf("certificate = %#v, %v", certificate, err)
	}
	if _, err := decryptResource(keyItem, &unlockedVault{id: vaultID, keyVersion: 1, vek: vek}, "certificate"); err == nil {
		t.Fatal("key ciphertext decrypted under certificate AAD")
	}
}

func TestDecryptResourceRejectsUnknownOrIncompletePayload(t *testing.T) {
	const vaultID = "33333333-3333-4333-8333-333333333333"
	vek := bytes.Repeat([]byte{0x72}, 32)
	for _, payload := range []map[string]any{
		{"name": "KEY", "material": map[string]any{}},
		{"name": "KEY", "material": map[string]any{"pemPublic": "PUBLIC"}, "unknown": true},
	} {
		item := encryptResourceFixture(t, vek, vaultID, "key", "66666666-6666-4666-8666-666666666666", "KEY", payload, 0x73)
		if _, err := decryptResource(item, &unlockedVault{id: vaultID, keyVersion: 1, vek: vek}, "key"); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("decryptResource() error = %v", err)
		}
	}
}

func encryptResourceFixture(t *testing.T, vek []byte, vaultID, resourceType, id, name string, payload any, marker byte) client.EncryptedResource {
	t.Helper()
	plaintext, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := secryncrypto.EncryptResourceWithRandom(plaintext, vek, secryncrypto.ResourceContext{
		VaultID: vaultID, ResourceType: resourceType, ResourceID: id, AADVersion: 1, KeyVersion: 1,
	}, bytes.NewReader(bytes.Repeat([]byte{marker}, 80)))
	if err != nil {
		t.Fatal(err)
	}
	nameIndex, err := secryncrypto.NameIndexHex(vek, vaultID, name)
	if err != nil {
		t.Fatal(err)
	}
	return client.EncryptedResource{ID: id, VaultID: vaultID, NameIndex: nameIndex, Version: 1, AADVersion: 1, KeyVersion: 1,
		Nonce: envelope.Nonce, Ciphertext: envelope.Ciphertext, WrappedDEK: envelope.WrappedDEK, UpdatedAt: "2026-09-20T00:00:00Z"}
}

type serviceFixture struct {
	server   *httptest.Server
	identity *identity.Identity
	item     client.EncryptedSecret
	name     string
	value    string
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	const (
		vaultID     = "33333333-3333-4333-8333-333333333333"
		recipientID = "11111111-1111-4111-8111-111111111111"
		secretID    = "22222222-2222-4222-8222-222222222222"
		secretName  = "PIPELINE_TOKEN"
		secretValue = "fixture-value"
	)
	keyPair, err := secryncrypto.GenerateRecipientKeyPairWithRandom(bytes.NewReader(bytes.Repeat([]byte{0x11}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	vek := bytes.Repeat([]byte{0x22}, 32)
	recipientContext := secryncrypto.RecipientContext{VaultID: vaultID, RecipientID: recipientID, KeyVersion: 1}
	recipientEnvelope, err := secryncrypto.WrapVEKForRecipientWithRandom(
		vek, keyPair.PublicKey, recipientContext, bytes.NewReader(bytes.Repeat([]byte{0x33}, 56)),
	)
	if err != nil {
		t.Fatal(err)
	}
	resourceContext := secryncrypto.ResourceContext{
		VaultID: vaultID, ResourceType: "secret", ResourceID: secretID, AADVersion: 1, KeyVersion: 1,
	}
	plaintext, err := json.Marshal(map[string]any{
		"name": secretName, "value": secretValue, "contentType": "text/plain", "tags": []string{"fixture"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceEnvelope, err := secryncrypto.EncryptResourceWithRandom(
		plaintext, vek, resourceContext, bytes.NewReader(bytes.Repeat([]byte{0x44}, 80)),
	)
	if err != nil {
		t.Fatal(err)
	}
	nameIndex, err := secryncrypto.NameIndexHex(vek, vaultID, secretName)
	if err != nil {
		t.Fatal(err)
	}
	item := client.EncryptedSecret{
		ID: secretID, VaultID: vaultID, NameIndex: nameIndex, Version: resourceEnvelope.Version,
		AADVersion: resourceEnvelope.AADVersion, KeyVersion: resourceEnvelope.KeyVersion,
		Nonce: resourceEnvelope.Nonce, Ciphertext: resourceEnvelope.Ciphertext,
		WrappedDEK: resourceEnvelope.WrappedDEK, Enabled: true, UpdatedAt: "2026-09-20T00:00:00Z",
	}
	fixture := &serviceFixture{item: item, name: secretName, value: secretValue}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/vaults/vault-uri/crypto/envelope":
			if r.Header.Get("X-Secryn-Recipient-ID") != recipientID {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(client.VaultKeyEnvelope{
				Version: recipientEnvelope.Version, VaultID: vaultID, RecipientID: recipientID,
				KeyVersion: recipientEnvelope.KeyVersion, Algorithm: recipientEnvelope.Algorithm,
				EphemeralPublicKey: recipientEnvelope.EphemeralPublicKey, Nonce: recipientEnvelope.Nonce,
				Ciphertext: recipientEnvelope.Ciphertext,
			})
		case r.URL.Path == "/v2/vaults/vault-uri/secrets":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "data": []client.EncryptedSecret{fixture.item}, "meta": map[string]any{"next_cursor": nil}})
		case strings.HasPrefix(r.URL.Path, "/v2/vaults/vault-uri/secrets/by-index/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "data": fixture.item})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	encodedPrivateKey := base64.RawURLEncoding.EncodeToString(keyPair.PrivateKey)
	fixture.identity, err = identity.Parse(recipientID, encodedPrivateKey)
	if err != nil {
		fixture.server.Close()
		t.Fatal(err)
	}
	return fixture
}
