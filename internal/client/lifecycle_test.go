package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	secryncrypto "github.com/secryn/secryn-cli/internal/crypto"
)

type lifecycleRoundTripFunc func(*http.Request) (*http.Response, error)

func (f lifecycleRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func lifecycleClient(t *testing.T, handler lifecycleRoundTripFunc) *Client {
	t.Helper()
	result, err := New("https://example.test", "access-key", &http.Client{Transport: handler})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func lifecycleResponse(status int, body any) *http.Response {
	payload, _ := json.Marshal(body)
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(payload))}
}

func TestGetCryptoContextValidatesModeKeyVersion(t *testing.T) {
	client := lifecycleClient(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/v2/vaults/vault-uri/crypto/context" || request.Header.Get("Authorization") != "Bearer access-key" {
			t.Fatalf("unexpected request: %s", request.URL.String())
		}
		return lifecycleResponse(http.StatusOK, map[string]any{
			"version": 1, "vault_id": "11111111-1111-4111-8111-111111111111",
			"encryption_mode": "e2ee", "key_version": 3, "bootstrap_eligible": false,
		}), nil
	})
	result, err := client.GetCryptoContext(context.Background(), "vault-uri")
	if err != nil || result.KeyVersion == nil || *result.KeyVersion != 3 {
		t.Fatalf("GetCryptoContext() = %#v, %v", result, err)
	}
}

func TestBootstrapRejectsSubstitutedResponse(t *testing.T) {
	request := lifecycleProvisionFixture()
	for _, mutate := range []func(*LifecycleResult){
		func(result *LifecycleResult) { result.Recipient.ID = "22222222-2222-4222-8222-222222222222" },
		func(result *LifecycleResult) { result.Recipient.Label = "swapped" },
		func(result *LifecycleResult) {
			result.Envelope.Ciphertext = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 48))
		},
	} {
		t.Run("substitution", func(t *testing.T) {
			responseEnvelope := request.Envelope
			response := LifecycleResult{Version: 1, VaultID: "11111111-1111-4111-8111-111111111111", EncryptionMode: "e2ee", KeyVersion: 1,
				Recipient: &Recipient{ID: request.Recipient.ID, Type: request.Recipient.Type, Label: request.Recipient.Label, PublicKey: request.Recipient.PublicKey, PublicKeyFingerprint: request.Recipient.PublicKeyFingerprint, Status: "active"},
				Envelope:  &responseEnvelope}
			mutate(&response)
			client := lifecycleClient(t, func(*http.Request) (*http.Response, error) {
				return lifecycleResponse(http.StatusCreated, response), nil
			})
			if _, err := client.BootstrapE2EE(context.Background(), "vault-uri", request); err == nil || !strings.Contains(err.Error(), "does not match") {
				t.Fatalf("BootstrapE2EE() error = %v", err)
			}
		})
	}
}

func TestRotationLifecycleRoutesAndBindsCommitID(t *testing.T) {
	rotationID := "33333333-3333-4333-8333-333333333333"
	storageID := "44444444-4444-4444-8444-444444444444"
	resourceID := "55555555-5555-4555-8555-555555555555"
	vaultID := "11111111-1111-4111-8111-111111111111"
	sourceDigest := strings.Repeat("d", 64)
	requests := 0
	client := lifecycleClient(t, func(request *http.Request) (*http.Response, error) {
		requests++
		switch requests {
		case 1:
			if request.Method != http.MethodGet || request.URL.Query().Get("kind") != "secret" || request.URL.Query().Get("limit") != "5" {
				t.Fatalf("unexpected source request: %s %s", request.Method, request.URL.String())
			}
			return lifecycleResponse(http.StatusOK, map[string]any{"version": 1, "data": []any{map[string]any{
				"kind": "secret", "storage_id": storageID, "resource_id": resourceID, "vault_id": vaultID,
				"source_digest": sourceDigest,
				"name_index":    strings.Repeat("a", 64), "version": 1, "aad_version": 1, "key_version": 1,
				"nonce":       base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 24)),
				"ciphertext":  base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16)),
				"wrapped_dek": map[string]any{"nonce": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 24)), "ciphertext": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 48))},
			}}, "meta": map[string]any{"next_cursor": nil}}), nil
		case 2:
			if request.Method != http.MethodPut {
				t.Fatalf("unexpected stage method: %s", request.Method)
			}
			var staged struct {
				Items []RotationStageItem `json:"items"`
			}
			if err := json.NewDecoder(request.Body).Decode(&staged); err != nil || len(staged.Items) != 1 || staged.Items[0].SourceDigest != sourceDigest {
				t.Fatalf("stage did not echo the exact source digest: %#v, %v", staged.Items, err)
			}
			return lifecycleResponse(http.StatusOK, map[string]any{"version": 1, "staged": 1}), nil
		case 3:
			return lifecycleResponse(http.StatusOK, map[string]any{"version": 1, "data": map[string]any{
				"id": "66666666-6666-4666-8666-666666666666", "from_key_version": 1, "to_key_version": 2,
				"status": "committed", "expected_secrets": 1, "expected_secret_versions": 0, "staged": 1, "committed_at": "2026-01-01T00:00:00Z",
			}}), nil
		default:
			t.Fatal("unexpected request")
			return nil, nil
		}
	})
	items, err := client.ListRotationSource(context.Background(), "vault-uri", rotationID, "secret")
	if err != nil || len(items) != 1 {
		t.Fatalf("ListRotationSource() = %d, %v", len(items), err)
	}
	if err := client.StageRotationItems(context.Background(), "vault-uri", rotationID, []RotationStageItem{{Kind: "secret", StorageID: storageID, SourceDigest: items[0].SourceDigest, NameIndex: strings.Repeat("b", 64), WrappedDEK: items[0].WrappedDEK}}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CommitRotation(context.Background(), "vault-uri", rotationID); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("CommitRotation() error = %v", err)
	}
}

func TestRotationSourceRejectsMissingOrMalformedDigest(t *testing.T) {
	rotationID := "33333333-3333-4333-8333-333333333333"
	base := map[string]any{
		"kind": "secret_version", "storage_id": "44444444-4444-4444-8444-444444444444",
		"resource_id": "55555555-5555-4555-8555-555555555555", "vault_id": "11111111-1111-4111-8111-111111111111",
		"name_index": strings.Repeat("a", 64), "version": 1, "aad_version": 1, "key_version": 1,
		"nonce":       base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 24)),
		"ciphertext":  base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16)),
		"wrapped_dek": map[string]any{"nonce": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 24)), "ciphertext": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 48))},
	}
	for _, digest := range []any{nil, strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 63)} {
		t.Run("invalid digest", func(t *testing.T) {
			item := make(map[string]any, len(base)+1)
			for key, value := range base {
				item[key] = value
			}
			if digest != nil {
				item["source_digest"] = digest
			}
			client := lifecycleClient(t, func(*http.Request) (*http.Response, error) {
				return lifecycleResponse(http.StatusOK, map[string]any{"version": 1, "data": []any{item}, "meta": map[string]any{"next_cursor": nil}}), nil
			})
			if _, err := client.ListRotationSource(context.Background(), "vault-uri", rotationID, "secret_version"); err == nil {
				t.Fatal("rotation source accepted a missing or malformed source digest")
			}
		})
	}
}

func TestRotationStageRejectsMissingOrMalformedDigestBeforeNetwork(t *testing.T) {
	requests := 0
	client := lifecycleClient(t, func(*http.Request) (*http.Response, error) {
		requests++
		return lifecycleResponse(http.StatusInternalServerError, nil), nil
	})
	base := RotationStageItem{
		Kind: "secret_version", StorageID: "44444444-4444-4444-8444-444444444444", NameIndex: strings.Repeat("b", 64),
		WrappedDEK: secryncrypto.WrappedKeyEnvelope{
			Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 48)),
		},
	}
	for _, digest := range []string{"", strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 63)} {
		item := base
		item.SourceDigest = digest
		if err := client.StageRotationItems(context.Background(), "vault-uri", "33333333-3333-4333-8333-333333333333", []RotationStageItem{item}); err == nil {
			t.Fatal("rotation stage accepted a missing or malformed source digest")
		}
	}
	if requests != 0 {
		t.Fatalf("invalid source digest reached the network %d times", requests)
	}
}

func lifecycleProvisionFixture() RecipientProvisionRequest {
	publicKey := bytes.Repeat([]byte{5}, 32)
	fingerprint := sha256.Sum256(publicKey)
	return RecipientProvisionRequest{
		Recipient: RecipientWrite{ID: "11111111-1111-4111-8111-111111111111", Type: "cli", Label: "CLI", PublicKey: base64.RawURLEncoding.EncodeToString(publicKey), PublicKeyFingerprint: hex.EncodeToString(fingerprint[:])},
		Envelope:  RecipientEnvelopeWrite{Version: 1, KeyVersion: 1, Algorithm: "X25519-HKDF-SHA256-XCHACHA20-POLY1305", EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)), Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 48))},
	}
}
