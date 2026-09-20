package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	secryncrypto "github.com/secryn/secryn-cli/internal/crypto"
)

func TestGetVaultKeyEnvelopeUsesRecipientHeader(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/vaults/vault-uri/crypto/envelope" || r.Header.Get("X-Secryn-Recipient-ID") != "11111111-1111-4111-8111-111111111111" {
			t.Error("request did not use the v2 envelope endpoint and recipient header")
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			t.Error("request did not retain access-key authorization")
		}
		_, _ = fmt.Fprintf(w, `{"version":1,"vault_id":"33333333-3333-4333-8333-333333333333","recipient_id":"11111111-1111-4111-8111-111111111111","key_version":3,"algorithm":"%s","ephemeral_public_key":"%s","nonce":"%s","ciphertext":"%s"}`,
			secryncrypto.RecipientWrapAlgorithm, encodedBytes(32, 1), encodedBytes(24, 2), encodedBytes(48, 3))
	}))
	defer ts.Close()

	api := newTestClient(t, ts)
	envelope, err := api.GetVaultKeyEnvelope(context.Background(), "vault-uri", "11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatalf("GetVaultKeyEnvelope() error = %v", err)
	}
	if envelope.VaultID != "33333333-3333-4333-8333-333333333333" || envelope.KeyVersion != 3 {
		t.Fatal("decoded vault key envelope metadata is invalid")
	}
}

func TestEncryptedSecretReadEndpoints(t *testing.T) {
	item := encryptedSecretFixture()
	nameIndex := item.NameIndex
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/vaults/vault-uri/secrets":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "data": []EncryptedSecret{item}, "meta": map[string]any{"next_cursor": nil}})
		case "/v2/vaults/vault-uri/secrets/by-index/" + nameIndex,
			"/v2/vaults/vault-uri/secrets/22222222-2222-4222-8222-222222222222":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "data": item})
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	api := newTestClient(t, ts)

	listed, err := api.ListEncryptedSecrets(context.Background(), "vault-uri")
	if err != nil || len(listed) != 1 || listed[0].ID != item.ID {
		t.Fatalf("ListEncryptedSecrets() = %#v, %v", listed, err)
	}
	byIndex, err := api.GetEncryptedSecretByIndex(context.Background(), "vault-uri", nameIndex)
	if err != nil || byIndex.ID != item.ID {
		t.Fatalf("GetEncryptedSecretByIndex() returned invalid result: %v", err)
	}
	byID, err := api.GetEncryptedSecret(context.Background(), "vault-uri", "22222222-2222-4222-8222-222222222222")
	if err != nil || byID.NameIndex != nameIndex {
		t.Fatalf("GetEncryptedSecret() returned invalid result: %v", err)
	}
}

func TestEncryptedSecretMutationEndpoints(t *testing.T) {
	item := encryptedSecretFixture()
	input := EncryptedSecretWrite{
		ID: item.ID, NameIndex: item.NameIndex, Version: item.Version, AADVersion: item.AADVersion,
		KeyVersion: item.KeyVersion, Nonce: item.Nonce, Ciphertext: item.Ciphertext,
		WrappedDEK: item.WrappedDEK, Enabled: true,
	}
	var methods []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method+" "+r.URL.Path)
		if r.URL.Query().Get("access_key") != "" {
			t.Error("API v2 must not use query-string access-key fallback")
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var got EncryptedSecretWrite
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode write request: %v", err)
		}
		if got.NameIndex != input.NameIndex || got.Ciphertext != input.Ciphertext {
			t.Error("write request changed opaque encrypted fields")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "data": item})
	}))
	defer ts.Close()
	api := newTestClient(t, ts)
	ctx := context.Background()

	if _, err := api.CreateEncryptedSecret(ctx, "vault-uri", input); err != nil {
		t.Fatalf("CreateEncryptedSecret() error = %v", err)
	}
	input.ID = ""
	if _, err := api.UpdateEncryptedSecret(ctx, "vault-uri", item.ID, input); err != nil {
		t.Fatalf("UpdateEncryptedSecret() error = %v", err)
	}
	if _, err := api.PatchEncryptedSecret(ctx, "vault-uri", item.ID, input); err != nil {
		t.Fatalf("PatchEncryptedSecret() error = %v", err)
	}
	if err := api.DeleteEncryptedSecret(ctx, "vault-uri", item.ID); err != nil {
		t.Fatalf("DeleteEncryptedSecret() error = %v", err)
	}
	want := []string{
		"POST /v2/vaults/vault-uri/secrets", "PUT /v2/vaults/vault-uri/secrets/22222222-2222-4222-8222-222222222222",
		"PATCH /v2/vaults/vault-uri/secrets/22222222-2222-4222-8222-222222222222", "DELETE /v2/vaults/vault-uri/secrets/22222222-2222-4222-8222-222222222222",
	}
	if strings.Join(methods, "|") != strings.Join(want, "|") {
		t.Fatalf("mutation requests = %v, want %v", methods, want)
	}
}

func TestAPIV2FailsClosedWithoutLegacyOrQueryRetry(t *testing.T) {
	var requests atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Query().Get("access_key") != "" {
			t.Error("E2EE request attempted an insecure fallback")
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"message":"not authorized"}`)
	}))
	defer ts.Close()
	api := newTestClient(t, ts)
	_, err := api.ListEncryptedSecrets(context.Background(), "vault-uri")
	if err == nil || requests.Load() != 1 {
		t.Fatalf("ListEncryptedSecrets() error = %v, requests = %d", err, requests.Load())
	}
}

func TestAPIV2RejectsUnknownVersionAndMalformedEnvelope(t *testing.T) {
	item := encryptedSecretFixture()
	item.Version = 2
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "data": item})
	}))
	defer ts.Close()
	api := newTestClient(t, ts)
	if _, err := api.GetEncryptedSecret(context.Background(), "vault-uri", "22222222-2222-4222-8222-222222222222"); err == nil {
		t.Fatal("unknown crypto version was accepted")
	}
}

func TestAPIV2RejectsUnknownResponseVersionAndMalformedEncoding(t *testing.T) {
	tests := []struct {
		name            string
		responseVersion int
		mutate          func(*EncryptedSecret)
	}{
		{name: "unknown response version", responseVersion: 2, mutate: func(*EncryptedSecret) {}},
		{name: "malformed nonce", responseVersion: 1, mutate: func(item *EncryptedSecret) { item.Nonce = "not+base64url" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			item := encryptedSecretFixture()
			test.mutate(&item)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"version": test.responseVersion, "data": []EncryptedSecret{item}, "meta": map[string]any{"next_cursor": nil}})
			}))
			defer server.Close()
			api := newTestClient(t, server)
			if _, err := api.ListEncryptedSecrets(context.Background(), "vault-uri"); err == nil {
				t.Fatal("malformed or unsupported API v2 response was accepted")
			}
		})
	}
}

func TestListEncryptedSecretsFollowsCursorPagination(t *testing.T) {
	first := encryptedSecretFixture()
	second := encryptedSecretFixture()
	second.ID = "44444444-4444-4444-8444-444444444444"
	second.NameIndex = strings.Repeat("b", 64)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Query().Get("limit") != "5" {
			t.Error("client did not request the bounded page limit")
		}
		if requests == 1 {
			if r.URL.Query().Get("cursor") != "" {
				t.Error("first page unexpectedly included a cursor")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "data": []EncryptedSecret{first}, "meta": map[string]any{"next_cursor": first.ID}})
			return
		}
		if r.URL.Query().Get("cursor") != first.ID {
			t.Error("second page did not use the server cursor")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "data": []EncryptedSecret{second}, "meta": map[string]any{"next_cursor": nil}})
	}))
	defer server.Close()
	api := newTestClient(t, server)
	items, err := api.ListEncryptedSecrets(context.Background(), "vault-uri")
	if err != nil || len(items) != 2 || requests != 2 {
		t.Fatalf("paginated list failed: count=%d requests=%d error=%v", len(items), requests, err)
	}
}

func TestListEncryptedSecretsRejectsCursorLoops(t *testing.T) {
	item := encryptedSecretFixture()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "data": []EncryptedSecret{item}, "meta": map[string]any{"next_cursor": item.ID}})
	}))
	defer server.Close()
	api := newTestClient(t, server)
	if _, err := api.ListEncryptedSecrets(context.Background(), "vault-uri"); err == nil {
		t.Fatal("cursor loop was accepted")
	}
}

func TestEncryptedSecretResponsesAreBoundToRequests(t *testing.T) {
	base := encryptedSecretFixture()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		item := base
		switch {
		case strings.Contains(r.URL.Path, "/by-index/"):
			item.NameIndex = strings.Repeat("b", 64)
		case r.Method == http.MethodGet:
			item.ID = "44444444-4444-4444-8444-444444444444"
		case r.Method == http.MethodPost:
			item.Ciphertext = encodedBytes(32, 9)
		case r.Method == http.MethodPut || r.Method == http.MethodPatch:
			item.Nonce = encodedBytes(24, 9)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "data": item})
	}))
	defer server.Close()
	api := newTestClient(t, server)
	ctx := context.Background()
	if _, err := api.GetEncryptedSecretByIndex(ctx, "vault-uri", base.NameIndex); err == nil {
		t.Fatal("by-index response substitution was accepted")
	}
	if _, err := api.GetEncryptedSecret(ctx, "vault-uri", base.ID); err == nil {
		t.Fatal("by-ID response substitution was accepted")
	}
	input := EncryptedSecretWrite{
		ID: base.ID, NameIndex: base.NameIndex, Version: base.Version, AADVersion: base.AADVersion,
		KeyVersion: base.KeyVersion, Nonce: base.Nonce, Ciphertext: base.Ciphertext,
		WrappedDEK: base.WrappedDEK, Enabled: true,
	}
	if _, err := api.CreateEncryptedSecret(ctx, "vault-uri", input); err == nil {
		t.Fatal("create response substitution was accepted")
	}
	input.ID = ""
	if _, err := api.UpdateEncryptedSecret(ctx, "vault-uri", base.ID, input); err == nil {
		t.Fatal("update response substitution was accepted")
	}
	if _, err := api.PatchEncryptedSecret(ctx, "vault-uri", base.ID, input); err == nil {
		t.Fatal("patch response substitution was accepted")
	}
}

func encryptedSecretFixture() EncryptedSecret {
	return EncryptedSecret{
		ID: "22222222-2222-4222-8222-222222222222", VaultID: "33333333-3333-4333-8333-333333333333", NameIndex: strings.Repeat("a", 64),
		Version: 1, AADVersion: 1, KeyVersion: 3, Nonce: encodedBytes(24, 4),
		Ciphertext: encodedBytes(32, 5), WrappedDEK: secryncrypto.WrappedKeyEnvelope{
			Nonce: encodedBytes(24, 6), Ciphertext: encodedBytes(48, 7),
		}, Enabled: true,
	}
}

func encodedBytes(count int, value byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{value}), count)))
}

func newTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	api, err := New(server.URL, "access-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return api
}
