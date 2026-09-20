package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEncryptedResourceReadEndpointsAndPagination(t *testing.T) {
	first := encryptedSecretFixture()
	second := encryptedSecretFixture()
	second.ID = "44444444-4444-4444-8444-444444444444"
	second.NameIndex = strings.Repeat("b", 64)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/vaults/vault-uri/keys":
			requests++
			if r.URL.Query().Get("limit") != "5" {
				t.Error("resource list did not use limit 5")
			}
			if requests == 1 {
				_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "resource_type": "key", "data": []EncryptedResource{first}, "meta": map[string]any{"next_cursor": first.ID}})
				return
			}
			if r.URL.Query().Get("cursor") != first.ID {
				t.Error("resource list did not follow the cursor")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "resource_type": "key", "data": []EncryptedResource{second}, "meta": map[string]any{"next_cursor": nil}})
		case r.URL.Path == "/v2/vaults/vault-uri/keys/by-index/"+first.NameIndex,
			r.URL.Path == "/v2/vaults/vault-uri/keys/"+first.ID:
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "resource_type": "key", "data": first})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	api := newTestClient(t, server)

	listed, err := api.ListEncryptedResources(context.Background(), "vault-uri", "key")
	if err != nil || len(listed) != 2 || requests != 2 {
		t.Fatalf("ListEncryptedResources() = %d items, %d requests, %v", len(listed), requests, err)
	}
	if _, err := api.GetEncryptedResourceByIndex(context.Background(), "vault-uri", "key", first.NameIndex); err != nil {
		t.Fatalf("GetEncryptedResourceByIndex() error = %v", err)
	}
	if _, err := api.GetEncryptedResource(context.Background(), "vault-uri", "key", first.ID); err != nil {
		t.Fatalf("GetEncryptedResource() error = %v", err)
	}
}

func TestEncryptedResourceResponsesAreBoundAndTyped(t *testing.T) {
	base := encryptedSecretFixture()
	tests := []struct {
		name      string
		kind      string
		requested string
		resource  string
		mutate    func(*EncryptedResource)
		wrongType string
	}{
		{name: "index substitution", kind: "index", requested: base.NameIndex, resource: "key", mutate: func(item *EncryptedResource) { item.NameIndex = strings.Repeat("b", 64) }},
		{name: "id substitution", kind: "id", requested: base.ID, resource: "certificate", mutate: func(item *EncryptedResource) { item.ID = "44444444-4444-4444-8444-444444444444" }},
		{name: "resource type substitution", kind: "id", requested: base.ID, resource: "key", mutate: func(*EncryptedResource) {}, wrongType: "certificate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				item := base
				test.mutate(&item)
				responseType := test.resource
				if test.wrongType != "" {
					responseType = test.wrongType
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "resource_type": responseType, "data": item})
			}))
			defer server.Close()
			api := newTestClient(t, server)
			var err error
			if test.kind == "index" {
				_, err = api.GetEncryptedResourceByIndex(context.Background(), "vault-uri", test.resource, test.requested)
			} else {
				_, err = api.GetEncryptedResource(context.Background(), "vault-uri", test.resource, test.requested)
			}
			if err == nil {
				t.Fatal("substituted encrypted resource response was accepted")
			}
		})
	}
}
