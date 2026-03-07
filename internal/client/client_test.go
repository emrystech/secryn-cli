package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListSecretsWrappedInVaultObject(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/vaults/vault-1" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"message":"unexpected path"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{
			"id":"8d242894-044e-461e-a0cc-d5f63841b7d7",
			"name":"stripe-ca",
			"secrets":[
				{
					"id":"ce144f6a-a662-4cd2-9325-cb93698b9ff1",
					"name":"secryn-payout-link-1",
					"value":"https://buy.stripe.com/eVq8wH64Re5Camo5iV8AE00",
					"content_type":"text/plain",
					"tags":[]
				}
			]
		}`)
	}))
	defer ts.Close()

	cli, err := New(ts.URL, "token", ts.Client())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	secrets, err := cli.ListSecrets(context.Background(), "vault-1")
	if err != nil {
		t.Fatalf("ListSecrets() error = %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("len(secrets) = %d, want 1", len(secrets))
	}
	if secrets[0].Name != "secryn-payout-link-1" {
		t.Fatalf("secrets[0].Name = %q, want secryn-payout-link-1", secrets[0].Name)
	}
	if secrets[0].Value != "https://buy.stripe.com/eVq8wH64Re5Camo5iV8AE00" {
		t.Fatalf("secrets[0].Value = %q, unexpected", secrets[0].Value)
	}
}

func TestGetSecretFallsBackToVaultPayloadOn404(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/vaults/vault-1/secrets/DB_PASSWORD":
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"message":"not found"}`)
		case "/v1/vaults/vault-1":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{
				"id":"vault-id",
				"name":"vault",
				"secrets":[{"name":"DB_PASSWORD","value":"super-secret"}]
			}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"message":"unexpected path"}`)
		}
	}))
	defer ts.Close()

	cli, err := New(ts.URL, "token", ts.Client())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	secret, err := cli.GetSecret(context.Background(), "vault-1", "DB_PASSWORD")
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if secret.Name != "DB_PASSWORD" {
		t.Fatalf("secret.Name = %q, want DB_PASSWORD", secret.Name)
	}
	if secret.Value != "super-secret" {
		t.Fatalf("secret.Value = %q, want super-secret", secret.Value)
	}
}

func TestAPIErrorHandling(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		body       string
		wantMsg    string
	}{
		{name: "unauthorized", statusCode: http.StatusUnauthorized, body: `{"message":"bad token"}`, wantMsg: "bad token"},
		{name: "forbidden", statusCode: http.StatusForbidden, body: `{"error":"denied"}`, wantMsg: "denied"},
		{name: "not-found", statusCode: http.StatusNotFound, body: `{"detail":"missing"}`, wantMsg: "missing"},
		{name: "gone", statusCode: http.StatusGone, body: "", wantMsg: "Gone"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/vaults/vault-1" {
					w.WriteHeader(http.StatusNotFound)
					_, _ = fmt.Fprint(w, `{"message":"unexpected path"}`)
					return
				}
				w.WriteHeader(tt.statusCode)
				_, _ = fmt.Fprint(w, tt.body)
			}))
			defer ts.Close()

			cli, err := New(ts.URL, "token", ts.Client())
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			_, err = cli.ListSecrets(context.Background(), "vault-1")
			if err == nil {
				t.Fatalf("ListSecrets() expected error")
			}

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("ListSecrets() error type = %T, want *APIError", err)
			}
			if apiErr.StatusCode != tt.statusCode {
				t.Fatalf("status = %d, want %d", apiErr.StatusCode, tt.statusCode)
			}
			if apiErr.Message != tt.wantMsg {
				t.Fatalf("message = %q, want %q", apiErr.Message, tt.wantMsg)
			}
		})
	}
}
